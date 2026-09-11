"""
Tests for the hardened async core: SSRF-safe redirects, the token-bucket rate
limiter and the bounded worker pool (backpressure + clean cancellation).

These use a fake aiohttp session (no network) so they are fast and hermetic.
"""

import asyncio
import time

import pytest

from web_security_scanner.core.scanner_core_async import (
    AsyncScannerCore,
    PinnedResolver,
    ScanConfig,
    SSRFRedirectError,
    TokenBucket,
    worker_pool,
)

# --- fake aiohttp session -------------------------------------------------

class FakeResponse:
    """Stands in for aiohttp's request context manager + response."""

    def __init__(self, status=200, headers=None, text=""):
        self.status = status
        self.headers = headers or {}
        self._text = text
        self.url = "http://target.example/"
        self.content = _FakeContent(text.encode() if isinstance(text, str) else text)
        self.closed = False

    async def text(self, errors="ignore"):
        return self._text

    def get_encoding(self):
        return "utf-8"

    def close(self):
        self.closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeContent:
    """Minimal stand-in for aiohttp's StreamReader."""

    def __init__(self, body: bytes):
        self._body = body

    async def iter_chunked(self, n):
        for i in range(0, len(self._body), n):
            yield self._body[i : i + n]


class FakeSession:
    def __init__(self, handler):
        self._handler = handler
        self.closed = False
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append((method, str(url), kwargs))
        return self._handler(method, str(url), kwargs)

    async def close(self):
        self.closed = True


def make_core(handler, **cfg):
    core = AsyncScannerCore(ScanConfig(**cfg))
    core.session = FakeSession(handler)
    return core


# --- SSRF: redirect protection -----------------------------------------

async def test_redirect_to_metadata_ip_is_blocked():
    """A 302 -> http://169.254.169.254/latest/meta-data/ must abort."""
    def handler(method, url, kwargs):
        if "169.254.169.254" in url:
            return FakeResponse(200, {}, "iam/security-credentials/...")
        return FakeResponse(
            302, {"Location": "http://169.254.169.254/latest/meta-data/"}
        )

    core = make_core(handler)
    with pytest.raises(SSRFRedirectError):
        await core.request("GET", "http://target.example/fetch?url=x")

    # The internal metadata endpoint was never actually contacted.
    assert all("169.254.169.254" not in u for _, u, _ in core.session.requests)


async def test_relative_redirect_to_loopback_is_blocked():
    def handler(method, url, kwargs):
        return FakeResponse(301, {"Location": "http://127.0.0.1:8080/admin"})

    core = make_core(handler)
    with pytest.raises(SSRFRedirectError):
        await core.request("GET", "http://target.example/go")


async def test_redirect_to_public_host_is_followed():
    def handler(method, url, kwargs):
        if url.endswith("/final"):
            return FakeResponse(200, {"X-Ok": "1"}, "final page")
        return FakeResponse(302, {"Location": "https://93.184.216.34/final"})

    core = make_core(handler)
    res = await core.request("GET", "http://target.example/start")
    assert res["status_code"] == 200
    assert res["text"] == "final page"


async def test_private_redirect_allowed_when_opted_in():
    def handler(method, url, kwargs):
        if "127.0.0.1" in url:
            return FakeResponse(200, {}, "internal ok")
        return FakeResponse(307, {"Location": "http://127.0.0.1:9000/x"})

    core = make_core(handler, allow_private_redirects=True)
    res = await core.request("GET", "http://target.example/")
    assert res["status_code"] == 200
    assert res["text"] == "internal ok"


async def test_cross_host_redirect_drops_injected_headers_and_cookies():
    """A payload in a request header / session cookie must not be replayed to
    a third-party host the target redirects us to."""
    seen = []

    def handler(method, url, kwargs):
        seen.append((url, dict(kwargs.get("headers") or {}), kwargs.get("cookies")))
        if url.startswith("https://93.184.216.34"):
            return FakeResponse(200, {}, "landed")
        return FakeResponse(302, {"Location": "https://93.184.216.34/callback"})

    core = make_core(handler)
    res = await core.request(
        "GET", "http://target.example/login",
        headers={"X-Forwarded-For": "' OR 1=1--"}, cookies={"sid": "SECRET"},
    )
    assert res["text"] == "landed"
    first, second = seen[0], seen[1]
    assert first[1].get("X-Forwarded-For") == "' OR 1=1--"
    assert "93.184.216.34" in second[0]
    assert "X-Forwarded-For" not in second[1]
    assert second[2] is None


async def test_same_host_redirect_keeps_injected_headers():
    seen = []

    def handler(method, url, kwargs):
        seen.append(dict(kwargs.get("headers") or {}))
        if url.endswith("/step2"):
            return FakeResponse(200, {}, "ok")
        return FakeResponse(302, {"Location": "http://93.184.216.34/step2"})

    core = make_core(handler)
    await core.request("GET", "http://93.184.216.34/step1",
                       headers={"X-Real-IP": "PWN"})
    assert all(h.get("X-Real-IP") == "PWN" for h in seen)


async def test_no_redirect_following_when_caller_opts_out():
    """allow_redirects=False (e.g. the open-redirect tester) is untouched."""
    def handler(method, url, kwargs):
        return FakeResponse(302, {"Location": "http://169.254.169.254/"})

    core = make_core(handler)
    res = await core.request("GET", "http://target.example/r", allow_redirects=False)
    assert res["status_code"] == 302
    assert res["headers"]["Location"] == "http://169.254.169.254/"


# --- SSRF: DNS-rebinding (TOCTOU) protection --------------------------

async def test_pinned_resolver_serves_the_addresses_the_guard_vetted():
    """The socket must go to the IP that was checked, not to a fresh lookup.

    Simulates DNS rebinding: the guard resolves to a public address, the zone
    then flips to loopback. The resolver must still hand out the vetted address.
    """
    core = AsyncScannerCore(ScanConfig())
    lookups = []
    loop = asyncio.get_running_loop()

    async def flipping_getaddrinfo(host, port, **kw):
        lookups.append(host)
        # First answer: public. Every answer after the guard has run: loopback.
        ip = "93.184.216.34" if len(lookups) == 1 else "127.0.0.1"
        return [(2, 1, 6, "", (ip, 0))]

    loop.getaddrinfo = flipping_getaddrinfo  # type: ignore[method-assign]
    try:
        await core._assert_public_url("http://rebind.example/x")
        records = await PinnedResolver(core).resolve("rebind.example", 80)
    finally:
        del loop.getaddrinfo

    # The zone flipped, but the connection is pinned to the vetted address and
    # no second lookup was ever made.
    assert [r["host"] for r in records] == ["93.184.216.34"]
    assert all(r["hostname"] == "rebind.example" for r in records)
    assert lookups == ["rebind.example"]


async def test_pinned_resolver_blocks_a_host_that_resolves_internal():
    core = AsyncScannerCore(ScanConfig())
    core._resolve_cache["evil.example"] = {"169.254.169.254"}
    with pytest.raises(SSRFRedirectError):
        await PinnedResolver(core).resolve("evil.example", 80)


async def test_pinned_resolver_allows_an_operator_supplied_private_target():
    """Scanning your own intranet host stays legal: the first hop is trusted."""
    core = AsyncScannerCore(ScanConfig())
    core._trusted_hosts.add("intranet.local")
    core._resolve_cache["intranet.local"] = {"10.0.0.5"}
    records = await PinnedResolver(core).resolve("intranet.local", 80)
    assert [r["host"] for r in records] == ["10.0.0.5"]


async def test_pinned_resolver_honours_assert_public_target_even_when_trusted():
    core = AsyncScannerCore(ScanConfig(assert_public_target=True))
    core._trusted_hosts.add("intranet.local")
    core._resolve_cache["intranet.local"] = {"10.0.0.5"}
    with pytest.raises(SSRFRedirectError):
        await PinnedResolver(core).resolve("intranet.local", 80)


# --- SSRF: trust is bound to the vetted (host, IP) pair, not the bare host --
# N1 in THREATS_TO_VALIDITY_SSRF.md: ``_trusted_hosts`` grants an operator-
# designated hostname an exemption from the public-address policy, but by
# itself says nothing about *which* address is legitimate. These pin trust to
# the address(es) actually vetted the first time, so a later resolution of the
# same alias to something else is refused rather than silently inherited.

async def test_trusted_host_rejects_a_later_address_that_was_never_vetted():
    """Same alias, different address: e.g. the DNS cache entry was evicted and
    the zone now answers with a different private address (rebinding), or an
    unrelated redirect elsewhere in the scan reuses this hostname. Either way
    the new address was never vetted for this host and must be refused, even
    though the hostname itself is trusted."""
    core = AsyncScannerCore(ScanConfig())
    core._trusted_hosts.add("intranet.local")

    core._resolve_cache["intranet.local"] = {"10.0.0.5"}
    records = await PinnedResolver(core).resolve("intranet.local", 80)
    assert [r["host"] for r in records] == ["10.0.0.5"]

    # Simulate the cache entry being evicted and the host re-resolving to a
    # different private address under the same trusted alias.
    core._resolve_cache["intranet.local"] = {"10.0.0.66"}
    with pytest.raises(SSRFRedirectError):
        await PinnedResolver(core).resolve("intranet.local", 80)


async def test_trusted_host_pins_a_dual_stack_resolution_as_one_batch():
    """A host with more than one legitimate trusted address (dual-stack, or
    multiple A records for the same target) must not reject its own second
    address as 'unexpected' — the whole first resolution is pinned together."""
    core = AsyncScannerCore(ScanConfig())
    core._trusted_hosts.add("intranet.local")
    core._resolve_cache["intranet.local"] = {"10.0.0.5", "fd00::5"}

    records = await PinnedResolver(core).resolve("intranet.local", 80)
    assert {r["host"] for r in records} == {"10.0.0.5", "fd00::5"}

    # Re-resolving to the exact same set (e.g. a later redirect back to the
    # same host) must still pass.
    records2 = await PinnedResolver(core).resolve("intranet.local", 80)
    assert {r["host"] for r in records2} == {"10.0.0.5", "fd00::5"}


async def test_multi_target_scan_cannot_hijack_a_previously_trusted_alias():
    """Multi-target scan scenario: the operator's target list points the
    scanner at intranet host A directly (a legitimate first hop —
    ``core.request()`` marks its hostname trusted the same way the real
    crawler does for every top-level target). The scan runs long enough that
    A's bounded DNS cache entry gets evicted (``_MAX_RESOLVE_CACHE``), and by
    the time the crawler reaches A again — or an unrelated target B's page
    happens to reference the same hostname — the zone answers with a
    different private address. ``core.request()`` uses a fake session that
    never touches real DNS, so the actual socket-open-time check this guards
    is exercised the same way the sibling ``test_pinned_resolver_*`` tests
    do: by calling :class:`PinnedResolver` directly, which is exactly what
    aiohttp's connector invokes for every hop, first or redirected."""
    core = make_core(lambda m, u, kw: FakeResponse(200, {}, "ok"))

    # Target A: a normal first-hop request marks the hostname trusted, and
    # its first resolution (address the operator's own DNS actually returned)
    # gets pinned.
    core._resolve_cache["intranet.local"] = {"10.0.0.5"}
    await core.request("GET", "http://intranet.local/")
    assert "intranet.local" in core._trusted_hosts
    records = await PinnedResolver(core).resolve("intranet.local", 80)
    assert [r["host"] for r in records] == ["10.0.0.5"]
    assert core._trusted_host_ips["intranet.local"] == frozenset({"10.0.0.5"})

    # The cache entry is evicted and the same alias now resolves elsewhere —
    # a hijack/rebinding attempt riding on the trust A already earned.
    del core._resolve_cache["intranet.local"]
    core._resolve_cache["intranet.local"] = {"10.0.0.66"}
    with pytest.raises(SSRFRedirectError):
        await PinnedResolver(core).resolve("intranet.local", 80)


async def test_pinned_resolver_passes_everything_when_private_is_allowed():
    core = AsyncScannerCore(ScanConfig(allow_private_redirects=True))
    core._resolve_cache["h.local"] = {"127.0.0.1"}
    records = await PinnedResolver(core).resolve("h.local", 8443)
    assert [r["host"] for r in records] == ["127.0.0.1"]


async def test_pinned_resolver_validates_ip_literals_without_dns():
    core = AsyncScannerCore(ScanConfig())
    with pytest.raises(SSRFRedirectError):
        await PinnedResolver(core).resolve("169.254.169.254", 80)
    ok = await PinnedResolver(core).resolve("93.184.216.34", 443)
    assert ok[0]["host"] == "93.184.216.34"


async def test_connector_actually_installs_the_pinned_resolver():
    """The guard is only TOCTOU-proof if aiohttp resolves through us."""
    core = AsyncScannerCore(ScanConfig())
    await core.start()
    try:
        assert isinstance(core.session.connector._resolver, PinnedResolver)
    finally:
        await core.close()


async def test_proxy_runs_without_pinning():
    """Under a proxy the scanner never resolves the target, so pinning the
    proxy's own address would only mis-apply the target policy."""
    core = AsyncScannerCore(ScanConfig(proxy="http://127.0.0.1:8080"))
    await core.start()
    try:
        assert not isinstance(core.session.connector._resolver, PinnedResolver)
    finally:
        await core.close()


async def test_resolve_cache_is_bounded():
    from web_security_scanner.core.scanner_core_async import _MAX_RESOLVE_CACHE

    core = AsyncScannerCore(ScanConfig())
    loop = asyncio.get_running_loop()

    async def fake_getaddrinfo(host, port, **kw):
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    loop.getaddrinfo = fake_getaddrinfo  # type: ignore[method-assign]
    try:
        for i in range(_MAX_RESOLVE_CACHE + 50):
            await core._resolve_host(f"h{i}.example")
    finally:
        del loop.getaddrinfo
    assert len(core._resolve_cache) <= _MAX_RESOLVE_CACHE
    assert "h0.example" not in core._resolve_cache        # oldest evicted first
    assert f"h{_MAX_RESOLVE_CACHE + 49}.example" in core._resolve_cache


async def test_warmed_endpoint_set_is_bounded():
    from web_security_scanner.core.scanner_core_async import _MAX_WARMED_ENDPOINTS

    core = make_core(lambda m, u, kw: FakeResponse(200, {}, "ok"))
    for i in range(_MAX_WARMED_ENDPOINTS + 10):
        core._warmed_endpoints.add(f"http://h/{i}")
    await core.warmup("http://h/fresh", 1)
    assert len(core._warmed_endpoints) <= _MAX_WARMED_ENDPOINTS


async def test_request_marks_only_the_first_hop_as_trusted():
    """A redirect target must never inherit the operator's trust."""
    def handler(method, url, kwargs):
        if "10.0.0.9" in url:
            return FakeResponse(200, {}, "internal")
        return FakeResponse(302, {"Location": "http://10.0.0.9/admin"})

    core = make_core(handler)
    with pytest.raises(SSRFRedirectError):
        await core.request("GET", "http://target.example/go")
    assert core._trusted_hosts == {"target.example"}


# --- warm-up phase (JVM latency-bias mitigation) ----------------------

async def test_warmup_fires_n_discards_and_is_idempotent_per_endpoint():
    hits = []

    def handler(method, url, kwargs):
        hits.append(url)
        return FakeResponse(200, {}, "ok")

    core = make_core(handler)
    n1 = await core.warmup("http://target.example/a?x=1", 3)
    n2 = await core.warmup("http://target.example/a?x=2", 3)  # same endpoint
    n3 = await core.warmup("http://target.example/b", 3)
    assert (n1, n2, n3) == (3, 0, 3)
    assert len(hits) == 6


async def test_warmup_noop_at_zero():
    core = make_core(lambda m, u, kw: FakeResponse(200, {}, "ok"))
    assert await core.warmup("http://target.example/a", 0) == 0
    assert core.session.requests == []


async def test_warmup_respects_rate_limit():
    core = make_core(lambda m, u, kw: FakeResponse(200, {}, "ok"), rate_limit=0.05)
    start = time.monotonic()
    await core.warmup("http://target.example/a", 4)
    assert time.monotonic() - start >= 0.1  # >=3 inter-request waits of ~50ms


async def test_warmup_stops_on_hard_failure():
    def handler(method, url, kwargs):
        raise RuntimeError("connection refused")

    core = make_core(handler)
    # request() swallows the exception into status_code=0 -> warmup breaks early.
    assert await core.warmup("http://target.example/a", 5) == 1


async def test_warmup_blocks_cross_host_redirect_to_metadata_ip():
    """warmup() must get the same SSRF protection as a normal request().

    warmup() discards its responses and skips telemetry, but it still goes
    through request() -> _request_following(), which is where the redirect
    chase and the SSRF guard live. This pins that: a warm-up burst chasing a
    302 to the cloud metadata endpoint must abort exactly like
    test_redirect_to_metadata_ip_is_blocked does for a normal request(), and
    the internal address must never actually be dialled.
    """
    def handler(method, url, kwargs):
        if "169.254.169.254" in url:
            return FakeResponse(200, {}, "iam/security-credentials/...")
        return FakeResponse(
            302, {"Location": "http://169.254.169.254/latest/meta-data/"}
        )

    core = make_core(handler)
    with pytest.raises(SSRFRedirectError):
        await core.warmup("http://target.example/fetch?url=x", 3)

    assert all("169.254.169.254" not in u for _, u, _ in core.session.requests)


# --- token bucket ------------------------------------------------------

async def test_token_bucket_enforces_rate():
    bucket = TokenBucket(rate=20.0, capacity=1)  # ~50 ms spacing
    start = time.monotonic()
    for _ in range(5):
        await bucket.acquire()
    elapsed = time.monotonic() - start
    # 1 free token + 4 waits of ~50 ms ≈ 0.2 s (generous CI bounds).
    assert 0.12 <= elapsed <= 0.8


async def test_token_bucket_does_not_serialize_below_rate():
    """Callers within budget proceed immediately (no lock-during-sleep)."""
    bucket = TokenBucket(rate=1000.0, capacity=50)
    start = time.monotonic()
    await asyncio.gather(*(bucket.acquire() for _ in range(50)))
    assert time.monotonic() - start < 0.1


# --- worker pool: backpressure ---------------------------------------

async def test_worker_pool_processes_all_items():
    processed = []

    async def worker(i):
        processed.append(i)

    await worker_pool(range(500), worker, concurrency=8)
    assert sorted(processed) == list(range(500))


async def test_worker_pool_is_backpressured():
    """The source iterator must never race far ahead of consumption."""
    produced = 0

    def gen():
        nonlocal produced
        for i in range(2000):
            produced += 1
            yield i

    processed = []

    async def worker(i):
        # queue(maxsize=concurrency*2=10) + workers(5) => bounded lookahead.
        assert produced <= len(processed) + 40, (produced, len(processed))
        processed.append(i)
        await asyncio.sleep(0)

    await worker_pool(gen(), worker, concurrency=5, queue_factor=2)
    assert len(processed) == 2000


async def test_worker_pool_bounds_concurrent_workers():
    inflight = 0
    peak = 0

    async def worker(i):
        nonlocal inflight, peak
        inflight += 1
        peak = max(peak, inflight)
        await asyncio.sleep(0.001)
        inflight -= 1

    await worker_pool(range(200), worker, concurrency=6)
    assert peak <= 6


# --- worker pool: clean cancellation --------------------------------

async def test_worker_pool_cancels_without_orphans():
    started = []

    async def worker(i):
        started.append(i)
        await asyncio.sleep(10)

    task = asyncio.create_task(worker_pool(range(100), worker, concurrency=4))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Let cancellations settle, then assert no leaked child tasks remain.
    await asyncio.sleep(0.01)
    leaked = [
        t for t in asyncio.all_tasks()
        if t is not asyncio.current_task() and not t.done()
    ]
    assert leaked == []
    assert len(started) == 4  # only `concurrency` workers ever started


async def test_worker_pool_cancels_when_a_worker_raises():
    seen = []

    async def worker(i):
        seen.append(i)
        if i == 3:
            raise RuntimeError("boom")
        await asyncio.sleep(0.5)

    with pytest.raises(RuntimeError):
        await worker_pool(range(50), worker, concurrency=4)

    await asyncio.sleep(0.01)
    leaked = [
        t for t in asyncio.all_tasks()
        if t is not asyncio.current_task() and not t.done()
    ]
    assert leaked == []


# --- User-Agent rotation --------------------------------------------

async def test_user_agent_is_rotated_per_request():
    seen = set()

    def handler(method, url, kwargs):
        seen.add(kwargs.get("headers", {}).get("User-Agent"))
        return FakeResponse(200, {}, "ok")

    core = make_core(handler)
    for _ in range(40):
        core.cache.cache.clear()  # defeat the response cache
        await core.request("GET", "http://target.example/")
    assert None not in seen
    assert len(seen) > 1  # more than one UA actually used


# --- orchestrator graceful shutdown --------------------------------

async def test_run_testers_timeout_cancels_and_awaits_every_tester():
    """max_duration must cancel AND await all testers (no orphan tasks)."""
    from web_security_scanner.web_security_scanner_async import WebSecurityScanner

    scanner = WebSecurityScanner({"core": {}})

    class HangTester:
        name = "hang"

        def __init__(self):
            self.cancelled = False

        async def run_test(self, url):
            try:
                await asyncio.sleep(100)
            except asyncio.CancelledError:
                self.cancelled = True
                raise

    testers = [HangTester() for _ in range(5)]
    await scanner._run_testers(testers, "http://x/", max_duration=0.1)

    assert all(t.cancelled for t in testers)
    await asyncio.sleep(0.01)
    leaked = [
        t for t in asyncio.all_tasks()
        if t is not asyncio.current_task() and not t.done()
    ]
    assert leaked == []


async def test_pinned_user_agent_is_not_rotated():
    seen = set()

    def handler(method, url, kwargs):
        seen.add(kwargs.get("headers", {}).get("User-Agent"))
        return FakeResponse(200, {}, "ok")

    core = make_core(handler, user_agent="pinned-agent/1.0")
    for i in range(5):
        await core.request("GET", f"http://target.example/{i}")
    # rotation helper adds nothing; the pinned UA rides on the session headers
    assert seen == {None}


# --- response cache key hygiene --------------------------------------------

def test_cache_key_uses_sha256_not_md5():
    """Keys must be a collision-resistant digest of attacker-influenced input."""
    from web_security_scanner.core.scanner_core_async import AsyncResponseCache

    cache = AsyncResponseCache()
    key = cache._generate_key("http://t/x", "get", None)
    assert len(key) == 64  # sha256 hexdigest, not md5's 32
    assert all(c in "0123456789abcdef" for c in key)


def test_cache_key_separates_requests_by_header_and_cookie():
    from web_security_scanner.core.scanner_core_async import AsyncResponseCache

    cache = AsyncResponseCache()
    base = cache._generate_key("http://t/x", "GET", None)
    with_hdr = cache._generate_key("http://t/x", "GET", None, headers={"X-Inj": "1"})
    with_ck = cache._generate_key("http://t/x", "GET", None, cookies={"sid": "1"})
    assert len({base, with_hdr, with_ck}) == 3


# --- session invariant is enforced even under `python -O` ------------------

async def test_request_following_without_session_raises_runtimeerror():
    """The core-loop guard must be a real check, not a strippable `assert`."""
    core = AsyncScannerCore(ScanConfig())
    assert core.session is None
    with pytest.raises(RuntimeError, match="session not initialised"):
        await core._request_following(
            "GET", "http://target.example/", False, None, {}
        )
