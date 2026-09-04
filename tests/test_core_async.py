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


async def test_no_redirect_following_when_caller_opts_out():
    """allow_redirects=False (e.g. the open-redirect tester) is untouched."""
    def handler(method, url, kwargs):
        return FakeResponse(302, {"Location": "http://169.254.169.254/"})

    core = make_core(handler)
    res = await core.request("GET", "http://target.example/r", allow_redirects=False)
    assert res["status_code"] == 302
    assert res["headers"]["Location"] == "http://169.254.169.254/"


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
