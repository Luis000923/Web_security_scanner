import asyncio
import hashlib
import ipaddress
import logging
import random
import socket
import ssl
import time
import urllib.parse
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult

from .telemetry_engine import AdaptiveConcurrencyController, TelemetryEngine

# Small pool of legitimate, current desktop User-Agents. One is picked at
# random per request (basic fingerprint rotation) unless the caller pinned a
# specific UA through ScanConfig.user_agent.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.1 Safari/605.1.15",
]

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# Proxy schemes aiohttp cannot handle through the per-request ``proxy=`` kwarg;
# they need an aiohttp_socks connector built at session creation.
_SOCKS_SCHEMES = ("socks5://", "socks5h://", "socks4://")

# Hard ceiling on how many *decompressed* response bytes we buffer in memory per
# request. Protects against infinite chunked streams and gzip/deflate bombs: the
# stream is read incrementally and abandoned once this many bytes accumulate.
MAX_RESPONSE_SIZE = 5 * 1024 * 1024        # 5 MiB
_READ_CHUNK = 64 * 1024                     # 64 KiB per iter_chunked step

# Caps on the two auxiliary caches that would otherwise grow for the whole scan.
# A crawl that touches tens of thousands of distinct hosts/endpoints would keep
# every one of them alive; these bound that at a few MB. Dropping an entry only
# costs a re-resolution (which is re-validated) or a repeated warm-up burst.
_MAX_RESOLVE_CACHE = 4096
_MAX_WARMED_ENDPOINTS = 8192
_MAX_BACKOFF_HOSTS = 4096

# ipaddress predicates that mark an address as "not a public destination".
_BLOCKED_IP_PREDICATES = (
    "is_private", "is_loopback", "is_link_local",
    "is_reserved", "is_multicast", "is_unspecified",
)


class SSRFRedirectError(Exception):
    """
    Raised when a redirect (or the address it resolves to) points at a
    private, loopback, link-local or otherwise non-public range.

    The request is aborted instead of letting the HTTP client chase an
    internal endpoint (e.g. the cloud metadata service at 169.254.169.254).
    """


def _addrinfo(hostname: str, ip: str, port: int) -> ResolveResult:
    """One aiohttp resolver record for an already-resolved literal address."""
    family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    return ResolveResult(
        hostname=hostname,
        host=ip,
        port=port,
        family=family,
        proto=socket.IPPROTO_TCP,
        flags=socket.AI_NUMERICHOST,
    )


class PinnedResolver(AbstractResolver):
    """DNS resolver that hands aiohttp only addresses the SSRF guard vetted.

    Without this, the guard is a TOCTOU check: :meth:`AsyncScannerCore.
    _assert_public_url` resolves a hostname, validates the addresses, and then
    passes the *name* to aiohttp — which resolves it a second time when it opens
    the socket. An attacker controlling the zone can answer the first lookup
    with a public address and the second with ``127.0.0.1`` or
    ``169.254.169.254`` (classic DNS rebinding), and the connection lands on the
    internal endpoint the guard just rejected.

    Pinning closes that window: every name already in the core's
    ``_resolve_cache`` — i.e. every host the guard has vetted — resolves to
    exactly the addresses that were checked, so the socket cannot be pointed
    anywhere else. A name the guard never saw (the first hop of a scan, which is
    supplied by the operator rather than the target) is resolved here, vetted
    under the same policy, and cached so any later redirect to it reuses this
    answer.

    Only the address is pinned: the request keeps its original URL, so TLS SNI
    and certificate hostname verification still run against the real name.
    """

    def __init__(self, core: "AsyncScannerCore") -> None:
        self._core = core

    async def resolve(self, host: str, port: int = 0,
                      family: int = socket.AF_INET) -> list[ResolveResult]:
        # An IP literal never went through DNS; validate it directly.
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            self._core._assert_ip_allowed(host, host)
            return [_addrinfo(host, host, port)]

        ips = await self._core._resolve_host(host)
        if not ips:
            raise SSRFRedirectError(f"Host {host!r} resolved to no addresses")
        # Vet the whole resolution as one batch (not one address at a time):
        # see _assert_ips_allowed for why a multi-address trusted host would
        # otherwise reject its own second address.
        self._core._assert_ips_allowed(ips, host)
        return [_addrinfo(host, ip, port) for ip in sorted(ips)]

    async def close(self) -> None:
        return None


@dataclass
class ScanConfig:
    max_concurrency: int = 50
    timeout: int = 10
    # None -> rotate a modern UA per request; a string pins that UA.
    user_agent: str | None = None
    # Extra User-Agent pool (e.g. loaded from --ua-file). When non-empty and no
    # UA is pinned, requests rotate over this list instead of the builtin one.
    extra_user_agents: list[str] = field(default_factory=list)
    proxy: str | None = None
    rate_limit: float = 0.0          # min seconds between requests (0 = unlimited)
    rate_burst: int = 1             # token-bucket capacity (allowed burst size)
    verify_ssl: bool = True
    headers: dict[str, str] = field(default_factory=dict)
    rotate_user_agent: bool = True
    max_redirects: int = 10
    # Granular socket timeouts (seconds). ``timeout`` above stays the overall
    # deadline; these two cap the slow-drip failure modes a tarpit relies on:
    #   sock_connect -> time allowed to establish the TCP/TLS connection
    #   sock_read    -> max gap between two received chunks of the body
    sock_connect_timeout: float = 5.0
    sock_read_timeout: float = 5.0
    # Max decompressed body bytes buffered per response (OOM / zip-bomb guard).
    max_response_size: int = MAX_RESPONSE_SIZE
    # SSRF guard: when False, redirects whose target resolves to a non-public
    # IP are aborted with SSRFRedirectError.
    allow_private_redirects: bool = False
    # aiohttp's default CookieJar silently drops cookies whose domain is a bare
    # IP address (RFC 6265 §5.3). The testbed (and many internal targets) is
    # reached by IP, so ``unsafe=True`` is the default here — authenticated
    # scans of ``127.0.0.1:8443`` would otherwise never keep their JSESSIONID.
    cookie_jar_unsafe: bool = True
    # When True, the *initial* request URL is also run through the SSRF
    # public-address check (the redirect chain is always checked). Off by
    # default so ordinary GET scans of an explicitly-supplied target are
    # unchanged; the advanced body/header/cookie vectors turn it on so a
    # mutated request can never be aimed at an internal endpoint either.
    assert_public_target: bool = False
    # ---- resilience: bounded retries + per-host adaptive throttling ------
    # All default to the pre-existing behaviour (no retries, no throttling)
    # so unit tests and normal scans see zero change unless opted in.
    #
    # ``max_retries``: extra attempts after the first, applied only to a hard
    # transport failure (status_code == 0 -- the exception path already
    # collapses into that) or, when ``adaptive_throttle`` is on, to a 429/503
    # response. 0 keeps the historical single-attempt behaviour.
    max_retries: int = 0
    retry_backoff_base: float = 0.5    # seconds, first retry's backoff floor
    retry_backoff_max: float = 8.0     # seconds, backoff ceiling before jitter
    # ``adaptive_throttle``: when a host answers 429/503, park *further*
    # requests to that host behind a per-host cooldown (honouring
    # ``Retry-After`` when present) instead of continuing to hammer it at the
    # scan's normal pace. Cooldown decays back to zero on the host's next
    # clean response. Scoped per-host so one throttled target never slows
    # down a concurrent scan of other targets in a --target-list run.
    adaptive_throttle: bool = False
    throttle_backoff_max: float = 30.0  # seconds, per-host cooldown ceiling
    # ---- adaptive concurrency control (Phase 2 real-time telemetry) ------
    # Off by default: the fixed ``max_concurrency`` semaphore behaves exactly
    # as before. When on, an AIMD governor (see core.telemetry_engine)
    # shrinks/grows the concurrency ceiling in reaction to observed
    # rate-limiting instead of hammering the target at a fixed pace for the
    # whole scan.
    adaptive_concurrency: bool = False
    adaptive_concurrency_min: int = 2
    adaptive_concurrency_window: int = 20
    adaptive_concurrency_high_watermark: float = 0.2
    adaptive_concurrency_low_watermark: float = 0.02


class TokenBucket:
    """
    Async token bucket rate limiter.

    Tokens refill continuously at ``rate`` per second up to ``capacity``.
    ``acquire`` computes the wait under a short-lived lock but **sleeps
    outside** it, so waiting for a token never occupies a concurrency slot and
    several callers can have requests in flight at a pace consistent with the
    configured rate (instead of the old lock-during-sleep that forced
    concurrency down to 1).
    """

    def __init__(self, rate: float, capacity: float = 1.0):
        self._rate = max(rate, 1e-6)
        self._capacity = max(float(capacity), 1.0)
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, amount: float = 1.0) -> None:
        amount = min(amount, self._capacity)
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self._capacity,
                    self._tokens + (now - self._updated) * self._rate,
                )
                self._updated = now
                if self._tokens >= amount:
                    self._tokens -= amount
                    return
                wait = (amount - self._tokens) / self._rate
            await asyncio.sleep(wait)


class HostBackoff:
    """Per-host adaptive cooldown driven by 429/503 responses.

    Deliberately separate from :class:`TokenBucket`: the token bucket paces
    every request at a fixed, operator-chosen rate regardless of target
    behaviour, while this reacts to what the *target* says (a rate-limit
    response or a ``Retry-After`` header) and only throttles the host that
    asked for it. A scan against a ``--target-list`` of several hosts keeps
    its normal pace against the hosts that are not complaining.

    ``penalize()`` returns the delay (seconds) the caller should wait before
    the *next* request to this host; it does not sleep itself, so the wait
    never holds a concurrency slot or the semaphore (same discipline as
    :meth:`TokenBucket.acquire`). Backoff is exponential in the number of
    consecutive throttle responses, capped at ``ceiling``, with full jitter
    (uniform in ``[0, computed_delay]``) so many probes in flight against the
    same host don't all resume in lockstep. ``Retry-After`` (seconds or an
    HTTP-date) overrides the computed delay when present and larger.
    """

    def __init__(self, ceiling: float = 30.0, max_hosts: int = 4096) -> None:
        self._ceiling = max(1.0, ceiling)
        self._max_hosts = max(1, max_hosts)
        self._state: dict[str, dict[str, float]] = {}

    @staticmethod
    def _parse_retry_after(value: str | None) -> float:
        if not value:
            return 0.0
        value = value.strip()
        if value.isdigit():
            return float(value)
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(value)
            if dt is None:
                return 0.0
            delta = dt.timestamp() - time.time()
            return max(0.0, delta)
        except (TypeError, ValueError):
            return 0.0

    def penalize(self, host: str, *, retry_after: str | None = None) -> float:
        """Record a throttle response for ``host``; returns the wait (s)."""
        if host not in self._state and len(self._state) >= self._max_hosts:
            self._state.clear()
        entry = self._state.setdefault(host, {"level": 0.0, "until": 0.0})
        entry["level"] = min(entry["level"] + 1.0, 10.0)
        computed = min(self._ceiling, (2.0 ** entry["level"]) * 0.25)
        delay = max(computed, self._parse_retry_after(retry_after))
        delay = min(delay, self._ceiling)
        entry["until"] = time.monotonic() + delay
        return random.uniform(0.0, delay) if delay > 0 else 0.0

    def relax(self, host: str) -> None:
        """A clean response from ``host``: decay its cooldown level."""
        entry = self._state.get(host)
        if entry is not None and entry["level"] > 0:
            entry["level"] = max(0.0, entry["level"] - 1.0)

    async def wait_if_needed(self, host: str) -> None:
        entry = self._state.get(host)
        if entry is None:
            return
        remaining = entry["until"] - time.monotonic()
        if remaining > 0:
            await asyncio.sleep(remaining)


async def worker_pool(
    work_items: Iterable[Any],
    worker: Callable[[Any], Awaitable[None]],
    *,
    concurrency: int,
    queue_factor: int = 2,
) -> None:
    """
    Consume ``work_items`` through a fixed pool of ``concurrency`` workers.

    ``work_items`` is iterated lazily via ``iter()``; a bounded queue
    (``concurrency * queue_factor`` slots) applies real backpressure. An
    iterator that would yield 50k payloads therefore never materialises 50k
    pending coroutines — at most ``concurrency + queue`` items are live at once.

    On cancellation (or if a worker raises) every worker and the feeder are
    cancelled and awaited before returning, so no orphan tasks leak.
    """
    concurrency = max(1, concurrency)
    queue: asyncio.Queue = asyncio.Queue(maxsize=concurrency * max(1, queue_factor))
    _STOP = object()
    iterator = iter(work_items)

    async def feed() -> None:
        for item in iterator:
            await queue.put(item)          # blocks when full -> backpressure
        for _ in range(concurrency):
            await queue.put(_STOP)

    async def run() -> None:
        while True:
            item = await queue.get()
            try:
                if item is _STOP:
                    return
                await worker(item)
            finally:
                queue.task_done()

    tasks = [asyncio.create_task(run()) for _ in range(concurrency)]
    feeder = asyncio.create_task(feed())
    try:
        await asyncio.gather(feeder, *tasks)
    except BaseException:
        for task in (feeder, *tasks):
            task.cancel()
        await asyncio.gather(feeder, *tasks, return_exceptions=True)
        raise


class AsyncResponseCache:
    """
    Response cache for the single-event-loop scanner.

    Access is confined to the asyncio loop (get/put are synchronous and never
    await), so no lock is needed — coroutines don't preempt each other between
    statements.
    """

    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self.cache: dict[str, Any] = {}
        self.max_size = max_size
        self.ttl = ttl
        self.access_times: dict[str, float] = {}

    @staticmethod
    def _normalize_mapping(mapping: Any) -> str:
        """Order-independent, canonical string for a headers/cookies mapping.

        ``{"B": "2", "a": "1"}`` and ``{"a": "1", "B": "2"}`` produce the same
        token so identical requests still hit the cache, while an injected
        header/cookie value changes it. Header names are matched
        case-insensitively (HTTP semantics); non-mapping / empty inputs collapse
        to ``""``.
        """
        if not mapping:
            return ""
        try:
            items = mapping.items()
        except AttributeError:
            return ""
        pairs = sorted((str(k).lower(), str(v)) for k, v in items)
        return ";".join(f"{k}={v}" for k, v in pairs)

    def _generate_key(self, url: str, method: str, data: Any,
                      headers: Any = None, cookies: Any = None) -> str:
        key_data = "-".join((
            url,
            method.upper(),
            str(data),
            self._normalize_mapping(headers),
            self._normalize_mapping(cookies),
        ))
        # SHA-256 (not MD5): the key derives from attacker-influenced URLs and
        # header/cookie values, so a collision-resistant digest keeps a crafted
        # request from shadowing an unrelated cached response.
        return hashlib.sha256(key_data.encode()).hexdigest()

    def get(self, url: str, method: str, data: Any = None,
            headers: Any = None, cookies: Any = None) -> dict | None:
        key = self._generate_key(url, method, data, headers, cookies)
        if key in self.cache:
            if time.time() - self.access_times.get(key, 0) < self.ttl:
                return self.cache[key]
            else:
                self._remove(key)
        return None

    def put(self, url: str, method: str, data: Any, response_data: dict,
            headers: Any = None, cookies: Any = None) -> None:
        if len(self.cache) >= self.max_size:
            self._evict_old_entries()

        key = self._generate_key(url, method, data, headers, cookies)
        self.cache[key] = response_data
        self.access_times[key] = time.time()

    def _remove(self, key: str) -> None:
        self.cache.pop(key, None)
        self.access_times.pop(key, None)

    def _evict_old_entries(self) -> None:
        if not self.access_times:
            return
        sorted_keys = sorted(self.access_times.items(), key=lambda x: x[1])
        # Always evict at least one entry: with a very small ``max_size`` the
        # 25% batch would round down to 0 and the cache would grow unbounded.
        to_remove = max(1, int(len(sorted_keys) * 0.25))
        for key, _ in sorted_keys[:to_remove]:
            self._remove(key)


class AsyncScannerCore:
    """
    Core scanner functionality using asyncio and aiohttp.

    Handles connection pooling, token-bucket rate limiting, response caching,
    fingerprint (User-Agent) rotation, and SSRF-safe redirect following.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.session: aiohttp.ClientSession | None = None
        self.cache = AsyncResponseCache()
        # Real-time request telemetry (latency/jitter/retries/throttle
        # detection, per host and per operational phase) -- always on,
        # in-memory only, and cheap (see core.telemetry_engine). Feeds the
        # enriched JSON report and, when adaptive_concurrency is on, the
        # AIMD governor below.
        self.telemetry_engine = TelemetryEngine()
        # Bounds requests actually in flight. A fixed asyncio.Semaphore unless
        # --adaptive-concurrency opts into the AIMD-governed resizable one.
        self._concurrency_controller: AdaptiveConcurrencyController | None = None
        if config.adaptive_concurrency:
            self._concurrency_controller = AdaptiveConcurrencyController(
                initial=config.max_concurrency,
                minimum=config.adaptive_concurrency_min,
                maximum=config.max_concurrency,
                window=config.adaptive_concurrency_window,
                high_watermark=config.adaptive_concurrency_high_watermark,
                low_watermark=config.adaptive_concurrency_low_watermark,
                telemetry=self.telemetry_engine,
            )
            self._semaphore: Any = self._concurrency_controller.semaphore
        else:
            self._semaphore = asyncio.Semaphore(config.max_concurrency)
        # Global request pacing, decoupled from the concurrency slot.
        self._rate_bucket: TokenBucket | None = None
        if config.rate_limit and config.rate_limit > 0:
            self._rate_bucket = TokenBucket(
                rate=1.0 / config.rate_limit, capacity=config.rate_burst
            )
        # Per-host 429/503 cooldown (see class docstring). Created unconditionally
        # (cheap, empty dict) but only ever populated/consulted when
        # ``config.adaptive_throttle`` is set, so it is a no-op otherwise.
        self._host_backoff = HostBackoff(
            ceiling=config.throttle_backoff_max, max_hosts=_MAX_BACKOFF_HOSTS
        )
        self._logger = logging.getLogger(__name__)
        # host -> {ip, ...}; avoids re-resolving on every redirect check AND
        # pins the addresses handed to aiohttp (see PinnedResolver).
        self._resolve_cache: dict[str, set[str]] = {}
        # Hostnames supplied by the operator / crawler as a request target
        # (rather than by a redirect the *target* chose). Scanning an internal
        # host you own is legitimate, so these keep the historical policy: a
        # private address is allowed unless ``assert_public_target`` is set.
        self._trusted_hosts: set[str] = set()
        # host -> the exact private/loopback/... address set vetted the FIRST
        # time that host resolved to one. Being in ``_trusted_hosts`` only
        # grants an exemption from the public-address policy at all; it does
        # not by itself say WHICH address is legitimate. Pinning closes that:
        # once "intranet.local" is seen to resolve to 10.0.0.5, a later
        # resolution of the same hostname to a *different* private address
        # (DNS rebinding after cache eviction, or a redirect from an unrelated
        # target reusing the same alias mid-scan — see THREATS_TO_VALIDITY_SSRF
        # N1) is refused instead of silently inheriting the old trust.
        self._trusted_host_ips: dict[str, frozenset[str]] = {}
        # Endpoints (scheme://netloc/path) already given a warm-up burst, so a
        # per-point warm-up call from a tester and the orchestrator's per-target
        # pre-warm never double-fire against the same endpoint.
        self._warmed_endpoints: set[str] = set()
        # Authenticated-scan state (see core.session_async). ``_auth_headers``
        # (e.g. a bearer token) is merged into every outgoing request; session
        # cookies live in the aiohttp jar and are attached automatically.
        self._session_manager: Any = None
        self._auth_headers: dict[str, str] = {}
        # One-shot guard so the "TLS verification disabled" warning is logged
        # once per scanner, not once per connector rebuild.
        self._ssl_notice_emitted = False

    def _is_socks_proxy(self) -> bool:
        proxy = (self.config.proxy or "").lower()
        return proxy.startswith(_SOCKS_SCHEMES)

    def _ssl_param(self) -> "bool | ssl.SSLContext":
        """SSL argument for the aiohttp connector.

        ``verify_ssl=True``  -> ``True``: aiohttp uses its default verifying
        context (normal production behaviour).

        ``verify_ssl=False`` -> an explicit permissive ``SSLContext`` with
        ``check_hostname=False`` and ``verify_mode=CERT_NONE``. This is stronger
        and more predictable than the bare ``ssl=False`` shortcut: it neutralises
        *both* certificate-chain and hostname checks in one object, behaves
        identically across aiohttp releases, and is required for local test
        benches that serve HTTPS with a self-signed cert (e.g. the OWASP
        Benchmark container on :8443). Without it aiohttp raises
        ``SSLCertVerificationError`` and every probe silently degrades to
        ``status_code=0``.
        """
        if self.config.verify_ssl:
            return True
        if not self._ssl_notice_emitted:
            self._logger.warning(
                "TLS certificate verification is DISABLED (verify_ssl=False). "
                "Self-signed / invalid certs will be accepted. Use only against "
                "systems you are authorized to test."
            )
            self._ssl_notice_emitted = True
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _build_connector(self) -> "aiohttp.BaseConnector":
        """TCP connector, or a SOCKS connector when a socks proxy is configured.

        SOCKS support is optional: it needs the ``aiohttp_socks`` package. HTTP
        proxying does not go through the connector (it rides on the per-request
        ``proxy=`` kwarg), so this only special-cases socks URLs.

        The TCP connector resolves through :class:`PinnedResolver` so the socket
        can only be opened to an address the SSRF guard already vetted. Under a
        proxy the scanner never resolves the target itself (the proxy does), so
        pinning would only mis-apply the target policy to the proxy's own
        address — the URL-level guard still runs, but the resolver is left
        alone.
        """
        if self._is_socks_proxy():
            try:
                from aiohttp_socks import ProxyConnector
            except ImportError as exc:  # pragma: no cover - optional dependency
                raise RuntimeError(
                    "SOCKS proxy requested but 'aiohttp_socks' is not installed; "
                    "run `pip install aiohttp_socks` or use an http(s):// proxy."
                ) from exc
            return ProxyConnector.from_url(
                self.config.proxy, ssl=self._ssl_param(),
                limit=self.config.max_concurrency,
            )
        resolver = None if self.config.proxy else PinnedResolver(self)
        return aiohttp.TCPConnector(
            limit=self.config.max_concurrency,
            ssl=self._ssl_param(),
            resolver=resolver,
        )

    async def start(self):
        """Initialize the aiohttp session."""
        if not self.session:
            connector = self._build_connector()
            headers = dict(self.config.headers)
            if self.config.user_agent:
                headers.setdefault("User-Agent", self.config.user_agent)
            # Explicit cookie jar so form-login / static session cookies persist
            # across the whole scan and auto-attach to every probe.
            self.session = aiohttp.ClientSession(
                connector=connector, headers=headers,
                cookie_jar=aiohttp.CookieJar(unsafe=self.config.cookie_jar_unsafe),
            )

    # ---- authenticated-session hooks --------------------------------

    def attach_session_manager(self, manager: Any) -> None:
        """Register a :class:`~...core.session_async.SessionManager` for
        transparent mid-scan re-authentication."""
        self._session_manager = manager

    def set_auth_header(self, name: str, value: str) -> None:
        """Persist a header (e.g. ``Authorization: Bearer …``) on every request."""
        self._auth_headers[str(name)] = str(value)

    def clear_auth_header(self, name: str) -> None:
        self._auth_headers.pop(str(name), None)

    async def close(self):
        """Close the aiohttp session (idempotent)."""
        session, self.session = self.session, None
        if session is not None and not session.closed:
            await session.close()
            # Let underlying transports (esp. TLS) finish closing.
            await asyncio.sleep(0)

    def set_max_concurrency(self, value: int) -> None:
        """Rebuild the concurrency gate for a new ceiling (e.g. a profile
        switch), preserving adaptive-concurrency mode if it was enabled.

        Replaces the previous pattern of the orchestrator reassigning
        ``core._semaphore`` directly, which would silently downgrade an
        adaptive-concurrency scan back to a fixed ``asyncio.Semaphore``.
        """
        value = max(1, int(value))
        self.config.max_concurrency = value
        if self._concurrency_controller is not None:
            self._concurrency_controller.maximum = value
            self._concurrency_controller.semaphore.resize(value)
            self._semaphore = self._concurrency_controller.semaphore
        else:
            self._semaphore = asyncio.Semaphore(value)

    # ---- worker pool passthrough ---------------------------------------

    async def run_worker_pool(self, work_items, worker, *, concurrency, queue_factor=2):
        """Instance-level alias for :func:`worker_pool` (bounded fan-out)."""
        await worker_pool(
            work_items, worker, concurrency=concurrency, queue_factor=queue_factor
        )

    # ---- fingerprinting ----------------------------------------------

    def _request_headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.config.rotate_user_agent and not self.config.user_agent:
            pool = self.config.extra_user_agents or USER_AGENTS
            headers["User-Agent"] = random.choice(pool)
        if extra:
            headers.update(extra)
        return headers

    # ---- SSRF guard -------------------------------------------------

    @staticmethod
    def _ip_is_blocked(ip_text: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return True  # unparseable -> treat as unsafe
        return any(getattr(ip, pred, False) for pred in _BLOCKED_IP_PREDICATES)

    def _assert_ip_allowed(self, ip: str, host: str) -> None:
        """Connection-time policy check for one resolved address.

        Thin wrapper around :meth:`_assert_ips_allowed` for the single-address
        case (an IP literal in the URL, where ``host == ip`` and no alias
        confusion is possible). Resolutions that can yield more than one
        address (a real hostname lookup) must go through
        :meth:`_assert_ips_allowed` instead, so the whole batch is vetted
        atomically — see its docstring for why.
        """
        self._assert_ips_allowed({ip}, host)

    def _assert_ips_allowed(self, ips: Iterable[str], host: str) -> None:
        """Connection-time policy check for every address one resolution of
        ``host`` produced.

        Enforced by :class:`PinnedResolver` on every socket the scanner opens,
        which is what makes the guard TOCTOU-proof rather than advisory. A
        private/loopback/link-local/... address is refused unless the operator
        opted in globally (``allow_private_redirects``) or ``host`` is one
        *they* pointed the scanner at (``_trusted_hosts``) — a target-chosen
        redirect never qualifies.

        Being in ``_trusted_hosts`` only grants the exemption in principle; it
        does not say which address is the legitimate one. The first time a
        trusted host resolves to a blocked address, that exact address set is
        pinned (``_trusted_host_ips``); every later resolution of the same
        hostname must match it. A later resolution that disagrees — the zone
        rebinds after the DNS cache entry is evicted, or an unrelated redirect
        elsewhere in a multi-target scan happens to reuse the same alias — is
        refused instead of silently inheriting trust from the hostname alone.
        This is what keeps a scan of one intranet target from becoming a
        standing exemption for anything that later answers to the same name.

        All addresses from one resolution are checked together (not one at a
        time) so that a host with several trusted addresses — dual-stack, or
        multiple A records for the same authorized target — pins its whole
        first-seen set instead of rejecting its own second address as an
        "unexpected" one.
        """
        blocked = {ip for ip in ips if self._ip_is_blocked(ip)}
        if not blocked or self.config.allow_private_redirects:
            return
        if self.config.assert_public_target or host not in self._trusted_hosts:
            raise SSRFRedirectError(
                f"Refusing to connect to {host!r}: resolves to non-public "
                f"address(es) {sorted(blocked)}"
            )
        pinned = self._trusted_host_ips.get(host)
        if pinned is None:
            # First blocked resolution ever seen for this operator-designated
            # host: this *is* the intranet target — pin exactly these addresses.
            self._trusted_host_ips[host] = frozenset(blocked)
            return
        rogue = blocked - pinned
        if rogue:
            raise SSRFRedirectError(
                f"Refusing to connect to {host!r}: address(es) {sorted(rogue)} "
                f"do not match the address(es) {sorted(pinned)} originally "
                "vetted for this trusted host (possible DNS rebinding or "
                "cross-target alias reuse)"
            )

    async def _resolve_host(self, host: str) -> set[str]:
        """Resolve ``host`` once and memoise it, so the address the SSRF guard
        vetted is the same one :class:`PinnedResolver` later hands the socket."""
        cached = self._resolve_cache.get(host)
        if cached is not None:
            return cached
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise SSRFRedirectError(f"Cannot resolve host {host!r}: {e}") from e
        ips = {str(info[4][0]) for info in infos}
        # Bounded FIFO: dicts preserve insertion order, so the oldest entries go
        # first. An evicted host is simply resolved (and re-vetted) again.
        while len(self._resolve_cache) >= _MAX_RESOLVE_CACHE:
            self._resolve_cache.pop(next(iter(self._resolve_cache)))
        self._resolve_cache[host] = ips
        return ips

    async def _assert_public_url(self, url: str) -> None:
        """Raise SSRFRedirectError if ``url``'s host is / resolves to non-public."""
        host = urllib.parse.urlparse(url).hostname
        if not host:
            raise SSRFRedirectError(f"Redirect target has no host: {url!r}")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass  # a name -> resolve below
        else:
            if self._ip_is_blocked(host):
                raise SSRFRedirectError(
                    f"Redirect to non-public address blocked: {url!r}"
                )
            return
        for ip in await self._resolve_host(host):
            if self._ip_is_blocked(ip):
                raise SSRFRedirectError(
                    f"Redirect to {url!r} resolves to blocked address {ip}"
                )

    # ---- safe body reading -----------------------------------------

    async def _safe_read(
        self, response: "aiohttp.ClientResponse"
    ) -> tuple[str, bool, int]:
        """
        Read a response body defensively.

        The body is consumed in ``_READ_CHUNK`` steps from the *decoded*
        (already decompressed by aiohttp) stream. As soon as the accumulated
        size would exceed ``config.max_response_size`` the read stops, the
        connection is force-closed so the server can't keep feeding us, and the
        partial body is returned with ``truncated=True``.

        Returns ``(text, truncated, raw_len)``.
        """
        limit = self.config.max_response_size
        chunks = []
        total = 0
        truncated = False
        async for chunk in response.content.iter_chunked(_READ_CHUNK):
            if total + len(chunk) > limit:
                chunks.append(chunk[: limit - total])
                total = limit
                truncated = True
                break
            chunks.append(chunk)
            total += len(chunk)

        if truncated:
            # Abandon the rest of the stream and drop the socket instead of
            # draining a potentially infinite body.
            response.close()

        body = b"".join(chunks)
        try:
            encoding = response.get_encoding()
        except (RuntimeError, LookupError):
            encoding = "utf-8"
        text = body.decode(encoding or "utf-8", errors="ignore")
        return text, truncated, total

    # ---- warm-up ---------------------------------------------------

    @staticmethod
    def _endpoint_key(url: str) -> str:
        """Endpoint identity for warm-up dedup: scheme://netloc/path (no query)."""
        parts = urllib.parse.urlsplit(url)
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    async def warmup(self, url: str, n: int, *, method: str = "GET",
                     **kwargs: Any) -> int:
        """Fire up to ``n`` discard requests at ``url`` to prime the server.

        Mitigates JVM JIT warm-up bias on the OWASP Benchmark testbed: the first
        hits to a cold endpoint run interpreted bytecode and are far slower than
        steady state, which inflates and destabilises any latency baseline
        captured straight after. These requests go through :meth:`request`
        (``use_cache=False``), so the **token bucket, concurrency semaphore and
        SSRF guard all still apply**; their responses are discarded and no
        telemetry row is emitted.

        Idempotent per endpoint (``scheme://netloc/path``) — a second call for
        the same endpoint (e.g. from a different tester) is a no-op and returns
        ``0``. Stops early on the first hard transport failure
        (``status_code == 0``); propagates :class:`SSRFRedirectError` and
        :class:`asyncio.CancelledError` untouched. Returns the number issued.
        """
        if n <= 0:
            return 0
        key = self._endpoint_key(url)
        if key in self._warmed_endpoints:
            return 0
        if len(self._warmed_endpoints) >= _MAX_WARMED_ENDPOINTS:
            # Bounded: at worst an old endpoint gets warmed a second time.
            self._warmed_endpoints.clear()
        self._warmed_endpoints.add(key)
        issued = 0
        for _ in range(n):
            try:
                resp = await self.request(method, url, use_cache=False, **kwargs)
            except asyncio.CancelledError:
                raise
            except SSRFRedirectError:
                raise
            issued += 1
            if not resp or resp.get("status_code", 0) == 0:
                break
        return issued

    # ---- request -----------------------------------------------------

    async def request(self, method: str, url: str, *,
                      use_cache: bool = True, **kwargs) -> dict[str, Any]:
        """
        Execute an HTTP request with caching, rate limiting, UA rotation and
        SSRF-safe redirect following.

        ``use_cache`` (default ``True``): when ``False`` both the cache read and
        the cache write are skipped, forcing a fresh round-trip. Advanced-vector
        probes (``header`` / ``cookie`` injection, adaptive-latency sampling)
        pass ``use_cache=False`` so a benign response can never mask a mutated
        request.

        The cache key covers URL + method + body + a normalized (order- and
        case-insensitive) digest of the outgoing headers and cookies, so a
        payload injected into a header or cookie no longer collides with the
        benign baseline for the same URL.

        Returns a dict: {status_code, text, headers, url, elapsed[, error]}.
        Raises :class:`SSRFRedirectError` if a redirect points somewhere
        internal. Propagates :class:`asyncio.CancelledError` untouched.
        """
        if not self.session:
            await self.start()

        follow_redirects = kwargs.pop("allow_redirects", True)
        caller_headers_original = kwargs.pop("headers", None)
        # Internal guard: a request replayed once after a transparent re-auth.
        reauth_retry = kwargs.pop("_reauth_retry", False)

        # Attach persistent auth headers (bearer token). Merged into
        # ``caller_headers`` so the existing cross-host redirect scrubbing drops
        # them at an origin boundary just like an injected header. Session
        # cookies are handled per-domain by the aiohttp jar and need nothing
        # here. An explicit caller header of the same name still wins.
        if self._auth_headers:
            caller_headers = dict(self._auth_headers)
            if caller_headers_original:
                caller_headers.update(caller_headers_original)
        else:
            caller_headers = caller_headers_original

        data = kwargs.get("data") or kwargs.get("json")
        cookies = kwargs.get("cookies")
        if use_cache:
            cached = self.cache.get(url, method, data, caller_headers, cookies)
            if cached:
                return cached

        # This URL was chosen by the operator / crawler, not by a redirect the
        # target served, so PinnedResolver may let it resolve to a private
        # address (scanning your own intranet is legitimate). Recorded before
        # the pre-flight check so ``assert_public_target`` still overrides it.
        first_hop_host = urllib.parse.urlparse(url).hostname
        if first_hop_host:
            self._trusted_hosts.add(first_hop_host)

        # Optional pre-flight SSRF check on the first hop (redirects are always
        # checked below). Applies identically to GET/POST/JSON/header/cookie
        # probes — the mutated request never leaves before this passes.
        if self.config.assert_public_target and not self.config.allow_private_redirects:
            await self._assert_public_url(url)

        # Rate gate BEFORE taking a concurrency slot: waiting for a token must
        # not hold a semaphore permit (that serialised everything before). This
        # gate and the semaphore below wrap EVERY request regardless of method
        # or injection vector.
        if self._rate_bucket is not None:
            await self._rate_bucket.acquire()

        result = await self._request_with_resilience(
            method, url, follow_redirects, caller_headers, kwargs, first_hop_host,
        )

        # Transparent re-authentication: if the response looks logged-out and a
        # session manager is attached, re-login once (rate-limited by the
        # manager's cooldown) and replay this exact request a single time.
        if (not reauth_retry and self._session_manager is not None
                and self._session_manager.looks_logged_out(result)):
            if await self._session_manager.maybe_reauth(self, result):
                return await self.request(
                    method, url, use_cache=False, allow_redirects=follow_redirects,
                    headers=caller_headers_original, _reauth_retry=True, **kwargs,
                )

        if use_cache and method.upper() == "GET" and result.get("status_code") == 200:
            self.cache.put(url, method, data, result, caller_headers, cookies)
        return result

    def _warn_if_tls_verification_error(self, exc: BaseException) -> None:
        """Surface a self-signed / untrusted-cert failure loudly, once.

        Without ``--no-verify-ssl`` a bench serving HTTPS with a self-signed
        certificate makes *every* probe fail at the TLS handshake; the request
        layer swallows that into ``status_code=0`` and the scan looks like it
        "ran" while detecting nothing. Rather than let that stay silent at DEBUG
        level, emit a single actionable WARNING the first time it happens.
        """
        if self.config.verify_ssl is False or self._ssl_notice_emitted:
            return
        cause: BaseException | None = exc
        seen = 0
        while cause is not None and seen < 6:
            if isinstance(cause, ssl.SSLCertVerificationError) or (
                isinstance(cause, ssl.SSLError)
                and "CERTIFICATE_VERIFY_FAILED" in str(cause)
            ):
                self._logger.warning(
                    "TLS certificate verification failed (%s). The target is "
                    "likely using a self-signed certificate. Re-run with "
                    "--no-verify-ssl to accept it — otherwise every request "
                    "degrades to status_code=0 and no vulnerability is found.",
                    type(cause).__name__,
                )
                self._ssl_notice_emitted = True
                return
            cause = cause.__cause__ or cause.__context__
            seen += 1

    async def _request_with_resilience(
        self, method: str, url: str, follow_redirects: bool,
        caller_headers: dict[str, str] | None, kwargs: dict[str, Any],
        host: str | None,
    ) -> dict[str, Any]:
        """Issue one logical request with bounded retries and host cooldown.

        With the defaults (``max_retries=0``, ``adaptive_throttle=False``)
        this is exactly the old single-attempt try/except -> ``status_code=0``
        behaviour, just factored out. Opting in changes two things:

        - a hard transport failure (exception, or a redirect chain that
          collapses to ``status_code=0``) is retried up to ``max_retries``
          times with exponential backoff + full jitter, each wait sleeping
          *outside* the semaphore so a backing-off probe never occupies a
          concurrency slot other probes (to other endpoints) could use;
        - with ``adaptive_throttle`` on, a 429/503 also counts as retryable
          and additionally parks *every future* request to this host behind
          a per-host cooldown (:class:`HostBackoff`) honouring ``Retry-After``
          when the target sends one. A clean response decays that cooldown.

        Never retries :class:`SSRFRedirectError` or ``CancelledError`` --
        those propagate immediately, same as before.
        """
        attempts = max(1, self.config.max_retries + 1)
        throttle_on = self.config.adaptive_throttle and host is not None
        result: dict[str, Any] = {}
        for attempt in range(attempts):
            if throttle_on and host is not None:
                await self._host_backoff.wait_if_needed(host)
            try:
                async with self._semaphore:
                    result = await self._request_following(
                        method, url, follow_redirects, caller_headers, kwargs
                    )
            except asyncio.CancelledError:
                raise
            except SSRFRedirectError:
                raise
            except Exception as e:
                self._logger.debug(f"Request failed: {url} - {e}")
                self._warn_if_tls_verification_error(e)
                result = {
                    "status_code": 0, "text": "", "headers": {},
                    "url": url, "elapsed": 0.0, "truncated": False, "error": str(e),
                }

            status = result.get("status_code", 0)
            throttled = bool(throttle_on and status in (429, 503))
            transient = status == 0

            # Real-time telemetry: record every raw attempt (including
            # retries the tester layer never sees), tagged with whichever
            # operational phase the orchestrator last set. Independent of
            # ``adaptive_throttle`` -- rate-limit detection here is always on.
            diag = self.telemetry_engine.record_request(
                host or "unknown", float(result.get("elapsed", 0.0) or 0.0),
                status, retried=attempt > 0,
            )
            if self._concurrency_controller is not None:
                self._concurrency_controller.on_outcome(
                    throttled=diag["rate_limited"], transient=transient,
                )

            host_delay = 0.0
            if throttle_on and host is not None:
                if throttled:
                    host_delay = self._host_backoff.penalize(
                        host, retry_after=result.get("headers", {}).get("Retry-After"),
                    )
                elif status != 0:
                    self._host_backoff.relax(host)

            if not (throttled or transient) or attempt == attempts - 1:
                return result

            if throttled:
                delay = host_delay
            else:
                base = self.config.retry_backoff_base * (2 ** attempt)
                delay = random.uniform(0.0, min(base, self.config.retry_backoff_max))
            if delay > 0:
                await asyncio.sleep(delay)
        return result

    async def _request_following(
        self, method: str, url: str, follow_redirects: bool,
        caller_headers: dict[str, str] | None, kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Issue the request, manually following redirects with SSRF checks."""
        timeout = aiohttp.ClientTimeout(
            total=self.config.timeout,
            sock_connect=self.config.sock_connect_timeout,
            sock_read=self.config.sock_read_timeout,
        )
        current_method = method
        current_url = url
        origin_host = urllib.parse.urlparse(url).hostname
        redirects = 0
        started = time.monotonic()
        # Not `assert`: this invariant must hold even under `python -O`, where
        # assertions are stripped and a None session would surface as an opaque
        # AttributeError deep inside the redirect loop.
        if self.session is None:
            raise RuntimeError(
                "HTTP session not initialised; call AsyncScannerCore.start() "
                "(or use the async context manager) before issuing requests"
            )

        # An http(s):// proxy rides on the per-request kwarg; a socks proxy is
        # already baked into the connector, so it must not be passed here.
        request_proxy = None if self._is_socks_proxy() else self.config.proxy

        while True:
            headers = self._request_headers(caller_headers)
            async with self.session.request(
                current_method, current_url,
                timeout=timeout, proxy=request_proxy,
                allow_redirects=False, headers=headers, **kwargs,
            ) as response:
                status = response.status
                resp_headers = dict(response.headers)
                final_url = str(response.url)
                location = response.headers.get("Location")
                # Redirects: skip reading the (usually empty) body entirely.
                if (follow_redirects and status in REDIRECT_STATUSES
                        and location and redirects < self.config.max_redirects):
                    text, truncated = "", False
                    response.close()
                else:
                    text, truncated, _ = await self._safe_read(response)

            if (follow_redirects and status in REDIRECT_STATUSES
                    and location and redirects < self.config.max_redirects):
                next_url = urllib.parse.urljoin(current_url, location)
                if not self.config.allow_private_redirects:
                    await self._assert_public_url(next_url)
                # Do not carry injected/session material across an origin
                # boundary: a payload placed in a request header or a session
                # cookie must not be replayed to a third-party host the target
                # redirected us to.
                if urllib.parse.urlparse(next_url).hostname != origin_host:
                    if caller_headers or kwargs.get("cookies"):
                        self._logger.debug(
                            "Cross-host redirect %s -> %s: dropping injected "
                            "headers/cookies", current_url, next_url,
                        )
                    caller_headers = None
                    kwargs.pop("cookies", None)
                redirects += 1
                # 303 always -> GET; 301/302 -> GET for non-idempotent methods
                # (matches how browsers and requests behave).
                if status == 303 or (
                    status in (301, 302) and current_method not in ("GET", "HEAD")
                ):
                    current_method = "GET"
                    kwargs.pop("data", None)
                    kwargs.pop("json", None)
                current_url = next_url
                continue

            return {
                "status_code": status,
                "text": text,
                "headers": resp_headers,
                "url": final_url,
                "elapsed": time.monotonic() - started,
                "truncated": truncated,
            }
