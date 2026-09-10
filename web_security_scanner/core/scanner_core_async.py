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
        for ip in sorted(ips):
            self._core._assert_ip_allowed(ip, host)
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
        # Bounds requests actually in flight.
        self._semaphore = asyncio.Semaphore(config.max_concurrency)
        # Global request pacing, decoupled from the concurrency slot.
        self._rate_bucket: TokenBucket | None = None
        if config.rate_limit and config.rate_limit > 0:
            self._rate_bucket = TokenBucket(
                rate=1.0 / config.rate_limit, capacity=config.rate_burst
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

        Enforced by :class:`PinnedResolver` on every socket the scanner opens,
        which is what makes the guard TOCTOU-proof rather than advisory. A
        private address is refused unless the operator opted in
        (``allow_private_redirects``) or the hostname is one *they* pointed the
        scanner at (``_trusted_hosts``) — a target-chosen redirect never
        qualifies.
        """
        if self.config.allow_private_redirects or not self._ip_is_blocked(ip):
            return
        if host in self._trusted_hosts and not self.config.assert_public_target:
            return
        raise SSRFRedirectError(
            f"Refusing to connect to {host!r}: resolves to non-public address {ip}"
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
            return {
                "status_code": 0, "text": "", "headers": {},
                "url": url, "elapsed": 0.0, "truncated": False, "error": str(e),
            }

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
