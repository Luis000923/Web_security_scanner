import asyncio
import hashlib
import ipaddress
import logging
import random
import socket
import time
import urllib.parse
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

import aiohttp

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

    def _generate_key(self, url: str, method: str, data: Any) -> str:
        key_data = f"{url}-{method}-{str(data)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def get(self, url: str, method: str, data: Any = None) -> dict | None:
        key = self._generate_key(url, method, data)
        if key in self.cache:
            if time.time() - self.access_times.get(key, 0) < self.ttl:
                return self.cache[key]
            else:
                self._remove(key)
        return None

    def put(self, url: str, method: str, data: Any, response_data: dict):
        if len(self.cache) >= self.max_size:
            self._evict_old_entries()

        key = self._generate_key(url, method, data)
        self.cache[key] = response_data
        self.access_times[key] = time.time()

    def _remove(self, key):
        if key in self.cache:
            del self.cache[key]
        if key in self.access_times:
            del self.access_times[key]

    def _evict_old_entries(self):
        if not self.access_times:
            return
        sorted_keys = sorted(self.access_times.items(), key=lambda x: x[1])
        to_remove = int(len(sorted_keys) * 0.25)
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
        # host -> {ip, ...}; avoids re-resolving on every redirect check.
        self._resolve_cache: dict[str, set] = {}

    def _is_socks_proxy(self) -> bool:
        proxy = (self.config.proxy or "").lower()
        return proxy.startswith(_SOCKS_SCHEMES)

    def _build_connector(self) -> "aiohttp.BaseConnector":
        """TCP connector, or a SOCKS connector when a socks proxy is configured.

        SOCKS support is optional: it needs the ``aiohttp_socks`` package. HTTP
        proxying does not go through the connector (it rides on the per-request
        ``proxy=`` kwarg), so this only special-cases socks URLs.
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
                self.config.proxy, ssl=self.config.verify_ssl,
                limit=self.config.max_concurrency,
            )
        return aiohttp.TCPConnector(
            limit=self.config.max_concurrency,
            ssl=self.config.verify_ssl,
        )

    async def start(self):
        """Initialize the aiohttp session."""
        if not self.session:
            connector = self._build_connector()
            headers = dict(self.config.headers)
            if self.config.user_agent:
                headers.setdefault("User-Agent", self.config.user_agent)
            self.session = aiohttp.ClientSession(connector=connector, headers=headers)

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

    async def _resolve_host(self, host: str) -> set:
        if host in self._resolve_cache:
            return self._resolve_cache[host]
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise SSRFRedirectError(f"Cannot resolve redirect host {host!r}: {e}") from e
        ips = {info[4][0] for info in infos}
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

    async def _safe_read(self, response: "aiohttp.ClientResponse") -> tuple:
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

    # ---- request -----------------------------------------------------

    async def request(self, method: str, url: str, **kwargs) -> dict[str, Any]:
        """
        Execute an HTTP request with caching, rate limiting, UA rotation and
        SSRF-safe redirect following.

        Returns a dict: {status_code, text, headers, url, elapsed[, error]}.
        Raises :class:`SSRFRedirectError` if a redirect points somewhere
        internal. Propagates :class:`asyncio.CancelledError` untouched.
        """
        if not self.session:
            await self.start()

        data = kwargs.get("data") or kwargs.get("json")
        cached = self.cache.get(url, method, data)
        if cached:
            return cached

        follow_redirects = kwargs.pop("allow_redirects", True)
        caller_headers = kwargs.pop("headers", None)

        # Rate gate BEFORE taking a concurrency slot: waiting for a token must
        # not hold a semaphore permit (that serialised everything before).
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
            return {
                "status_code": 0, "text": "", "headers": {},
                "url": url, "elapsed": 0.0, "truncated": False, "error": str(e),
            }

        if method.upper() == "GET" and result.get("status_code") == 200:
            self.cache.put(url, method, data, result)
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
        redirects = 0
        started = time.monotonic()
        assert self.session is not None  # started by AsyncScannerCore.start()

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
