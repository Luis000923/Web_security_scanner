"""Decoupled asynchronous HTTP client with connection pooling, rate limiting, and exponential backoff retries.

Provides:
- Connection pool with configurable TCP connection limits.
- Concurrency control via asyncio.Semaphore (resizing supported).
- Token-bucket rate limiting decoupled from concurrency permits.
- Automatic retries with exponential backoff and full jitter.
- Defensively bounded streaming of response bodies (memory exhaustion protection).
"""

from __future__ import annotations

import asyncio
import logging
import random
import ssl
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import aiohttp
from aiohttp.abc import AbstractResolver

_READ_CHUNK = 64 * 1024  # 64 KiB per chunk
MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5 MiB


class TokenBucket:
    """Async token bucket rate limiter.

    Tokens refill continuously at ``rate`` per second up to ``capacity``.
    Caller sleeps outside the lock so rate pacing never blocks the concurrency gate.
    """

    def __init__(self, rate: float, capacity: float = 1.0) -> None:
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


@dataclass
class HTTPClientConfig:
    """Configuration options for AsyncHTTPClient."""

    max_concurrency: int = 50
    timeout: int = 10
    rate_limit: float = 0.0  # min seconds between requests (0 = unlimited)
    rate_burst: int = 1
    max_retries: int = 0
    retry_backoff_base: float = 0.5
    retry_backoff_max: float = 10.0
    verify_ssl: bool = True
    proxy: str | None = None
    user_agent: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookie_jar_unsafe: bool = False
    max_response_size: int = MAX_RESPONSE_SIZE


class AsyncHTTPClient:
    """Decoupled async HTTP client encapsulating connection pooling, rate limiting, and retries."""

    def __init__(
        self,
        config: HTTPClientConfig | None = None,
        *,
        resolver: AbstractResolver | None = None,
        custom_semaphore: Any | None = None,
    ) -> None:
        self.config = config or HTTPClientConfig()
        self._resolver = resolver
        self._custom_semaphore = custom_semaphore
        self.session: aiohttp.ClientSession | None = None
        self._logger = logging.getLogger(__name__)

        # Concurrency limiter
        if custom_semaphore is not None:
            self._semaphore = custom_semaphore
        else:
            self._semaphore = asyncio.Semaphore(self.config.max_concurrency)

        # Rate limiter
        self._rate_bucket: TokenBucket | None = None
        if self.config.rate_limit and self.config.rate_limit > 0:
            self._rate_bucket = TokenBucket(
                rate=1.0 / self.config.rate_limit, capacity=self.config.rate_burst
            )

    @property
    def semaphore(self) -> Any:
        return self._semaphore

    @property
    def rate_bucket(self) -> TokenBucket | None:
        return self._rate_bucket

    def set_concurrency(self, value: int) -> None:
        """Adjust the concurrency limit dynamically."""
        value = max(1, int(value))
        self.config.max_concurrency = value
        if hasattr(self._semaphore, "resize"):
            self._semaphore.resize(value)
        else:
            self._semaphore = asyncio.Semaphore(value)

    def _ssl_context(self) -> bool | ssl.SSLContext:
        if self.config.verify_ssl:
            return True
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _build_connector(self) -> aiohttp.BaseConnector:
        ssl_param = self._ssl_context()
        proxy = (self.config.proxy or "").lower()
        if proxy.startswith(("socks5://", "socks5h://", "socks4://")):
            try:
                from aiohttp_socks import ProxyConnector

                return ProxyConnector.from_url(
                    self.config.proxy,
                    ssl=ssl_param,
                    limit=self.config.max_concurrency,
                )
            except ImportError as exc:
                raise RuntimeError(
                    "SOCKS proxy requested but 'aiohttp_socks' is not installed."
                ) from exc

        return aiohttp.TCPConnector(
            limit=self.config.max_concurrency,
            ssl=ssl_param,
            resolver=self._resolver,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )

    async def start(self) -> None:
        """Initialize the client session and connection pool."""
        if not self.session or self.session.closed:
            connector = self._build_connector()
            headers = dict(self.config.headers)
            if self.config.user_agent:
                headers.setdefault("User-Agent", self.config.user_agent)

            self.session = aiohttp.ClientSession(
                connector=connector,
                headers=headers,
                cookie_jar=aiohttp.CookieJar(unsafe=self.config.cookie_jar_unsafe),
            )

    async def close(self) -> None:
        """Close the client session and release connection pool resources."""
        session, self.session = self.session, None
        if session is not None and not session.closed:
            await session.close()
            await asyncio.sleep(0)

    @property
    def is_closed(self) -> bool:
        return self.session is None or self.session.closed

    async def _read_body_defensively(
        self, response: aiohttp.ClientResponse
    ) -> tuple[str, bool, int]:
        """Read response body incrementally, stopping if max_response_size is exceeded."""
        limit = self.config.max_response_size
        chunks: list[bytes] = []
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
            response.close()

        body = b"".join(chunks)
        try:
            encoding = response.get_encoding()
        except (RuntimeError, LookupError):
            encoding = "utf-8"
        text = body.decode(encoding or "utf-8", errors="ignore")
        return text, truncated, total

    async def send_single_request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        allow_redirects: bool = True,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute one HTTP round-trip without internal retries, inside the semaphore."""
        if not self.session or self.session.closed:
            await self.start()
        assert self.session is not None

        start_time = time.monotonic()
        timeout = aiohttp.ClientTimeout(
            total=self.config.timeout,
            connect=min(5.0, self.config.timeout),
        )
        proxy = self.config.proxy if not (self.config.proxy or "").startswith("socks") else None

        async with self._semaphore:
            async with self.session.request(
                method,
                url,
                timeout=timeout,
                proxy=proxy,
                allow_redirects=allow_redirects,
                headers=headers,
                **kwargs,
            ) as response:
                status = response.status
                text, truncated, _len = await self._read_body_defensively(response)
                elapsed = time.monotonic() - start_time
                resp_headers = {str(k): str(v) for k, v in response.headers.items()}
                return {
                    "status_code": status,
                    "text": text,
                    "headers": resp_headers,
                    "url": str(response.url),
                    "elapsed": elapsed,
                    "truncated": truncated,
                }

    async def execute_with_retry(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        allow_redirects: bool = True,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute request with rate limiting and exponential backoff retries."""
        attempts = max(1, self.config.max_retries + 1)
        result: dict[str, Any] = {}

        for attempt in range(attempts):
            # Rate limiting gate (waits OUTSIDE the semaphore permit)
            if self._rate_bucket is not None:
                await self._rate_bucket.acquire()

            try:
                result = await self.send_single_request(
                    method, url, headers=headers, allow_redirects=allow_redirects, **kwargs
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._logger.debug(f"HTTP request error: {url} - {exc}")
                result = {
                    "status_code": 0,
                    "text": "",
                    "headers": {},
                    "url": url,
                    "elapsed": 0.0,
                    "truncated": False,
                    "error": str(exc),
                }

            status = result.get("status_code", 0)
            is_transient = status == 0

            # If request succeeded or this was the final attempt, return result
            if not is_transient or attempt == attempts - 1:
                return result

            # Exponential backoff with full jitter
            base = self.config.retry_backoff_base * (2**attempt)
            delay = random.uniform(0.0, min(base, self.config.retry_backoff_max))
            if delay > 0:
                await asyncio.sleep(delay)

        return result
