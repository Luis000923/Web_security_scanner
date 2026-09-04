"""Scope engine and SSRF filter (ported from ``route-mapper``).

Three-layer anti-SSRF defence applied to every discovered URL:

1. :func:`normalize_url` - rejects anything that is not navigable http(s) and
   strips CRLF / NUL so a crawled URL can never be used for header injection.
2. :meth:`ScopeEngine.host_in_scope` - the host must match the seed exactly
   or, with subdomains enabled, be an explicit suffix of it. The Public Suffix
   List is never consulted, so ``evil-example.com`` is not in scope for
   ``example.com``.
3. :meth:`ScopeEngine.assert_ip_allowed` - a pre-flight DNS resolution; the
   URL is rejected unless *every* resolved address is public (no loopback,
   private, link-local, CGNAT, multicast, reserved or unspecified range).

Only ``ipaddress`` and ``socket`` from the standard library are used.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Callable
from urllib.parse import parse_qsl, quote, urldefrag, urlencode, urljoin, urlparse, urlunparse

Resolver = Callable[[str], list[str]]

# Carrier-Grade NAT (RFC 6598). ``ipaddress`` only marks it private from
# Python 3.13 on, so it is checked explicitly for every supported version.
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_PATH_SAFE = "/:@!$&'()*+,;=~-._"
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_FORBIDDEN = ("\n", "\r", "\x00")


class ScopeViolation(Exception):
    """The target URL is outside the authorised scope of the crawl."""


class SsrfViolation(Exception):
    """The host resolves to a non-public address (loopback, private, ...)."""


def _encode_component(value: str, safe: str) -> str:
    """Percent-encode Unicode while preserving already-valid ``%XX`` sequences."""
    out: list[str] = []
    last = 0
    for match in _PCT_RE.finditer(value):
        out.append(quote(value[last:match.start()], safe=safe))
        out.append(match.group(0).upper())
        last = match.end()
    out.append(quote(value[last:], safe=safe))
    return "".join(out)


def _encode_host(host: str) -> str | None:
    """Convert an IDN host to its ASCII (punycode) form; ``None`` if invalid."""
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None


def _normalize_query(query: str) -> str:
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True)
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for pair in pairs:
        if pair in seen:
            continue
        seen.add(pair)
        unique.append(pair)
    unique.sort(key=lambda kv: (kv[0], kv[1]))
    return urlencode(unique)


def normalize_url(url: str) -> str | None:
    """Normalise a URL or return ``None`` if it is not navigable http(s).

    Drops the fragment, lower-cases the scheme and host, removes the default
    port, strips a trailing slash (except at the root), sorts the query string
    and rejects any URL carrying CR, LF or NUL.
    """
    if not url:
        return None
    if any(ch in url for ch in _FORBIDDEN):
        return None

    url, _ = urldefrag(url.strip())
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return None

    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not hostname:
        return None

    scheme = parsed.scheme.lower()
    host = _encode_host(hostname.lower())
    if host is None:
        return None

    netloc = host
    if port and port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"

    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    path = _encode_component(path, _PATH_SAFE)

    return urlunparse((scheme, netloc, path, parsed.params, _normalize_query(parsed.query), ""))


def resolve_link(base_url: str, href: str) -> str | None:
    """Resolve a relative ``href`` against ``base_url`` and normalise it."""
    try:
        absolute = urljoin(base_url, href)
    except ValueError:
        return None
    return normalize_url(absolute)


def is_blocked_ip(ip: str) -> bool:
    """``True`` if ``ip`` belongs to a range that must never be contacted."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.version == 4 and addr in _CGNAT_NETWORK:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def is_valid_subdomain(host: str, root: str, *, include_subdomains: bool) -> bool:
    """Strict host match against the seed, without guessing suffixes."""
    host = host.lower().rstrip(".")
    root = root.lower().rstrip(".")
    if not host or not root:
        return False
    if host == root:
        return True
    if include_subdomains:
        return host.endswith("." + root)
    return False


def _default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


class ScopeEngine:
    """Decides whether a URL is allowed by the domain and IP policies."""

    def __init__(
        self,
        root_host: str,
        *,
        include_subdomains: bool,
        resolver: Resolver | None = None,
    ) -> None:
        self._root = root_host.lower().rstrip(".")
        self._include_subdomains = include_subdomains
        self._resolver: Resolver = resolver or _default_resolver

    @property
    def root_host(self) -> str:
        return self._root

    def host_in_scope(self, host: str) -> bool:
        return is_valid_subdomain(
            host, self._root, include_subdomains=self._include_subdomains
        )

    def assert_ip_allowed(self, host: str) -> list[str]:
        """Resolve ``host`` and verify every address is public.

        Returns the resolved IPs or raises :class:`SsrfViolation`.
        """
        try:
            ips = self._resolver(host)
        except OSError as exc:
            raise SsrfViolation(f"could not resolve {host!r}: {exc}") from exc
        if not ips:
            raise SsrfViolation(f"{host!r} resolved to no address")
        for ip in ips:
            if is_blocked_ip(ip):
                raise SsrfViolation(f"{host!r} resolves to a non-public address ({ip})")
        return ips

    def validate_url(self, url: str) -> list[str]:
        """Validate scope + SSRF for ``url``. Raises on any failure."""
        normalized = normalize_url(url)
        if normalized is None:
            raise ScopeViolation(f"URL not navigable: {url!r}")
        host = urlparse(normalized).hostname
        if not host:
            raise ScopeViolation(f"URL without host: {url!r}")
        if not self.host_in_scope(host):
            raise ScopeViolation(f"{host!r} outside the scope of {self._root!r}")
        return self.assert_ip_allowed(host)

    async def validate_url_async(self, url: str) -> bool:
        """Non-blocking :meth:`validate_url`; returns ``True`` when allowed.

        The pure layers (normalisation, domain scope) run inline; the blocking
        DNS resolution is pushed to a worker thread so the event loop is never
        stalled.
        """
        normalized = normalize_url(url)
        if normalized is None:
            return False
        host = urlparse(normalized).hostname
        if not host or not self.host_in_scope(host):
            return False
        try:
            await asyncio.to_thread(self.assert_ip_allowed, host)
        except SsrfViolation:
            return False
        return True
