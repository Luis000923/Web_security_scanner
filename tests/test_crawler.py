"""Tests for WebMapperAsync spider-trap / OOM protections."""

import pytest

from tests.conftest import MockScanner
from web_security_scanner.modules.web_mapper_async import WebMapperAsync


def _trap_responder(method, url, kwargs):
    """
    Infinite spider trap: every page /a/b/c... links one level deeper
    (/a/b/c/<n+1>) AND to a fresh ?id=<n> variant of the same path.
    """
    from urllib.parse import urlparse

    path = urlparse(url).path.rstrip("/") or "/"
    depth = len([p for p in path.split("/") if p])
    deeper = f"http://trap.test{path}/{depth + 1}"
    variants = "".join(
        f'<a href="http://trap.test{path or "/"}?id={i}">v{i}</a>' for i in range(50)
    )
    return {
        "status_code": 200,
        "text": f'<html><body><a href="{deeper}">deeper</a>{variants}</body></html>',
        "headers": {},
        "url": url,
    }


async def _noop(self):
    return None


@pytest.mark.asyncio
async def test_crawler_stops_at_max_depth(monkeypatch):
    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", _noop)
    mapper = WebMapperAsync(MockScanner(_trap_responder), max_urls=10_000, crawl_delay=0)

    data = await mapper.map_website("http://trap.test/1", max_depth=3)

    # Deepest path crawled must not exceed base(1 segment) + max_depth hops.
    from urllib.parse import urlparse
    max_segments = max(
        len([p for p in urlparse(u).path.split("/") if p]) for u in mapper.visited_urls
    )
    assert max_segments <= 1 + 3
    # It terminated and returned a (partial) map instead of looping forever.
    assert data["structure"] is mapper.site_structure
    assert len(mapper.visited_urls) < 10_000


@pytest.mark.asyncio
async def test_crawler_hard_url_cap(monkeypatch):
    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", _noop)
    mapper = WebMapperAsync(MockScanner(_trap_responder), max_urls=15, crawl_delay=0)

    await mapper.map_website("http://trap.test/1", max_depth=50)

    assert len(mapper.visited_urls) <= 15
    assert mapper.limit_reached is True


@pytest.mark.asyncio
async def test_signature_cap_blocks_query_param_trap(monkeypatch):
    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", _noop)
    mapper = WebMapperAsync(MockScanner(_trap_responder), max_urls=10_000, crawl_delay=0)

    await mapper.map_website("http://trap.test/1", max_depth=2)

    # ?id=N variants are capped *per path signature*, not crawled 50-wide per
    # node. (Distinct paths — /1, /1/2 — each get their own capped budget.)
    from collections import Counter
    from urllib.parse import urlparse
    per_path = Counter(urlparse(u).path for u in mapper.visited_urls if "id=" in u)
    assert per_path, "trap should have produced ?id= variants"
    assert max(per_path.values()) <= WebMapperAsync.MAX_URLS_PER_SIGNATURE


def test_normalize_url_strips_fragment_and_junk():
    mapper = WebMapperAsync(MockScanner(_trap_responder))
    a = mapper._normalize_url("http://x.test/page?b=2&a=1&utm_source=nl#section")
    b = mapper._normalize_url("http://x.test/page?a=1&b=2")
    assert a == b
    assert "#" not in a and "utm_source" not in a


@pytest.mark.asyncio
async def test_generate_map_async_is_offloaded(tmp_path, monkeypatch):
    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", _noop)
    mapper = WebMapperAsync(MockScanner(_trap_responder), max_urls=5, crawl_delay=0)
    data = await mapper.map_website("http://trap.test/1", max_depth=1)
    out = tmp_path / "map.html"
    path = await mapper.generate_map_async(data, str(out))
    assert out.exists() and path == str(out)
