"""Crawling a private laboratory requires an explicit opt-in."""

from types import SimpleNamespace

import pytest

from tests.conftest import MockScanner
from web_security_scanner.modules.web_mapper_async import WebMapperAsync


@pytest.mark.asyncio
@pytest.mark.parametrize("allow_private", [False, True])
async def test_private_crawl_respects_opt_in_and_scope(monkeypatch, allow_private):
    async def noop(self):
        return None

    async def reject_private(url):
        raise ValueError("private IP blocked")

    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", noop)
    scanner = MockScanner(lambda method, url, kwargs: {
        "text": '<a href="/lectura.php?file=demo">read</a>'
                '<a href="http://192.168.1.2/outside">outside</a>',
        "headers": {"Content-Type": "text/html"},
    })
    scanner.config = SimpleNamespace(allow_private_redirects=allow_private)
    scanner._assert_public_url = reject_private
    mapper = WebMapperAsync(scanner, crawl_delay=0, respect_robots=False)
    await mapper.map_website("http://127.0.0.1:18765/index.php?q=libro", max_depth=1)
    if allow_private:
        assert any("lectura.php?file=demo" in url for url in mapper.visited_urls)
        assert all("192.168.1.2" not in url for url in mapper.visited_urls)
    else:
        assert not mapper.visited_urls
