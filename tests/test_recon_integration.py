"""Phase 1 recon integration (route-mapper capabilities).

A fake HTTP surface exposes:
    /                 - HTML landing page linking to /login?next=/ and app.js
    /static/app.js    - a JS bundle referencing "/api/v2/users"
    /sitemap.xml      - a sitemap declaring /products?id=1 and an out-of-scope URL

The tests assert that sitemap URLs and JS-mined endpoints are discovered,
scope-filtered, and handed to the vulnerability testers (Phase 2).
"""

import pytest

from tests.conftest import MockScanner
from web_security_scanner.modules.recon import (
    ReconConfig,
    ReconEngine,
    ScopeEngine,
    ScopeViolation,
    extract_js_endpoints,
    parse_sitemap,
)
from web_security_scanner.modules.web_mapper_async import WebMapperAsync

BASE = "http://target.test/"

_LANDING = """<html><body>
  <a href="/login?next=/dashboard">login</a>
  <a href="/products?id=1">products</a>
  <a href="https://evil.test/phish">external</a>
  <script src="/static/app.js"></script>
</body></html>"""

_APP_JS = """
const API = "/api/v2/users";
fetch("/api/v2/orders");
const img = "/assets/logo.png";     // static noise, must be ignored
"""

_SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://target.test/products?id=1</loc></url>
  <url><loc>http://target.test/help/faq</loc></url>
  <url><loc>http://other-domain.test/leak</loc></url>
</urlset>"""


def _responder(method, url, kwargs):
    from urllib.parse import urlparse

    path = urlparse(url).path
    if path in ("", "/"):
        return {"text": _LANDING, "headers": {"Content-Type": "text/html"}}
    if path == "/static/app.js":
        return {"text": _APP_JS, "headers": {"Content-Type": "application/javascript"}}
    if path == "/sitemap.xml":
        return {"text": _SITEMAP, "headers": {"Content-Type": "application/xml"}}
    if path == "/robots.txt":
        return {"status_code": 404, "text": ""}
    # Every other in-scope path answers 200 with a trivial HTML body.
    return {"text": f"<html><body>ok {path}</body></html>",
            "headers": {"Content-Type": "text/html"}}


# --- pure helpers ---------------------------------------------------------


def test_extract_js_endpoints_finds_api_and_skips_static():
    eps = extract_js_endpoints(_APP_JS)
    assert "/api/v2/users" in eps
    assert "/api/v2/orders" in eps
    assert "/assets/logo.png" not in eps


def test_parse_sitemap_reads_loc_and_rejects_dtd():
    locs = parse_sitemap(_SITEMAP)
    assert "http://target.test/products?id=1" in locs
    assert "http://target.test/help/faq" in locs
    assert parse_sitemap('<!DOCTYPE x [<!ENTITY a "b">]><urlset/>') == []


def test_scope_engine_three_layers():
    engine = ScopeEngine("target.test", include_subdomains=False,
                          resolver=lambda h: ["93.184.216.34"])
    assert engine.host_in_scope("target.test")
    assert not engine.host_in_scope("evil.test")
    with pytest.raises(ScopeViolation):
        engine.validate_url("http://evil.test/")
    with pytest.raises(ScopeViolation):
        engine.validate_url("ftp://target.test/")  # layer 1: scheme


# --- recon crawl --------------------------------------------------------


@pytest.mark.asyncio
async def test_recon_discovers_sitemap_and_js_endpoints(monkeypatch):
    async def _noop(self):
        return None

    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", _noop)
    mapper = WebMapperAsync(MockScanner(_responder), crawl_delay=0)
    engine = ReconEngine(
        mapper,
        ReconConfig(max_urls=100, max_depth=3, crawl_delay=0.0,
                    use_sitemap=True, parse_js=True, include_subdomains=True),
    )

    result = await engine.run(BASE)

    # JS endpoint mined out of the bundle, resolved and scope-checked.
    assert "http://target.test/api/v2/users" in mapper.js_endpoints
    assert "http://target.test/api/v2/orders" in mapper.js_endpoints

    # Sitemap URLs seeded (in scope only).
    assert any("target.test/products" in u for u in mapper.sitemap_urls)
    assert all("other-domain.test" not in u for u in mapper.sitemap_urls)

    # Out-of-scope link never crawled.
    assert all("evil.test" not in u for u in mapper.visited_urls)

    # All of the above are queued as tester targets.
    joined = " ".join(result.targets)
    assert "/api/v2/users" in joined
    assert "/products" in joined
    assert BASE in result.targets


# --- Phase 2 ingestion ------------------------------------------------


class _RecordingTester:
    name = "recorder"
    description = "records the URLs it is asked to test"

    def __init__(self):
        self.seen: list[str] = []

    async def run_test(self, target_url, **kwargs):
        self.seen.append(target_url)


@pytest.mark.asyncio
async def test_discovered_targets_reach_the_testers(monkeypatch):
    from web_security_scanner.core.scanner_core_async import ScanConfig
    from web_security_scanner.web_security_scanner_async import WebSecurityScanner

    class FakeCore:
        def __init__(self, responder):
            self._responder = responder
            self.config = ScanConfig()

        async def start(self):
            return None

        async def close(self):
            return None

        async def request(self, method, url, **kwargs):
            resp = self._responder(method, url, kwargs)
            resp.setdefault("status_code", 200)
            resp.setdefault("text", "")
            resp.setdefault("headers", {})
            resp.setdefault("elapsed", 0.0)
            resp.setdefault("url", url)
            return resp

        async def run_worker_pool(self, items, worker, *, concurrency, queue_factor=2):
            for item in items:
                await worker(item)

    scanner = WebSecurityScanner({"recon": {"use_sitemap": True}})
    scanner.core = FakeCore(_responder)
    scanner.mapper.scanner = scanner.core
    scanner.recon = ReconEngine(scanner.mapper, scanner.recon_config)

    recorder = _RecordingTester()
    scanner.testers = [recorder]

    monkeypatch.setattr(scanner.mapper, "_discover_subdomains", lambda: _async_none())
    monkeypatch.setattr(
        scanner.mapper, "generate_map_async",
        lambda *a, **k: _async_value("reports/fake_map.html"),
    )

    results = await scanner.run_scan(BASE, generate_map=True)

    assert results["target"] == BASE
    joined = " ".join(recorder.seen)
    assert "/api/v2/users" in joined, recorder.seen
    assert "/products" in joined, recorder.seen
    assert BASE in recorder.seen


async def _async_none():
    return None


async def _async_value(value):
    return value
