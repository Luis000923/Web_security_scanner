"""Phase 4 — headless-browser recon + DOM-XSS tracing.

These tests never require Playwright: they exercise the pure helpers, the
graceful-degradation path when the dependency is absent, and the wiring that
turns a browser DOM-XSS finding into a vulnerability event + telemetry row.
A single opt-in test runs a real Chromium pass when Playwright is installed.
"""

import pytest

from tests.conftest import MockScanner
from web_security_scanner.modules.recon import (
    DOM_XSS_CANARY,
    MONITORED_SINKS,
    BrowserRecon,
    BrowserReconResult,
    DomXssFinding,
    ReconConfig,
    ReconEngine,
)
from web_security_scanner.modules.recon.browser_engine import _INSTRUMENTATION
from web_security_scanner.modules.web_mapper_async import WebMapperAsync

BASE = "http://target.test/"

_LANDING = """<html><body>
  <a href="/app?id=1">app</a>
  <script>/* nothing */</script>
</body></html>"""


def _responder(method, url, kwargs):
    from urllib.parse import urlparse

    path = urlparse(url).path
    if path in ("", "/"):
        return {"text": _LANDING, "headers": {"Content-Type": "text/html"}}
    if path == "/robots.txt":
        return {"status_code": 404, "text": ""}
    return {"text": f"<html><body>ok {path}</body></html>",
            "headers": {"Content-Type": "text/html"}}


# --- pure helpers -------------------------------------------------------


def test_instrumentation_covers_every_monitored_sink():
    for sink in MONITORED_SINKS:
        assert sink in _INSTRUMENTATION, sink
    # The callback bridge name must match what BrowserRecon exposes.
    assert "__wssDomXssReport" in _INSTRUMENTATION


def test_nav_targets_plant_the_canary_in_sources():
    recon = BrowserRecon(max_pages=8)
    targets = recon._nav_targets(BASE, {f"{BASE}app": ["id", "next"]})
    assert BASE in targets
    assert f"{BASE}#{DOM_XSS_CANARY}" in targets
    assert any(f"id={DOM_XSS_CANARY}" in t for t in targets)
    assert any(f"next={DOM_XSS_CANARY}" in t for t in targets)
    assert len(targets) <= 8


def test_nav_targets_respects_max_pages():
    recon = BrowserRecon(max_pages=2)
    targets = recon._nav_targets(BASE, {f"{BASE}a": ["p1", "p2", "p3"]})
    assert len(targets) == 2


def test_in_scope_same_origin_only():
    recon = BrowserRecon(same_origin_only=True)
    assert recon._in_scope("http://target.test/x", "target.test")
    assert not recon._in_scope("http://evil.test/x", "target.test")
    assert not recon._in_scope("http://sub.target.test/x", "target.test")


def test_dom_xss_finding_to_vulnerability_shape():
    finding = DomXssFinding(
        url="http://target.test/#x", sink="eval",
        source="location.hash", sample="alert(1)", param="q",
    )
    vuln = finding.to_vulnerability()
    assert vuln["type"] == "DOM-based XSS"
    assert vuln["severity"] == "high"
    assert vuln["parameter"] == "q"
    assert "eval" in vuln["evidence"]


# --- graceful degradation --------------------------------------------


@pytest.mark.asyncio
async def test_explore_is_noop_without_playwright(monkeypatch):
    monkeypatch.setattr(
        "web_security_scanner.modules.recon.browser_engine.async_playwright", None
    )
    recon = BrowserRecon()
    assert recon.available() is False
    result = await recon.explore(BASE)
    assert isinstance(result, BrowserReconResult)
    assert result.available is False
    assert not result.dom_xss and not result.discovered_urls


@pytest.mark.asyncio
async def test_recon_engine_runs_with_browser_flag_and_no_playwright(monkeypatch):
    monkeypatch.setattr(
        "web_security_scanner.modules.recon.browser_engine.async_playwright", None
    )

    async def _noop(self):
        return None

    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", _noop)
    mapper = WebMapperAsync(MockScanner(_responder), crawl_delay=0)
    engine = ReconEngine(
        mapper,
        ReconConfig(max_urls=50, max_depth=2, crawl_delay=0.0, use_browser=True),
    )
    result = await engine.run(BASE)
    assert result.browser_endpoints == []
    assert result.dom_xss_findings == []
    assert BASE in result.targets


@pytest.mark.asyncio
async def test_recon_engine_merges_browser_endpoints_and_findings():
    """A stub BrowserRecon injects endpoints + a DOM-XSS finding."""

    class StubBrowser:
        def available(self):
            return True

        async def explore(self, base_url, seed_params=None):
            res = BrowserReconResult()
            res.discovered_urls = {"http://target.test/api/spa?tok=1"}
            res.dom_xss = [DomXssFinding(
                url="http://target.test/#p", sink="innerHTML",
                source="location.hash", sample="<img src=x onerror=1>",
            )]
            return res

    mapper = WebMapperAsync(MockScanner(_responder), crawl_delay=0)
    mapper.discovered_params = {}
    engine = ReconEngine(
        mapper,
        ReconConfig(max_urls=1, max_depth=0, crawl_delay=0.0, use_browser=True),
        browser=StubBrowser(),
    )
    # Skip the HTTP crawl entirely — only the browser merge matters here.
    async def _fake_map(url, **kw):
        return {"statistics": {}}

    engine._mapper.map_website = _fake_map  # type: ignore[assignment]
    engine._mapper.get_scan_targets = lambda *a, **k: [BASE]  # type: ignore[assignment]

    result = await engine.run(BASE)
    assert "http://target.test/api/spa?tok=1" in result.targets
    assert len(result.dom_xss_findings) == 1
    assert result.dom_xss_findings[0].sink == "innerHTML"


# --- orchestrator wiring --------------------------------------------


@pytest.mark.asyncio
async def test_handle_dom_xss_emits_vuln_and_telemetry():
    from web_security_scanner.web_security_scanner_async import WebSecurityScanner

    scanner = WebSecurityScanner({})
    seen = []
    scanner.event_emitter.on(
        __import__(
            "web_security_scanner.events.event_emitter", fromlist=["ScanEventType"]
        ).ScanEventType.VULNERABILITY_FOUND,
        lambda **kw: seen.append(kw.get("vulnerability")),
    )

    class FakeTelemetry:
        def __init__(self):
            self.rows = []

        def record(self, row):
            self.rows.append(row)

    scanner.telemetry = FakeTelemetry()

    class R:
        dom_xss_findings = [
            DomXssFinding(url="http://t/#a", sink="eval",
                         source="location.hash", sample="x"),
        ]

    await scanner._handle_dom_xss(R())

    assert len(seen) == 1
    assert seen[0]["type"] == "DOM-based XSS"
    assert len(scanner.telemetry.rows) == 1
    row = scanner.telemetry.rows[0]
    assert row["vector"] == "domsink"
    assert row["decision"] is True
    assert row["context"] == "dom_xss"


@pytest.mark.asyncio
async def test_handle_dom_xss_noop_when_no_findings():
    from web_security_scanner.web_security_scanner_async import WebSecurityScanner

    scanner = WebSecurityScanner({})

    class R:
        dom_xss_findings = []

    await scanner._handle_dom_xss(R())  # must not raise


# --- real browser (opt-in) -----------------------------------------


@pytest.mark.asyncio
async def test_real_dom_xss_flow_detected():
    if not BrowserRecon.available():
        pytest.skip("Playwright not installed")

    import aiohttp
    from aiohttp import web

    page = (
        "<html><body><div id=out></div><script>"
        "document.getElementById('out').innerHTML = "
        "decodeURIComponent(location.hash.slice(1));"
        "</script></body></html>"
    )

    async def handler(request):
        return web.Response(text=page, content_type="text/html")

    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        recon = BrowserRecon(settle_time=0.3, max_pages=2)
        result = await recon.explore(f"http://127.0.0.1:{port}/")
        assert result.available is True
        assert any(f.sink == "innerHTML" for f in result.dom_xss), result.error
    finally:
        await runner.cleanup()
        del aiohttp
