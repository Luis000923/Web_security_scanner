"""Attack-surface correlation and Risk/Value prioritization (final phase).

Covers both layers:

* Unit tests against :class:`SurfaceCorrelator` directly - classification
  into surface categories and the resulting Risk/Value score/priority.
* An end-to-end recon test (fake HTTP surface, mirroring
  ``tests/test_recon_integration.py``) asserting that the critical endpoints
  it discovers (an admin panel and a file-upload form) are ranked ahead of a
  throwaway generic page in ``ReconResult.targets`` / ``prioritized_targets``
  and are correctly rendered into the final recon HTML report.
"""

import pytest

from tests.conftest import MockScanner
from web_security_scanner.modules.recon import (
    PrioritizedTarget,
    ReconConfig,
    ReconEngine,
    SurfaceCorrelator,
)
from web_security_scanner.modules.recon.surface_correlator import (
    ADMIN_PANEL,
    API_ENDPOINT,
    FILE_UPLOAD,
    GENERIC,
    SENSITIVE_FILE,
    VULNERABLE_FRAMEWORK,
)
from web_security_scanner.modules.web_mapper_async import WebMapperAsync

BASE = "http://target.test/"

# --- pure SurfaceCorrelator unit tests --------------------------------------


def test_admin_panel_outranks_generic_page():
    correlator = SurfaceCorrelator()
    results = correlator.correlate([
        "http://target.test/about",
        "http://target.test/wp-admin/",
    ])
    by_url = {r.url: r for r in results}

    admin = by_url["http://target.test/wp-admin/"]
    generic = by_url["http://target.test/about"]

    assert ADMIN_PANEL in admin.categories
    assert GENERIC in generic.categories
    assert admin.score > generic.score
    assert admin.priority in ("CRITICAL", "HIGH")
    assert generic.priority in ("LOW", "INFO")

    # Sorted descending by score - admin panel comes first.
    assert results[0].url == admin.url


def test_file_upload_endpoint_with_post_form_scores_high():
    correlator = SurfaceCorrelator()
    forms = [{
        "url": "http://target.test/upload",
        "action": "/upload",
        "method": "POST",
        "inputs": 3,
    }]
    results = correlator.correlate(
        ["http://target.test/upload"], forms=forms,
    )
    target = results[0]

    assert FILE_UPLOAD in target.categories
    assert target.form_count == 1
    assert target.priority in ("CRITICAL", "HIGH")


def test_api_endpoint_with_query_params_ranked_above_bare_api_endpoint():
    correlator = SurfaceCorrelator()
    results = correlator.correlate(
        ["http://target.test/api/v1/users", "http://target.test/api/v1/health"],
        params_by_url={"http://target.test/api/v1/users": ["id", "role"]},
    )
    by_url = {r.url: r for r in results}
    users = by_url["http://target.test/api/v1/users"]
    health = by_url["http://target.test/api/v1/health"]

    assert API_ENDPOINT in users.categories
    assert API_ENDPOINT in health.categories
    assert users.score > health.score  # query params bump the score up
    assert users.param_count == 2


def test_sensitive_file_exposure_is_critical():
    correlator = SurfaceCorrelator()
    results = correlator.correlate(["http://target.test/.git/config"])
    target = results[0]

    assert SENSITIVE_FILE in target.categories
    assert target.priority == "CRITICAL"


def test_vulnerable_framework_requires_fingerprint_confirmation():
    correlator = SurfaceCorrelator()
    url = "http://target.test/wp-content/plugins/foo/ajax.php"

    # No technology fingerprinted for the domain -> not flagged as a
    # confirmed vulnerable-framework path (still classified generic/other).
    unconfirmed = correlator.correlate([url])[0]
    assert VULNERABLE_FRAMEWORK not in unconfirmed.categories

    # WordPress fingerprinted for the domain -> the plugin path is now a
    # confirmed vulnerable-component hit with a fingerprint bonus.
    confirmed = correlator.correlate(
        [url],
        technologies={"target.test": [{"name": "WordPress", "type": "CMS"}]},
    )[0]
    assert VULNERABLE_FRAMEWORK in confirmed.categories
    assert confirmed.priority in ("CRITICAL", "HIGH")
    assert confirmed.score > unconfirmed.score
    assert any("fingerprint-confirmed" in e for e in confirmed.evidence)


def test_hidden_js_mined_endpoint_gets_a_bonus_and_evidence():
    correlator = SurfaceCorrelator()
    url = "http://target.test/api/internal/debug"
    visible = correlator.correlate([url])[0]
    hidden = correlator.correlate([url], hidden_urls=[url])[0]

    assert hidden.hidden is True
    assert hidden.score > visible.score
    assert any("JS mining" in e for e in hidden.evidence)


def test_summarize_counts_by_priority():
    correlator = SurfaceCorrelator()
    results = correlator.correlate([
        "http://target.test/.env",
        "http://target.test/about",
    ])
    summary = SurfaceCorrelator.summarize(results)
    assert summary["CRITICAL"] == 1
    assert sum(summary.values()) == 2


def test_sort_order_is_deterministic_on_score_ties():
    correlator = SurfaceCorrelator()
    results = correlator.correlate([
        "http://target.test/b/about",
        "http://target.test/a/about",
    ])
    # Both GENERIC, equal score -> alphabetical tie-break.
    assert [r.url for r in results] == [
        "http://target.test/a/about",
        "http://target.test/b/about",
    ]


# --- end-to-end recon integration -------------------------------------------

_LANDING = """<html><body>
  <a href="/about">about</a>
  <a href="/admin/dashboard">admin</a>
  <a href="/upload">upload</a>
</body></html>"""

_ADMIN_PAGE = "<html><body>admin dashboard</body></html>"

_UPLOAD_PAGE = """<html><body>
  <form action="/upload" method="POST">
    <input type="file" name="avatar">
    <input type="text" name="description">
  </form>
</body></html>"""

_ABOUT_PAGE = "<html><body>Just an about page, nothing sensitive here.</body></html>"


def _responder(method, url, kwargs):
    from urllib.parse import urlparse

    path = urlparse(url).path
    if path in ("", "/"):
        return {"text": _LANDING, "headers": {"Content-Type": "text/html"}}
    if path == "/admin/dashboard":
        return {"text": _ADMIN_PAGE, "headers": {"Content-Type": "text/html"}}
    if path == "/upload":
        return {"text": _UPLOAD_PAGE, "headers": {"Content-Type": "text/html"}}
    if path == "/about":
        return {"text": _ABOUT_PAGE, "headers": {"Content-Type": "text/html"}}
    if path == "/robots.txt":
        return {"status_code": 404, "text": ""}
    return {"status_code": 404, "text": ""}


@pytest.mark.asyncio
async def test_critical_endpoints_ranked_first_in_attack_queue(monkeypatch):
    async def _noop(self):
        return None

    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", _noop)
    mapper = WebMapperAsync(MockScanner(_responder), crawl_delay=0)
    engine = ReconEngine(
        mapper, ReconConfig(max_urls=100, max_depth=3, crawl_delay=0.0),
    )

    result = await engine.run(BASE)

    admin_url = "http://target.test/admin/dashboard"
    upload_url = "http://target.test/upload"
    about_url = "http://target.test/about"

    assert admin_url in result.targets
    assert upload_url in result.targets
    assert about_url in result.targets

    by_url = {pt.url: pt for pt in result.prioritized_targets}
    assert by_url[admin_url].priority in ("CRITICAL", "HIGH")
    assert by_url[upload_url].priority in ("CRITICAL", "HIGH")
    assert by_url[admin_url].score > by_url[about_url].score
    assert by_url[upload_url].score > by_url[about_url].score

    # The attack queue (result.targets) is reordered by Risk/Value score, so
    # both critical endpoints precede the low-value generic page.
    about_idx = result.targets.index(about_url)
    admin_idx = result.targets.index(admin_url)
    upload_idx = result.targets.index(upload_url)
    assert admin_idx < about_idx
    assert upload_idx < about_idx


@pytest.mark.asyncio
async def test_priority_targets_listed_in_final_recon_report(monkeypatch):
    from web_security_scanner.report_generator import build_structured_report
    from web_security_scanner.web_security_scanner_async import WebSecurityScanner

    async def _noop(self):
        return None

    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", _noop)
    mapper = WebMapperAsync(MockScanner(_responder), crawl_delay=0)
    engine = ReconEngine(
        mapper, ReconConfig(max_urls=100, max_depth=3, crawl_delay=0.0),
    )

    result = await engine.run(BASE)

    # map_data is enriched with the priority queue before the JSON/PDF report
    # is rendered (mirrors WebSecurityScanner.run_scan's own call sequence).
    assert "priority_targets" in result.map_data
    assert result.map_data["statistics"]["surface_priority"]["CRITICAL"] >= 1 or \
        result.map_data["statistics"]["surface_priority"]["HIGH"] >= 1

    scan_data = {
        "target": BASE, "profile": "balanced", "vulnerabilities": [],
        "technologies": {}, "statistics": {},
        "recon": WebSecurityScanner._recon_summary(result.map_data),
    }
    report = build_structured_report(scan_data)
    urls = {pt["url"] for pt in report["attack_surface"]["prioritized_targets"]}

    assert "http://target.test/admin/dashboard" in urls
    assert "http://target.test/upload" in urls
    priorities = {pt["priority"] for pt in report["attack_surface"]["prioritized_targets"]}
    assert priorities & {"CRITICAL", "HIGH"}


def test_prioritized_target_survives_correlation_failure(monkeypatch):
    """A correlator exception degrades to an INFO-priority pass-through queue
    instead of aborting recon (mirrors every other defensive Phase 1 path)."""
    from web_security_scanner.modules.recon.recon_engine import ReconEngine as _RE

    class _BoomCorrelator:
        def __init__(self, logger=None):
            pass

        def correlate(self, *a, **kw):
            raise RuntimeError("boom")

    monkeypatch.setattr(
        "web_security_scanner.modules.recon.recon_engine.SurfaceCorrelator",
        _BoomCorrelator,
    )
    engine = _RE.__new__(_RE)
    engine._log = __import__("logging").getLogger("test")
    result = engine._correlate_surface(
        BASE, ["http://target.test/a", "http://target.test/b"], {}, set()
    )
    assert all(isinstance(r, PrioritizedTarget) for r in result)
    assert all(r.priority == "INFO" for r in result)
