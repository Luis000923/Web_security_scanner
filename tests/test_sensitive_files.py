"""Tests for the sensitive-asset exposure detector.

Two layers, mirroring ``tests/test_surface_correlation.py``:

* Unit tests against :class:`SensitiveFileDetector` directly (a fake
  ``MockScanner`` responder stands in for the target).
* An end-to-end recon integration test asserting a detected exposure is
  merged into the recon candidate pool and ranked CRITICAL by
  :class:`SurfaceCorrelator`.
"""

from __future__ import annotations

import itertools
from urllib.parse import urlparse

import pytest

from tests.conftest import MockScanner
from web_security_scanner.modules.recon import ReconConfig, ReconEngine
from web_security_scanner.modules.recon.sensitive_files_detector import (
    RISK_CRITICAL,
    SensitiveFileDetector,
)
from web_security_scanner.modules.web_mapper_async import WebMapperAsync

BASE = "http://target.test/"


def _not_found(*_args, **_kwargs) -> dict:
    return {"status_code": 404, "text": "Not Found"}


# --- SensitiveFileDetector unit tests ---------------------------------------


@pytest.mark.asyncio
async def test_detects_exposed_git_head_and_confirms_via_body_content():
    def responder(method, url, kwargs):
        if url.endswith("/.git/HEAD"):
            return {"status_code": 200, "text": "ref: refs/heads/main\n"}
        return _not_found()

    detector = SensitiveFileDetector(MockScanner(responder), max_base_paths=1, max_concurrent=4)
    result = await detector.detect(BASE)

    by_path = {f.path: f for f in result.findings}
    assert ".git/HEAD" in by_path
    finding = by_path[".git/HEAD"]
    assert finding.risk == RISK_CRITICAL
    assert finding.category == "vcs"
    assert finding.confidence == "CONFIRMED"
    assert finding.url == "http://target.test/.git/HEAD"
    assert result.baseline_established is True


@pytest.mark.asyncio
async def test_soft_404_page_is_not_reported():
    """A custom 200-status 'not found' page must be filtered by the baseline."""
    def responder(method, url, kwargs):
        return {"status_code": 200, "text": "<html><body>Sorry, that page was not found.</body></html>"}

    detector = SensitiveFileDetector(MockScanner(responder), max_base_paths=1, max_concurrent=4)
    result = await detector.detect(BASE)

    assert result.findings == []
    assert result.baseline_established is True


@pytest.mark.asyncio
async def test_soft_404_tolerates_minor_dynamic_content():
    """Small per-response variance (timestamps, request ids) must not defeat the filter."""
    counter = itertools.count()

    def responder(method, url, kwargs):
        n = next(counter)
        return {"status_code": 200,
                "text": f"<html><body>404 - page not found (ref #{n:06d})</body></html>"}

    detector = SensitiveFileDetector(MockScanner(responder), max_base_paths=1, max_concurrent=4)
    result = await detector.detect(BASE)

    assert result.findings == []


@pytest.mark.asyncio
async def test_protected_file_reported_at_medium_confidence():
    def responder(method, url, kwargs):
        if url.endswith("/.env"):
            return {"status_code": 403, "text": "Forbidden"}
        return _not_found()

    detector = SensitiveFileDetector(MockScanner(responder), max_base_paths=1, max_concurrent=4)
    result = await detector.detect(BASE)

    by_path = {f.path: f for f in result.findings}
    assert ".env" in by_path
    finding = by_path[".env"]
    assert finding.risk == RISK_CRITICAL
    assert finding.confidence == "MEDIUM"
    assert finding.status_code == 403


@pytest.mark.asyncio
async def test_server_error_status_is_not_reported():
    def responder(method, url, kwargs):
        if url.endswith("/.env"):
            return {"status_code": 500, "text": "Internal Server Error"}
        return _not_found()

    detector = SensitiveFileDetector(MockScanner(responder), max_base_paths=1, max_concurrent=4)
    result = await detector.detect(BASE)

    assert result.findings == []


@pytest.mark.asyncio
async def test_probes_discovered_base_paths_not_only_root():
    def responder(method, url, kwargs):
        if url == "http://target.test/backup/backup.sql":
            return {"status_code": 200,
                    "text": "-- MySQL dump\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n"}
        return _not_found()

    detector = SensitiveFileDetector(MockScanner(responder), max_base_paths=3, max_concurrent=4)
    result = await detector.detect(BASE, base_paths=["/backup"])

    urls = {f.url for f in result.findings}
    assert "http://target.test/backup/backup.sql" in urls
    finding = next(f for f in result.findings if f.url.endswith("backup.sql"))
    assert finding.confidence == "CONFIRMED"


@pytest.mark.asyncio
async def test_extra_names_are_probed_alongside_the_built_in_catalog():
    def responder(method, url, kwargs):
        if url.endswith("/custom-secret.txt"):
            return {"status_code": 200, "text": "shh"}
        return _not_found()

    detector = SensitiveFileDetector(
        MockScanner(responder), extra_names=["custom-secret.txt"], max_base_paths=1, max_concurrent=4,
    )
    result = await detector.detect(BASE)

    assert any(f.path == "custom-secret.txt" for f in result.findings)


@pytest.mark.asyncio
async def test_default_wordlist_entries_are_probed():
    def responder(method, url, kwargs):
        if url.endswith("/phpinfo.php"):
            return {"status_code": 200, "text": "phpinfo() output - PHP Version 8.1"}
        return _not_found()

    detector = SensitiveFileDetector(MockScanner(responder), max_base_paths=1, max_concurrent=4)
    result = await detector.detect(BASE)

    assert any(f.path == "phpinfo.php" for f in result.findings)


@pytest.mark.asyncio
async def test_probe_failure_is_swallowed_not_raised():
    def responder(method, url, kwargs):
        raise RuntimeError("connection reset")

    detector = SensitiveFileDetector(MockScanner(responder), max_base_paths=1, max_concurrent=4)
    result = await detector.detect(BASE)

    assert result.findings == []


def test_to_vulnerability_maps_critical_risk_to_critical_severity():
    from web_security_scanner.modules.recon.sensitive_files_detector import SensitiveFileFinding

    finding = SensitiveFileFinding(
        url="http://target.test/.env", path=".env", risk=RISK_CRITICAL, category="credentials",
        status_code=200, content_length=42, confidence="CONFIRMED", evidence="exposed",
    )
    vuln = finding.to_vulnerability()
    assert vuln["severity"] == "Critical"
    assert vuln["confidence"] == "CONFIRMED"
    assert vuln["url"] == "http://target.test/.env"


# --- end-to-end recon integration -------------------------------------------

_LANDING = '<html><body><a href="/about">about</a></body></html>'
_ABOUT_PAGE = "<html><body>Just an about page.</body></html>"
_ENV_BODY = "DB_PASSWORD=supersecret\nAPI_KEY=xyz123\n"


def _recon_responder(method, url, kwargs):
    path = urlparse(url).path
    if path in ("", "/"):
        return {"text": _LANDING, "headers": {"Content-Type": "text/html"}}
    if path == "/about":
        return {"text": _ABOUT_PAGE, "headers": {"Content-Type": "text/html"}}
    if path == "/.env":
        return {"text": _ENV_BODY, "headers": {"Content-Type": "text/plain"}}
    return {"status_code": 404, "text": ""}


@pytest.mark.asyncio
async def test_recon_engine_surfaces_and_ranks_sensitive_file_exposure(monkeypatch):
    async def _noop(self):
        return None

    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", _noop)
    mapper = WebMapperAsync(MockScanner(_recon_responder), crawl_delay=0)
    engine = ReconEngine(
        mapper,
        ReconConfig(max_urls=100, max_depth=3, crawl_delay=0.0, detect_sensitive_files=True),
    )

    result = await engine.run(BASE)

    assert any(f.path == ".env" for f in result.sensitive_files)
    env_url = next(f.url for f in result.sensitive_files if f.path == ".env")

    # Merged into the surface-correlation candidate pool -> ranked CRITICAL.
    by_url = {pt.url: pt for pt in result.prioritized_targets}
    assert env_url in by_url
    assert by_url[env_url].priority == "CRITICAL"
    assert "sensitive_file" in by_url[env_url].categories

    assert "sensitive_files" in result.map_data


@pytest.mark.asyncio
async def test_recon_engine_skips_sensitive_file_detection_when_disabled(monkeypatch):
    async def _noop(self):
        return None

    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", _noop)
    mapper = WebMapperAsync(MockScanner(_recon_responder), crawl_delay=0)
    engine = ReconEngine(
        mapper,
        ReconConfig(max_urls=100, max_depth=3, crawl_delay=0.0),  # detect_sensitive_files=False
    )

    result = await engine.run(BASE)

    assert result.sensitive_files == []
    assert "sensitive_files" not in result.map_data
