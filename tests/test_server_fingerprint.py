"""Tests for the server/infrastructure fingerprinter and MS15-034 Safe PoC Probe.

Mirrors the two-layer style of ``tests/test_surface_correlation.py``: pure
unit tests against :class:`ServerFingerprinter` driven by a ``MockScanner``
responder that can distinguish the initial banner-grab request from the
active ``Range``-header probe via its ``kwargs``.
"""

from __future__ import annotations

import pytest

from tests.conftest import MockScanner
from web_security_scanner.modules.recon.server_fingerprinter import (
    PocFinding,
    ServerFingerprinter,
)

BASE = "http://target.test/"


def _is_active_probe(kwargs: dict) -> bool:
    headers = kwargs.get("headers") or {}
    return "Range" in headers


# --- banner-only advisories ---------------------------------------------


@pytest.mark.asyncio
async def test_vulnerable_apache_banner_flagged_as_banner_only():
    def responder(method, url, kwargs):
        return {"status_code": 200, "text": "ok", "headers": {"Server": "Apache/2.4.49 (Unix)"}}

    fp = ServerFingerprinter(MockScanner(responder))
    result = await fp.fingerprint(BASE)

    assert any(f.product == "Apache" and f.version == "2.4.49" for f in result.fingerprints)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.cve_id == "CVE-2021-41773"
    assert finding.confidence == "MEDIUM"
    assert finding.poc_method == "banner-only"


@pytest.mark.asyncio
async def test_patched_apache_banner_not_flagged():
    def responder(method, url, kwargs):
        return {"status_code": 200, "text": "ok", "headers": {"Server": "Apache/2.4.54"}}

    fp = ServerFingerprinter(MockScanner(responder))
    result = await fp.fingerprint(BASE)

    assert result.findings == []


@pytest.mark.asyncio
async def test_vulnerable_nginx_banner_flagged():
    def responder(method, url, kwargs):
        return {"status_code": 200, "text": "ok", "headers": {"Server": "nginx/1.16.1"}}

    fp = ServerFingerprinter(MockScanner(responder))
    result = await fp.fingerprint(BASE)

    assert any(f.cve_id == "CVE-2019-20372" for f in result.findings)


@pytest.mark.asyncio
async def test_x_powered_by_and_via_headers_are_parsed():
    def responder(method, url, kwargs):
        return {
            "status_code": 200, "text": "ok",
            "headers": {"X-Powered-By": "PHP/7.2.24", "Via": "1.1 proxy (Varnish/6.6)"},
        }

    fp = ServerFingerprinter(MockScanner(responder))
    result = await fp.fingerprint(BASE)

    products = {(f.product, f.version) for f in result.fingerprints}
    assert ("PHP", "7.2.24") in products
    assert ("Varnish", "6.6") in products


@pytest.mark.asyncio
async def test_no_headers_yields_no_fingerprints():
    def responder(method, url, kwargs):
        return {"status_code": 200, "text": "ok", "headers": {}}

    fp = ServerFingerprinter(MockScanner(responder))
    result = await fp.fingerprint(BASE)

    assert result.fingerprints == []
    assert result.findings == []


# --- MS15-034 / CVE-2015-1635: active Safe PoC Probe ----------------------


@pytest.mark.asyncio
async def test_iis_banner_alone_never_reported_without_active_confirmation():
    """A vulnerable-looking IIS banner alone must never produce a finding."""
    def responder(method, url, kwargs):
        return {"status_code": 200, "text": "ok", "headers": {"Server": "Microsoft-IIS/7.5"}}

    fp = ServerFingerprinter(MockScanner(responder), enable_active_probes=False)
    result = await fp.fingerprint(BASE)

    assert any(f.product == "Microsoft-IIS" for f in result.fingerprints)
    assert result.findings == []


@pytest.mark.asyncio
async def test_ms15_034_confirmed_via_active_range_probe():
    def responder(method, url, kwargs):
        if _is_active_probe(kwargs):
            return {"status_code": 416, "text": "Requested Range Not Satisfiable"}
        return {"status_code": 200, "text": "ok", "headers": {"Server": "Microsoft-IIS/7.5"}}

    fp = ServerFingerprinter(MockScanner(responder), enable_active_probes=True)
    result = await fp.fingerprint(BASE)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.cve_id == "CVE-2015-1635"
    assert finding.confidence == "CONFIRMED"
    assert finding.poc_method == "active-range-probe"
    assert finding.severity == "Critical"


@pytest.mark.asyncio
async def test_ms15_034_not_reported_when_patched_returns_400():
    def responder(method, url, kwargs):
        if _is_active_probe(kwargs):
            return {"status_code": 400, "text": "Bad Request"}
        return {"status_code": 200, "text": "ok", "headers": {"Server": "Microsoft-IIS/8.5"}}

    fp = ServerFingerprinter(MockScanner(responder), enable_active_probes=True)
    result = await fp.fingerprint(BASE)

    assert result.findings == []


@pytest.mark.asyncio
async def test_ms15_034_inconclusive_response_not_reported():
    """Neither 416 nor 400: the differential is ambiguous, so nothing is reported."""
    def responder(method, url, kwargs):
        if _is_active_probe(kwargs):
            return {"status_code": 200, "text": "ok"}
        return {"status_code": 200, "text": "ok", "headers": {"Server": "Microsoft-IIS/8.0"}}

    fp = ServerFingerprinter(MockScanner(responder), enable_active_probes=True)
    result = await fp.fingerprint(BASE)

    assert result.findings == []


@pytest.mark.asyncio
async def test_non_vulnerable_iis_version_skips_active_probe_entirely():
    probe_calls = []

    def responder(method, url, kwargs):
        if _is_active_probe(kwargs):
            probe_calls.append(url)
            return {"status_code": 416, "text": "should never be reached"}
        return {"status_code": 200, "text": "ok", "headers": {"Server": "Microsoft-IIS/10.0"}}

    fp = ServerFingerprinter(MockScanner(responder), enable_active_probes=True)
    result = await fp.fingerprint(BASE)

    assert probe_calls == []
    assert result.findings == []


@pytest.mark.asyncio
async def test_active_probe_transport_failure_is_inconclusive_not_raised():
    def responder(method, url, kwargs):
        if _is_active_probe(kwargs):
            raise RuntimeError("connection reset")
        return {"status_code": 200, "text": "ok", "headers": {"Server": "Microsoft-IIS/7.5"}}

    fp = ServerFingerprinter(MockScanner(responder), enable_active_probes=True)
    result = await fp.fingerprint(BASE)

    assert result.findings == []


# --- robustness -----------------------------------------------------------


@pytest.mark.asyncio
async def test_initial_request_failure_returns_empty_result():
    def responder(method, url, kwargs):
        raise RuntimeError("target unreachable")

    fp = ServerFingerprinter(MockScanner(responder))
    result = await fp.fingerprint(BASE)

    assert result.fingerprints == []
    assert result.findings == []
    assert result.url == BASE


def test_to_vulnerability_shape():
    finding = PocFinding(
        cve_id="CVE-2015-1635", name="MS15-034", product="Microsoft-IIS", version=None,
        severity="Critical", confidence="CONFIRMED", evidence="confirmed via active probe",
        poc_method="active-range-probe",
    )
    vuln = finding.to_vulnerability("http://target.test/")
    assert vuln["cve_id"] == "CVE-2015-1635"
    assert vuln["severity"] == "Critical"
    assert vuln["confidence"] == "CONFIRMED"
    assert vuln["url"] == "http://target.test/"


def test_to_vulnerabilities_aggregates_result_findings():
    from web_security_scanner.modules.recon.server_fingerprinter import (
        ServerFingerprint,
        ServerFingerprintResult,
    )

    result = ServerFingerprintResult(
        url=BASE,
        fingerprints=[ServerFingerprint(header="server", raw_value="Apache/2.4.49",
                                         product="Apache", version="2.4.49", evidence="server: Apache/2.4.49")],
        findings=[PocFinding(
            cve_id="CVE-2021-41773", name="Apache path traversal", product="Apache", version="2.4.49",
            severity="Critical", confidence="MEDIUM", evidence="banner-derived", poc_method="banner-only",
        )],
    )
    vulns = result.to_vulnerabilities()
    assert len(vulns) == 1
    assert vulns[0]["cve_id"] == "CVE-2021-41773"
