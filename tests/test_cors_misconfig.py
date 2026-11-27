"""Unit tests for cors_misconfig_async.CorsMisconfigTester."""

from conftest import collect_vulns

from web_security_scanner.modules.vulnerability_testers.cors_misconfig_async import (
    MARKER_DOMAIN,
    CorsMisconfigTester,
)


def _headers_for(origin: str) -> dict:
    """Server reflects the incoming Origin and allows credentials — the
    classic dangerous CORS misconfiguration."""
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
    }


async def test_reflected_origin_with_credentials_flagged_high():
    def r(method, url, kwargs):
        origin = kwargs.get("headers", {}).get("Origin", "")
        return {"headers": _headers_for(origin)}

    found = await collect_vulns(CorsMisconfigTester, r)
    assert len(found) >= 1
    assert all(f["severity"] == "High" for f in found)
    assert all(f["confidence"] == "HIGH" for f in found)


async def test_null_origin_with_credentials_flagged():
    def r(method, url, kwargs):
        origin = kwargs.get("headers", {}).get("Origin", "")
        if origin == "null":
            return {"headers": _headers_for("null")}
        return {"headers": {}}

    found = await collect_vulns(CorsMisconfigTester, r)
    assert len(found) == 1
    assert "null" in found[0]["payload"]


async def test_wildcard_without_credentials_not_flagged():
    """The standard public-API pattern (ACAO: * and no Allow-Credentials)
    is intentionally safe and must not be reported."""
    def r(method, url, kwargs):
        return {"headers": {"Access-Control-Allow-Origin": "*"}}

    found = await collect_vulns(CorsMisconfigTester, r)
    assert found == []


async def test_fixed_allowlisted_origin_not_flagged():
    """Server always answers with a fixed, legitimate origin regardless of
    what we sent — not a reflection, so not vulnerable."""
    def r(method, url, kwargs):
        return {"headers": _headers_for("https://trusted.example.com")}

    found = await collect_vulns(CorsMisconfigTester, r)
    assert found == []


async def test_no_cors_headers_not_flagged():
    def r(method, url, kwargs):
        return {"headers": {}}

    found = await collect_vulns(CorsMisconfigTester, r)
    assert found == []


async def test_reflects_marker_origin_specifically():
    def r(method, url, kwargs):
        origin = kwargs.get("headers", {}).get("Origin", "")
        return {"headers": _headers_for(origin)}

    found = await collect_vulns(CorsMisconfigTester, r)
    # Origen canario aleatorio por ejecución, subdominio del dominio marcador.
    assert any(MARKER_DOMAIN in f["payload"] for f in found)


async def test_credentials_false_with_reflection_not_flagged():
    """Reflecting Origin without Allow-Credentials is the safe, if slightly
    unusual, pattern used by some public APIs that still want per-origin
    caching — should not be reported."""
    def r(method, url, kwargs):
        origin = kwargs.get("headers", {}).get("Origin", "")
        return {"headers": {"Access-Control-Allow-Origin": origin}}

    found = await collect_vulns(CorsMisconfigTester, r)
    assert found == []
