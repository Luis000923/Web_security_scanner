"""Unit tests for prototype_pollution_async.PrototypePollutionTester."""

from conftest import MockScanner

from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.prototype_pollution_async import (
    PrototypePollutionTester,
)

TARGET = "http://target/api/settings"


async def _run(responder, accepts_json_body=False):
    em = ScanEventEmitter()
    found: list[dict] = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k.get("vulnerability")))
    tester = PrototypePollutionTester(MockScanner(responder), em, {"payload_delay": 0})
    await tester.run_test(TARGET, accepts_json_body=accepts_json_body)
    return found


async def test_query_vector_crash_only_on_polluted_flagged():
    # Sólo la contaminación de toString rompe el runtime; una clave inocua
    # bajo __proto__ (control de nombre de clave) no.
    def r(method, url, kwargs):
        if "__proto__[toString]" in url:
            return {"status_code": 500, "text": "TypeError: x.toString is not a function"}
        return {"status_code": 200, "text": "ok"}

    found = await _run(r)
    assert len(found) == 1
    assert found[0]["confidence"] == "HIGH"
    assert found[0]["vector"] == "query"
    assert found[0]["evidence_kind"] == "interpreter_error"


async def test_generally_fragile_endpoint_not_flagged():
    """Endpoint 500s on ANY extra query param (control included) — the crash
    isn't specific to prototype pollution, so this must not be reported."""
    def r(method, url, kwargs):
        if "?" in url:
            return {"status_code": 500, "text": "generic error"}
        return {"status_code": 200, "text": "ok"}

    found = await _run(r)
    assert found == []


async def test_healthy_endpoint_not_flagged():
    def r(method, url, kwargs):
        return {"status_code": 200, "text": "ok"}

    found = await _run(r)
    assert found == []


async def test_transient_500_not_reproduced_not_flagged():
    """A one-off 500 on the polluted probe that doesn't reproduce on the
    confirmation retry must not be reported."""
    calls = {"n": 0}

    def r(method, url, kwargs):
        if "__proto__" in url:
            calls["n"] += 1
            if calls["n"] == 1:
                return {"status_code": 500, "text": "unrelated blip"}
            return {"status_code": 200, "text": "ok"}
        return {"status_code": 200, "text": "ok"}

    found = await _run(r)
    assert found == []


async def test_json_body_vector_crash_signature_flagged():
    def r(method, url, kwargs):
        body = kwargs.get("json") or {}
        if "toString" in (body.get("__proto__") or {}):
            return {"status_code": 200, "text": "Cannot convert object to primitive value"}
        return {"status_code": 200, "text": "ok"}

    found = await _run(r, accepts_json_body=True)
    assert any(f["vector"] == "json_body" for f in found)
