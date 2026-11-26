"""Unit tests for jwt_tester_async.JwtAttackTester."""

import base64
import json

from conftest import MockScanner

from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.jwt_tester_async import JwtAttackTester

TARGET = "http://target/api/me"


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_token(alg="HS256", **payload_extra) -> str:
    header = {"alg": alg, "typ": "JWT"}
    payload = {"sub": "1", "exp": 9999999999, **payload_extra}
    return f"{_b64url(header)}.{_b64url(payload)}.realsignature"


async def _run(responder, token=None, config=None):
    em = ScanEventEmitter()
    found: list[dict] = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k.get("vulnerability")))
    scanner = MockScanner(responder)
    scanner._auth_headers = {}
    cfg = {"payload_delay": 0, "max_payloads": 8}
    if config:
        cfg.update(config)
    tester = JwtAttackTester(scanner, em, cfg)
    kwargs = {"token": token} if token else {}
    await tester.run_test(TARGET, **kwargs)
    return found


def _auth_header(kwargs) -> str:
    return kwargs.get("headers", {}).get("Authorization", "")


def _decodes_as_jwt(kwargs) -> bool:
    """Servidor que decodifica el JWT pero nunca verifica la firma: rechaza
    cualquier bearer que no sea un JWT bien formado (control negativo)."""
    header = _auth_header(kwargs)
    token = header[len("Bearer "):] if header.startswith("Bearer ") else ""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
    except ValueError:
        return False
    return True


async def test_server_accepts_alg_none_flagged_critical():
    """A server that decodes the token but never checks the algorithm or the
    signature accepts every forged variant, while still rejecting a bearer
    value that is not a JWT at all."""
    def r(method, url, kwargs):
        if _decodes_as_jwt(kwargs):
            return {"status_code": 200, "text": '{"user":"bob"}'}
        return {"status_code": 401, "text": "Unauthorized"}

    found = await _run(r, token=_make_token())
    assert len(found) >= 1
    assert all(f["confidence"] == "HIGH" for f in found)
    assert all(f["severity"] == "Critical" for f in found)


async def test_server_properly_rejects_forged_tokens_not_flagged():
    def r(method, url, kwargs):
        header = _auth_header(kwargs)
        token = header[len("Bearer "):] if header.startswith("Bearer ") else ""
        if token == _make_token():
            return {"status_code": 200, "text": '{"user":"bob"}'}
        return {"status_code": 401, "text": "Unauthorized"}

    found = await _run(r, token=_make_token())
    assert found == []


async def test_no_token_available_no_crash_no_findings():
    def r(method, url, kwargs):
        return {"status_code": 200, "text": "no jwt here"}

    found = await _run(r, token=None)
    assert found == []


async def test_malformed_token_two_segments_ignored():
    def r(method, url, kwargs):
        return {"status_code": 200, "text": "x"}

    found = await _run(r, token="not.a.validjwt.extra")
    assert found == []


async def test_discovers_token_from_auth_headers_attribute():
    token = _make_token()

    def r(method, url, kwargs):
        if _decodes_as_jwt(kwargs):
            return {"status_code": 200, "text": "accepted"}
        return {"status_code": 401, "text": "Unauthorized"}

    em = ScanEventEmitter()
    found: list[dict] = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k.get("vulnerability")))
    scanner = MockScanner(r)
    scanner._auth_headers = {"Authorization": f"Bearer {token}"}
    tester = JwtAttackTester(scanner, em, {"payload_delay": 0})
    await tester.run_test(TARGET)
    assert len(found) >= 1


async def test_403_response_also_treated_as_rejection():
    def r(method, url, kwargs):
        header = _auth_header(kwargs)
        token = header[len("Bearer "):] if header.startswith("Bearer ") else ""
        if token == _make_token():
            return {"status_code": 200, "text": '{"user":"bob"}'}
        return {"status_code": 403, "text": "Forbidden"}

    found = await _run(r, token=_make_token())
    assert found == []
