"""Unit tests for account_enum_async.AccountEnumerationTester."""

from conftest import MockScanner

from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.account_enum_async import (
    AccountEnumerationTester,
)

TARGET = "http://target/login"
LOGIN_FORM = {
    "action": "http://target/login",
    "fields": {"username": "", "password": ""},
}


async def _run(responder, form=LOGIN_FORM, config=None):
    em = ScanEventEmitter()
    found: list[dict] = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k.get("vulnerability")))
    cfg = {"payload_delay": 0, "max_payloads": 8}
    if config:
        cfg.update(config)
    tester = AccountEnumerationTester(MockScanner(responder), em, cfg)
    await tester.run_test(TARGET, form=form)
    return found


def _username_from(kwargs) -> str:
    return kwargs.get("data", {}).get("username", "")


async def test_different_status_code_flagged_high():
    def r(method, url, kwargs):
        user = _username_from(kwargs)
        status = 200 if user == "admin" else 404
        return {"status_code": status, "text": "same body"}

    found = await _run(r)
    assert len(found) == 1
    assert found[0]["confidence"] == "HIGH"
    assert found[0]["severity"] == "Medium"


async def test_different_body_flagged_medium():
    def r(method, url, kwargs):
        user = _username_from(kwargs)
        if user == "admin":
            text = "Error: incorrect password for this account."
        else:
            text = "Error: no account found with that username."
        return {"status_code": 200, "text": text}

    found = await _run(r)
    assert len(found) == 1
    assert found[0]["confidence"] == "MEDIUM"


async def test_identical_responses_not_flagged():
    def r(method, url, kwargs):
        return {"status_code": 200, "text": "Invalid username or password."}

    found = await _run(r)
    assert found == []


async def test_no_timing_false_positive_on_fast_identical_target():
    """Both candidates get the same body/status and near-zero elapsed time
    in the mock — must not spuriously flag a timing side-channel."""
    def r(method, url, kwargs):
        return {"status_code": 200, "text": "Invalid credentials"}

    found = await _run(r)
    assert found == []


async def test_skips_non_login_form_without_password_field():
    form = {"action": TARGET, "fields": {"search": ""}}

    def r(method, url, kwargs):
        return {"status_code": 200, "text": "ok"}

    found = await _run(r, form=form)
    assert found == []


async def test_skips_form_without_recognizable_username_field():
    form = {"action": TARGET, "fields": {"secret_id": "", "password": ""}}

    def r(method, url, kwargs):
        return {"status_code": 200, "text": "ok"}

    found = await _run(r, form=form)
    assert found == []


async def test_missing_form_kwarg_no_crash():
    def r(method, url, kwargs):
        return {"status_code": 200, "text": "ok"}

    em = ScanEventEmitter()
    found: list[dict] = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k.get("vulnerability")))
    tester = AccountEnumerationTester(MockScanner(r), em, {"payload_delay": 0})
    await tester.run_test(TARGET)
    assert found == []


async def test_custom_known_username_honored():
    def r(method, url, kwargs):
        user = _username_from(kwargs)
        status = 200 if user == "root_operator" else 403
        return {"status_code": status, "text": "x"}

    em = ScanEventEmitter()
    collected: list[dict] = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: collected.append(k.get("vulnerability")))
    tester = AccountEnumerationTester(MockScanner(r), em, {"payload_delay": 0})
    await tester.run_test(TARGET, form=LOGIN_FORM, known_username="root_operator")
    assert len(collected) == 1
