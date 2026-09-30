"""Dedicated unit tests for csrf_tester_async.CSRFTester.

Complements the smoke coverage in test_testers.py (missing-token / rotating-
token / double-submit / missing-SameSite happy paths already live there) with
the SameSite=None branch and a couple of matching-logic edge cases that were
not yet exercised anywhere.
"""

from http.cookies import Morsel

from conftest import MockScanner

from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.csrf_tester_async import CSRFTester

TARGET = "http://target/page"


def _morsel(key: str, value: str, *, samesite: str | None = None, secure: bool = False) -> Morsel:
    m: Morsel = Morsel()
    m.set(key, value, value)
    if samesite is not None:
        m["samesite"] = samesite
    m["secure"] = secure
    return m


class _FakeJar:
    """Minimal stand-in for ``aiohttp.CookieJar``: iterable of morsels."""

    def __init__(self, morsels):
        self._morsels = list(morsels)

    def __iter__(self):
        return iter(self._morsels)


class _FakeSession:
    def __init__(self, cookie_jar):
        self.cookie_jar = cookie_jar


async def _run_csrf(responder, cookies=(), config=None):
    """Run CSRFTester against ``TARGET`` and collect emitted vulnerabilities."""
    em = ScanEventEmitter()
    found: list[dict] = []
    logs: list[str] = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k.get("vulnerability")))
    em.on(ScanEventType.LOG_MESSAGE, lambda **k: logs.append(k.get("message")))
    scanner = MockScanner(responder)
    scanner.session = _FakeSession(_FakeJar(cookies))
    cfg = {"payload_delay": 0, "max_payloads": 8}
    if config:
        cfg.update(config)
    tester = CSRFTester(scanner, em, cfg)
    await tester.run_test(TARGET)
    return found, logs


def _form(token: str = "tok") -> str:
    return (f'<form method="POST" action="/transfer">'
            f'<input name="csrf_token" value="{token}"></form>')


# ---- SameSite=None branch (not covered by test_testers.py's missing-SameSite
# and double-submit cases, which both exercise the "attribute absent" branch) --

async def test_samesite_none_without_secure_flagged_low():
    """SameSite=None lacking Secure is a broken (spec-invalid) cookie config,
    even though modern browsers drop such a cookie outright."""
    def r(m, u, kw):
        return {"text": _form()}
    cookie = _morsel("sessionid", "abc", samesite="None", secure=False)
    found, _ = await _run_csrf(r, cookies=[cookie])
    matches = [f for f in found if "SameSite=None" in f["evidence"]]
    assert len(matches) == 1
    assert matches[0]["confidence"] == "LOW"
    assert matches[0]["severity"] == "Low"


async def test_samesite_none_with_secure_not_flagged():
    """SameSite=None + Secure is a valid (if permissive) configuration for a
    cookie that legitimately needs cross-site delivery — not itself a finding."""
    def r(m, u, kw):
        return {"text": _form()}
    cookie = _morsel("sessionid", "abc", samesite="None", secure=True)
    found, _ = await _run_csrf(r, cookies=[cookie])
    assert found == []


async def test_samesite_strict_not_flagged():
    def r(m, u, kw):
        return {"text": _form()}
    cookie = _morsel("sessionid", "abc", samesite="Strict", secure=True)
    found, _ = await _run_csrf(r, cookies=[cookie])
    assert found == []


# ---- cookie-hint matching ----------------------------------------------------

async def test_non_session_cookie_ignored():
    """A cookie whose name doesn't look like an auth/session cookie (see
    SESSION_COOKIE_HINTS) must not trigger the SameSite heuristic even with no
    SameSite attribute at all — an analytics cookie's laxness isn't a CSRF
    weakness."""
    def r(m, u, kw):
        return {"text": _form()}
    cookie = _morsel("_ga_analytics", "xyz")  # no samesite, but not session-like
    found, _ = await _run_csrf(r, cookies=[cookie])
    assert found == []


async def test_multiple_session_cookies_each_evaluated():
    def r(m, u, kw):
        return {"text": _form()}
    cookies = [
        _morsel("sessionid", "a"),                                  # no samesite -> MEDIUM
        _morsel("auth_token", "b", samesite="None", secure=False),  # -> LOW
    ]
    found, _ = await _run_csrf(r, cookies=cookies)
    confidences = sorted(f["confidence"] for f in found)
    assert confidences == ["LOW", "MEDIUM"]


# ---- token-field matching by id (not just name) ------------------------------

async def test_token_matched_by_field_id_not_name():
    """A CSRF field detected by its ``id`` attribute, not its ``name`` — some
    frameworks (e.g. ASP.NET) name the field generically but id it clearly."""
    def r(m, u, kw):
        return {"text": ('<form method="POST" action="/transfer">'
                          '<input id="__RequestVerificationToken" name="field1" '
                          'value="tok"></form>')}
    found, _ = await _run_csrf(r)
    # No missing-token finding; the id-matched field is recognized.
    assert not any(f["evidence"] == "State-changing form has no CSRF token field"
                   for f in found)


async def test_put_and_patch_forms_also_checked():
    """STATE_CHANGING_METHODS covers PUT/PATCH/DELETE, not just POST."""
    def r(m, u, kw):
        return {"text": '<form method="PUT" action="/resource"><input name="x"></form>'}
    found, _ = await _run_csrf(r)
    assert len(found) == 1
    assert found[0]["parameter"] == "PUT"
