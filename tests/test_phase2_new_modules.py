"""Unit tests for the Phase 2 new modules from PLAN_DESARROLLO.md:

stored_xss, xssi, file_upload, access_control, brute_force,
credential_exposure, cookie_analyzer, protocol_injection.
"""

from http.cookies import Morsel

from conftest import MockScanner, collect_vulns

from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.access_control_tester_async import (
    AccessControlTester,
)
from web_security_scanner.modules.vulnerability_testers.brute_force_detector_async import (
    BruteForceDetector,
)
from web_security_scanner.modules.vulnerability_testers.cookie_analyzer_async import (
    CookieAnalyzer,
)
from web_security_scanner.modules.vulnerability_testers.credential_exposure_tester_async import (
    CredentialExposureTester,
)
from web_security_scanner.modules.vulnerability_testers.file_upload_tester_async import (
    FileUploadTester,
)
from web_security_scanner.modules.vulnerability_testers.protocol_injection_tester_async import (
    ProtocolInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.stored_xss_tester_async import (
    StoredXSSTester,
)
from web_security_scanner.modules.vulnerability_testers.xssi_tester_async import (
    CALLBACK_PARAM_NAMES,
    XSSITester,
)


async def _run_with_form(tester_cls, responder, target, form, *, config=None):
    """Like ``collect_vulns`` but threads ``form`` through ``run_test`` kwargs
    (the vector these form-driven testers actually read it from), since
    ``collect_vulns`` only forwards ``config`` to the constructor."""
    em = ScanEventEmitter()
    found = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k.get("vulnerability")))
    cfg = {"payload_delay": 0, "max_payloads": 8}
    if config:
        cfg.update(config)
    tester = tester_cls(MockScanner(responder), em, cfg)
    await tester.run_test(target, form=form)
    return found


# ---- Stored XSS --------------------------------------------------------------

async def test_stored_xss_detected_on_readback():
    store = {"comment": ""}

    def r(m, u, kw):
        if m == "POST":
            store["comment"] = kw.get("data", {}).get("comment", "")
            return {"text": "saved"}
        return {"text": f"<html>comments: {store['comment']}</html>"}

    found = await _run_with_form(
        StoredXSSTester, r, "http://target/post",
        {"action": "http://target/post", "fields": {"comment": "hi"}})
    assert len(found) == 1
    assert found[0]["confidence"] == "HIGH"


async def test_stored_xss_no_form_kwarg_is_noop():
    def r(m, u, kw):
        return {"text": "<html>whatever</html>"}
    found = await collect_vulns(StoredXSSTester, r, target="http://target/post")
    assert found == []


async def test_stored_xss_escaped_readback_not_flagged():
    def r(m, u, kw):
        if m == "POST":
            return {"text": "saved"}
        return {"text": "<html>comments: &lt;script&gt;alert(1)&lt;/script&gt;</html>"}

    found = await _run_with_form(
        StoredXSSTester, r, "http://target/post",
        {"action": "http://target/post", "fields": {"comment": "hi"}})
    assert found == []


# ---- XSSI ----------------------------------------------------------------

async def test_xssi_unprotected_array_flagged():
    def r(m, u, kw):
        return {
            "text": '[{"email": "a@corp.com", "username": "a"}]',
            "headers": {"Content-Type": "application/json"},
        }
    found = await collect_vulns(XSSITester, r, target="http://target/api/users")
    assert len(found) == 1
    assert found[0]["confidence"] == "MEDIUM"


async def test_xssi_protected_prefix_not_flagged():
    def r(m, u, kw):
        return {
            "text": ")]}'\n[{\"email\": \"a@corp.com\"}]",
            "headers": {"Content-Type": "application/json"},
        }
    found = await collect_vulns(XSSITester, r, target="http://target/api/users")
    assert found == []


async def test_xssi_no_sensitive_fields_not_flagged():
    def r(m, u, kw):
        return {
            "text": '[{"color": "blue"}, {"color": "red"}]',
            "headers": {"Content-Type": "application/json"},
        }
    found = await collect_vulns(XSSITester, r, target="http://target/api/colors")
    assert found == []


async def test_xssi_mislabeled_jsonp_with_sensitive_data_high_confidence():
    def r(m, u, kw):
        return {
            "text": 'callback({"email": "a@corp.com", "token": "abc"})',
            "headers": {"Content-Type": "text/html"},
        }
    found = await collect_vulns(XSSITester, r, target="http://target/feed.gtl?uid=1")
    mislabeled_hits = [f for f in found if "text/html" in f["evidence"]]
    assert len(mislabeled_hits) == 1
    assert mislabeled_hits[0]["confidence"] == "HIGH"


async def test_xssi_properly_labeled_jsonp_not_flagged_as_mislabeled():
    def r(m, u, kw):
        return {
            "text": 'callback({"email": "a@corp.com"})',
            "headers": {"Content-Type": "application/javascript"},
        }
    found = await collect_vulns(XSSITester, r, target="http://target/feed.gtl?uid=1")
    assert not any("text/html" in f["evidence"] for f in found)


async def test_xssi_controllable_callback_detected():
    def r(m, u, kw):
        from conftest import param_value
        cb = param_value(u, "callback")
        if cb:
            return {"text": f"{cb}({{}})", "headers": {"Content-Type": "application/javascript"}}
        return {"text": "default({})", "headers": {"Content-Type": "application/javascript"}}

    found = await collect_vulns(XSSITester, r, target="http://target/feed.gtl?uid=1")
    callback_hits = [f for f in found if f.get("parameter") == "callback"]
    assert len(callback_hits) == 1
    assert callback_hits[0]["confidence"] == "HIGH"


async def test_xssi_fixed_callback_not_controllable_not_flagged():
    def r(m, u, kw):
        return {"text": "fixedName({})", "headers": {"Content-Type": "application/javascript"}}

    found = await collect_vulns(XSSITester, r, target="http://target/feed.gtl?uid=1")
    assert not any(f.get("parameter") in CALLBACK_PARAM_NAMES for f in found)


# ---- File Upload -----------------------------------------------------------

async def test_file_upload_confirmed_when_served_back_executable():
    def r(m, u, kw):
        if m == "POST":
            return {"status_code": 200,
                     "text": '<a href="/uploads/shell.php">file</a>',
                     "headers": {}}
        return {"status_code": 200, "text": "WSS_UPLOAD_anything",
                "headers": {"Content-Type": "text/html"}}

    found = await _run_with_form(
        FileUploadTester, r, "http://target/upload",
        {"action": "http://target/upload", "file_field": "avatar"})
    assert found
    assert any(f["confidence"] == "HIGH" for f in found)


async def test_file_upload_rejected_extension_not_flagged():
    def r(m, u, kw):
        return {"status_code": 415, "text": "invalid file type"}

    found = await _run_with_form(
        FileUploadTester, r, "http://target/upload",
        {"action": "http://target/upload", "file_field": "avatar"})
    assert found == []


async def test_file_upload_filename_traversal_detected():
    def r(m, u, kw):
        return {"status_code": 200,
                "text": '<a href="/uploads/victim_user/wss_traversal.html">file</a>'}

    found = await _run_with_form(
        FileUploadTester, r, "http://target/upload",
        {"action": "http://target/upload", "file_field": "avatar"})
    traversal_hits = [f for f in found if f["payload"] == "../victim_user/wss_traversal.html"]
    assert len(traversal_hits) == 1
    assert traversal_hits[0]["severity"] == "Critical"


async def test_file_upload_no_auth_accepted_flagged():
    def r(m, u, kw):
        return {"status_code": 200, "text": "upload ok"}

    found = await _run_with_form(
        FileUploadTester, r, "http://target/upload",
        {"action": "http://target/upload", "file_field": "avatar"})
    noauth_hits = [f for f in found if f["payload"] == "N/A" and "auth" in f["evidence"].lower()]
    assert len(noauth_hits) == 1


async def test_file_upload_no_form_kwarg_is_noop():
    def r(m, u, kw):
        raise AssertionError("must not fire any request without a file_field form")
    found = await collect_vulns(FileUploadTester, r, target="http://target/upload")
    assert found == []


# ---- Access Control ---------------------------------------------------------

async def test_access_control_forced_browsing_hit():
    def r(m, u, kw):
        if u == "http://target/admin/":
            return {"status_code": 200,
                     "text": "Admin Dashboard - manage users and settings here " + "x" * 40}
        return {"status_code": 404, "text": "not found"}

    found = await collect_vulns(AccessControlTester, r, target="http://target/page")
    admin_hits = [f for f in found if f["url"] == "http://target/admin/"]
    assert len(admin_hits) == 1
    assert admin_hits[0]["severity"] == "High"


async def test_access_control_generic_404_shell_not_flagged():
    def r(m, u, kw):
        return {"status_code": 200, "text": "404 Not Found - Page Not Found"}
    found = await collect_vulns(AccessControlTester, r, target="http://target/page")
    assert found == []


async def test_access_control_unauthenticated_sensitive_data_high():
    def r(m, u, kw):
        if u == "http://target/profile.gtl":
            return {"status_code": 200, "text": '{"email": "a@corp.com"}'}
        return {"status_code": 404, "text": "not found"}

    found = await collect_vulns(AccessControlTester, r, target="http://target/profile.gtl")
    hits = [f for f in found if f["parameter"] == "<no-cookie>"]
    assert len(hits) == 1
    assert hits[0]["confidence"] == "HIGH"


async def test_access_control_unauthenticated_no_sensitive_data_medium():
    def r(m, u, kw):
        if u == "http://target/dashboard":
            return {"status_code": 200, "text": "welcome to your dashboard"}
        return {"status_code": 404, "text": "not found"}

    found = await collect_vulns(AccessControlTester, r, target="http://target/dashboard")
    hits = [f for f in found if f["parameter"] == "<no-cookie>"]
    assert len(hits) == 1
    assert hits[0]["confidence"] == "MEDIUM"


async def test_access_control_non_protected_path_not_checked():
    def r(m, u, kw):
        if u == "http://target/blog/post-1" and kw.get("headers") == {"Cookie": ""}:
            raise AssertionError("must not fire a no-cookie probe for a non-protected path")
        return {"status_code": 404, "text": "not found"}

    found = await collect_vulns(AccessControlTester, r, target="http://target/blog/post-1")
    assert not any(f["parameter"] == "<no-cookie>" for f in found)


async def test_access_control_verb_tampering_bypass_detected():
    def r(m, u, kw):
        if m == "GET" and not kw.get("headers"):
            return {"status_code": 403, "text": "forbidden"}
        if m == "HEAD":
            return {"status_code": 200,
                     "text": "Protected internal resource with real content here " + "y" * 40}
        return {"status_code": 403, "text": "forbidden"}

    found = await collect_vulns(AccessControlTester, r, target="http://target/private")
    tamper_hits = [f for f in found if "verb-tamper" in f["payload"]]
    assert len(tamper_hits) == 1
    assert tamper_hits[0]["confidence"] == "HIGH"


# ---- Brute Force -------------------------------------------------------------

async def test_brute_force_no_mitigation_flagged():
    def r(m, u, kw):
        return {"status_code": 200, "text": "invalid credentials"}

    found = await _run_with_form(
        BruteForceDetector, r, "http://target/login",
        {"action": "http://target/login", "fields": {"username": "a", "password": "x"}},
        config={"brute_force_attempts": 4})
    assert len(found) == 1
    assert found[0]["confidence"] == "MEDIUM"


async def test_brute_force_lockout_detected_not_flagged():
    calls = {"n": 0}
    def r(m, u, kw):
        calls["n"] += 1
        if calls["n"] >= 3:
            return {"status_code": 429, "text": "too many attempts"}
        return {"status_code": 200, "text": "invalid credentials"}

    found = await _run_with_form(
        BruteForceDetector, r, "http://target/login",
        {"action": "http://target/login", "fields": {"username": "a", "password": "x"}},
        config={"brute_force_attempts": 8})
    assert found == []
    assert calls["n"] == 3  # stopped as soon as lockout was observed


async def test_brute_force_recognizes_bare_pw_field_name():
    """Google Gruyere-shaped login form: password field literally named 'pw',
    not 'password'/'pwd' -- must still be recognized as a login form."""
    def r(m, u, kw):
        return {"status_code": 200, "text": "invalid credentials"}

    found = await _run_with_form(
        BruteForceDetector, r, "http://target/login",
        {"action": "http://target/login", "fields": {"uid": "a", "pw": "x"}},
        config={"brute_force_attempts": 3})
    assert len(found) == 1
    assert found[0]["parameter"] == "pw"


async def test_brute_force_no_password_field_is_noop():
    def r(m, u, kw):
        raise AssertionError("must not fire requests for a non-login form")
    found = await _run_with_form(
        BruteForceDetector, r, "http://target/search",
        {"action": "http://target/search", "fields": {"q": "x"}})
    assert found == []


# ---- Credential Exposure -----------------------------------------------------

async def test_credential_exposure_aws_key_in_body_flagged():
    def r(m, u, kw):
        return {"status_code": 200,
                "text": "config: AKIAABCDEFGHIJKLMNOP embedded in bundle"}

    found = await collect_vulns(CredentialExposureTester, r, target="http://target/app.js")
    assert len(found) == 1
    assert found[0]["severity"] == "Critical"


async def test_credential_exposure_clean_page_not_flagged():
    def r(m, u, kw):
        return {"status_code": 200, "text": "<html>Welcome to our site</html>"}
    found = await collect_vulns(CredentialExposureTester, r, target="http://target/page")
    assert found == []


async def test_credential_exposure_scans_linked_same_origin_js():
    def r(m, u, kw):
        if u == "http://target/page":
            return {"status_code": 200,
                    "text": '<html><script src="/static/bundle.js"></script></html>'}
        if u == "http://target/static/bundle.js":
            return {"status_code": 200, "text": "password: 'SuperSecret123'"}
        return {"status_code": 404, "text": ""}

    found = await collect_vulns(CredentialExposureTester, r, target="http://target/page")
    assert len(found) == 1
    assert found[0]["url"] == "http://target/static/bundle.js"


async def test_credential_exposure_get_login_form_flagged():
    def r(m, u, kw):
        return {"status_code": 200,
                "text": ('<form method="GET" action="/login">'
                          '<input name="user"><input name="password" type="password">'
                          '</form>')}
    found = await collect_vulns(CredentialExposureTester, r, target="http://target/login")
    login_hits = [f for f in found if f["url"] == "/login"]
    assert len(login_hits) == 1
    assert login_hits[0]["severity"] == "High"


async def test_credential_exposure_post_login_form_not_flagged():
    def r(m, u, kw):
        return {"status_code": 200,
                "text": ('<form method="POST" action="/login">'
                          '<input name="user"><input name="password" type="password">'
                          '</form>')}
    found = await collect_vulns(CredentialExposureTester, r, target="http://target/login")
    assert not any(f["url"] == "/login" for f in found)


# ---- Cookie Analyzer ----------------------------------------------------------

def _morsel(key: str, value: str) -> Morsel:
    m: Morsel = Morsel()
    m.set(key, value, value)
    return m


class _FakeJar:
    def __init__(self, morsels):
        self._morsels = list(morsels)

    def __iter__(self):
        return iter(self._morsels)


class _FakeSession:
    def __init__(self, cookie_jar):
        self.cookie_jar = cookie_jar


async def _run_cookie_analyzer(responder, cookies, target):
    from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
    em = ScanEventEmitter()
    found = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k.get("vulnerability")))
    scanner = MockScanner(responder)
    scanner.session = _FakeSession(_FakeJar(cookies))
    tester = CookieAnalyzer(scanner, em, {"payload_delay": 0, "max_payloads": 8})
    await tester.run_test(target)
    return found


async def test_cookie_plaintext_role_flagged():
    def r(m, u, kw):
        return {"text": "ok"}
    cookie = _morsel("session", "8f14e45|42|admin")
    found = await _run_cookie_analyzer(r, [cookie], "http://target/page")
    assert any("role name in plaintext" in f["evidence"] for f in found)


async def test_cookie_plaintext_uid_flagged():
    def r(m, u, kw):
        return {"text": "ok"}
    cookie = _morsel("session", "8f14e45|42|guest")
    found = await _run_cookie_analyzer(r, [cookie], "http://target/page")
    assert any("numeric user id in plaintext" in f["evidence"] for f in found)


async def test_cookie_opaque_random_token_not_flagged():
    def r(m, u, kw):
        return {"text": "ok"}
    cookie = _morsel("session", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")
    found = await _run_cookie_analyzer(r, [cookie], "http://target/page")
    assert found == []


async def test_cookie_analyzer_checks_arbitrarily_named_cookie():
    """No name-based prefilter: a cookie named anything (not just 'session'/
    'sid'/...) is still checked -- e.g. Google Gruyere's real session cookie
    is literally named 'GRUYERE', which matches no common hint."""
    def r(m, u, kw):
        return {"text": "ok"}
    cookie = _morsel("GRUYERE", "51292534|pepe||author")
    found = await _run_cookie_analyzer(r, [cookie], "http://target/page")
    assert any("role name in plaintext" in f["evidence"] for f in found)


# ---- Protocol Injection -------------------------------------------------------

async def test_protocol_injection_javascript_href_sink_detected():
    store = {"website": ""}

    def r(m, u, kw):
        if m == "POST":
            store["website"] = kw.get("data", {}).get("website", "")
            return {"text": "saved"}
        return {"text": f'<html><a href="{store["website"]}">site</a></html>'}

    found = await _run_with_form(
        ProtocolInjectionTester, r, "http://target/profile",
        {"action": "http://target/profile", "fields": {"website": "https://example.com"}})
    assert found
    assert all(f["confidence"] == "HIGH" for f in found)


async def test_protocol_injection_no_sink_reflection_not_flagged():
    def r(m, u, kw):
        if m == "POST":
            return {"text": "saved"}
        return {"text": "<html>no reflection here</html>"}

    found = await _run_with_form(
        ProtocolInjectionTester, r, "http://target/profile",
        {"action": "http://target/profile", "fields": {"website": "https://example.com"}})
    assert found == []


async def test_protocol_injection_no_form_kwarg_is_noop():
    def r(m, u, kw):
        raise AssertionError("must not fire requests without a form")
    found = await collect_vulns(ProtocolInjectionTester, r, target="http://target/profile")
    assert found == []
