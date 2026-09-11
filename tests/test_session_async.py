"""Authenticated scanning: form login, static cookies, bearer token, re-auth.

Public/unauthenticated flows must stay byte-for-byte identical when no session
config is supplied — see ``test_no_session_config_is_inert``.
"""

import json

import pytest
from aiohttp import web

from web_security_scanner.core import manifest_async
from web_security_scanner.core.scanner_core_async import AsyncScannerCore, ScanConfig
from web_security_scanner.core.session_async import (
    PRIMARY_ROLE,
    IdentityPool,
    SessionConfig,
    SessionManager,
    _walk_dotted,
)

# ---------------------------------------------------------------------------
# Unit
# ---------------------------------------------------------------------------

def test_walk_dotted():
    obj = {"data": {"access_token": "abc", "roles": ["admin", "user"]}}
    assert _walk_dotted(obj, "data.access_token") == "abc"
    assert _walk_dotted(obj, "data.roles.1") == "user"
    assert _walk_dotted(obj, "data.missing.x") is None


def test_session_config_from_dict_ignores_unknown_keys(caplog):
    cfg = SessionConfig.from_dict({"login_url": "http://h/login", "bogus": 1})
    assert cfg.login_url == "http://h/login"
    assert cfg.active and cfg.does_form_login is False  # no username yet


def test_session_config_from_json_and_yaml(tmp_path):
    payload = {"login_url": "http://h/login", "username": "u", "password": "p",
               "static_cookies": {"sid": "x"}}
    j = tmp_path / "s.json"
    j.write_text(json.dumps(payload))
    y = tmp_path / "s.yaml"
    y.write_text("login_url: http://h/login\nusername: u\npassword: p\n")
    assert SessionConfig.from_file(j).does_form_login
    assert SessionConfig.from_file(y).username == "u"


def test_looks_logged_out():
    sm = SessionManager(SessionConfig(
        login_url="http://h/accounts/login/", username="u", password="p",
        logged_out_markers=["Please sign in"]))
    assert sm.looks_logged_out({"status_code": 401, "url": "http://h/x", "text": ""})
    assert sm.looks_logged_out({"status_code": 200,
                                "url": "http://h/accounts/login/?next=/x", "text": ""})
    assert sm.looks_logged_out({"status_code": 200, "url": "http://h/x",
                                "text": "<h1>Please sign in</h1>"})
    assert not sm.looks_logged_out({"status_code": 200, "url": "http://h/x", "text": "ok"})


def test_session_config_identities_rejects_primary_role_key():
    with pytest.raises(ValueError, match="reserved primary role"):
        SessionConfig(identities={PRIMARY_ROLE: {"login_url": "http://h/login"}})


def test_session_config_identities_accepted_and_parsed_from_dict():
    cfg = SessionConfig.from_dict({
        "login_url": "http://h/login", "username": "admin", "password": "p",
        "identities": {"B": {"login_url": "http://h/login",
                              "username": "bob", "password": "q"}},
    })
    assert set(cfg.identities) == {"B"}
    assert cfg.identities["B"]["username"] == "bob"


def test_identity_pool_resolves_primary_role_without_starting_anything():
    """A pool with zero secondary identities must resolve ``PRIMARY_ROLE`` to
    the primary core it was built with, and nothing else -- the common case
    of a scan with no ``session.identities`` configured never touches network
    or constructs a secondary ``AsyncScannerCore``."""
    primary_core = object()  # identity suffices; IdentityPool never calls it here
    pool = IdentityPool(primary_core)
    assert pool.get(PRIMARY_ROLE) is primary_core
    assert pool.get("B") is None
    assert pool.roles == [PRIMARY_ROLE]
    assert pool.secondary_roles == []


def test_manifest_redacts_session_secrets():
    cfg = {
        "core": {"timeout": 10},
        "session": {"login_url": "http://h/login", "username": "admin",
                    "password": "s3cr3t", "static_cookies": {"sid": "abc"},
                    "token": "eyJhbGc", "cookie_jar_file": "/tmp/jar"},
    }
    m = manifest_async.build_manifest(run_id="r", config=cfg, global_seed=None)
    sess = m["config"]["session"]
    assert sess["password"] == "***"
    assert sess["static_cookies"] == "***"
    assert sess["token"] == "***"
    assert sess["cookie_jar_file"] == "***"
    assert sess["username"] == "admin"        # not a secret
    assert sess["login_url"] == "http://h/login"


def test_manifest_redacts_cookie_header_but_keeps_cookie_jar_flag():
    """A raw ``Cookie`` header value is masked; the ``cookie_jar_unsafe`` bool
    (exact-match miss) is passed through untouched."""
    cfg = {
        "core": {"cookie_jar_unsafe": True,
                 "headers": {"Cookie": "JSESSIONID=abc", "Accept": "*/*"}},
    }
    m = manifest_async.build_manifest(run_id="r", config=cfg, global_seed=None)
    core = m["config"]["core"]
    assert core["cookie_jar_unsafe"] is True
    assert core["headers"]["Cookie"] == "***"
    assert core["headers"]["Accept"] == "*/*"


def test_manifest_scrubs_secrets_hidden_inside_values():
    """Key-name redaction alone misses a token riding inside a neutral value."""
    cfg = {
        "session": {
            "login_url": "https://app.example/cb?next=/x&access_token=abc123XYZ",
            "cookie_jar": "https://svc:hunter2@jar.example/cookies.txt",
        },
        "core": {"headers": {
            "X-Trace": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.QQQQQQQQ",
            "Accept": "*/*",
        }},
        "notes": ["deploy key sk-abcdefghijklmnopqrstuvwx", "nothing to see"],
    }
    m = manifest_async.build_manifest(run_id="r", config=cfg, global_seed=None)
    sess = m["config"]["session"]
    assert sess["login_url"] == "https://app.example/cb?next=/x&access_token=***"
    assert "hunter2" not in sess["cookie_jar"]      # exact-key mask still wins
    hdrs = m["config"]["core"]["headers"]
    assert hdrs["X-Trace"] == "Bearer ***"
    assert hdrs["Accept"] == "*/*"
    assert m["config"]["notes"] == ["deploy key ***", "nothing to see"]


def test_scrub_secret_values_is_a_noop_on_ordinary_text():
    for text in ("http://target.example/search?q=hello&page=2",
                 "balanced", "", "GET /index.html"):
        assert manifest_async.scrub_secret_values(text) == text


def test_scrub_secret_values_masks_bare_jwt_and_url_credentials():
    scrub = manifest_async.scrub_secret_values
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJl"
    assert scrub(f"token={jwt}") == "token=***"
    assert scrub("https://admin:s3cr3t@intranet/") == "https://***:***@intranet/"


def test_walk_dotted_edge_cases():
    assert _walk_dotted({"a": [{"b": 1}]}, "a.0.b") == 1
    assert _walk_dotted({"a": [1, 2]}, "a.-1") == 2
    assert _walk_dotted({"a": [1]}, "a.5") is None
    assert _walk_dotted({"a": 1}, "a.b") is None       # scalar mid-path
    assert _walk_dotted(None, "a") is None


# ---------------------------------------------------------------------------
# Integration — real aiohttp app
# ---------------------------------------------------------------------------

@pytest.fixture
async def auth_app():
    """A tiny app: /login sets JSESSIONID; /protected needs it; /jwt-login
    returns a token; /expiring is 401 until a re-login flips a flag."""
    state = {"reauth_seen": 0, "expired": True}

    # Two independent users, each getting their own session cookie value, so
    # a test can tell which authenticated identity a later request rode in on.
    creds = {("admin", "hunter2"): "SESSION-OK", ("bob", "wonderland"): "SESSION-OK-B"}

    async def login(request):
        data = await request.post()
        key = (data.get("user"), data.get("pw"))
        cookie = creds.get(key)
        if cookie:
            resp = web.Response(text="welcome")
            resp.set_cookie("JSESSIONID", cookie)
            state["expired"] = False
            return resp
        return web.Response(status=403, text="bad creds")

    async def protected(request):
        if request.cookies.get("JSESSIONID") == "SESSION-OK":
            return web.Response(text="secret area")
        return web.Response(status=401, text="Please sign in")

    async def idor_resource(request):
        # Deliberately vulnerable: any authenticated session (admin's OR
        # bob's) sees admin's data -- object-level access control is missing
        # entirely. Mirrors a broken ``/api/profile?id=<admin's id>`` endpoint.
        if request.cookies.get("JSESSIONID") in creds.values():
            return web.Response(text="email admin@corp.com username admin profile data")
        return web.Response(status=401, text="Please sign in")

    async def safe_resource(request):
        # Correctly isolated: each session sees only its own data. Padded to
        # unambiguously different lengths (>10% apart) so the length-based
        # response_differs_significantly heuristic reliably tells them apart.
        owner_padding = {"SESSION-OK": ("admin", "a" * 80), "SESSION-OK-B": ("bob", "")}
        entry = owner_padding.get(request.cookies.get("JSESSIONID"))
        if entry is None:
            return web.Response(status=401, text="Please sign in")
        owner, padding = entry
        return web.Response(
            text=f"email {owner}@corp.com username {owner} profile data {padding}")

    async def jwt_login(request):
        return web.json_response({"data": {"access_token": "JWT-123"}})

    async def needs_bearer(request):
        if request.headers.get("Authorization") == "Bearer JWT-123":
            return web.Response(text="bearer ok")
        return web.Response(status=401, text="no token")

    async def expiring(request):
        if request.cookies.get("JSESSIONID") == "SESSION-OK" and not state["expired"]:
            return web.Response(text="fresh")
        return web.Response(status=401, text="Please sign in")

    app = web.Application()
    app.router.add_post("/login", login)
    app.router.add_get("/protected", protected)
    app.router.add_post("/jwt-login", jwt_login)
    app.router.add_get("/needs-bearer", needs_bearer)
    app.router.add_get("/expiring", expiring)
    app.router.add_get("/idor-resource", idor_resource)
    app.router.add_get("/safe-resource", safe_resource)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield f"http://127.0.0.1:{port}", state
    finally:
        await runner.cleanup()


def _core():
    return AsyncScannerCore(ScanConfig(timeout=5, allow_private_redirects=True))


async def test_form_login_persists_session_cookie(auth_app):
    base, _ = auth_app
    core = _core()
    await core.start()
    try:
        pre = await core.request("GET", f"{base}/protected", use_cache=False)
        assert pre["status_code"] == 401

        sm = SessionManager(SessionConfig(
            login_url=f"{base}/login", username="admin", password="hunter2",
            username_field="user", password_field="pw"))
        assert await sm.authenticate(core, force=True) is True

        post = await core.request("GET", f"{base}/protected", use_cache=False)
        assert post["status_code"] == 200 and "secret area" in post["text"]
    finally:
        await core.close()


async def test_jwt_token_extracted_and_attached(auth_app):
    base, _ = auth_app
    core = _core()
    await core.start()
    try:
        sm = SessionManager(SessionConfig(
            login_url=f"{base}/jwt-login", username="x", password="y",
            token_json_path="data.access_token"))
        assert await sm.authenticate(core, force=True) is True
        assert core._auth_headers.get("Authorization") == "Bearer JWT-123"
        r = await core.request("GET", f"{base}/needs-bearer", use_cache=False)
        assert r["status_code"] == 200
    finally:
        await core.close()


async def test_static_cookie_injection(auth_app):
    base, _ = auth_app
    core = _core()
    await core.start()
    try:
        sm = SessionManager(SessionConfig(
            static_cookies={"JSESSIONID": "SESSION-OK"}))
        sm.apply_static(core, base)
        r = await core.request("GET", f"{base}/protected", use_cache=False)
        assert r["status_code"] == 200
    finally:
        await core.close()


async def test_cookie_jar_file_netscape(auth_app, tmp_path):
    base, _ = auth_app
    host = base.split("//")[1].split(":")[0]
    jar = tmp_path / "cookies.txt"
    jar.write_text(
        "# Netscape HTTP Cookie File\n"
        f"{host}\tFALSE\t/\tFALSE\t0\tJSESSIONID\tSESSION-OK\n")
    core = _core()
    await core.start()
    try:
        sm = SessionManager(SessionConfig(cookie_jar_file=str(jar),
                                          login_url=f"{base}/"))
        sm.apply_static(core, base)
        r = await core.request("GET", f"{base}/protected", use_cache=False)
        assert r["status_code"] == 200
    finally:
        await core.close()


async def test_transparent_reauth_on_expiry(auth_app):
    base, state = auth_app
    core = _core()
    await core.start()
    try:
        sm = SessionManager(SessionConfig(
            login_url=f"{base}/login", username="admin", password="hunter2",
            username_field="user", password_field="pw",
            reauth_cooldown=0.0, logged_out_markers=["Please sign in"]))
        await sm.authenticate(core, force=True)
        core.attach_session_manager(sm)

        # Server-side expire the session, then a probe should self-heal.
        state["expired"] = True
        r = await core.request("GET", f"{base}/expiring", use_cache=False)
        assert r["status_code"] == 200 and r["text"] == "fresh"
        assert sm.reauth_count == 1
    finally:
        await core.close()


async def test_concurrent_logged_out_probes_trigger_single_relogin():
    """A burst of concurrent probes that all see a logged-out response must
    cause exactly one re-login (lock + cooldown coalescing), not one per probe."""
    logins = {"n": 0}

    async def login(request):
        logins["n"] += 1
        resp = web.Response(text="ok")
        resp.set_cookie("JSESSIONID", f"S{logins['n']}")
        return resp

    async def always_expired(request):
        return web.Response(status=401, text="Please sign in")

    app = web.Application()
    app.router.add_post("/login", login)
    app.router.add_get("/x", always_expired)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    base = f"http://127.0.0.1:{port}"
    core = _core()
    await core.start()
    try:
        sm = SessionManager(SessionConfig(
            login_url=f"{base}/login", username="u", password="p",
            reauth_cooldown=30.0, logged_out_markers=["Please sign in"]))
        await sm.authenticate(core, force=True)
        core.attach_session_manager(sm)
        logins["n"] = 0
        # Clear the cooldown left by the initial login so the burst is free to
        # re-auth; the lock + cooldown must then still collapse it to one call.
        sm._last_attempt = 0.0

        import asyncio as _aio
        await _aio.gather(*[
            core.request("GET", f"{base}/x", use_cache=False) for _ in range(12)
        ])
        # One re-login for the whole burst; the cooldown suppresses the rest.
        assert logins["n"] == 1
        assert sm.reauth_count == 1
    finally:
        await core.close()
        await runner.cleanup()


async def test_no_session_config_is_inert(auth_app):
    """Without a manager: no auth headers, jar empty, behaviour unchanged."""
    base, _ = auth_app
    core = _core()
    await core.start()
    try:
        r = await core.request("GET", f"{base}/protected", use_cache=False)
        assert r["status_code"] == 401
        assert core._auth_headers == {}
        assert core._session_manager is None
    finally:
        await core.close()


# ---------------------------------------------------------------------------
# Orchestrator wiring
# ---------------------------------------------------------------------------

async def test_scanner_authenticates_before_recon(auth_app):
    from web_security_scanner.web_security_scanner_async import WebSecurityScanner

    base, _ = auth_app
    scanner = WebSecurityScanner({
        "core": {"allow_private_redirects": True},
        "session": {"login_url": f"{base}/login", "username": "admin",
                    "password": "hunter2", "username_field": "user",
                    "password_field": "pw"},
    })
    await scanner.core.start()
    try:
        assert await scanner._authenticate(base) is True
        assert scanner.core._session_manager is scanner.session_manager
        r = await scanner.core.request("GET", f"{base}/protected", use_cache=False)
        assert r["status_code"] == 200
    finally:
        await scanner.core.close()


async def test_auth_required_failure_aborts(auth_app):
    from web_security_scanner.web_security_scanner_async import WebSecurityScanner

    base, _ = auth_app
    scanner = WebSecurityScanner({
        "core": {"allow_private_redirects": True},
        "session": {"login_url": f"{base}/login", "username": "admin",
                    "password": "WRONG", "username_field": "user",
                    "password_field": "pw", "required": True},
    })
    await scanner.core.start()
    try:
        assert await scanner._authenticate(base) is False
    finally:
        await scanner.core.close()


# ---------------------------------------------------------------------------
# Multi-identity (IdentityPool) — cross-session IDOR prerequisite
# ---------------------------------------------------------------------------

def _multi_identity_session_cfg(base: str) -> dict:
    return {
        "login_url": f"{base}/login", "username": "admin", "password": "hunter2",
        "username_field": "user", "password_field": "pw",
        "identities": {
            "B": {"login_url": f"{base}/login", "username": "bob",
                  "password": "wonderland", "username_field": "user",
                  "password_field": "pw"},
        },
    }


async def test_identity_pool_starts_secondary_identity_concurrently(auth_app):
    base, _ = auth_app
    core = _core()
    await core.start()
    try:
        sm = SessionManager(SessionConfig.from_dict(_multi_identity_session_cfg(base)))
        assert await sm.authenticate(core, force=True) is True  # role A (primary)

        pool = IdentityPool(core)
        await pool.start_all(sm.cfg.identities, core.config, target_url=base)
        try:
            assert pool.secondary_roles == ["B"]
            core_b = pool.get("B")
            assert core_b is not None and core_b is not core   # independent transport

            # Role A's own view of the protected resource, and role B's --
            # both authenticated, through two entirely separate ClientSessions.
            r_a = await core.request("GET", f"{base}/protected", use_cache=False)
            assert r_a["status_code"] == 200
            r_b = await core_b.request("GET", f"{base}/idor-resource", use_cache=False)
            assert r_b["status_code"] == 200
        finally:
            await pool.close()
    finally:
        await core.close()


async def test_identity_pool_start_all_is_noop_without_identities(auth_app):
    """Zero identities configured -> no secondary AsyncScannerCore is even
    constructed (byte-identical to a single-identity scan)."""
    base, _ = auth_app
    core = _core()
    await core.start()
    try:
        pool = IdentityPool(core)
        await pool.start_all({}, core.config, target_url=base)
        assert pool.secondary_roles == []
        await pool.close()  # must not raise on an empty pool
    finally:
        await core.close()


async def test_idor_tester_confirms_cross_session_bypass_via_real_identity_pool(auth_app):
    """End-to-end: WebSecurityScanner wires an IdentityPool from
    ``session.identities`` into every tester's config, and IDORTester uses it
    to catch the deliberately-broken ``/idor-resource`` endpoint (any
    authenticated session sees admin's data) against a real second aiohttp
    login -- not a mock."""
    from web_security_scanner.modules.vulnerability_testers.idor_tester_async import (
        IDORTester,
    )
    from web_security_scanner.web_security_scanner_async import WebSecurityScanner

    base, _ = auth_app
    scanner = WebSecurityScanner({
        "core": {"allow_private_redirects": True},
        "session": _multi_identity_session_cfg(base),
    })
    await scanner.core.start()
    try:
        assert await scanner._authenticate(base) is True
        assert scanner.identity_pool is not None
        assert scanner.config["testers"]["identity_pool"] is scanner.identity_pool

        tester = IDORTester(scanner.core, scanner.event_emitter, scanner.config["testers"])
        found: list[dict] = []
        from web_security_scanner.events.event_emitter import ScanEventType
        scanner.event_emitter.on(
            ScanEventType.VULNERABILITY_FOUND,
            lambda **k: found.append(k.get("vulnerability")))

        await tester.run_test(f"{base}/idor-resource?id=1")

        assert len(found) == 1
        assert found[0]["confidence"] == "CONFIRMED"
        assert found[0]["payload"] == "cross-session:B"
    finally:
        if scanner.identity_pool is not None:
            await scanner.identity_pool.close()
        await scanner.core.close()


async def test_idor_tester_no_finding_against_properly_isolated_resource(auth_app):
    """Negative control: the same multi-identity setup against a *correctly*
    isolated endpoint must not report anything."""
    from web_security_scanner.modules.vulnerability_testers.idor_tester_async import (
        IDORTester,
    )
    from web_security_scanner.web_security_scanner_async import WebSecurityScanner

    base, _ = auth_app
    scanner = WebSecurityScanner({
        "core": {"allow_private_redirects": True},
        "session": _multi_identity_session_cfg(base),
    })
    await scanner.core.start()
    try:
        assert await scanner._authenticate(base) is True
        tester = IDORTester(scanner.core, scanner.event_emitter, scanner.config["testers"])
        found: list[dict] = []
        from web_security_scanner.events.event_emitter import ScanEventType
        scanner.event_emitter.on(
            ScanEventType.VULNERABILITY_FOUND,
            lambda **k: found.append(k.get("vulnerability")))

        await tester.run_test(f"{base}/safe-resource?id=1")

        assert found == []
    finally:
        if scanner.identity_pool is not None:
            await scanner.identity_pool.close()
        await scanner.core.close()
