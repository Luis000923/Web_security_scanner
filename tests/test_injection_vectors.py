"""Multi-vector injection surface: POST body / JSON / header / cookie.

Covers the plumbing added on top of the existing InjectionPoint scaffolding:
recursive JSON-leaf enumeration, dotted-path assignment into nested lists,
per-call header/cookie overrides, and that the token bucket + concurrency
semaphore + SSRF guard still wrap the non-GET request types.
"""

import pytest
from conftest import MockScanner

from web_security_scanner.core.scanner_core_async import (
    AsyncScannerCore,
    ScanConfig,
    SSRFRedirectError,
)
from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.base_tester_async import (
    DEFAULT_INJECTABLE_HEADERS,
    VulnerabilityTester,
    _iter_leaf_paths,
    _set_dotted,
)
from web_security_scanner.modules.vulnerability_testers.sql_injection_async import (
    SQLInjectionTester,
)


class _Dummy(VulnerabilityTester):
    name = "dummy"
    description = "dummy"

    async def run_test(self, target_url, **kwargs):  # pragma: no cover
        return None


def _tester(**config):
    return _Dummy(MockScanner(lambda *a, **k: {}), ScanEventEmitter(), config)


# ---- recursive JSON serialization ------------------------------------------


def test_iter_leaf_paths_walks_nested_dicts_and_lists():
    tpl = {"a": 1, "b": {"c": 2, "d": {"e": 3}}, "f": [10, {"g": 4}]}
    assert _iter_leaf_paths(tpl) == ["a", "b.c", "b.d.e", "f.0", "f.1.g"]


def test_iter_leaf_paths_ignores_empty_containers():
    assert _iter_leaf_paths({"a": {}, "b": [], "c": 1}) == ["c"]


def test_set_dotted_into_nested_dict():
    obj = {"user": {"profile": {"id": "x"}}}
    _set_dotted(obj, "user.profile.id", "PAYLOAD")
    assert obj == {"user": {"profile": {"id": "PAYLOAD"}}}


def test_set_dotted_into_list_index_grows_list():
    obj = {"roles": ["a", "b"]}
    _set_dotted(obj, "roles.1", "PAYLOAD")
    assert obj["roles"] == ["a", "PAYLOAD"]
    _set_dotted(obj, "roles.4", "P2")
    assert obj["roles"] == ["a", "PAYLOAD", None, None, "P2"]


def test_set_dotted_creates_list_for_numeric_next_segment():
    obj = {}
    _set_dotted(obj, "items.0.name", "PAYLOAD")
    assert obj == {"items": [{"name": "PAYLOAD"}]}


# ---- iter_injection_points: JSON body -------------------------------------


def test_json_form_enumerates_every_leaf_as_jsonparam():
    t = _tester()
    form = {"action": "http://h/api", "enctype": "json",
            "fields": {"user": {"name": "a", "roles": ["admin"]}, "note": "n"}}
    points = t.iter_injection_points("http://h/api", form=form)
    params = {(p.vector, p.param) for p in points}
    assert params == {
        ("jsonparam", "user.name"),
        ("jsonparam", "user.roles.0"),
        ("jsonparam", "note"),
    }
    assert all(p.http_method == "POST" for p in points)


def test_build_probe_jsonparam_mutates_one_leaf_only():
    t = _tester()
    form = {"action": "http://h/api", "enctype": "json",
            "fields": {"a": {"b": 1}, "c": 2}}
    point = next(p for p in t.iter_injection_points("http://h/api", form=form)
                 if p.param == "a.b")
    method, url, kwargs = t.build_probe(point, "PWN", base_url="http://h/api")
    assert method == "POST" and url == "http://h/api"
    assert kwargs["json"] == {"a": {"b": "PWN"}, "c": 2}


def test_form_urlencoded_stays_flat():
    t = _tester()
    form = {"action": "http://h/f", "enctype": "form",
            "fields": {"user": "a", "pass": "b"}}
    points = t.iter_injection_points("http://h/f", form=form)
    assert {(p.vector, p.param) for p in points} == {
        ("formparam", "user"), ("formparam", "pass")}
    _, _, kw = t.build_probe(points[0], "X", base_url="http://h/f")
    assert kw["data"] == {"user": "X", "pass": "b"}


# ---- iter_injection_points: headers + cookies ----------------------------


def test_inject_headers_default_set_from_config_sentinel():
    t = _tester(inject_headers="__default__")
    pts = t.iter_injection_points("http://h/x")
    assert {p.param for p in pts if p.vector == "header"} == set(DEFAULT_INJECTABLE_HEADERS)


def test_inject_headers_per_call_override_wins_over_config():
    t = _tester(inject_headers="__default__")
    pts = t.iter_injection_points("http://h/x", inject_headers=["X-Custom"])
    assert {p.param for p in pts if p.vector == "header"} == {"X-Custom"}


def test_cookie_points_carry_full_template():
    t = _tester()
    pts = t.iter_injection_points("http://h/x",
                                  inject_cookies={"sid": "abc", "role": "user"})
    ck = [p for p in pts if p.vector == "cookie"]
    assert {p.param for p in ck} == {"sid", "role"}
    _, _, kw = t.build_probe(ck[0], "PWN", base_url="http://h/x")
    assert kw["cookies"]["role"] == "user"  # untouched field preserved
    assert kw["cookies"][ck[0].param] == "PWN"


# ---- concurrency / token bucket / SSRF over the new request types --------


class _SpyCore(AsyncScannerCore):
    def __init__(self, config):
        super().__init__(config)
        self.calls = []

    async def _request_following(self, method, url, follow_redirects,
                                 caller_headers, kwargs):
        # Assert we are inside a held semaphore permit.
        assert self._semaphore._value < self.config.max_concurrency
        self.calls.append((method, url, dict(kwargs)))
        return {"status_code": 200, "text": "", "headers": {}, "url": url,
                "elapsed": 0.0, "truncated": False}


@pytest.mark.asyncio
async def test_token_bucket_and_semaphore_wrap_post_json_probe():
    cfg = ScanConfig(max_concurrency=4, rate_limit=0.05)
    core = _SpyCore(cfg)
    await core.request("POST", "http://h/api", json={"a": "PWN"}, use_cache=False)
    await core.request("GET", "http://h/x", headers={"X-Forwarded-For": "PWN"},
                       use_cache=False)
    assert core._rate_bucket is not None
    assert [c[0] for c in core.calls] == ["POST", "GET"]
    await core.close()


@pytest.mark.asyncio
async def test_assert_public_target_blocks_internal_post():
    cfg = ScanConfig(assert_public_target=True)
    core = AsyncScannerCore(cfg)
    with pytest.raises(SSRFRedirectError):
        await core.request("POST", "http://127.0.0.1/api", json={"a": "x"},
                           use_cache=False)
    await core.close()


# ---- end-to-end: a tester over a header vector ---------------------------


@pytest.mark.asyncio
async def test_sqli_tester_fires_on_header_vector():
    seen = {}

    def responder(method, url, kwargs):
        hdrs = kwargs.get("headers") or {}
        xff = hdrs.get("X-Forwarded-For", "")
        seen["method"] = method
        if "'" in xff:
            return {"text": "You have an error in your SQL syntax; near"}
        return {"text": "ok"}

    em = ScanEventEmitter()
    found = []
    em.on(ScanEventType.VULNERABILITY_FOUND,
          lambda **k: found.append(k.get("vulnerability")))
    t = SQLInjectionTester(MockScanner(responder), em,
                           {"payload_delay": 0, "max_payloads": 20})
    await t.run_test("http://h/x", inject_headers=["X-Forwarded-For"])
    assert found and found[0]["vector"] == "header"
    assert found[0]["parameter"] == "X-Forwarded-For"
    assert seen["method"] == "GET"
