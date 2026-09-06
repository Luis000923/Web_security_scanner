"""Tests for the shared VulnerabilityTester base: runtime WAF-bypass mutation."""

import logging

from conftest import MockScanner

from web_security_scanner.core.payload_loader import Payload
from web_security_scanner.events.event_emitter import ScanEventEmitter
from web_security_scanner.modules.vulnerability_testers import base_tester_async as base_mod
from web_security_scanner.modules.vulnerability_testers.base_tester_async import (
    VulnerabilityTester,
)
from web_security_scanner.modules.vulnerability_testers.xss_tester_async import XSSTester


class _DummyTester(VulnerabilityTester):
    """Concrete tester exposing only the shared payload plumbing."""

    name = "dummy"
    description = "dummy"

    async def run_test(self, target_url, **kwargs):  # pragma: no cover - unused
        return None


def _make_tester(cls=_DummyTester, *, mutator=None, **config):
    return cls(MockScanner(lambda *a, **k: {}), ScanEventEmitter(), config,
               mutator=mutator)


def _sig(vector, *, category="xss", context="generic", destructive=False):
    return Payload(vector=vector, category=category, context=context,
                   confidence="HIGH", severity="High", destructive=destructive)


def _patch_corpus(monkeypatch, corpus):
    class _FakeLoader:
        async def get_payloads(self, _vt, **_kw):
            return tuple(corpus)

    monkeypatch.setattr(base_mod, "get_payload_loader", lambda: _FakeLoader())


# ---- initialisation ----------------------------------------------------


def test_mutator_and_transforms_default_to_inert():
    t = _make_tester()
    assert t.waf_bypass_transforms == []
    assert t.mutator is not None


def test_transforms_are_read_and_normalised_from_config():
    t = _make_tester(waf_bypass_transforms=["url_encode", "  ", "random_case"])
    assert t.waf_bypass_transforms == ["url_encode", "random_case"]


def test_injected_mutator_is_used():
    from web_security_scanner.core.payload_mutator import PayloadMutator

    sentinel = PayloadMutator()
    assert _make_tester(mutator=sentinel).mutator is sentinel


# ---- _apply_runtime_mutations via load_payload_vectors ----------------


async def test_no_transforms_leaves_vectors_untouched(monkeypatch):
    _patch_corpus(monkeypatch, [_sig("<script>alert(1)</script>")])
    vectors = await _make_tester(max_payloads=10).load_payload_vectors("xss")
    assert vectors == ["<script>alert(1)</script>"]


async def test_url_encode_transform_rewrites_every_vector(monkeypatch):
    _patch_corpus(monkeypatch, [_sig("<script>alert(1)</script>"), _sig("<img src=x>")])
    t = _make_tester(max_payloads=10, waf_bypass_transforms=["url_encode"])
    assert await t.load_payload_vectors("xss") == [
        "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "%3Cimg%20src%3Dx%3E",
    ]


async def test_double_url_encode_transform_rewrites_every_vector(monkeypatch):
    _patch_corpus(monkeypatch, [_sig("<x>")])
    t = _make_tester(max_payloads=10, waf_bypass_transforms=["double_url_encode"])
    assert await t.load_payload_vectors("xss") == ["%253Cx%253E"]


async def test_transform_chain_is_applied_in_order(monkeypatch):
    _patch_corpus(monkeypatch, [_sig("A<b>")])
    t = _make_tester(max_payloads=10, waf_bypass_transforms=["html_entity", "url_encode"])
    # html_entity: "A<b>" -> "&#65;&#60;&#98;&#62;", then url_encode
    assert await t.load_payload_vectors("xss") == [
        "%26%2365%3B%26%2360%3B%26%2398%3B%26%2362%3B"
    ]


async def test_unknown_transform_warns_once_and_keeps_original(monkeypatch, caplog):
    _patch_corpus(monkeypatch, [_sig("<script>"), _sig("<img>")])
    t = _make_tester(max_payloads=10, waf_bypass_transforms=["url_encode", "does_not_exist"])
    with caplog.at_level(logging.WARNING):
        vectors = await t.load_payload_vectors("xss")
    # unknown name dropped, known one still applied
    assert vectors == ["%3Cscript%3E", "%3Cimg%3E"]
    warnings = [r for r in caplog.records if "does_not_exist" in r.getMessage()]
    assert len(warnings) == 1


async def test_destructive_vectors_are_not_mutated_without_allow(monkeypatch):
    _patch_corpus(monkeypatch, [
        _sig("'; DROP TABLE users--", category="sql_injection", destructive=True),
        _sig("' OR '1'='1", category="sql_injection"),
    ])
    t = _make_tester(max_payloads=10, waf_bypass_transforms=["url_encode"])
    vectors = await t.load_payload_vectors("sql_injection")
    # destructive one stays raw so filter_payloads' string gate still catches it
    assert "'; DROP TABLE users--" in vectors
    assert "%27%20OR%20%271%27%3D%271" in vectors
    assert t.filter_payloads(vectors) == ["%27%20OR%20%271%27%3D%271"]


async def test_destructive_vectors_are_mutated_when_allowed(monkeypatch):
    _patch_corpus(monkeypatch, [
        _sig("'; DROP TABLE users--", category="sql_injection", destructive=True),
    ])
    t = _make_tester(
        max_payloads=10, allow_destructive=True, waf_bypass_transforms=["url_encode"],
    )
    assert await t.load_payload_vectors("sql_injection") == [
        "%27%3B%20DROP%20TABLE%20users--"
    ]


# ---- end-to-end: a tester actually fires the transformed vectors ------


async def test_xss_tester_executes_transformed_vectors(monkeypatch):
    _patch_corpus(monkeypatch, [_sig("<script>alert(1)</script>", context="html_body")])
    seen: list[str] = []

    def responder(method, url, kwargs):
        seen.append(url)
        return {"text": "<html>ok</html>", "headers": {"Content-Type": "text/html"}}

    em = ScanEventEmitter()
    tester = XSSTester(MockScanner(responder), em,
                       {"payload_delay": 0, "max_payloads": 5,
                        "waf_bypass_transforms": ["url_encode"]})
    await tester.run_test("http://target/page?q=1")

    # the tester loaded and fired the mutated vector, not the raw one
    assert tester.payloads == ["%3Cscript%3Ealert%281%29%3C%2Fscript%3E"]
    # inject_param percent-encodes the (already url-encoded) vector again on the wire
    assert seen and all("%253Cscript%253E" in u for u in seen)
