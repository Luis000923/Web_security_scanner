"""Phase 2 — ablation toggles / experiment feature flags.

Covers the payload-pipeline switches (``--no-interleave`` / ``--no-priority`` /
``--payload-order``), the two-stage-validation switch (``--no-runtime-confirm``),
the ``--target-list`` recon-skip bridge and ``--global-seed`` reproducibility.
"""

import json
import random

from conftest import MockScanner

from web_security_scanner.cli import _build_config, _build_parser, _load_target_list
from web_security_scanner.core.payload_loader import Payload
from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers import base_tester_async as base_mod
from web_security_scanner.modules.vulnerability_testers.base_tester_async import (
    VulnerabilityTester,
)
from web_security_scanner.modules.vulnerability_testers.sql_injection_async import (
    SQLInjectionTester,
)
from web_security_scanner.web_security_scanner_async import WebSecurityScanner


class _DummyTester(VulnerabilityTester):
    name = "dummy"
    description = "dummy"

    async def run_test(self, target_url, **kwargs):  # pragma: no cover - unused
        return None


def _make(**config):
    return _DummyTester(MockScanner(lambda *a, **k: {}), ScanEventEmitter(), config)


def _corpus(monkeypatch, corpus):
    class _FakeLoader:
        async def get_payloads(self, _vt, **_kw):
            return tuple(corpus)

    monkeypatch.setattr(base_mod, "get_payload_loader", lambda: _FakeLoader())


def _p(vector, *, context="generic", confidence="LOW", severity="Low"):
    return Payload(vector=vector, category="xss", context=context,
                   confidence=confidence, severity=severity)


# ---- defaults --------------------------------------------------------------


def test_toggles_default_to_production_behaviour():
    t = _make()
    assert t.interleave_payloads is True
    assert t.prioritize_payloads is True
    assert t.payload_order == "natural"
    assert t.runtime_confirm is True


# ---- --no-priority / --no-interleave -------------------------------------


async def test_priority_sort_on_by_default(monkeypatch):
    _corpus(monkeypatch, [_p("lo", confidence="LOW"), _p("hi", confidence="HIGH")])
    vs = await _make(max_payloads=10).load_payload_vectors("xss")
    assert vs == ["hi", "lo"]


async def test_no_priority_preserves_corpus_order(monkeypatch):
    _corpus(monkeypatch, [_p("lo", confidence="LOW"), _p("hi", confidence="HIGH")])
    vs = await _make(max_payloads=10, priority=False).load_payload_vectors("xss")
    assert vs == ["lo", "hi"]


async def test_no_interleave_keeps_context_blocks(monkeypatch):
    _corpus(monkeypatch, [
        _p("a1", context="a"), _p("a2", context="a"), _p("b1", context="b"),
    ])
    vs = await _make(max_payloads=10, priority=False,
                     interleave=False).load_payload_vectors("xss")
    assert vs == ["a1", "a2", "b1"]


# ---- --payload-order ----------------------------------------------------


async def test_payload_order_random_is_seed_reproducible(monkeypatch):
    _corpus(monkeypatch, [_p(f"v{i}") for i in range(8)])
    random.seed(1234)
    first = await _make(max_payloads=10, payload_order="random").load_payload_vectors("xss")
    random.seed(1234)
    second = await _make(max_payloads=10, payload_order="random").load_payload_vectors("xss")
    assert first == second
    assert sorted(first) == [f"v{i}" for i in range(8)]


async def test_payload_order_freq_leads_with_largest_context(monkeypatch):
    _corpus(monkeypatch, [
        _p("s1", context="small"),
        _p("b1", context="big"), _p("b2", context="big"), _p("b3", context="big"),
    ])
    vs = await _make(max_payloads=10, priority=False, interleave=False,
                     payload_order="freq").load_payload_vectors("xss")
    assert vs[:3] == ["b1", "b2", "b3"]
    assert vs[3] == "s1"


# ---- --no-runtime-confirm --------------------------------------------


def _sqli(config):
    def responder(_method, url, _kwargs):
        slow = any(s in url.lower() for s in ("sleep", "benchmark", "waitfor", "delay"))
        return {"status_code": 200, "text": "ok", "headers": {},
                "url": url, "elapsed": 9.0 if slow else 0.1}

    em = ScanEventEmitter()
    found: list = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **kw: found.append(kw["vulnerability"]))
    t = SQLInjectionTester(MockScanner(responder), em,
                           {"payload_delay": 0, "max_payloads": 40, **config})
    return t, found


async def test_sqli_time_based_confirms_by_default():
    t, found = _sqli({})
    await t.run_test("http://t/x?q=1")
    assert found and found[0]["confidence"] == "CONFIRMED"
    assert "verification=CONFIRMED" in found[0]["evidence"]


async def test_sqli_no_runtime_confirm_uses_apriori():
    t, found = _sqli({"runtime_confirm": False})
    await t.run_test("http://t/x?q=1")
    assert found
    assert found[0]["confidence"] != "CONFIRMED"
    assert "skipped(a-priori)" in found[0]["evidence"]


# ---- --target-list recon-skip bridge -------------------------------


def test_targets_from_list_folds_param_and_dedupes():
    out = WebSecurityScanner._targets_from_list([
        {"url": "http://x/a", "param": "id", "method": "GET"},
        {"url": "http://x/b", "method": "POST"},
        {"url": "http://x/a?id=9", "param": "id"},
        {"method": "GET"},  # no url -> dropped
    ])
    assert [t["url"] for t in out] == ["http://x/a?id=1", "http://x/b"]
    assert all(t["kwargs"] == {} for t in out)


def test_targets_from_list_builds_advanced_vector_kwargs():
    out = WebSecurityScanner._targets_from_list([
        {"url": "http://x/api", "json": {"user": {"name": "a"}}},
        {"url": "http://x/f", "vector": "formparam", "param": "q"},
        {"url": "http://x/h", "vector": "header", "param": "X-Forwarded-For"},
        {"url": "http://x/c", "cookies": {"sid": "abc"}},
    ])
    assert out[0]["kwargs"]["form"]["enctype"] == "json"
    assert out[0]["kwargs"]["form"]["fields"] == {"user": {"name": "a"}}
    assert out[1]["kwargs"]["form"]["enctype"] == "form"
    assert out[2]["kwargs"]["inject_headers"] == ["X-Forwarded-For"]
    assert out[3]["kwargs"]["inject_cookies"] == {"sid": "abc"}


def test_load_target_list_roundtrip(tmp_path):
    f = tmp_path / "targets.json"
    f.write_text(json.dumps([{"url": "http://x/a", "param": "q"}, {"url": "http://x/b"}]))
    assert _load_target_list(str(f)) == [
        {"url": "http://x/a", "param": "q", "method": "GET"},
        {"url": "http://x/b", "param": None, "method": "GET"},
    ]


def test_load_target_list_rejects_bad_shape(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"url": "http://x"}))
    try:
        _load_target_list(str(f))
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for non-array target-list")


# ---- CLI wiring ------------------------------------------------------


def test_cli_flags_wire_into_config():
    args = _build_parser().parse_args([
        "scan", "http://x/", "--telemetry-dir", "/tmp/t", "--no-interleave",
        "--no-priority", "--payload-order", "freq", "--no-runtime-confirm",
        "--global-seed", "7",
    ])
    cfg = _build_config(args)
    assert cfg["testers"]["interleave"] is False
    assert cfg["testers"]["priority"] is False
    assert cfg["testers"]["payload_order"] == "freq"
    assert cfg["testers"]["runtime_confirm"] is False
    assert cfg["telemetry"] == {"enabled": True, "dir": "/tmp/t", "run_id": "seed7"}
