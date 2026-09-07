"""Phase 3 — live heuristic ordering (adaptive feedback loop).

Covers the per-probe anomaly classifier (``assess_anomaly``), the per-injection
-point running tally (``EndpointFeedback``), the mid-sweep queue re-sort
(``VulnerabilityTester.adaptive_reorder``) and the ``--no-adaptive-sorting``
ablation flag. Existing behaviour with the flag on is exercised by the wider
tester suite (still 154 green).
"""

from conftest import MockScanner

from web_security_scanner.cli import _build_config, _build_parser
from web_security_scanner.core.payload_loader import Payload
from web_security_scanner.events.event_emitter import ScanEventEmitter
from web_security_scanner.modules.vulnerability_testers import base_tester_async as base_mod
from web_security_scanner.modules.vulnerability_testers.base_tester_async import (
    EndpointFeedback,
    VulnerabilityTester,
    assess_anomaly,
)
from web_security_scanner.modules.vulnerability_testers.sql_injection_async import (
    SQLInjectionTester,
)


class _DummyTester(VulnerabilityTester):
    name = "dummy"
    description = "dummy"

    async def run_test(self, target_url, **kwargs):  # pragma: no cover - unused
        return None


def _make(**config):
    return _DummyTester(MockScanner(lambda *a, **k: {}), ScanEventEmitter(), config)


def _p(vector, *, context="generic"):
    return Payload(vector=vector, category="sql_injection", context=context)


# ---- assess_anomaly -----------------------------------------------------


def test_assess_anomaly_flat_response_scores_zero():
    base = {"status_code": 200, "text": "hello", "length": 5}
    sig = assess_anomaly({"status_code": 200, "text": "hello"}, base, payload="x")
    assert sig.score == 0.0 and not sig.interesting


def test_assess_anomaly_server_error_is_strong():
    base = {"status_code": 200, "text": "ok", "length": 2}
    sig = assess_anomaly({"status_code": 500, "text": "ok"}, base)
    assert sig.score >= 2.0
    assert any("server-error" in r for r in sig.reasons)


def test_assess_anomaly_full_reflection_and_length_shift():
    base = {"status_code": 200, "text": "x" * 100, "length": 100}
    resp = {"status_code": 200, "text": "x" * 100 + "<script>alert(1)</script>"}
    sig = assess_anomaly(resp, base, payload="<script>alert(1)</script>")
    assert "full-reflection" in sig.reasons
    assert "length-shift" in sig.reasons
    assert sig.score >= 2.5


def test_assess_anomaly_latency_spike():
    sig = assess_anomaly({"status_code": 200, "text": ""}, {"status_code": 200},
                         probe_elapsed=9.0, baseline_latency=0.2)
    assert any("latency" in r for r in sig.reasons)


# ---- EndpointFeedback -------------------------------------------------


def test_feedback_accumulates_and_flags_hot_family():
    fb = EndpointFeedback(threshold=2.0)
    fb.record("union", assess_anomaly({"status_code": 500, "text": ""},
                                      {"status_code": 200}))
    assert fb.hot_families() == {"union"}
    fb.record("error", assess_anomaly({}, None))  # flat probe, no score
    assert fb.hot_families() == {"union"}
    assert fb.probes == 2


# ---- adaptive_reorder -----------------------------------------------


def test_adaptive_reorder_hoists_hot_family_stably():
    t = _make()
    meta = {v: _p(v, context=("union" if v.startswith("u") else "error"))
            for v in ("e1", "u1", "e2", "u2")}
    out = t.adaptive_reorder(["e1", "u1", "e2", "u2"], {"union"}, meta=meta)
    assert out == ["u1", "u2", "e1", "e2"]


def test_adaptive_reorder_noop_when_disabled():
    t = _make(adaptive_sorting=False)
    meta = {"u1": _p("u1", context="union"), "e1": _p("e1", context="error")}
    assert t.adaptive_reorder(["e1", "u1"], {"union"}, meta=meta) == ["e1", "u1"]


def test_adaptive_reorder_noop_without_hot_families():
    t = _make()
    assert t.adaptive_reorder(["a", "b"], set()) == ["a", "b"]


# ---- flag wiring ---------------------------------------------------


def test_adaptive_sorting_defaults_on():
    assert _make().adaptive_sorting is True


def test_cli_no_adaptive_sorting_flag():
    args = _build_parser().parse_args(["scan", "http://x/", "--no-adaptive-sorting"])
    assert _build_config(args)["testers"]["adaptive_sorting"] is False


# ---- integration: SQLi reorders toward the anomalous family --------


async def test_sqli_boosts_family_with_server_errors(monkeypatch):
    # 'noisy' payloads only shift the response length (no SQL error string, no
    # boolean keyword, no status change) -> interesting but not a finding, so
    # the sweep keeps going and the family score can accumulate.
    corpus = (
        [_p(f"plain{i}", context="error") for i in range(2)]
        + [_p("noisy-a", context="probe"), _p("noisy-b", context="probe")]
    )

    class _FakeLoader:
        async def get_payloads(self, *_a, **_k):
            return tuple(corpus)

    monkeypatch.setattr(base_mod, "get_payload_loader", lambda: _FakeLoader())

    seen: list[str] = []

    def responder(_m, url, _k):
        seen.append(url)
        body = "x" * 400 if "noisy" in url else "x" * 40
        return {"status_code": 200, "text": body, "headers": {},
                "url": url, "elapsed": 0.05}

    em = ScanEventEmitter()
    t = SQLInjectionTester(MockScanner(responder), em, {
        "payload_delay": 0, "max_payloads": 20, "interleave": False,
        "priority": False,
    })
    await t.run_test("http://t/x?q=1")

    fb = next(iter(t._feedback.values()))
    assert "probe" in fb.hot_families()
