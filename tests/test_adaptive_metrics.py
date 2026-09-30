"""Tests for the WAF/LB-aware anomaly scoring refinements, EndpointFeedback's
concept-drift decay, VulnerabilityTester.adaptive_metrics_snapshot, and the
core.adaptive_metrics IEEE export module.
"""

import json

from conftest import MockScanner

from web_security_scanner.core.adaptive_metrics import (
    EvasionCounters,
    aggregate_ieee_metrics,
    export_ieee_metrics_json,
)
from web_security_scanner.events.event_emitter import ScanEventEmitter
from web_security_scanner.modules.vulnerability_testers.base_tester_async import (
    EndpointFeedback,
    VulnerabilityTester,
    assess_anomaly,
)


class _DummyTester(VulnerabilityTester):
    name = "dummy"
    description = "dummy"

    async def run_test(self, target_url, **kwargs):  # pragma: no cover - unused
        return None


def _make(**config):
    return _DummyTester(MockScanner(lambda *a, **k: {}), ScanEventEmitter(), config)


# ---- assess_anomaly: infra-noise / waf-block / robust latency -------------


def test_502_is_infra_noise_not_a_full_server_error():
    sig = assess_anomaly(
        {"status_code": 502, "text": ""}, {"status_code": 200, "text": "", "length": 0},
    )
    assert any(r.startswith("infra-noise:502") for r in sig.reasons)
    # 0.5 (infra-noise) + 1.0 (length-shift: status flip alone counts as a
    # differing response in response_differs_significantly) = 1.5, well below
    # the 2.0 a genuine 500 server-error scores on its own.
    assert sig.score == 1.5
    assert sig.throttled is False


def test_504_is_also_infra_noise():
    sig = assess_anomaly(
        {"status_code": 504, "text": ""}, {"status_code": 200, "text": "", "length": 0},
    )
    assert any(r.startswith("infra-noise:504") for r in sig.reasons)
    assert sig.score == 1.5


def test_infra_noise_weight_is_lower_than_server_error_weight():
    baseline = {"status_code": 200, "text": "ok", "length": 2}
    infra = assess_anomaly({"status_code": 502, "text": "ok"}, baseline)
    server_error = assess_anomaly({"status_code": 500, "text": "ok"}, baseline)
    assert infra.score < server_error.score


def test_infra_noise_does_not_fire_when_status_matches_a_flaky_baseline():
    # A target whose *baseline itself* was captured as 502 (already flaky)
    # must not keep re-scoring "infra-noise" on every probe that also comes
    # back 502 -- only a *change* from baseline is a signal, same rule every
    # other status branch follows.
    sig = assess_anomaly(
        {"status_code": 502, "text": "x"}, {"status_code": 502, "text": "x", "length": 1},
    )
    assert sig.score == 0.0
    assert sig.reasons == ()


def test_500_still_scores_as_full_server_error_unaffected_by_infra_noise_change():
    sig = assess_anomaly(
        {"status_code": 500, "text": "ok"},
        {"status_code": 200, "text": "ok", "length": 2},
    )
    assert any(r.startswith("server-error:500") for r in sig.reasons)
    assert sig.score >= 2.0


def test_403_is_tagged_waf_block_not_generic_status():
    sig = assess_anomaly(
        {"status_code": 403, "text": ""}, {"status_code": 200, "text": "", "length": 0},
    )
    assert any(r.startswith("waf-block:403") for r in sig.reasons)
    assert not any(r.startswith("status:") for r in sig.reasons)
    # +1.0 waf-block, +1.0 length-shift (any status flip also counts as a
    # differing response in response_differs_significantly).
    assert sig.score == 2.0


def test_401_and_406_are_also_waf_block():
    for code in (401, 406):
        sig = assess_anomaly(
            {"status_code": code, "text": ""}, {"status_code": 200, "text": "", "length": 0},
        )
        assert any(r.startswith(f"waf-block:{code}") for r in sig.reasons)


def test_generic_status_change_unaffected():
    sig = assess_anomaly(
        {"status_code": 301, "text": ""}, {"status_code": 200, "text": "", "length": 0},
    )
    assert any(r.startswith("status:200->301") for r in sig.reasons)


def test_latency_uses_robust_upper_bound_when_provided():
    # 1.0s elapsed is below the crude 2*baseline+1 = 2.2s bar but above a
    # tighter robust bound of 0.5s -> only scores with the robust bound given.
    without_bound = assess_anomaly(
        {"status_code": 200, "text": ""}, {"status_code": 200},
        probe_elapsed=1.0, baseline_latency=0.6,
    )
    with_bound = assess_anomaly(
        {"status_code": 200, "text": ""}, {"status_code": 200},
        probe_elapsed=1.0, baseline_latency=0.6, latency_upper_bound=0.5,
    )
    assert not any("latency" in r for r in without_bound.reasons)
    assert any("latency" in r for r in with_bound.reasons)


def test_latency_robust_bound_suppresses_false_positive_from_crude_formula():
    # 1.5s elapsed WOULD trip the crude 2*0.2+1=1.4s bar, but the robust
    # window (learned wider variance mid-sweep) says up to 2.0s is normal.
    sig = assess_anomaly(
        {"status_code": 200, "text": ""}, {"status_code": 200},
        probe_elapsed=1.5, baseline_latency=0.2, latency_upper_bound=2.0,
    )
    assert not any("latency" in r for r in sig.reasons)


# ---- EndpointFeedback: decay + reason_tags ---------------------------------


def test_decay_default_is_byte_identical_to_cumulative_forever():
    fb = EndpointFeedback(threshold=100.0)  # threshold irrelevant here
    # each 500-vs-200 probe scores 3.0 (2.0 server-error + 1.0 length-shift)
    for _ in range(3):
        fb.record("union", assess_anomaly(
            {"status_code": 500, "text": ""}, {"status_code": 200, "text": "", "length": 0}))
    assert fb.scores["union"] == 9.0  # 3.0 + 3.0 + 3.0, no decay


def test_decay_below_one_discounts_older_evidence():
    fb = EndpointFeedback(threshold=100.0, decay=0.5)
    for _ in range(3):
        fb.record("union", assess_anomaly(
            {"status_code": 500, "text": ""}, {"status_code": 200, "text": "", "length": 0}))
    # 3.0 -> *0.5+3.0=4.5 -> *0.5+3.0=5.25, strictly less than the undecayed 9.0
    assert fb.scores["union"] == 5.25
    assert fb.scores["union"] < 9.0


def test_reason_tags_count_throttled_and_infra_noise_even_at_zero_score():
    fb = EndpointFeedback()
    fb.record("generic", assess_anomaly(
        {"status_code": 429, "text": ""}, {"status_code": 200, "text": "", "length": 0}))
    fb.record("generic", assess_anomaly(
        {"status_code": 502, "text": ""}, {"status_code": 200, "text": "", "length": 0}))
    assert fb.reason_tags.get("throttled") == 1
    assert fb.reason_tags.get("infra-noise") == 1
    assert fb.probes == 2
    assert fb.hot_families() == set()  # neither counts toward a boost


def test_decay_is_clamped_to_zero_one_range():
    assert EndpointFeedback(decay=5.0).decay == 1.0
    assert EndpointFeedback(decay=-1.0).decay == 0.0


# ---- VulnerabilityTester.adaptive_feedback_decay wiring --------------------


def test_tester_default_decay_is_one():
    t = _make()
    assert t.adaptive_feedback_decay == 1.0


def test_tester_reads_decay_from_config():
    t = _make(adaptive_feedback_decay=0.8)
    fb = t.feedback_for("http://x/?a=1")
    assert fb.decay == 0.8


def test_tester_invalid_decay_falls_back_to_one():
    t = _make(adaptive_feedback_decay="not-a-number")
    assert t.adaptive_feedback_decay == 1.0


# ---- adaptive_metrics_snapshot ---------------------------------------------


def test_snapshot_aggregates_across_points():
    t = _make()
    fb1 = t.feedback_for("http://x/?a=1")
    fb1.record("union", assess_anomaly(
        {"status_code": 500, "text": ""}, {"status_code": 200, "text": "", "length": 0}))
    fb2 = t.feedback_for("http://x/?b=1")
    fb2.record("generic", assess_anomaly(
        {"status_code": 429, "text": ""}, {"status_code": 200, "text": "", "length": 0}))

    snap = t.adaptive_metrics_snapshot()
    assert snap["tester"] == "_DummyTester"
    assert snap["points_tracked"] == 2
    assert snap["total_probes"] == 2
    assert snap["reason_counts"]["server-error"] == 1
    assert snap["reason_counts"]["throttled"] == 1


def test_snapshot_empty_tester_is_all_zero():
    t = _make()
    snap = t.adaptive_metrics_snapshot()
    assert snap == {
        "tester": "_DummyTester",
        "points_tracked": 0,
        "points_boosted": 0,
        "total_probes": 0,
        "reason_counts": {},
    }


# ---- core.adaptive_metrics: aggregation + export ---------------------------


def test_aggregate_ieee_metrics_sums_multiple_testers():
    snapshots = [
        {"tester": "XSSTester", "points_tracked": 5, "points_boosted": 1,
         "total_probes": 40, "reason_counts": {"full-reflection": 3, "waf-block": 2}},
        {"tester": "SQLInjectionTester", "points_tracked": 5, "points_boosted": 2,
         "total_probes": 60, "reason_counts": {"server-error": 4, "throttled": 5}},
    ]
    metrics = aggregate_ieee_metrics(snapshots, run_id="run-1")
    assert metrics.total_probes == 100
    assert metrics.points_tracked == 10
    assert metrics.points_boosted == 3
    assert metrics.reason_counts["waf-block"] == 2
    assert metrics.reason_counts["throttled"] == 5


def test_noise_suppression_rate_matches_definition():
    snapshots = [{
        "tester": "t", "points_tracked": 1, "points_boosted": 0, "total_probes": 10,
        "reason_counts": {"throttled": 3, "infra-noise": 1, "server-error": 2, "waf-block": 4},
    }]
    metrics = aggregate_ieee_metrics(snapshots)
    # noise = 3+1=4; signal_total = noise + server-error(2) + waf-block(4) = 10
    assert metrics.noise_suppression_rate() == 0.4


def test_waf_block_rate_and_hot_boost_rate():
    snapshots = [{
        "tester": "t", "points_tracked": 4, "points_boosted": 1, "total_probes": 20,
        "reason_counts": {"waf-block": 5},
    }]
    metrics = aggregate_ieee_metrics(snapshots)
    assert metrics.waf_block_rate() == 0.25
    assert metrics.hot_boost_rate() == 0.25


def test_evasion_effectiveness_full_and_none_and_negative():
    good = EvasionCounters(baseline_total=100, baseline_blocked=40,
                            mutated_total=100, mutated_blocked=0)
    assert good.effectiveness() == 1.0

    worse = EvasionCounters(baseline_total=100, baseline_blocked=10,
                             mutated_total=100, mutated_blocked=20)
    assert worse.effectiveness() == -1.0

    empty = EvasionCounters()
    assert empty.effectiveness() is None
    assert empty.baseline_block_rate() is None


def test_to_dict_is_json_serialisable_and_carries_the_scope_note():
    metrics = aggregate_ieee_metrics(
        [{"tester": "t", "points_tracked": 1, "points_boosted": 0,
          "total_probes": 1, "reason_counts": {}}],
        run_id="run-2",
        evasion=EvasionCounters(baseline_total=10, baseline_blocked=5,
                                 mutated_total=10, mutated_blocked=1),
    )
    d = metrics.to_dict()
    encoded = json.dumps(d)  # must not raise
    assert '"run_id": "run-2"' in encoded
    assert d["evasion"]["effectiveness"] == 0.8
    assert "NOT ground-truth precision" in d["note"]


def test_export_ieee_metrics_json_writes_a_readable_file(tmp_path):
    metrics = aggregate_ieee_metrics(
        [{"tester": "t", "points_tracked": 2, "points_boosted": 1,
          "total_probes": 8, "reason_counts": {"waf-block": 1}}],
        run_id="run-3",
    )
    out = export_ieee_metrics_json(metrics, tmp_path / "nested" / "adaptive_engine.json")
    assert out.exists()
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["run_id"] == "run-3"
    assert loaded["rates"]["waf_block_rate"] == 0.125
