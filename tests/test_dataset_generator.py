"""Curation-pipeline tests for ai_module.dataset_generator."""
from __future__ import annotations

import json

from ai_module import dataset_generator as dg


def _native_row(**over):
    row = {
        "run_id": "r1", "timestamp": "2026-09-01T10:00:00Z", "request_index": 1,
        "tester_id": "XSSTester", "payload_id": "p1", "context": "html_text",
        "confidence_apriori": "MEDIUM", "url": "https://t/BenchmarkTest00001?name=x",
        "method": "GET", "param": "name", "vector": "getparam", "elapsed_time": 0.1,
        "decision": True, "confidence_final": "HIGH",
    }
    row.update(over)
    return row


def test_classify_noise_flags_transport_errors_but_keeps_clean_native_rows():
    assert dg.classify_noise(_native_row()) is None
    assert dg.classify_noise(_native_row(error="Connection reset by peer")) == "network_error"
    assert dg.classify_noise(_native_row(url="")) == "missing_url"
    assert dg.classify_noise(_native_row(elapsed_time=999.0)) == "implausible_latency"
    assert dg.classify_noise(_native_row(status_code=502, decision=False)) == "server_error"
    assert dg.classify_noise(_native_row(truncated=True, response_body="")) == "truncated_empty"


def test_clean_rows_drops_noise_and_counts_reasons():
    rows = [_native_row(), _native_row(is_timeout=True), {"not": "a probe"}]
    kept, stats = dg.clean_rows(rows)
    assert len(kept) == 1
    assert stats["noise:timeout"] == 1
    assert stats["skipped:not_a_probe"] == 1


def test_normalize_body_truncates_to_reflection_window():
    payload = "xss_ab12cd"
    body = ("A" * 5000) + f"<div>{payload}</div>" + ("B" * 5000)
    out = dg.normalize_body(body, payload, max_bytes=512)
    assert payload in out
    assert len(out) < len(body)
    assert out.startswith("…") and out.endswith("…")


def test_normalize_body_passes_short_bodies_through():
    assert dg.normalize_body("<p>hi</p>", "hi") == "<p>hi</p>"


def test_normalize_body_rejects_binary():
    assert "binary" in dg.normalize_body("\x00\x01\x02\xff" * 50, "")


def test_dedup_collapses_identical_samples():
    s1 = dg.Sample("sys", "u", "a", meta={"_dedup": "k"})
    s2 = dg.Sample("sys", "u", "a", meta={"_dedup": "k"})
    s3 = dg.Sample("sys", "u2", "a2", meta={"_dedup": "j"})
    out, removed = dg.dedup([s1, s2, s3])
    assert len(out) == 2 and removed == 1


def test_balance_classes_enforces_ratio():
    samples = (
        [dg.Sample("s", "u", "a", meta={"label": "TRUE_POSITIVE"}) for _ in range(10)]
        + [dg.Sample("s", "u", "a", meta={"label": "FALSE_POSITIVE"}) for _ in range(3)]
    )
    out, before = dg.balance_classes(samples, ratio=1.0, seed=0)
    counts = {}
    for s in out:
        counts[s.meta["label"]] = counts.get(s.meta["label"], 0) + 1
    assert counts == {"TRUE_POSITIVE": 3, "FALSE_POSITIVE": 3}
    assert before == {"TRUE_POSITIVE": 10, "FALSE_POSITIVE": 3}


def test_write_split_is_stratified(tmp_path):
    samples = (
        [dg.Sample("s", f"u{i}", "a", meta={"label": "TRUE_POSITIVE"}) for i in range(10)]
        + [dg.Sample("s", f"v{i}", "a", meta={"label": "FALSE_POSITIVE"}) for i in range(10)]
    )
    sizes = dg.write_split(samples, tmp_path / "d.jsonl", "alpaca", 0.8, seed=1)
    assert sizes == {"train": 16, "val": 4}
    val = [json.loads(x) for x in (tmp_path / "d.val.jsonl").read_text().splitlines()]
    labels = {r["meta"]["label"] for r in val}
    assert labels == {"TRUE_POSITIVE", "FALSE_POSITIVE"}


_SEEDS = [
    {"vclass": "xss", "payload": "<script>alert('WSSc4n4ry77')</script>",
     "context": "html_text", "vector": "getparam", "apriori": "MEDIUM",
     "scanner_conf": "HIGH", "base_latency_ms": 20.0, "tester_id": "XSSTester"},
    {"vclass": "sqli", "payload": "' OR '1'='1", "context": "boolean_blind",
     "vector": "getparam", "apriori": "MEDIUM", "scanner_conf": "MEDIUM",
     "base_latency_ms": 18.0, "tester_id": "SQLInjectionTester"},
    {"vclass": "pathtraver", "payload": "../../../../etc/passwd",
     "context": "file_read", "vector": "getparam", "apriori": "MEDIUM",
     "scanner_conf": "MEDIUM", "base_latency_ms": 19.0,
     "tester_id": "PathTraversalTester"},
]


def test_synthetic_triage_is_balanced_across_three_classes():
    out = list(dg.synthesize_triage_samples(_SEEDS, multiplier=40, seed=7))
    assert len(out) >= len(_SEEDS) * 30
    counts = {}
    for s in out:
        counts[s.meta["label"]] = counts.get(s.meta["label"], 0) + 1
    assert set(counts) == {"TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"}
    lo, hi = min(counts.values()), max(counts.values())
    assert hi - lo <= 2                      # driven to near-perfect balance
    assert all(s.meta["label_source"] == "synthetic" for s in out)
    assert all(s.meta["synthetic"] is True for s in out)


def test_synthetic_labels_are_consistent_with_the_shared_assessor():
    for s in dg.synthesize_triage_samples(_SEEDS, multiplier=30, seed=11):
        ev = s.meta["_evidence"]
        a = dg._assess_evidence(
            ev, context=ev.get("injection_context", ""),
            vclass=s.meta["suspected_class"],
        )
        verdict = json.loads(s.assistant)["verdict"]
        if verdict == "TRUE_POSITIVE":
            assert a["discriminating"], s.meta["scenario"]
        elif verdict == "FALSE_POSITIVE":
            assert not a["discriminating"], s.meta["scenario"]
        else:
            assert not a["discriminating"] and a["within_noise"], s.meta["scenario"]


def test_synthetic_reasoning_cites_the_mocked_body_evidence():
    by_scen = {}
    for s in dg.synthesize_triage_samples(_SEEDS, multiplier=60, seed=3):
        by_scen.setdefault(s.meta["scenario"], s)

    err = by_scen["sql_error_disclosure"]
    assert "Response body excerpt:" in err.user
    reasoning = json.loads(err.assistant)["reasoning"].lower()
    assert "error" in reasoning and ("sql" in reasoning or "parser" in reasoning)

    esc = json.loads(by_scen["xss_output_encoded"].assistant)["reasoning"].lower()
    assert "encod" in esc or "inert" in esc

    waf = json.loads(by_scen["waf_block_page"].assistant)["reasoning"].lower()
    assert "waf" in waf or "block" in waf

    tp_file = by_scen["path_traversal_file_read"]
    assert "root:" in tp_file.user
    assert json.loads(tp_file.assistant)["verdict"] == "TRUE_POSITIVE"


def test_synthetic_bodies_never_leak_the_real_endpoint():
    for s in dg.synthesize_triage_samples(_SEEDS, multiplier=20, seed=5):
        assert "/app/target_endpoint/" in s.user
        assert "BenchmarkTest" not in s.user and "/benchmark/" not in s.user


def test_cli_synthetic_multiplier_amplifies_triage(tmp_path):
    tele = tmp_path / "telemetry_run.jsonl"
    tele.write_text(
        "\n".join(
            json.dumps(r) for r in [
                _native_row(url="https://t/BenchmarkTest00001?name=%3Cscript%3E",
                            payload="<script>alert(1)</script>"),
                _native_row(request_index=2, tester_id="SQLInjectionTester",
                            url="https://t/BenchmarkTest00002?q=%27",
                            payload="' OR '1'='1", context="boolean_blind",
                            confidence_final="MEDIUM"),
            ]
        )
    )
    csv = tmp_path / "expectedresults-1.2.csv"
    csv.write_text(
        "# name, category, real, cwe\n"
        "BenchmarkTest00001,xss,true,79\n"
        "BenchmarkTest00002,sqli,false,89\n"
    )
    out = tmp_path / "triage.jsonl"
    rc = dg.main([
        "--telemetry", str(tele), "--benchmark-csv", str(csv),
        "--task", "triage", "--format", "alpaca", "--out", str(out),
        "--split", "0.9", "--synthetic-multiplier", "25",
        "--report", str(tmp_path / "m.json"),
    ])
    assert rc == 0
    manifest = json.loads((tmp_path / "m.json").read_text())
    tri = manifest["tasks"][0]
    assert tri["synthetic"]["built"] >= 40
    assert set(tri["synthetic"]["class_counts"]) == {
        "TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"}
    train = (tmp_path / "triage.train.jsonl").read_text().splitlines()
    val = (tmp_path / "triage.val.jsonl").read_text().splitlines()
    assert len(train) + len(val) == tri["split"]["train"] + tri["split"]["val"]
    ins_train = {json.loads(x)["input"] for x in train}
    ins_val = {json.loads(x)["input"] for x in val}
    assert ins_train.isdisjoint(ins_val)          # no train/val leakage


def test_end_to_end_triage_with_benchmark_oracle(tmp_path):
    tele = tmp_path / "telemetry_run.jsonl"
    tele.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                _native_row(url="https://t/BenchmarkTest00001?name=%3Cb%3E",
                            response_body="reflected <b> here"),
                _native_row(request_index=2, url="https://t/BenchmarkTest00002?name=y",
                            tester_id="XSSTester"),
                _native_row(request_index=3, error="SSL handshake failed"),
            ]
        )
    )
    csv = tmp_path / "expectedresults-1.2.csv"
    csv.write_text(
        "# name, category, real, cwe\n"
        "BenchmarkTest00001,xss,true,79\n"
        "BenchmarkTest00002,xss,false,79\n"
    )
    out = tmp_path / "triage.jsonl"
    rc = dg.main([
        "--telemetry", str(tele), "--benchmark-csv", str(csv),
        "--task", "triage", "--format", "alpaca", "--out", str(out),
        "--report", str(tmp_path / "manifest.json"),
    ])
    assert rc == 0
    recs = [json.loads(x) for x in out.read_text().splitlines()]
    labels = sorted(r["meta"]["label"] for r in recs)
    assert labels == ["FALSE_POSITIVE", "TRUE_POSITIVE"]
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["clean_stats"]["noise:network_error"] == 1
    assert manifest["cleaned_rows"] == 2
