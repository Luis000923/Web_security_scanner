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
