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


# --------------------------------------------------------------------------- #
# Standalone Path-Traversal / Command-Injection seeds
# --------------------------------------------------------------------------- #

def _suspected_class(sample) -> str:
    for line in sample.user.splitlines():
        if line.startswith("Suspected class:"):
            return line.split(":", 1)[1].strip()
    return "?"


def test_standalone_seeds_cover_pathtraver_and_cmdi():
    seeds = dg._standalone_triage_seeds()
    by_class = {}
    for s in seeds:
        by_class.setdefault(s["vclass"], []).append(s)
    assert {"pathtraver", "cmdi"} <= set(by_class)
    for vclass in ("pathtraver", "cmdi"):
        assert len(by_class[vclass]) >= 8
        for s in by_class[vclass]:
            # same shape as _triage_seeds() output
            assert {"vclass", "payload", "context", "vector", "apriori",
                    "scanner_conf", "base_latency_ms", "tester_id"} <= set(s)
            assert s["standalone_seed"] is True
    payloads = " ".join(s["payload"] for s in by_class["pathtraver"])
    assert "../" in payloads and "%2f" in payloads and "%00" in payloads
    assert "/etc/passwd" in payloads              # absolute path
    cmd_payloads = [s["payload"] for s in by_class["cmdi"]]
    assert "; id" in cmd_payloads and "`id`" in cmd_payloads
    assert any("%0a" in p for p in cmd_payloads)  # newline injection


def test_every_class_has_a_scenario_in_all_three_verdicts():
    for vclass in ("pathtraver", "cmdi"):
        buckets = {
            v: [sc.name for sc in dg._SCENARIOS
                if sc.verdict == v and dg._scenario_applies(sc, vclass)]
            for v in dg._VERDICTS
        }
        for v, names in buckets.items():
            assert names, f"{vclass} has no {v} scenario"


def test_synthesis_from_standalone_seeds_only_is_balanced_and_consistent():
    seeds = dg._standalone_triage_seeds()
    out = list(dg.synthesize_triage_samples(seeds, multiplier=40, seed=7))
    assert len(out) >= 400

    verdicts = {}
    cls_verdict = {}
    for s in out:
        verdicts[s.meta["label"]] = verdicts.get(s.meta["label"], 0) + 1
        key = (s.meta["suspected_class"], s.meta["label"])
        cls_verdict[key] = cls_verdict.get(key, 0) + 1

    assert set(verdicts) == {"TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"}
    lo, hi = min(verdicts.values()), max(verdicts.values())
    assert hi - lo <= 2                                  # driven to balance

    # both new classes get non-trivial coverage in every verdict
    for vclass in ("pathtraver", "cmdi"):
        for v in dg._VERDICTS:
            assert cls_verdict.get((vclass, v), 0) >= 5, (vclass, v)

    # labels never contradict the shared assessor
    for s in out:
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

    # the mocked bodies carry the concrete disclosure / command-output evidence
    by_scen = {}
    for s in out:
        by_scen.setdefault(s.meta["scenario"], s)
    assert "root:" in by_scen["path_traversal_file_read"].user
    assert json.loads(
        by_scen["path_traversal_file_read"].assistant)["verdict"] == "TRUE_POSITIVE"
    cmd_out = by_scen["cmd_injection_output"].user
    assert "uid=" in cmd_out or "Windows IP Configuration" in cmd_out


def test_cli_injects_standalone_classes_when_telemetry_lacks_them(tmp_path):
    # telemetry has ONLY sqli + xss rows (the real-world situation)
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
        "--split", "0.9", "--synthetic-multiplier", "30",
        "--report", str(tmp_path / "m.json"),
    ])
    assert rc == 0
    manifest = json.loads((tmp_path / "m.json").read_text())
    syn = manifest["tasks"][0]["synthetic"]
    assert syn["telemetry_seed_classes"] == {"xss": 1, "sqli": 1}
    assert syn["seed_classes"].get("pathtraver", 0) >= 8
    assert syn["seed_classes"].get("cmdi", 0) >= 8
    assert syn["standalone_seeds"] >= 16
    assert syn["suspected_class_counts"].get("pathtraver", 0) > 0
    assert syn["suspected_class_counts"].get("cmdi", 0) > 0

    recs = [json.loads(x) for x in
            (tmp_path / "triage.train.jsonl").read_text().splitlines()
            + (tmp_path / "triage.val.jsonl").read_text().splitlines()]
    classes = {_suspected_class(dg.Sample("", r["input"], "")) for r in recs}
    assert {"pathtraver", "cmdi"} <= classes

    ins_train = {json.loads(x)["input"]
                 for x in (tmp_path / "triage.train.jsonl").read_text().splitlines()}
    ins_val = {json.loads(x)["input"]
               for x in (tmp_path / "triage.val.jsonl").read_text().splitlines()}
    assert ins_train.isdisjoint(ins_val)             # split stays disjoint


def test_cli_no_standalone_seeds_flag_opts_out(tmp_path):
    tele = tmp_path / "telemetry_run.jsonl"
    tele.write_text(json.dumps(
        _native_row(url="https://t/BenchmarkTest00001?name=%3Cscript%3E",
                    payload="<script>alert(1)</script>")))
    csv = tmp_path / "expectedresults-1.2.csv"
    csv.write_text("# name, category, real, cwe\nBenchmarkTest00001,xss,true,79\n")
    rc = dg.main([
        "--telemetry", str(tele), "--benchmark-csv", str(csv),
        "--task", "triage", "--format", "alpaca", "--out", str(tmp_path / "t.jsonl"),
        "--split", "0.9", "--synthetic-multiplier", "20", "--no-standalone-seeds",
        "--report", str(tmp_path / "m.json"),
    ])
    assert rc == 0
    syn = json.loads((tmp_path / "m.json").read_text())["tasks"][0]["synthetic"]
    assert "pathtraver" not in syn["seed_classes"]
    assert "cmdi" not in syn["seed_classes"]
    assert syn["standalone_seeds"] == 0


# --------------------------------------------------------------------------- #
# Redirect-parameter false positives must not become TRUE_POSITIVE weak labels
# --------------------------------------------------------------------------- #

def _weak_labels_for(param: str, tmp_path, name: str) -> list[str]:
    """Weak-label a boolean-based probe whose only signal is a response change.

    Three sibling rows pin the run baseline near 0.1 s so the probe below sits
    *outside* jitter without being a timing oracle: a-priori HIGH + an
    off-baseline latency, no body evidence — the exact profile that used to be
    weak-labelled TRUE_POSITIVE on a ``next=`` parameter.
    """
    tele = tmp_path / f"telemetry_{name}.jsonl"
    rows = [
        _native_row(request_index=i, tester_id="SQLInjectionTester",
                    context="boolean_based", param="q", decision=False,
                    confidence_final="LOW", confidence_apriori="LOW",
                    url=f"https://t/search?q=probe{i}", elapsed_time=0.1)
        for i in range(3)
    ]
    rows.append(_native_row(
        request_index=9, tester_id="SQLInjectionTester", context="boolean_based",
        url=f"https://t/accounts/login/?{param}=%27%20OR%20%271%27%3D%271",
        param=param, confidence_apriori="HIGH", confidence_final="HIGH",
        elapsed_time=0.5,
    ))
    tele.write_text("\n".join(json.dumps(r) for r in rows))
    out = tmp_path / f"triage_{name}.jsonl"
    assert dg.main([
        "--telemetry", str(tele), "--task", "triage", "--format", "alpaca",
        "--out", str(out), "--weak-labels", "--no-standalone-seeds",
    ]) == 0
    recs = [json.loads(x) for x in out.read_text().splitlines()]
    # The probe of interest is the only HIGH-a-priori sample.
    return [r["meta"]["label"] for r in recs
            if "\"apriori_confidence\": \"HIGH\"" in r["input"]]


def test_weak_label_on_redirect_param_is_a_false_positive(tmp_path):
    # `next` holds a URL the app validates: a differential with no body/timing
    # signal is a false positive, however confident the scanner was.
    assert _weak_labels_for("next", tmp_path, "next") == ["FALSE_POSITIVE"]


def test_weak_label_on_ordinary_param_keeps_the_scanner_verdict(tmp_path):
    assert _weak_labels_for("id", tmp_path, "id") == ["TRUE_POSITIVE"]


def test_redirect_param_role_is_visible_to_the_model(tmp_path):
    tele = tmp_path / "telemetry_role.jsonl"
    tele.write_text(json.dumps(_native_row(
        tester_id="SQLInjectionTester", url="https://t/login/?next=%27",
        param="next", confidence_final="HIGH",
    )))
    out = tmp_path / "triage_role.jsonl"
    assert dg.main([
        "--telemetry", str(tele), "--task", "triage", "--format", "alpaca",
        "--out", str(out), "--weak-labels", "--no-standalone-seeds",
    ]) == 0
    prompt = json.loads(out.read_text().splitlines()[0])["input"]
    # The parameter name itself stays anonymised; only its role is exposed.
    assert "redirect/flow-control destination" in prompt
    assert "Parameter: p" not in prompt or "next" not in prompt.split("Observed")[0]
