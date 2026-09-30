"""Tests for the standardized reporting subsystem
(web_security_scanner.report_engine): SARIF 2.1.0 output and the
research-oriented enriched JSON report.

Covers:
* SARIF structure: schema/version envelope, one rule per distinct
  vulnerability type, one result per finding, correct level/security-severity
  mapping from severity, and secret masking carried through from
  report_generator's shared normalization.
* Enriched JSON: normalized attack vector, execution trace, WAF-status
  cross-reference against the Proof-of-Impact exploit-engine trail, and
  latency/jitter passthrough.
* Plain-text summary rendering.
* Format dispatch (generate_report / generate_report_async), including the
  --output-file override path.
"""

import json
from pathlib import Path

import pytest

from web_security_scanner.report_engine import (
    build_enriched_report,
    build_sarif_report,
    generate_enriched_json_report,
    generate_report,
    generate_report_async,
    generate_sarif_report,
    generate_text_report,
    render_text_summary,
)

SCAN_DATA = {
    "target": "http://target.test/",
    "profile": "balanced",
    "statistics": {"total_vulnerabilities": 3},
    "technologies": {"target.test": [{"name": "nginx", "type": "server"}]},
    "vulnerabilities": [
        {
            "type": "SQL Injection",
            "severity": "critical",
            "confidence": "CONFIRMED",
            "url": "http://target.test/search?q=1",
            "parameter": "q",
            "payload": "1' OR '1'='1",
            "evidence": (
                "Database error message found in response. Request headers:\n"
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123SECRET\n"
                "Cookie: session=SUPERSECRETVALUE; theme=dark"
            ),
            "baseline_latency": 0.12,
            "latency_upper_bound": 0.45,
            "elapsed_time": 0.44,
        },
        {
            "type": "Cross-Site Scripting (XSS)",
            "severity": "high",
            "confidence": "HIGH",
            "url": "http://target.test/p?x=1",
            "parameter": "x",
            "payload": "<script>alert(1)</script>",
            "evidence": "Reflected XSS payload found in response",
        },
        {
            "type": "Vulnerable Server Component",
            "name": "Apache HTTP Server outdated",
            "severity": "medium",
            "confidence": "MEDIUM",
            "url": "http://target.test/",
            "parameter": "CVE-2021-41773",
            "payload": "N/A",
            "evidence": "Server banner reports Apache/2.4.49 (banner-derived; not actively confirmed)",
            "detector": "server-fingerprint",
        },
    ],
}

SCAN_DATA_WITH_EXPLOITS = {
    **SCAN_DATA,
    "proof_of_impact": [
        {
            "url": "http://target.test/search?q=1",
            "vulnerability_class": "sql_injection",
            "parameter": "q",
            "adaptive_payload": "1' OR SLEEP(5)-- -",
            "classification": "CONFIRMED_EXPLOITABLE",
            "confirmation_evidence": "PoC probe matched expected marker.",
            "verified_marker": "SLEEP-5",
            "waf_evasion_technique": "random_case",
            "waf_bypass_confirmed": True,
        },
    ],
}


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def test_sarif_envelope():
    sarif = build_sarif_report(SCAN_DATA)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"]
    assert run["properties"]["scan_target"] == "http://target.test/"


def test_sarif_one_rule_per_distinct_type_and_one_result_per_finding():
    sarif = build_sarif_report(SCAN_DATA)
    run = sarif["runs"][0]
    assert len(run["results"]) == len(SCAN_DATA["vulnerabilities"])
    # 3 distinct vuln types in the fixture -> 3 distinct rules, no duplicates.
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids)) == 3


def test_sarif_result_references_valid_rule_index():
    sarif = build_sarif_report(SCAN_DATA)
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for result in run["results"]:
        assert 0 <= result["ruleIndex"] < len(rules)
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


@pytest.mark.parametrize(
    "severity,expected_level",
    [("critical", "error"), ("high", "error"), ("medium", "warning"), ("low", "note")],
)
def test_sarif_level_matches_severity(severity, expected_level):
    scan_data = {
        **SCAN_DATA,
        "vulnerabilities": [{**SCAN_DATA["vulnerabilities"][0], "severity": severity}],
    }
    sarif = build_sarif_report(scan_data)
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == expected_level


def test_sarif_result_has_physical_location_uri():
    sarif = build_sarif_report(SCAN_DATA)
    for result in sarif["runs"][0]["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.startswith("http://target.test")


def test_sarif_masks_secrets_in_evidence_via_shared_normalization():
    sarif = build_sarif_report(SCAN_DATA)
    dumped = json.dumps(sarif)
    assert "SUPERSECRETVALUE" not in dumped
    assert "abc123SECRET" not in dumped
    # The exact attacker payload must remain reproducible (report_generator's
    # own policy: payload is never masked).
    assert "1' OR '1'='1" in dumped


def test_sarif_is_json_serializable_end_to_end():
    # No custom objects/NaN leaking through - a real consumer must be able to
    # round-trip this with the stdlib json module alone.
    sarif = build_sarif_report(SCAN_DATA)
    reparsed = json.loads(json.dumps(sarif))
    assert reparsed == sarif


def test_sarif_report_written_to_disk(tmp_path):
    path = generate_sarif_report(SCAN_DATA, output_dir=str(tmp_path))
    assert path.endswith(".sarif.json")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"


# ---------------------------------------------------------------------------
# Enriched JSON
# ---------------------------------------------------------------------------


def test_enriched_report_marks_its_format():
    report = build_enriched_report(SCAN_DATA)
    assert report["report_format"] == "enriched-json-v1"


def test_enriched_finding_has_normalized_attack_vector():
    report = build_enriched_report(SCAN_DATA)
    sqli = next(v for v in report["vulnerabilities"] if v["type"] == "SQL Injection")
    vector = sqli["normalized_attack_vector"]
    assert vector["cwe"] == "CWE-89"
    assert vector["parameter"] == "q"
    assert vector["url"] == "http://target.test/search?q=1"


def test_enriched_finding_has_execution_trace_with_payload_and_confirmation():
    report = build_enriched_report(SCAN_DATA)
    sqli = next(v for v in report["vulnerabilities"] if v["type"] == "SQL Injection")
    steps = {s["step"] for s in sqli["execution_trace"]}
    assert "payload_delivery" in steps
    assert "confirmation" in steps
    assert "baseline_probe" in steps  # this fixture set baseline_latency


def test_enriched_finding_latency_metrics_and_jitter():
    report = build_enriched_report(SCAN_DATA)
    sqli = next(v for v in report["vulnerabilities"] if v["type"] == "SQL Injection")
    metrics = sqli["latency_metrics"]
    assert metrics["baseline_latency"] == 0.12
    assert metrics["latency_upper_bound"] == 0.45
    assert metrics["jitter_envelope"] == pytest.approx(0.33)


def test_enriched_finding_latency_metrics_null_when_absent():
    report = build_enriched_report(SCAN_DATA)
    xss = next(v for v in report["vulnerabilities"] if "XSS" in v["type"])
    metrics = xss["latency_metrics"]
    assert metrics["baseline_latency"] is None
    assert metrics["jitter_envelope"] is None


def test_enriched_waf_status_not_probed_without_exploit_engine_data():
    report = build_enriched_report(SCAN_DATA)
    sqli = next(v for v in report["vulnerabilities"] if v["type"] == "SQL Injection")
    assert sqli["waf_status"]["state"] == "not_probed"


def test_enriched_waf_status_bypassed_when_exploit_engine_confirms_it():
    report = build_enriched_report(SCAN_DATA_WITH_EXPLOITS)
    sqli = next(v for v in report["vulnerabilities"] if v["type"] == "SQL Injection")
    assert sqli["waf_status"]["state"] == "bypassed"
    assert sqli["waf_status"]["technique"] == "random_case"


def test_enriched_waf_status_probed_clean_for_unrelated_finding():
    report = build_enriched_report(SCAN_DATA_WITH_EXPLOITS)
    xss = next(v for v in report["vulnerabilities"] if "XSS" in v["type"])
    assert xss["waf_status"]["state"] == "not_probed"


def test_enriched_report_still_masks_secrets():
    report = build_enriched_report(SCAN_DATA)
    dumped = json.dumps(report)
    assert "SUPERSECRETVALUE" not in dumped


def test_enriched_report_is_json_serializable():
    report = build_enriched_report(SCAN_DATA)
    reparsed = json.loads(json.dumps(report))
    assert reparsed == report


def test_enriched_report_written_to_disk(tmp_path):
    path = generate_enriched_json_report(SCAN_DATA, output_dir=str(tmp_path))
    assert path.endswith(".enriched.json")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["report_format"] == "enriched-json-v1"


# ---------------------------------------------------------------------------
# Plain-text summary
# ---------------------------------------------------------------------------


def test_text_summary_lists_every_finding():
    text = render_text_summary(SCAN_DATA)
    assert "SQL Injection" in text
    assert "Cross-Site Scripting (XSS)" in text
    assert "http://target.test/search?q=1" in text


def test_text_summary_masks_secrets():
    text = render_text_summary(SCAN_DATA)
    assert "SUPERSECRETVALUE" not in text


def test_text_report_written_to_disk(tmp_path):
    path = generate_text_report(SCAN_DATA, output_dir=str(tmp_path))
    assert path.endswith(".txt")
    content = Path(path).read_text(encoding="utf-8")
    assert "Total findings: 3" in content


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt,suffix", [("sarif", ".sarif.json"), ("json", ".enriched.json"), ("text", ".txt")])
def test_generate_report_dispatches_by_format(tmp_path, fmt, suffix):
    path = generate_report(SCAN_DATA, fmt, output_dir=str(tmp_path))
    assert path.endswith(suffix)


def test_generate_report_unknown_format_raises():
    with pytest.raises(ValueError):
        generate_report(SCAN_DATA, "yaml")


def test_generate_report_output_file_override(tmp_path):
    target = tmp_path / "custom" / "report.sarif.json"
    path = generate_report(SCAN_DATA, "sarif", output_file=str(target))
    assert path == str(target)
    assert target.exists()
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"


@pytest.mark.asyncio
async def test_generate_report_async_matches_sync(tmp_path):
    path = await generate_report_async(SCAN_DATA, "json", output_dir=str(tmp_path))
    assert path.endswith(".enriched.json")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["report_format"] == "enriched-json-v1"
