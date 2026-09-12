"""Tests for the dual JSON/PDF report engine (web_security_scanner.report_generator).

Covers:
* Structured JSON: payload/probe, technical mechanism, business impact,
  remediation and confirmation status are listed for every finding; the
  prioritized attack-surface tree, sensitive files and server fingerprint
  make it into the report; the risk matrix tallies severities correctly.
* Confirmation-status classification: CONFIRMED vs BANNER_ONLY vs UNCONFIRMED.
* Secret masking is preserved (Bearer tokens / cookies redacted from evidence,
  the attacker payload itself is never redacted).
* PDF generation produces a well-formed file and never chokes on
  attacker-controlled markup-breaking characters in payload/evidence text.
* Format dispatch (generate_reports / generate_reports_async).
"""

import json
from pathlib import Path
from typing import Any

import pytest
from reportlab.platypus import Table

from web_security_scanner.report_generator import (
    _pdf_critical_impact_evidence,
    _pdf_styles,
    build_structured_report,
    generate_json_report,
    generate_pdf_report,
    generate_reports,
    generate_reports_async,
)

XSS_PAYLOAD = "<script>alert(1)</script>"


def _story_text(story: list[Any]) -> str:
    """Flatten a ReportLab story's Paragraph text, recursing into Table
    cells, so a unit test can assert on rendered content without parsing
    the compressed PDF byte stream."""
    chunks: list[str] = []
    for flowable in story:
        if isinstance(flowable, Table):
            for row in flowable._cellvalues:
                for cell in row:
                    chunks.append(getattr(cell, "text", ""))
        else:
            chunks.append(getattr(flowable, "text", ""))
    return "\n".join(chunks)

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
        },
        {
            "type": "Cross-Site Scripting (XSS)",
            "severity": "high",
            "confidence": "HIGH",
            "url": f"http://target.test/p?x={XSS_PAYLOAD}",
            "parameter": "x\"><img src=x onerror=alert(1)>",
            "payload": XSS_PAYLOAD,
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

SCAN_DATA_WITH_RECON = {
    **SCAN_DATA,
    "recon": {
        "priority_targets": [
            {
                "url": "http://target.test/admin/dashboard",
                "categories": ["admin_panel"],
                "score": 72.5,
                "priority": "CRITICAL",
                "evidence": ["path matches admin_panel pattern: /admin(?:/|$)"],
            },
            {
                "url": "http://target.test/about",
                "categories": ["generic"],
                "score": 5.0,
                "priority": "INFO",
                "evidence": [],
            },
        ],
        "surface_priority": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 1},
        "sensitive_files": [
            {
                "url": "http://target.test/.env",
                "path": "/.env",
                "risk": "CRITICAL",
                "category": "credentials",
                "status_code": 200,
                "confidence": "HIGH",
                "evidence": "dotenv-style KEY=VALUE lines found",
            }
        ],
        "server_fingerprint": {
            "fingerprints": [{"header": "Server", "product": "Apache", "version": "2.4.49"}],
            "findings": [
                {"cve_id": "CVE-2021-41773", "name": "Path Traversal", "severity": "Critical",
                 "confidence": "MEDIUM", "poc_method": "banner-only"},
            ],
        },
    },
}


SCAN_DATA_WITH_EXPLOITS = {
    **SCAN_DATA,
    "proof_of_impact": [
        {
            "url": "http://target.test/render?tpl=1",
            "vulnerability_class": "rce",
            "payload_category": "ssti",
            "parameter": "tpl",
            "vector": "query",
            "adaptive_payload": "{{7*7}}",
            "technology_context": {"language": "python", "database": "unknown", "server": "unknown"},
            "classification": "CONFIRMED_EXPLOITABLE",
            "confirmation_evidence": (
                "Non-destructive PoC probe matched expected evidence marker(s) "
                "['49'] — reproduced on an independent replay. "
                "Cookie: session=SUPERSECRETVALUE"
            ),
            "impact_analysis": "Remote code execution hands the attacker full control.",
            "surface_priority": "CRITICAL",
            "surface_score": 92.0,
            "verified_marker": "49",
            "waf_evasion_technique": "random_case",
            "waf_bypass_confirmed": True,
        },
        {
            "url": "http://target.test/search?q=1",
            "vulnerability_class": "sql_injection",
            "payload_category": "sql_injection",
            "parameter": "q",
            "vector": "query",
            "adaptive_payload": "1 OR SLEEP(5)",
            "technology_context": {"language": "php", "database": "mysql", "server": "apache"},
            "classification": "POTENTIAL",
            "confirmation_evidence": "Response differed significantly from the benign baseline.",
            "impact_analysis": "A confirmed SQL injection gives direct database access.",
            "surface_priority": "HIGH",
            "surface_score": 75.0,
            "verified_marker": None,
            "waf_evasion_technique": None,
            "waf_bypass_confirmed": False,
        },
        {
            "url": "http://target.test/safe?x=1",
            "vulnerability_class": "xss",
            "payload_category": "xss",
            "parameter": "x",
            "vector": "query",
            "adaptive_payload": "<script>canary</script>",
            "technology_context": {"language": "unknown", "database": "unknown", "server": "unknown"},
            "classification": "SAFE",
            "confirmation_evidence": "No exploitation evidence observed.",
            "impact_analysis": "",
            "surface_priority": "HIGH",
            "surface_score": 60.0,
            "verified_marker": None,
            "waf_evasion_technique": None,
            "waf_bypass_confirmed": False,
        },
    ],
}


SCAN_DATA_WITH_TIME_BASED_EXPLOIT = {
    **SCAN_DATA,
    "proof_of_impact": [
        {
            "url": "http://target.test/ping?host=127.0.0.1",
            "vulnerability_class": "rce",
            "payload_category": "command_injection",
            "parameter": "host",
            "vector": "query",
            "adaptive_payload": "127.0.0.1; sleep 5",
            "technology_context": {"language": "php", "database": "unknown", "server": "apache"},
            "classification": "CONFIRMED_EXPLOITABLE",
            "confirmation_evidence": (
                "Time-based PoC: probe took 5.21s vs a 0.12s baseline (adaptive "
                "threshold +1.50s); confirmation=CONFIRMED "
                "(reduced-delay-first, non-destructive)."
            ),
            "impact_analysis": "Remote code execution hands the attacker full control.",
            "surface_priority": "CRITICAL",
            "surface_score": 95.0,
            "verified_marker": "induced delay 5.21s vs 0.12s baseline (+1.50s adaptive threshold)",
            "waf_evasion_technique": None,
            "waf_bypass_confirmed": False,
        },
    ],
}


def test_critical_impact_evidence_supports_time_based_delay_marker():
    """A confirmed RCE reached via time-based (retardo temporal) validation --
    not just the arithmetic 7*7=49 marker -- must also be structured into the
    "Critical Impact Evidence" section, with no WAF bypass implied when none
    was needed (direct delivery)."""
    report = build_structured_report(SCAN_DATA_WITH_TIME_BASED_EXPLOIT)
    entries = report["critical_impact_evidence"]

    assert len(entries) == 1
    entry = entries[0]
    assert entry["vulnerability_class"] == "rce"
    assert entry["successful_payload"] == "127.0.0.1; sleep 5"
    assert "induced delay" in entry["verified_marker"]
    assert "5.21s" in entry["verified_marker"]
    assert entry["waf_evasion_technique"] is None
    assert entry["waf_bypass_confirmed"] is False


def test_pdf_critical_impact_evidence_renders_time_based_delay_marker():
    report = build_structured_report(SCAN_DATA_WITH_TIME_BASED_EXPLOIT)
    styles = _pdf_styles()
    story = _pdf_critical_impact_evidence(report, styles)

    rendered = _story_text(story)
    assert "induced delay" in rendered
    assert "5.21s" in rendered
    # No perimeter block was encountered for this attempt -- the PDF must say
    # so rather than implying an evasion technique that was never needed.
    assert "No WAF perimeter block was encountered" in rendered


def test_critical_impact_evidence_filters_to_confirmed_exploitable_only():
    report = build_structured_report(SCAN_DATA_WITH_EXPLOITS)
    entries = report["critical_impact_evidence"]

    assert len(entries) == 1
    entry = entries[0]
    assert entry["vulnerability_class"] == "rce"
    assert entry["affected_vector"] == "http://target.test/render?tpl=1 (parameter: tpl)"
    assert entry["successful_payload"] == "{{7*7}}"
    assert entry["verified_marker"] == "49"
    assert entry["waf_evasion_technique"] == "random_case"
    assert entry["waf_bypass_confirmed"] is True
    assert "control" in entry["impact_analysis"]


def test_critical_impact_evidence_masks_secrets_in_impact_validation():
    report = build_structured_report(SCAN_DATA_WITH_EXPLOITS)
    entry = report["critical_impact_evidence"][0]

    assert "SUPERSECRETVALUE" not in entry["impact_validation"]
    assert "Cookie: ***" in entry["impact_validation"]
    # The exact successful payload must stay reproducible, never redacted.
    assert entry["successful_payload"] == "{{7*7}}"


def test_critical_impact_evidence_empty_when_no_confirmed_exploits():
    report = build_structured_report(SCAN_DATA)
    assert report["critical_impact_evidence"] == []


def test_json_report_includes_critical_impact_evidence(tmp_path):
    path = Path(generate_json_report(SCAN_DATA_WITH_EXPLOITS, output_dir=str(tmp_path)))
    data = json.loads(path.read_text(encoding="utf-8"))

    assert len(data["critical_impact_evidence"]) == 1
    assert data["critical_impact_evidence"][0]["waf_evasion_technique"] == "random_case"


def test_pdf_critical_impact_evidence_section_renders_waf_bypass_telemetry():
    report = build_structured_report(SCAN_DATA_WITH_EXPLOITS)
    styles = _pdf_styles()
    story = _pdf_critical_impact_evidence(report, styles)

    rendered = _story_text(story)
    assert "Critical Impact Evidence" in rendered
    assert "WAF Bypass Telemetry" in rendered
    assert "random_case" in rendered
    assert "{{7*7}}" in rendered
    assert "49" in rendered
    # Only the confirmed-exploitable entry is rendered, not the POTENTIAL/SAFE ones.
    assert "1 OR SLEEP(5)" not in rendered


def test_pdf_critical_impact_evidence_section_empty_state():
    report = build_structured_report(SCAN_DATA)
    styles = _pdf_styles()
    story = _pdf_critical_impact_evidence(report, styles)

    rendered = _story_text(story)
    assert "No confirmed-exploitable" in rendered


def test_pdf_report_with_critical_impact_evidence_is_generated(tmp_path):
    path = Path(generate_pdf_report(SCAN_DATA_WITH_EXPLOITS, output_dir=str(tmp_path)))
    raw = path.read_bytes()
    assert raw.startswith(b"%PDF")
    assert len(raw) > 1000


def test_json_report_structure_and_payloads(tmp_path):
    path = Path(generate_json_report(SCAN_DATA_WITH_RECON, output_dir=str(tmp_path)))
    data = json.loads(path.read_text(encoding="utf-8"))

    assert data["report_metadata"]["engagement_target"] == "http://target.test/"
    findings = data["vulnerabilities"]
    assert len(findings) == 3
    for finding in findings:
        for key in ("payload", "technical_mechanism", "business_impact", "remediation",
                    "confirmation_status", "risk_level", "vector"):
            assert key in finding and finding[key], f"missing/empty {key} in {finding}"

    sqli = next(f for f in findings if f["type"] == "SQL Injection")
    assert sqli["payload"] == "1' OR '1'='1"
    assert "parameterized" in sqli["remediation"].lower()
    assert sqli["confirmation_status"] == "CONFIRMED"


def test_json_report_lists_attack_surface_and_sensitive_files(tmp_path):
    path = Path(generate_json_report(SCAN_DATA_WITH_RECON, output_dir=str(tmp_path)))
    data = json.loads(path.read_text(encoding="utf-8"))

    surface_urls = {t["url"] for t in data["attack_surface"]["prioritized_targets"]}
    assert "http://target.test/admin/dashboard" in surface_urls
    assert data["attack_surface"]["surface_priority_summary"]["CRITICAL"] == 1

    assert data["sensitive_files"][0]["url"] == "http://target.test/.env"
    assert data["server_fingerprint"]["fingerprints"][0]["product"] == "Apache"


def test_risk_matrix_tallies_severities():
    report = build_structured_report(SCAN_DATA_WITH_RECON)
    matrix = report["executive_summary"]["risk_matrix"]
    assert matrix["Critical"] == 1
    assert matrix["High"] == 1
    assert matrix["Medium"] == 1
    assert matrix["Low"] == 0


def test_confirmation_status_confirmed_banner_only_unconfirmed():
    report = build_structured_report(SCAN_DATA_WITH_RECON)
    by_type = {v["type"]: v for v in report["vulnerabilities"]}

    assert by_type["SQL Injection"]["confirmation_status"] == "CONFIRMED"
    assert by_type["Vulnerable Server Component"]["confirmation_status"] == "BANNER_ONLY"
    assert by_type["Cross-Site Scripting (XSS)"]["confirmation_status"] == "UNCONFIRMED"

    summary = report["executive_summary"]
    assert summary["confirmed_findings"] == 1
    assert summary["banner_only_findings"] == 1


def test_json_report_masks_secrets_but_keeps_payload(tmp_path):
    path = Path(generate_json_report(SCAN_DATA_WITH_RECON, output_dir=str(tmp_path)))
    data = json.loads(path.read_text(encoding="utf-8"))
    sqli = next(f for f in data["vulnerabilities"] if f["type"] == "SQL Injection")

    assert "Authorization: Bearer ***" in sqli["evidence"]
    assert "Cookie: ***" in sqli["evidence"]
    assert "SUPERSECRETVALUE" not in sqli["evidence"]
    assert "abc123SECRET" not in sqli["evidence"]
    # The exact attacker payload is never redacted - it must stay reproducible.
    assert sqli["payload"] == "1' OR '1'='1"


def test_json_report_backward_compatible_vuln_keys(tmp_path):
    """tools/eval_oracle.py reads report["vulnerabilities"][i]["url"/"parameter"/"type"]."""
    path = Path(generate_json_report(SCAN_DATA, output_dir=str(tmp_path)))
    data = json.loads(path.read_text(encoding="utf-8"))
    for key in ("type", "url", "parameter", "severity", "confidence", "payload"):
        assert key in data["vulnerabilities"][0]


def test_pdf_report_is_generated(tmp_path):
    path = Path(generate_pdf_report(SCAN_DATA_WITH_RECON, output_dir=str(tmp_path)))
    assert path.exists()
    raw = path.read_bytes()
    assert raw.startswith(b"%PDF")
    assert len(raw) > 1000


def test_pdf_report_survives_markup_breaking_payloads(tmp_path):
    """A payload containing '<', '>', '&' must not corrupt ReportLab's

    Paragraph markup parser or crash report generation - the PDF equivalent
    of the old HTML report's XSS-escaping test.
    """
    hostile = {
        **SCAN_DATA,
        "vulnerabilities": [
            {
                "type": "Cross-Site Scripting (XSS)",
                "severity": "high",
                "confidence": "HIGH",
                "url": "http://target.test/p?x=<script>alert(1)</script>",
                "parameter": "x\"><img src=x onerror=alert(1)>",
                "payload": "<b>&</b><img src=x onerror=alert(1)>",
                "evidence": "reflected <script>&amp;</script> unescaped",
            }
        ],
    }
    path = Path(generate_pdf_report(hostile, output_dir=str(tmp_path)))
    assert path.read_bytes().startswith(b"%PDF")


def test_pdf_report_with_no_findings(tmp_path):
    empty = {**SCAN_DATA, "vulnerabilities": []}
    path = Path(generate_pdf_report(empty, output_dir=str(tmp_path)))
    assert path.read_bytes().startswith(b"%PDF")


def test_generate_reports_dispatches_json_and_pdf(tmp_path):
    paths = generate_reports(SCAN_DATA, ["json", "pdf"], output_dir=str(tmp_path))
    assert set(paths) == {"json", "pdf"}
    assert Path(paths["json"]).exists()
    assert Path(paths["pdf"]).exists()


def test_generate_reports_ignores_unknown_format(tmp_path):
    paths = generate_reports(SCAN_DATA, ["json", "html"], output_dir=str(tmp_path))
    assert set(paths) == {"json"}


@pytest.mark.asyncio
async def test_generate_reports_async_matches_sync(tmp_path):
    paths = await generate_reports_async(SCAN_DATA, ["json"], output_dir=str(tmp_path))
    assert Path(paths["json"]).exists()
