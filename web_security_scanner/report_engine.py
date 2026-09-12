"""Standardized reporting subsystem: SARIF 2.1.0 + enriched research JSON.

This module is additive to :mod:`web_security_scanner.report_generator`; it
never mutates that module's structures and never changes the default JSON/PDF
report pair the CLI has always produced. It builds two *new*, opt-in output
formats on top of the same ``scan_data`` shape returned by
:meth:`WebSecurityScanner.run_scan` and reuses
:func:`~.report_generator.build_structured_report` as its single source of
truth for finding normalization (severity/confidence ordering, secret
masking, confirmation status), so all three formats (JSON, SARIF, enriched
JSON) always agree on what a finding *is*.

* :func:`build_sarif_report` - maps every finding to the OASIS `SARIF 2.1.0
  <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>`_
  schema (``tool.driver.rules`` + ``results``), so the scan's findings can be
  ingested by any SARIF-consuming pipeline (GitHub code scanning, IDE
  plugins, aggregators).
* :func:`build_enriched_report` - a research-oriented superset of the
  standard structured report: each finding gains a normalized attack-vector
  descriptor, a reconstructed execution trace, WAF-bypass status (cross
  referenced against the Proof-of-Impact exploit-engine trail) and whatever
  latency/timing telemetry the tester attached to it.
* :func:`generate_sarif_report` / :func:`generate_enriched_json_report` -
  write the above to disk (mirroring
  :func:`report_generator.generate_json_report`'s contract: return the
  written path) and their ``_async`` counterparts run the write in a worker
  thread so the CLI's event loop is never blocked.
* :func:`render_text_summary` / :func:`generate_text_report` - a minimal
  plain-text summary for terminals/CI logs that don't want JSON or a PDF.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .report_generator import (
    SCANNER_NAME,
    SCANNER_VERSION,
    build_structured_report,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(value: str) -> str:
    """``"Cross-Site Scripting (XSS)"`` -> ``"cross-site-scripting-xss"``."""
    slug = _SLUG_RE.sub("-", value.strip().lower()).strip("-")
    return slug or "unknown-finding"


# ---------------------------------------------------------------------------
# CWE / OWASP taxonomy lookup - keyed by substring match against the
# finding's "type", ordered most-specific-first (mirrors
# report_generator._VULN_KB's matching strategy so the two stay consistent).
# ---------------------------------------------------------------------------

_DEFAULT_TAXONOMY = {"cwe": "CWE-693", "owasp_category": "A04:2021 - Insecure Design"}

_TAXONOMY: list[tuple[tuple[str, ...], dict[str, str]]] = [
    (("sensitive file exposure", "exposed sensitive file"),
     {"cwe": "CWE-538", "owasp_category": "A05:2021 - Security Misconfiguration"}),
    (("vulnerable server component", "cve"),
     {"cwe": "CWE-1104", "owasp_category": "A06:2021 - Vulnerable and Outdated Components"}),
    (("dom-based xss", "dom xss"),
     {"cwe": "CWE-79", "owasp_category": "A03:2021 - Injection"}),
    (("nosql",), {"cwe": "CWE-943", "owasp_category": "A03:2021 - Injection"}),
    (("sql injection", "sqli"), {"cwe": "CWE-89", "owasp_category": "A03:2021 - Injection"}),
    (("cross-site scripting", "xss"),
     {"cwe": "CWE-79", "owasp_category": "A03:2021 - Injection"}),
    (("server-side request forgery", "ssrf"),
     {"cwe": "CWE-918", "owasp_category": "A10:2021 - Server-Side Request Forgery"}),
    (("command injection",), {"cwe": "CWE-78", "owasp_category": "A03:2021 - Injection"}),
    (("path traversal", "lfi", "local file inclusion"),
     {"cwe": "CWE-22", "owasp_category": "A01:2021 - Broken Access Control"}),
    (("xml external entity", "xxe"),
     {"cwe": "CWE-611", "owasp_category": "A05:2021 - Security Misconfiguration"}),
    (("template injection", "ssti"),
     {"cwe": "CWE-1336", "owasp_category": "A03:2021 - Injection"}),
    (("cross-site request forgery", "csrf"),
     {"cwe": "CWE-352", "owasp_category": "A01:2021 - Broken Access Control"}),
    (("insecure direct object reference", "idor"),
     {"cwe": "CWE-639", "owasp_category": "A01:2021 - Broken Access Control"}),
    (("open redirect",), {"cwe": "CWE-601", "owasp_category": "A01:2021 - Broken Access Control"}),
]


def _taxonomy_of(vuln_type: str) -> dict[str, str]:
    haystack = vuln_type.lower()
    for needles, entry in _TAXONOMY:
        if any(needle in haystack for needle in needles):
            return entry
    return _DEFAULT_TAXONOMY


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

# SARIF result "level" per finding severity (error/warning/note/none).
_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# GitHub-style "security-severity" numeric score (0.0-10.0) per severity,
# used by SARIF consumers that rank/filter results (e.g. GitHub code scanning).
_SEVERITY_TO_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}


def _sarif_rule(vuln_type: str, taxonomy: dict[str, str]) -> dict[str, Any]:
    rule_id = _slugify(vuln_type)
    return {
        "id": rule_id,
        "name": re.sub(r"\s+", "", vuln_type.title()),
        "shortDescription": {"text": vuln_type},
        "fullDescription": {
            "text": f"{vuln_type} ({taxonomy['cwe']}, {taxonomy['owasp_category']})."
        },
        "properties": {
            "tags": ["security", taxonomy["cwe"], taxonomy["owasp_category"]],
            "cwe": taxonomy["cwe"],
            "owasp_category": taxonomy["owasp_category"],
        },
    }


def _sarif_result(vuln: dict[str, Any], rule_id: str, rule_index: int) -> dict[str, Any]:
    severity = str(vuln.get("severity", "info")).lower()
    level = _SEVERITY_TO_SARIF_LEVEL.get(severity, "note")
    url = str(vuln.get("url") or "")
    parameter = vuln.get("parameter") or vuln.get("param") or ""
    message = (
        f"{vuln.get('type', 'Unknown')} detected"
        f"{f' via parameter {parameter!r}' if parameter else ''} "
        f"(confidence: {vuln.get('confidence', 'N/A')}, "
        f"confirmation: {vuln.get('confirmation_status', 'UNCONFIRMED')})."
    )
    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": url or "unknown://target"},
                }
            }
        ],
        "partialFingerprints": {
            "webSecurityScannerFindingHash/v1": _slugify(
                f"{vuln.get('type', '')}-{url}-{parameter}"
            )
        },
        "properties": {
            "security-severity": _SEVERITY_TO_SCORE.get(severity, "0.0"),
            "confidence": vuln.get("confidence", "N/A"),
            "confirmation_status": vuln.get("confirmation_status", "UNCONFIRMED"),
            "parameter": parameter or None,
            "payload": vuln.get("payload", "N/A"),
            # LLM triage pipeline (Phase 2, Point 3), when --enable-ai-triaging
            # / --ai-synthesize were used: stage 1's verdict and stage 2's
            # cross-validation/PoC-replay outcome, so a SARIF consumer can see
            # exactly why a finding's confidence/confirmation carries an AI
            # contribution.
            "ai_verified": vuln.get("ai_verified"),
            "ai_verdict": vuln.get("ai_verdict"),
            "ai_cross_validated": vuln.get("ai_cross_validated"),
            "ai_cross_validation_confirmed": vuln.get("ai_cross_validation_confirmed"),
        },
    }


_EXPLOIT_RULE_ID = "exploit-engine-proof-of-impact"


def _sarif_exploit_rule() -> dict[str, Any]:
    return {
        "id": _EXPLOIT_RULE_ID,
        "name": "ExploitEngineProofOfImpact",
        "shortDescription": {"text": "Adaptive Proof-of-Impact exploitation attempt"},
        "fullDescription": {
            "text": "One non-destructive Proof-of-Impact probe from the adaptive "
                    "exploit engine (--enable-exploit-engine), containment-gated "
                    "per modules.containment_core.SafetyGate."
        },
        "properties": {"tags": ["security", "exploit-engine", "containment"]},
    }


def _sarif_exploit_result(attempt: dict[str, Any], rule_index: int) -> dict[str, Any]:
    """One exploit-engine attempt as a SARIF result, carrying the Phase 3
    containment audit trail (``containment_vector`` / ``containment_profile``)
    in its properties -- CONTAINED_SIMULATION (sandboxed token echo) or
    CONTROLLED_EXECUTION (the engine's real, already non-destructive probe).
    """
    classification = str(attempt.get("classification", "SAFE"))
    level = "error" if classification == "CONFIRMED_EXPLOITABLE" else "note"
    url = str(attempt.get("url") or "")
    parameter = attempt.get("parameter") or ""
    return {
        "ruleId": _EXPLOIT_RULE_ID,
        "ruleIndex": rule_index,
        "level": level,
        "message": {
            "text": (
                f"{attempt.get('vulnerability_class', 'unknown')} Proof-of-Impact probe "
                f"({classification}) via {attempt.get('containment_vector')}"
                f"{f' on parameter {parameter!r}' if parameter else ''}."
            )
        },
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": url or "unknown://target"}}}
        ],
        "partialFingerprints": {
            "webSecurityScannerExploitAttemptHash/v1": _slugify(
                f"{attempt.get('vulnerability_class', '')}-{url}-{parameter}"
            )
        },
        "properties": {
            "classification": classification,
            "containment_vector": attempt.get("containment_vector"),
            "containment_profile": attempt.get("containment_profile"),
            "surface_priority": attempt.get("surface_priority"),
            "waf_bypass_confirmed": attempt.get("waf_bypass_confirmed"),
        },
    }


def build_sarif_report(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log (``{version, $schema, runs: [...]}``) from
    ``scan_data``.

    Reuses :func:`report_generator.build_structured_report` for finding
    normalization, so severity ordering, secret masking and confirmation
    status are identical to the standard JSON/PDF reports. When the scan ran
    the exploit engine (``--enable-exploit-engine``), every Proof-of-Impact
    attempt is also emitted as its own SARIF result under a dedicated rule,
    carrying the Phase 3 containment audit trail
    (``CONTAINED_SIMULATION``/``CONTROLLED_EXECUTION``) in its properties.
    """
    structured = build_structured_report(scan_data)
    vulns = structured["vulnerabilities"]

    rules: list[dict[str, Any]] = []
    rule_index_by_id: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for vuln in vulns:
        vuln_type = str(vuln.get("type") or vuln.get("name") or "Unknown")
        taxonomy = _taxonomy_of(vuln_type)
        rule_id = _slugify(vuln_type)
        if rule_id not in rule_index_by_id:
            rule_index_by_id[rule_id] = len(rules)
            rules.append(_sarif_rule(vuln_type, taxonomy))
        results.append(_sarif_result(vuln, rule_id, rule_index_by_id[rule_id]))

    exploit_attempts = structured.get("proof_of_impact", {}).get("attempts", [])
    if exploit_attempts:
        rule_index_by_id[_EXPLOIT_RULE_ID] = len(rules)
        rules.append(_sarif_exploit_rule())
        for attempt in exploit_attempts:
            results.append(
                _sarif_exploit_result(attempt, rule_index_by_id[_EXPLOIT_RULE_ID])
            )

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": SCANNER_NAME.replace(" ", ""),
                        "fullName": SCANNER_NAME,
                        "version": SCANNER_VERSION,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "TARGET_ROOT": {"uri": str(scan_data.get("target") or "")}
                },
                "properties": {
                    "scan_target": scan_data.get("target"),
                    "scan_profile": scan_data.get("profile"),
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                },
                "results": results,
            }
        ],
    }


def generate_sarif_report(scan_data: dict[str, Any], output_dir: str = "reports") -> str:
    """Write the SARIF report and return its path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"scan_{_timestamp()}.sarif.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(build_sarif_report(scan_data), f, indent=2, ensure_ascii=False)
    return str(path)


# ---------------------------------------------------------------------------
# Enriched JSON (research-oriented superset of the standard structured report)
# ---------------------------------------------------------------------------

# Vulnerability fields that carry per-probe timing telemetry when a tester
# attaches it (see base_tester_async's time-based confirmation path). Not
# every finding has these - testers that don't confirm via timing simply
# never set them, and the field is reported as null.
_LATENCY_FIELDS = ("elapsed_time", "probe_elapsed", "baseline_latency", "latency_upper_bound")


def _normalized_attack_vector(vuln: dict[str, Any], taxonomy: dict[str, str]) -> dict[str, Any]:
    return {
        "cwe": taxonomy["cwe"],
        "owasp_category": taxonomy["owasp_category"],
        "method": vuln.get("method", "GET"),
        "url": vuln.get("url"),
        "parameter": vuln.get("parameter") or vuln.get("param"),
        "injection_context": vuln.get("evidence_kind") or vuln.get("context"),
        "vector_kind": vuln.get("vector_kind") or vuln.get("vector") or "query",
    }


def _execution_trace(vuln: dict[str, Any]) -> list[dict[str, Any]]:
    trace: list[dict[str, Any]] = []
    if vuln.get("baseline_latency") is not None:
        trace.append({
            "step": "baseline_probe",
            "detail": f"Benign baseline latency sampled: {vuln['baseline_latency']}s",
        })
    trace.append({
        "step": "payload_delivery",
        "payload": vuln.get("payload", "N/A"),
        "detector": vuln.get("detector"),
    })
    if vuln.get("evidence"):
        trace.append({"step": "evidence_observed", "evidence": vuln["evidence"]})
    if vuln.get("ai_verified") is not None:
        trace.append({
            "step": "ai_triage",
            "verdict": vuln.get("ai_verdict"),
            "confidence": vuln.get("ai_confidence"),
        })
    if vuln.get("ai_cross_validated") is not None:
        trace.append({
            "step": "ai_cross_validation",
            "confirmed": vuln.get("ai_cross_validation_confirmed"),
            "payloads_tried": vuln.get("ai_cross_validation_payloads_tried", []),
        })
    trace.append({
        "step": "confirmation",
        "status": vuln.get("confirmation_status", "UNCONFIRMED"),
        "confidence": vuln.get("confidence", "N/A"),
    })
    return trace


def _waf_status(vuln: dict[str, Any], attempts: list[dict[str, Any]]) -> dict[str, Any]:
    """Cross-reference a finding against the Proof-of-Impact exploit-engine
    trail (``scan_data['proof_of_impact']``) for WAF-bypass evidence on the
    same URL/parameter. Findings from a scan that never ran the exploit
    engine (``--enable-exploit-engine``) are reported ``"not_probed"``.
    """
    if not attempts:
        return {"state": "not_probed", "technique": None}

    url = str(vuln.get("url") or "")
    parameter = str(vuln.get("parameter") or vuln.get("param") or "")
    matches = [
        a for a in attempts
        if str(a.get("url") or "") == url
        and str(a.get("parameter") or "") == parameter
    ]
    if not matches:
        return {"state": "not_probed", "technique": None}
    if any(a.get("waf_bypass_confirmed") for a in matches):
        techniques = [a.get("waf_evasion_technique") for a in matches if a.get("waf_bypass_confirmed")]
        return {"state": "bypassed", "technique": next((t for t in techniques if t), None)}
    return {"state": "probed_clean", "technique": None}


def _latency_metrics(vuln: dict[str, Any]) -> dict[str, Any]:
    metrics = {field: vuln.get(field) for field in _LATENCY_FIELDS}
    baseline = metrics.get("baseline_latency")
    upper = metrics.get("latency_upper_bound")
    metrics["jitter_envelope"] = (
        round(upper - baseline, 6) if isinstance(baseline, (int, float)) and isinstance(upper, (int, float)) else None
    )
    return metrics


def build_enriched_report(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Build the enriched research JSON report: the standard structured
    report (see :func:`report_generator.build_structured_report`) with, per
    finding, a normalized attack-vector descriptor, a reconstructed
    execution trace, WAF-bypass cross-reference and any latency/jitter
    telemetry the tester attached.
    """
    structured = build_structured_report(scan_data)
    attempts = structured["proof_of_impact"]["attempts"]

    enriched_vulns = []
    for vuln in structured["vulnerabilities"]:
        vuln_type = str(vuln.get("type") or vuln.get("name") or "Unknown")
        taxonomy = _taxonomy_of(vuln_type)
        enriched = dict(vuln)
        enriched["normalized_attack_vector"] = _normalized_attack_vector(vuln, taxonomy)
        enriched["execution_trace"] = _execution_trace(vuln)
        enriched["waf_status"] = _waf_status(vuln, attempts)
        enriched["latency_metrics"] = _latency_metrics(vuln)
        enriched_vulns.append(enriched)

    report = dict(structured)
    report["report_format"] = "enriched-json-v1"
    report["server_fingerprint_digest"] = structured.get("server_fingerprint")
    report["vulnerabilities"] = enriched_vulns
    # Phase 2, Point 2: real-time telemetry (latency/jitter/retries/WAF-evasion
    # effectiveness, per operational phase and per host), when the scan
    # collected it (see core.telemetry_engine.TelemetryEngine.snapshot).
    if scan_data.get("realtime_telemetry") is not None:
        report["realtime_telemetry"] = scan_data["realtime_telemetry"]
    return report


def generate_enriched_json_report(scan_data: dict[str, Any], output_dir: str = "reports") -> str:
    """Write the enriched JSON report and return its path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"scan_{_timestamp()}.enriched.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(build_enriched_report(scan_data), f, indent=2, ensure_ascii=False)
    return str(path)


# ---------------------------------------------------------------------------
# Plain-text summary (terminal / CI logs)
# ---------------------------------------------------------------------------


def render_text_summary(scan_data: dict[str, Any]) -> str:
    """Render a short human-readable text summary (no ANSI color codes) of
    the scan: target, risk matrix, then one line per finding."""
    structured = build_structured_report(scan_data)
    meta = structured["report_metadata"]
    summary = structured["executive_summary"]
    lines = [
        f"{SCANNER_NAME} v{SCANNER_VERSION} - scan report",
        f"Target: {meta.get('engagement_target')}",
        f"Profile: {meta.get('scan_profile')}",
        f"Generated: {meta.get('generated_at')}",
        "",
        f"Total findings: {summary['total_findings']}",
        "Risk matrix: " + ", ".join(
            f"{level}={count}" for level, count in summary["risk_matrix"].items()
        ),
        "",
    ]
    for vuln in structured["vulnerabilities"]:
        parameter = vuln.get("parameter") or vuln.get("param") or "-"
        lines.append(
            f"[{vuln.get('severity', 'info').upper():<8}] "
            f"{vuln.get('type', 'Unknown')} @ {vuln.get('url', '-')} "
            f"(parameter={parameter}, confidence={vuln.get('confidence', 'N/A')}, "
            f"status={vuln.get('confirmation_status', 'UNCONFIRMED')})"
        )
    return "\n".join(lines) + "\n"


def generate_text_report(scan_data: dict[str, Any], output_dir: str = "reports") -> str:
    """Write the plain-text summary and return its path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"scan_{_timestamp()}.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_text_summary(scan_data))
    return str(path)


# ---------------------------------------------------------------------------
# Format dispatch (mirrors report_generator.generate_reports[_async])
# ---------------------------------------------------------------------------

_GENERATORS = {
    "sarif": generate_sarif_report,
    "json": generate_enriched_json_report,
    "text": generate_text_report,
}


def generate_report(scan_data: dict[str, Any], output_format: str,
                    output_dir: str = "reports", output_file: str | None = None) -> str:
    """Generate a single report in ``output_format`` (``sarif``/``json``/``text``).

    When ``output_file`` is given the report is written there directly
    (parent directories created as needed); otherwise it is written to
    ``output_dir`` under a timestamped default name, matching
    :func:`report_generator.generate_reports`'s convention.
    """
    if output_format not in _GENERATORS:
        raise ValueError(
            f"unknown output format {output_format!r}; expected one of "
            f"{sorted(_GENERATORS)}"
        )
    if output_file is None:
        return _GENERATORS[output_format](scan_data, output_dir)

    path = Path(output_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    builders = {
        "sarif": lambda: json.dumps(build_sarif_report(scan_data), indent=2, ensure_ascii=False),
        "json": lambda: json.dumps(build_enriched_report(scan_data), indent=2, ensure_ascii=False),
        "text": lambda: render_text_summary(scan_data),
    }
    path.write_text(builders[output_format](), encoding="utf-8")
    return str(path)


async def generate_report_async(scan_data: dict[str, Any], output_format: str,
                                output_dir: str = "reports",
                                output_file: str | None = None) -> str:
    """Non-blocking version of :func:`generate_report` (runs in a worker
    thread via ``asyncio.to_thread``, same convention as
    :func:`report_generator.generate_reports_async`)."""
    return await asyncio.to_thread(
        generate_report, scan_data, output_format, output_dir, output_file
    )
