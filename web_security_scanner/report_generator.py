"""Structured (JSON) and executive/technical (PDF) report generation.

Replaces the deprecated HTML report and the deprecated recon HTML map
(``WebMapperAsync.generate_map`` / ``reports.generate_html_report``) with a
single dual-format reporting engine:

* :func:`generate_json_report` - a full machine-readable snapshot of the
  engagement: the prioritized attack-surface tree, sensitive-file exposures,
  server fingerprints, every finding with its exact payload/probe and
  confirmation status (``CONFIRMED`` / ``BANNER_ONLY`` / ``UNCONFIRMED``), and
  a Critical/High/Medium/Low risk matrix.
* :func:`generate_pdf_report` - a typeset PDF (cover page, executive summary +
  risk matrix, then one detailed breakdown per finding: vulnerability name,
  affected vector/URL, exact payload/probe, technical mechanism, business
  impact, and remediation) built with ReportLab from the same structured data.

Both formats consume the same ``scan_data`` shape returned by
:meth:`WebSecurityScanner.run_scan` (``{target, profile, vulnerabilities,
technologies, statistics, recon, ai_triage, ...}``); see
:func:`build_structured_report`.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .utils.validation import mask_secrets

SCANNER_NAME = "Web Security Scanner"
# Kept in sync with pyproject.toml's [project].version by hand - there is no
# runtime package metadata lookup here to keep report generation dependency-free.
SCANNER_VERSION = "5.2.0"

# ---------------------------------------------------------------------------
# Shared vulnerability normalization (severity / confidence / secret masking)
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CONFIDENCE_ORDER = {"confirmed": 0, "high": 1, "medium": 2, "low": 3}

# Vulnerability fields that may embed request/response fragments and therefore
# the operator's own secrets. Masked before being written to ANY report format.
# Deliberately excludes "payload" - the exact attacker payload/probe must be
# reproduced verbatim for the finding to be actionable.
_MASKED_FIELDS = ("evidence", "request", "response", "headers", "raw", "details")

RISK_LEVELS = ("Critical", "High", "Medium", "Low", "Informational")

_SEVERITY_TO_RISK_LEVEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _mask_vuln(vuln: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of ``vuln`` with secrets redacted from its text."""
    cleaned = dict(vuln)
    for key in _MASKED_FIELDS:
        if key in cleaned:
            cleaned[key] = mask_secrets(cleaned[key])
    return cleaned


def _confidence_of(v: dict[str, Any]) -> str:
    """Read a vulnerability's confidence, tolerating old reports without it."""
    raw = v.get("confidence")
    if not raw:
        return "N/A"
    val = str(raw).strip().upper()
    return val if val in ("LOW", "MEDIUM", "HIGH", "CONFIRMED") else "N/A"


def _severity_of(v: dict[str, Any]) -> str:
    return str(v.get("severity", "info")).lower()


def _risk_level_of(v: dict[str, Any]) -> str:
    return _SEVERITY_TO_RISK_LEVEL.get(_severity_of(v), "Informational")


def _sorted_vulns(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        vulns,
        key=lambda v: (
            SEVERITY_ORDER.get(_severity_of(v), 5),
            CONFIDENCE_ORDER.get(_confidence_of(v).lower(), 4),
        ),
    )


def _confirmation_status(v: dict[str, Any]) -> str:
    """Classify how solidly a finding was established.

    ``CONFIRMED`` - actively verified (a safe PoC probe succeeded, or a
    tester's own two-stage validation confirmed the signal).
    ``BANNER_ONLY`` - inferred from a version banner / header alone (e.g. a
    server-fingerprint advisory that could not be actively verified) and
    therefore may be a false positive if the banner is stale or spoofed.
    ``UNCONFIRMED`` - a heuristic/differential signal (HIGH/MEDIUM/LOW
    confidence) that was never actively re-verified.
    """
    confidence = _confidence_of(v)
    if confidence == "CONFIRMED":
        return "CONFIRMED"
    evidence = str(v.get("evidence") or "")
    if v.get("detector") == "server-fingerprint" or "banner" in evidence.lower():
        return "BANNER_ONLY"
    return "UNCONFIRMED"


def _risk_matrix(vulns: list[dict[str, Any]]) -> dict[str, int]:
    matrix = dict.fromkeys(RISK_LEVELS, 0)
    for v in vulns:
        matrix[_risk_level_of(v)] += 1
    return matrix


# ---------------------------------------------------------------------------
# Vulnerability knowledge base: technical mechanism / business impact /
# remediation, keyed by a substring match against the finding's "type".
# Ordered most-specific-first so e.g. "nosql" is matched before "sql".
# ---------------------------------------------------------------------------

_DEFAULT_KB = {
    "mechanism": (
        "The target endpoint accepted attacker-influenced input and produced a "
        "response consistent with unsafe handling of that input, as evidenced "
        "by the probe below."
    ),
    "business_impact": (
        "Depending on exploitation depth this class of weakness can lead to "
        "unauthorized data access, service disruption, or a foothold for "
        "further compromise - each carrying financial, regulatory and "
        "reputational cost proportional to the data or system exposed."
    ),
    "remediation": (
        "Validate and sanitize all attacker-controlled input server-side, "
        "apply the principle of least privilege to the affected component, "
        "and re-test with the payload below after remediation."
    ),
}

_VULN_KB: list[tuple[tuple[str, ...], dict[str, str]]] = [
    (("sensitive file exposure", "exposed sensitive file"), {
        "mechanism": (
            "A configuration, backup, version-control or credential file was "
            "reachable over HTTP without authentication, confirmed by a "
            "non-destructive GET probe against a baseline of the site's soft-404 "
            "behavior."
        ),
        "business_impact": (
            "Exposed source, credentials or infrastructure configuration lets an "
            "attacker skip reconnaissance entirely and move straight to "
            "credential reuse, source-code review for further bugs, or direct "
            "database access - a direct confidentiality breach with potential "
            "regulatory (GDPR/PCI-DSS) notification obligations."
        ),
        "remediation": (
            "Remove the file from the web root (or block it at the web-server/"
            "reverse-proxy layer), rotate any credentials it contained, and add "
            "a CI check that fails the build if secrets or VCS metadata are "
            "deployed to a public directory."
        ),
    }),
    (("vulnerable server component", "cve"), {
        "mechanism": (
            "The server's Server/X-Powered-By/Via banner (optionally confirmed "
            "by a safe, non-destructive active probe) matches a product/version "
            "known to be affected by the referenced CVE."
        ),
        "business_impact": (
            "An unpatched, publicly disclosed vulnerability in a fingerprinted "
            "component is one of the most reliably automated attack paths - "
            "public exploit code often exists, turning a single unpatched host "
            "into a full compromise with minimal attacker effort."
        ),
        "remediation": (
            "Apply the vendor's fixed version/hotfix, and where a banner-only "
            "match cannot be actively confirmed, prioritize the underlying "
            "patch or hotfix cycle for the fingerprinted component regardless."
        ),
    }),
    (("dom-based xss", "dom xss"), {
        "mechanism": (
            "Attacker-influenced data flowed from a client-side source (URL, "
            "postMessage, storage) into a dangerous DOM sink (innerHTML, "
            "eval, document.write) without sanitisation, observed live in a "
            "headless-browser instrumentation pass."
        ),
        "business_impact": (
            "Client-side script execution in a victim's authenticated session "
            "enables session/token theft, UI redressing and full account "
            "takeover - entirely server-log-invisible, which extends detection "
            "and incident-response time."
        ),
        "remediation": (
            "Sanitize or encode data before it reaches a DOM sink (prefer "
            "textContent over innerHTML), and adopt a strict Content-Security-"
            "Policy that disallows inline script execution."
        ),
    }),
    (("nosql",), {
        "mechanism": (
            "A NoSQL query operator (e.g. ``$where``/``$ne``/``$gt``) injected "
            "into a parameter altered the query's logic, changing the "
            "application's response in a way inconsistent with normal input."
        ),
        "business_impact": (
            "Query-logic manipulation can bypass authentication, dump entire "
            "collections, or in ``$where``-style engines execute arbitrary "
            "server-side JavaScript - a critical confidentiality and integrity "
            "breach of the backing datastore."
        ),
        "remediation": (
            "Use a query builder / ODM that parameterizes input instead of "
            "string-concatenating it into query documents, and reject any "
            "request body field whose type doesn't match the expected schema."
        ),
    }),
    (("sql injection", "sqli"), {
        "mechanism": (
            "A crafted SQL payload altered the structure of the backend query "
            "(via error-based, boolean-differential or time-based confirmation), "
            "proving the parameter reaches the database layer unsanitised."
        ),
        "business_impact": (
            "SQL injection routinely enables full database exfiltration "
            "(customer PII, credentials, payment data), data tampering, or - "
            "via stacked queries/`xp_cmdshell`-class features - remote command "
            "execution; it remains one of the costliest breach categories in "
            "both direct fines and reputational damage."
        ),
        "remediation": (
            "Use parameterized queries / prepared statements exclusively (never "
            "string-concatenate user input into SQL), apply least-privilege "
            "database accounts, and enable query logging/WAF virtual patching "
            "as defense in depth."
        ),
    }),
    (("cross-site scripting", "xss"), {
        "mechanism": (
            "An attacker-supplied script payload was reflected or stored and "
            "rendered back into the page without contextual output encoding, "
            "confirmed by the payload's markers surviving in the response body."
        ),
        "business_impact": (
            "Script execution in another user's session enables session/cookie "
            "theft, credential phishing overlays, and - against an admin "
            "session - full application takeover; regulated data exposed this "
            "way carries breach-notification cost."
        ),
        "remediation": (
            "Apply context-aware output encoding at every render sink, adopt a "
            "strict Content-Security-Policy (no ``unsafe-inline``), and mark "
            "session cookies ``HttpOnly``/``Secure``/``SameSite``."
        ),
    }),
    (("server-side request forgery", "ssrf"), {
        "mechanism": (
            "The server was induced to issue an outbound request to an "
            "attacker-chosen URL/host on the application's behalf, confirmed "
            "via an out-of-band or response-differential signal."
        ),
        "business_impact": (
            "SSRF is a common pivot into cloud metadata endpoints "
            "(credential theft), internal-only admin interfaces, and other "
            "hosts the perimeter firewall would otherwise block - frequently "
            "escalating a single web bug into full internal-network compromise."
        ),
        "remediation": (
            "Validate outbound destinations against an allow-list, block "
            "requests to link-local/private/loopback ranges at the network "
            "layer, and disable HTTP redirect-following for user-supplied URLs."
        ),
    }),
    (("command injection",), {
        "mechanism": (
            "Attacker-controlled input reached a shell/OS command execution "
            "sink, confirmed by observing command output (or a time-based "
            "delay) in the response."
        ),
        "business_impact": (
            "Operating-system command execution is full remote code execution: "
            "the attacker gains the privileges of the application process, "
            "typically enabling complete host compromise, lateral movement and "
            "ransomware deployment."
        ),
        "remediation": (
            "Never pass user input to a shell; use language-native APIs "
            "(argument arrays, not string concatenation) and run the process "
            "under a least-privilege, sandboxed account."
        ),
    }),
    (("path traversal", "lfi", "local file inclusion"), {
        "mechanism": (
            "A ``../`` (or encoded/absolute-path) sequence in a file-path "
            "parameter escaped the intended directory, confirmed by the "
            "content of a known system file appearing in the response."
        ),
        "business_impact": (
            "Arbitrary file read exposes source code, configuration secrets "
            "and credential stores; combined with a log/upload-poisoning "
            "primitive it frequently escalates to remote code execution."
        ),
        "remediation": (
            "Resolve and canonicalize the requested path, then reject anything "
            "outside an explicit allow-listed base directory; avoid passing "
            "user input to filesystem APIs at all where feasible."
        ),
    }),
    (("xml external entity", "xxe"), {
        "mechanism": (
            "The XML parser resolved an attacker-defined external entity, "
            "confirmed by the entity's target file content (or an OOB "
            "callback) appearing in the application's response."
        ),
        "business_impact": (
            "XXE enables local file disclosure, internal SSRF, and in some "
            "parser configurations denial of service (billion-laughs) - a "
            "direct confidentiality and availability risk to the host and "
            "any internal service it can reach."
        ),
        "remediation": (
            "Disable DTD processing and external entity resolution in the XML "
            "parser configuration (the safe default in most modern libraries); "
            "prefer a data format that has no entity-expansion concept (JSON)."
        ),
    }),
    (("cross-site request forgery", "csrf"), {
        "mechanism": (
            "A state-changing request succeeded without a valid, "
            "per-session anti-CSRF token being required or verified, "
            "confirmed by resubmitting the request without (or with a "
            "mismatched) token."
        ),
        "business_impact": (
            "An attacker can force an authenticated victim's browser to "
            "perform unwanted state changes (fund transfers, password/email "
            "changes, privilege grants) - directly threatening account "
            "integrity and, for financial actions, causing measurable loss."
        ),
        "remediation": (
            "Require a per-session, unpredictable CSRF token validated "
            "server-side on every state-changing request, and set "
            "``SameSite=Lax``/``Strict`` on session cookies as defense in depth."
        ),
    }),
    (("insecure direct object reference", "idor"), {
        "mechanism": (
            "An identifier in the request (path/query/body) referenced another "
            "user's resource, and the server returned or modified it without "
            "an ownership/authorization check."
        ),
        "business_impact": (
            "IDOR is a direct horizontal-privilege-escalation path to other "
            "users' data - one of the most common causes of large-scale PII "
            "breaches, since it is trivially scriptable across an entire ID "
            "range."
        ),
        "remediation": (
            "Enforce an object-level authorization check on every request "
            "(verify the authenticated principal owns or is entitled to the "
            "referenced resource) rather than relying on the ID being "
            "unguessable."
        ),
    }),
    (("open redirect",), {
        "mechanism": (
            "A redirect/URL parameter was echoed unvalidated into a "
            "``Location`` header or client-side navigation, confirmed by the "
            "response redirecting to an attacker-controlled external host."
        ),
        "business_impact": (
            "Open redirects are weaponized in phishing campaigns - the "
            "malicious link starts on the trusted domain, which defeats "
            "naive user and mail-filter trust heuristics and damages the "
            "brand's anti-phishing reputation."
        ),
        "remediation": (
            "Validate redirect targets against an allow-list of internal "
            "paths/hosts; if external redirects are required, interstitial-"
            "warn the user before leaving the site."
        ),
    }),
    (("server-side template injection", "ssti"), {
        "mechanism": (
            "A template-engine expression injected into user input was "
            "evaluated server-side, confirmed by an arithmetic or "
            "introspection payload's result appearing in the response."
        ),
        "business_impact": (
            "Most template engines allow escaping the sandbox to arbitrary "
            "code execution - SSTI is routinely a direct path to full remote "
            "code execution on the application server."
        ),
        "remediation": (
            "Never render user input as a template string; pass it only as "
            "template *data* (variables), and keep the template engine's "
            "sandboxing/autoescape settings on their strictest default."
        ),
    }),
    (("crlf",), {
        "mechanism": (
            "Injected ``\\r\\n`` sequences in a header-bound parameter split "
            "the HTTP response, confirmed by attacker-controlled headers/body "
            "appearing in the raw response."
        ),
        "business_impact": (
            "Response splitting enables HTTP response smuggling, cache "
            "poisoning and reflected XSS via injected headers - undermining "
            "the integrity of what every downstream cache/proxy/browser "
            "believes the server actually said."
        ),
        "remediation": (
            "Strip or reject CR/LF characters from any value written into a "
            "response header, and use a framework's structured header API "
            "instead of manual string concatenation."
        ),
    }),
    (("jndi", "log4shell"), {
        "mechanism": (
            "A JNDI lookup expression (``${jndi:ldap://...}``-style) placed in "
            "a commonly-logged field triggered an outbound lookup to an "
            "attacker-controlled directory server."
        ),
        "business_impact": (
            "Log4Shell-class JNDI injection is unauthenticated remote code "
            "execution reachable from a single logged HTTP header - among the "
            "most severe vulnerability classes disclosed in recent years, with "
            "mass internet-wide exploitation within hours of disclosure."
        ),
        "remediation": (
            "Patch the logging library to a version with JNDI lookups disabled "
            "by default, and block outbound LDAP/RMI from the application tier "
            "at the network layer as defense in depth."
        ),
    }),
    (("ldap injection",), {
        "mechanism": (
            "LDAP filter metacharacters injected into a search/bind parameter "
            "altered the query's logic, confirmed by a boolean-differential "
            "response."
        ),
        "business_impact": (
            "LDAP injection can bypass authentication against the directory "
            "service or exfiltrate its contents (user accounts, group "
            "membership) - a direct compromise of the organization's "
            "identity backbone."
        ),
        "remediation": (
            "Escape LDAP special characters in user input per RFC 4515, or use "
            "a library that parameterizes filters instead of concatenating "
            "them."
        ),
    }),
    (("insecure deserialization", "deserialization"), {
        "mechanism": (
            "A crafted serialized object was accepted and deserialized by the "
            "application, confirmed by an observable side effect (timing, "
            "error signature, or callback) consistent with gadget-chain "
            "execution."
        ),
        "business_impact": (
            "Insecure deserialization is frequently a direct path to remote "
            "code execution via known gadget chains in the platform's "
            "standard library or common dependencies - full host compromise "
            "with no prior authentication in many cases."
        ),
        "remediation": (
            "Never deserialize untrusted data with a general-purpose "
            "deserializer; use a data-only format (JSON) with strict schema "
            "validation, or a signed/allow-listed deserialization mode."
        ),
    }),
    (("missing security header",), {
        "mechanism": (
            "A defense-in-depth HTTP security header (CSP, X-Frame-Options, "
            "HSTS, X-Content-Type-Options, ...) was absent or misconfigured on "
            "the response."
        ),
        "business_impact": (
            "Missing headers rarely stand alone as a breach vector, but each "
            "one removes a layer of defense-in-depth against clickjacking, "
            "MIME-sniffing and downgrade attacks - raising both the likelihood "
            "and blast radius of any other finding in this report."
        ),
        "remediation": (
            "Set the missing header at the framework or reverse-proxy layer "
            "with a conservative default policy, and verify it with an "
            "automated header-policy check in CI."
        ),
    }),
    (("information disclosure",), {
        "mechanism": (
            "A response header or body revealed internal implementation "
            "detail (software version, stack trace, internal path) beyond "
            "what the endpoint's function requires."
        ),
        "business_impact": (
            "Disclosed version/technology fingerprints accelerate an "
            "attacker's reconnaissance phase, directly shortening the time to "
            "a targeted exploit for every other finding in this engagement."
        ),
        "remediation": (
            "Suppress verbose banners/stack traces in production "
            "configuration, and return generic error pages to unauthenticated "
            "clients."
        ),
    }),
]


def _lookup_kb(vuln_type: str) -> dict[str, str]:
    haystack = vuln_type.lower()
    for needles, entry in _VULN_KB:
        if any(needle in haystack for needle in needles):
            return entry
    return _DEFAULT_KB


def _enrich_finding(v: dict[str, Any]) -> dict[str, Any]:
    """Merge a raw vulnerability dict with confidence, confirmation status,
    secret masking and the technical/business knowledge-base text."""
    cleaned = _mask_vuln(v)
    vuln_type = str(cleaned.get("type") or cleaned.get("name") or "Unknown")
    kb = _lookup_kb(vuln_type)
    parameter = cleaned.get("parameter") or cleaned.get("param") or ""
    cleaned["confidence"] = _confidence_of(cleaned)
    cleaned["risk_level"] = _risk_level_of(cleaned)
    cleaned["confirmation_status"] = _confirmation_status(cleaned)
    cleaned["vector"] = (
        f"{cleaned.get('url', '')} (parameter: {parameter})"
        if parameter else str(cleaned.get("url", ""))
    )
    cleaned.setdefault("payload", "N/A")
    cleaned["technical_mechanism"] = kb["mechanism"]
    cleaned["business_impact"] = kb["business_impact"]
    cleaned["remediation"] = kb["remediation"]
    return cleaned


# ---------------------------------------------------------------------------
# Structured report assembly (shared by both output formats)
# ---------------------------------------------------------------------------


_EXPLOIT_MASKED_FIELDS = ("confirmation_evidence",)


def _mask_exploit_attempt(attempt: dict[str, Any]) -> dict[str, Any]:
    """Redact secrets from a Proof-of-Impact attempt's free-text evidence.

    ``adaptive_payload`` is deliberately left untouched (same policy as a
    vulnerability's ``payload`` field) — the exact PoC vector must stay
    reproducible.
    """
    cleaned = dict(attempt)
    for key in _EXPLOIT_MASKED_FIELDS:
        if key in cleaned:
            cleaned[key] = mask_secrets(cleaned[key])
    return cleaned


def _build_critical_impact_evidence(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Assemble the "Critical Impact Evidence & WAF Bypass Telemetry" section.

    One structured entry per adaptive exploit-engine attempt (see
    :mod:`~.modules.exploit_engine`) that reached ``CONFIRMED_EXPLOITABLE`` --
    a deterministic, non-destructive evidence marker (an arithmetic tell like
    ``49`` from ``{{7*7}}``, a reproduced response-latency delay, ...)
    independently reproduced on replay. Each entry records the affected
    vector, the exact successful payload -- including the WAF-evasion
    technique that was required to deliver it past a perimeter block, when
    one was -- and the verified marker itself, for direct executive/PDF
    consumption. Never derived from a real command executed against the
    host: the underlying probe is capped at ``max_intrusion="low"`` and
    excludes destructive vectors outright (see ``ExploitEngine``).
    """
    attempts = scan_data.get("proof_of_impact") or []
    evidence: list[dict[str, Any]] = []
    for raw in attempts:
        if raw.get("classification") != "CONFIRMED_EXPLOITABLE":
            continue
        a = _mask_exploit_attempt(raw)
        parameter = a.get("parameter") or ""
        evidence.append({
            "vulnerability_class": a.get("vulnerability_class"),
            "affected_vector": (
                f"{a.get('url', '')} (parameter: {parameter})" if parameter else str(a.get("url", ""))
            ),
            "successful_payload": a.get("adaptive_payload"),
            "verified_marker": a.get("verified_marker"),
            "waf_evasion_technique": a.get("waf_evasion_technique"),
            "waf_bypass_confirmed": bool(a.get("waf_bypass_confirmed", False)),
            "impact_validation": a.get("confirmation_evidence"),
            "impact_analysis": a.get("impact_analysis"),
        })
    return evidence


def _build_proof_of_impact(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Assemble the "Proof-of-Impact & Exploitation Evidence" section from
    the adaptive exploit engine's audit trail (``scan_data['proof_of_impact']``,
    populated only when ``--enable-exploit-engine`` was used)."""
    attempts = [_mask_exploit_attempt(a) for a in (scan_data.get("proof_of_impact") or [])]
    return {
        "total_attempts": len(attempts),
        "confirmed_exploitable": sum(
            1 for a in attempts if a.get("classification") == "CONFIRMED_EXPLOITABLE"
        ),
        "potential": sum(1 for a in attempts if a.get("classification") == "POTENTIAL"),
        "safe": sum(1 for a in attempts if a.get("classification") == "SAFE"),
        "attempts": attempts,
    }


def build_structured_report(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Build the full machine-readable engagement report from ``scan_data``
    (the dict returned by :meth:`WebSecurityScanner.run_scan`).
    """
    vulns = [_enrich_finding(v) for v in _sorted_vulns(scan_data.get("vulnerabilities", []))]
    recon = scan_data.get("recon") or {}
    risk_matrix = _risk_matrix(vulns)

    report: dict[str, Any] = {
        "report_metadata": {
            "generator": SCANNER_NAME,
            "generator_version": SCANNER_VERSION,
            "generated_at": datetime.now().isoformat(),
            "engagement_target": scan_data.get("target"),
            "scan_profile": scan_data.get("profile"),
        },
        "executive_summary": {
            "total_findings": len(vulns),
            "risk_matrix": risk_matrix,
            "confirmed_findings": sum(
                1 for v in vulns if v["confirmation_status"] == "CONFIRMED"
            ),
            "banner_only_findings": sum(
                1 for v in vulns if v["confirmation_status"] == "BANNER_ONLY"
            ),
            "technologies_detected": sum(
                len(t) for t in scan_data.get("technologies", {}).values()
            ),
        },
        "attack_surface": {
            "prioritized_targets": recon.get("priority_targets", []),
            "surface_priority_summary": recon.get("surface_priority", {}),
            "subdomains": recon.get("subdomains", []),
            "js_endpoints": recon.get("js_endpoints", []),
            "sitemap_urls": recon.get("sitemap_urls", []),
        },
        "sensitive_files": recon.get("sensitive_files", []),
        "server_fingerprint": recon.get("server_fingerprint"),
        "technologies": scan_data.get("technologies", {}),
        "statistics": scan_data.get("statistics", {}),
        # "vulnerabilities" is the canonical, backward-compatible key consumed
        # by tools/eval_oracle.py and tools/run_experiments.py.
        "vulnerabilities": vulns,
        "proof_of_impact": _build_proof_of_impact(scan_data),
        "critical_impact_evidence": _build_critical_impact_evidence(scan_data),
    }
    # LLM triage audit trail (present only when --enable-ai-triaging was used);
    # tools/eval_oracle.py reads it to score the real false-positive
    # suppression rate and any false negatives the model introduced.
    if scan_data.get("ai_triage") is not None:
        report["ai_triage"] = scan_data["ai_triage"]
    return report


def generate_json_report(scan_data: dict[str, Any], output_dir: str = "reports") -> str:
    """Write the structured JSON report and return its path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"scan_{_timestamp()}.json"
    payload = build_structured_report(scan_data)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return str(path)


# ---------------------------------------------------------------------------
# PDF report (ReportLab)
# ---------------------------------------------------------------------------

_RISK_COLOR = {
    "Critical": colors.HexColor("#8B0000"),
    "High": colors.HexColor("#D35400"),
    "Medium": colors.HexColor("#B8860B"),
    "Low": colors.HexColor("#2874A6"),
    "Informational": colors.HexColor("#616161"),
}


def _p(value: Any) -> str:
    """Escape a dynamic value for safe embedding in a ReportLab Paragraph.

    ReportLab's ``Paragraph`` interprets a small XML-like markup subset; every
    attacker-influenced field (URL, payload, evidence, parameter name) is
    escaped here so a hostile probe response can never corrupt the report's
    markup or masquerade as report-generated content.
    """
    text = str(value) if value is not None else ""
    return _xml_escape(text).replace("\n", "<br/>")


def _pdf_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle(
            "ReportTitle", parent=base["Title"], fontSize=24, leading=28,
            spaceAfter=12,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle", parent=base["Normal"], fontSize=13, leading=18,
            textColor=colors.HexColor("#444444"), alignment=TA_CENTER,
        ),
        "h1": ParagraphStyle(
            "H1", parent=base["Heading1"], fontSize=16, spaceBefore=12, spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"], fontSize=13, spaceBefore=10, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontSize=9.5, leading=13,
        ),
        "mono": ParagraphStyle(
            "Mono", parent=base["Code"], fontSize=8.5, leading=11,
            backColor=colors.HexColor("#F2F2F2"), borderPadding=4,
        ),
        "meta": ParagraphStyle(
            "Meta", parent=base["Normal"], fontSize=10, leading=14,
        ),
    }
    return styles


def _pdf_cover(report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    meta = report["report_metadata"]
    story: list[Any] = [
        Spacer(1, 4 * cm),
        Paragraph("Web Application Security Assessment", styles["title"]),
        Paragraph("Executive &amp; Technical Report", styles["subtitle"]),
        Spacer(1, 2 * cm),
    ]
    rows = [
        ["Engagement target", _p(meta.get("engagement_target"))],
        ["Scan profile", _p(meta.get("scan_profile"))],
        ["Report generated", _p(meta.get("generated_at"))],
        ["Generated by", f"{_p(meta.get('generator'))} v{_p(meta.get('generator_version'))}"],
    ]
    table = Table(
        [[Paragraph(f"<b>{k}</b>", styles["meta"]), Paragraph(v, styles["meta"])] for k, v in rows],
        colWidths=[5.5 * cm, 9.5 * cm],
    )
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F2F2F2")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(table)
    story.append(Spacer(1, 1.5 * cm))
    story.append(Paragraph(
        "CONFIDENTIAL - authorized security testing engagement. This report "
        "contains vulnerability details and must be handled under the "
        "engagement's confidentiality agreement.",
        styles["body"],
    ))
    return story


def _pdf_executive_summary(report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    summary = report["executive_summary"]
    matrix = summary["risk_matrix"]
    story: list[Any] = [Paragraph("Executive Summary", styles["h1"])]
    story.append(Paragraph(
        f"This engagement produced <b>{summary['total_findings']}</b> finding(s) "
        f"across <b>{summary['technologies_detected']}</b> fingerprinted "
        f"technology component(s). <b>{summary['confirmed_findings']}</b> "
        f"finding(s) were actively confirmed; "
        f"<b>{summary['banner_only_findings']}</b> are banner-derived and "
        f"pending active confirmation.",
        styles["body"],
    ))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("Risk Matrix", styles["h2"]))
    header = ["Critical", "High", "Medium", "Low", "Informational"]
    counts = [str(matrix.get(level, 0)) for level in header]
    matrix_table = Table([header, counts], colWidths=[3 * cm] * 5)
    matrix_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BACKGROUND", (0, 1), (0, 1), _RISK_COLOR["Critical"]),
        ("BACKGROUND", (1, 1), (1, 1), _RISK_COLOR["High"]),
        ("BACKGROUND", (2, 1), (2, 1), _RISK_COLOR["Medium"]),
        ("BACKGROUND", (3, 1), (3, 1), _RISK_COLOR["Low"]),
        ("BACKGROUND", (4, 1), (4, 1), _RISK_COLOR["Informational"]),
        ("TEXTCOLOR", (0, 1), (-1, 1), colors.white),
    ]))
    story.append(matrix_table)

    surface = report["attack_surface"]["surface_priority_summary"]
    if surface:
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph("Attack Surface Priority", styles["h2"]))
        levels = [lvl for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if lvl in surface]
        story.append(Paragraph(
            ", ".join(f"<b>{lvl}</b>: {_p(surface[lvl])}" for lvl in levels),
            styles["body"],
        ))

    sensitive_files = report["sensitive_files"]
    if sensitive_files:
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph("Sensitive Files Detected", styles["h2"]))
        rows = [["Risk", "URL", "Category"]] + [
            [_p(f.get("risk")), _p(f.get("url")), _p(f.get("category"))]
            for f in sensitive_files[:20]
        ]
        t = Table(
            [[Paragraph(c, styles["body"]) for c in row] for row in rows],
            colWidths=[2 * cm, 10.5 * cm, 3.5 * cm],
        )
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEEEEE")),
        ]))
        story.append(t)

    fingerprint = report["server_fingerprint"]
    if fingerprint:
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph("Server / Infrastructure Fingerprint", styles["h2"]))
        for fp in fingerprint.get("fingerprints", []):
            story.append(Paragraph(
                f"&#8226; {_p(fp.get('header'))}: <b>{_p(fp.get('product'))}</b> "
                f"{_p(fp.get('version') or '')}",
                styles["body"],
            ))

    return story


def _pdf_findings(report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    story: list[Any] = [Paragraph("Detailed Findings", styles["h1"])]
    vulns = report["vulnerabilities"]
    if not vulns:
        story.append(Paragraph("No vulnerabilities were found during this engagement.", styles["body"]))
        return story

    for i, v in enumerate(vulns, 1):
        risk_level = v["risk_level"]
        color = _RISK_COLOR.get(risk_level, _RISK_COLOR["Informational"])
        header_style = ParagraphStyle(
            f"Finding{i}", parent=styles["h2"], textColor=color,
        )
        story.append(Paragraph(
            f"{i}. {_p(v.get('type') or v.get('name') or 'Unknown')} "
            f"[{_p(risk_level)} / {_p(v['confidence'])} / {_p(v['confirmation_status'])}]",
            header_style,
        ))
        rows = [
            ["Vector / URL", _p(v.get("vector"))],
            ["Payload / Probe applied", _p(v.get("payload"))],
            ["Technical mechanism", _p(v.get("technical_mechanism"))],
            ["Business impact", _p(v.get("business_impact"))],
            ["Remediation", _p(v.get("remediation"))],
        ]
        if v.get("evidence"):
            rows.append(["Evidence", _p(v.get("evidence"))])
        table = Table(
            [[Paragraph(f"<b>{k}</b>", styles["body"]), Paragraph(val, styles["body"])]
             for k, val in rows],
            colWidths=[3.5 * cm, 11.5 * cm],
        )
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
        story.append(Spacer(1, 0.5 * cm))
    return story


_EXPLOIT_CLASSIFICATION_COLOR = {
    "CONFIRMED_EXPLOITABLE": colors.HexColor("#8B0000"),
    "POTENTIAL": colors.HexColor("#B8860B"),
    "SAFE": colors.HexColor("#2E7D32"),
}


def _pdf_proof_of_impact(report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    """"Proof-of-Impact & Exploitation Evidence" section: one entry per
    adaptive exploit-engine attempt (see ``modules.exploit_engine``), detailing
    the vector, the technology-adapted payload used, the confirmation
    response and the business-impact analysis of a real exploitation."""
    story: list[Any] = [Paragraph("Proof-of-Impact &amp; Exploitation Evidence", styles["h1"])]
    poi = report["proof_of_impact"]
    attempts = poi["attempts"]
    if not attempts:
        story.append(Paragraph(
            "No adaptive exploitation attempts were run for this engagement "
            "(enable with --enable-exploit-engine).",
            styles["body"],
        ))
        return story

    story.append(Paragraph(
        f"<b>{poi['total_attempts']}</b> non-destructive Proof-of-Impact probe(s) "
        f"attempted against the highest-value (CRITICAL/HIGH) attack-surface "
        f"targets: <b>{poi['confirmed_exploitable']}</b> confirmed exploitable, "
        f"<b>{poi['potential']}</b> potential (requiring manual review), "
        f"<b>{poi['safe']}</b> came back clean.",
        styles["body"],
    ))
    story.append(Spacer(1, 0.3 * cm))

    for i, a in enumerate(attempts, 1):
        classification = str(a.get("classification", "SAFE"))
        color = _EXPLOIT_CLASSIFICATION_COLOR.get(classification, colors.HexColor("#616161"))
        header_style = ParagraphStyle(f"Exploit{i}", parent=styles["h2"], textColor=color)
        story.append(Paragraph(
            f"{i}. {_p(a.get('vulnerability_class'))} on {_p(a.get('url'))} [{_p(classification)}]",
            header_style,
        ))
        tech = a.get("technology_context") or {}
        rows = [
            ["Injection vector", f"{_p(a.get('vector'))}:{_p(a.get('parameter'))}"],
            ["Adaptive payload used", _p(a.get("adaptive_payload"))],
            ["Payload category", _p(a.get("payload_category"))],
            ["Technology context", _p(
                f"language={tech.get('language')}, database={tech.get('database')}, "
                f"server={tech.get('server')}"
            )],
            ["Confirmation evidence", _p(a.get("confirmation_evidence"))],
            ["Impact on the business", _p(a.get("impact_analysis"))],
            ["Surface priority", _p(f"{a.get('surface_priority')} (score {a.get('surface_score')})")],
        ]
        table = Table(
            [[Paragraph(f"<b>{k}</b>", styles["body"]), Paragraph(v, styles["body"])]
             for k, v in rows],
            colWidths=[3.5 * cm, 11.5 * cm],
        )
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
        story.append(Spacer(1, 0.5 * cm))
    return story


def _pdf_critical_impact_evidence(report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    """"Critical Impact Evidence & WAF Bypass Telemetry" section: one entry
    per confirmed-exploitable Proof-of-Impact attempt (see
    ``modules.exploit_engine``), presenting the affected vector, the exact
    successful payload, the WAF-evasion technique that delivered it past a
    perimeter block (when one was needed) and the verified response marker
    -- the strongest, executive-facing evidence class this engagement
    produces, built entirely from safe, non-destructive probes."""
    story: list[Any] = [Paragraph("Critical Impact Evidence &amp; WAF Bypass Telemetry", styles["h1"])]
    entries = report.get("critical_impact_evidence") or []
    if not entries:
        story.append(Paragraph(
            "No confirmed-exploitable Proof-of-Impact marker was reproduced for "
            "this engagement.",
            styles["body"],
        ))
        return story

    bypassed_count = sum(1 for e in entries if e.get("waf_bypass_confirmed"))
    story.append(Paragraph(
        f"<b>{len(entries)}</b> finding(s) reached <b>CONFIRMED_EXPLOITABLE</b> -- a "
        "deterministic, non-destructive impact marker independently reproduced "
        f"on replay. <b>{bypassed_count}</b> of them required bypassing a "
        "perimeter WAF block via an adaptive lexical-mutation retry before the "
        "marker could be confirmed.",
        styles["body"],
    ))
    story.append(Spacer(1, 0.3 * cm))

    for i, e in enumerate(entries, 1):
        header_style = ParagraphStyle(
            f"CriticalImpact{i}", parent=styles["h2"],
            textColor=_EXPLOIT_CLASSIFICATION_COLOR["CONFIRMED_EXPLOITABLE"],
        )
        story.append(Paragraph(
            f"{i}. {_p(e.get('vulnerability_class'))} - {_p(e.get('affected_vector'))}",
            header_style,
        ))
        technique = e.get("waf_evasion_technique")
        waf_row = (
            f"Perimeter block bypassed via <b>{_p(technique)}</b> lexical mutation."
            if e.get("waf_bypass_confirmed") and technique
            else "No WAF perimeter block was encountered; direct delivery."
        )
        rows = [
            ["Successful payload", _p(e.get("successful_payload"))],
            ["Verified response marker", _p(e.get("verified_marker"))],
            ["WAF bypass telemetry", waf_row],
            ["Impact validation", _p(e.get("impact_validation"))],
            ["Business impact", _p(e.get("impact_analysis"))],
        ]
        table = Table(
            [[Paragraph(f"<b>{k}</b>", styles["body"]), Paragraph(val, styles["body"])]
             for k, val in rows],
            colWidths=[3.5 * cm, 11.5 * cm],
        )
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
        story.append(Spacer(1, 0.5 * cm))
    return story


def generate_pdf_report(scan_data: dict[str, Any], output_dir: str = "reports") -> str:
    """Write the executive/technical PDF report and return its path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"scan_{_timestamp()}.pdf"
    report = build_structured_report(scan_data)
    styles = _pdf_styles()

    doc = SimpleDocTemplate(
        str(path), pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm,
        title=f"Security Assessment Report - {report['report_metadata'].get('engagement_target') or ''}",
    )
    story: list[Any] = []
    story += _pdf_cover(report, styles)
    story.append(PageBreak())
    story += _pdf_executive_summary(report, styles)
    story.append(PageBreak())
    story += _pdf_findings(report, styles)
    story.append(PageBreak())
    story += _pdf_proof_of_impact(report, styles)
    story.append(PageBreak())
    story += _pdf_critical_impact_evidence(report, styles)
    doc.build(story)
    return str(path)


# ---------------------------------------------------------------------------
# Format dispatch
# ---------------------------------------------------------------------------

_GENERATORS = {
    "json": generate_json_report,
    "pdf": generate_pdf_report,
}


def generate_reports(scan_data: dict[str, Any], formats: list[str], output_dir: str = "reports") -> dict[str, str]:
    """Generate the requested report formats; returns {format: path}."""
    paths: dict[str, str] = {}
    for fmt in formats:
        generator = _GENERATORS.get(fmt)
        if generator is not None:
            paths[fmt] = generator(scan_data, output_dir)
    return paths


async def generate_reports_async(scan_data: dict[str, Any], formats: list[str],
                                 output_dir: str = "reports") -> dict[str, str]:
    """
    Non-blocking version of :func:`generate_reports`.

    Report rendering and the synchronous disk writes are run in a worker
    thread via ``asyncio.to_thread`` so calling this from within the running
    event loop (the CLI does) never blocks it.
    """
    return await asyncio.to_thread(generate_reports, scan_data, formats, output_dir)
