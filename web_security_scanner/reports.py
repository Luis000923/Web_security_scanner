"""
Report generation for the Web Security Scanner (CLI, no Flask).

Consumes the async scanner's vulnerability format:
    {type, url, parameter, payload, severity, evidence}

Writes timestamped files into an output directory so concurrent scans never
clobber each other (fixes the old fixed-filename-in-cwd collision bug).
"""

import asyncio
import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .utils.validation import mask_secrets


def _e(value: Any) -> str:
    """HTML-escape a dynamic value, quoting so it is safe inside attributes too.

    Every attacker-influenced field (URL, payload, parameter name, evidence
    text) flows through here before it lands in the HTML report, so the scanner
    can never inject working markup into the document a human opens to read it.
    """
    return html.escape(str(value), quote=True)


# Vulnerability fields that may embed request/response fragments and therefore
# the operator's own secrets. Masked before being written to ANY report format.
_MASKED_FIELDS = ("evidence", "request", "response", "headers", "raw", "details")


def _mask_vuln(vuln: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of ``vuln`` with secrets redacted from its text."""
    cleaned = dict(vuln)
    for key in _MASKED_FIELDS:
        if key in cleaned:
            cleaned[key] = mask_secrets(cleaned[key])
    return cleaned


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


CONFIDENCE_ORDER = {"confirmed": 0, "high": 1, "medium": 2, "low": 3}


def _confidence_of(v: dict[str, Any]) -> str:
    """Read a vulnerability's confidence, tolerating old reports without it."""
    raw = v.get("confidence")
    if not raw:
        return "N/A"
    val = str(raw).strip().upper()
    return val if val in ("LOW", "MEDIUM", "HIGH", "CONFIRMED") else "N/A"


def _sorted_vulns(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        vulns,
        key=lambda v: (
            SEVERITY_ORDER.get(str(v.get("severity", "info")).lower(), 5),
            CONFIDENCE_ORDER.get(_confidence_of(v).lower(), 4),
        ),
    )


def generate_json_report(scan_data: dict[str, Any], output_dir: str = "reports") -> str:
    """Write a JSON report and return its path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"scan_{_timestamp()}.json"
    payload = {
        "generated_at": datetime.now().isoformat(),
        "target": scan_data.get("target"),
        "profile": scan_data.get("profile"),
        "statistics": scan_data.get("statistics", {}),
        "technologies": scan_data.get("technologies", {}),
        "vulnerabilities": [
            {**_mask_vuln(v), "confidence": _confidence_of(v)}
            for v in _sorted_vulns(scan_data.get("vulnerabilities", []))
        ],
        "map_report": scan_data.get("map_report"),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return str(path)


def generate_html_report(scan_data: dict[str, Any], output_dir: str = "reports") -> str:
    """Write an HTML report and return its path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"scan_{_timestamp()}.html"

    # Redact operator secrets BEFORE anything is rendered/escaped.
    vulns = [_mask_vuln(v) for v in _sorted_vulns(scan_data.get("vulnerabilities", []))]
    target = _e(scan_data.get("target", ""))
    profile = _e(scan_data.get("profile", ""))

    if vulns:
        rows = "".join(
            "<tr>"
            f"<td class='sev sev-{_e(str(v.get('severity','info')).lower())}'>{_e(v.get('severity',''))}</td>"
            f"<td class='conf conf-{_e(_confidence_of(v).lower().replace('/',''))}'>{_e(_confidence_of(v))}</td>"
            f"<td>{_e(v.get('type',''))}</td>"
            f"<td>{_e(v.get('url',''))}</td>"
            f"<td>{_e(v.get('parameter',''))}</td>"
            f"<td><code>{_e(v.get('payload',''))}</code></td>"
            f"<td>{_e(v.get('evidence',''))}</td>"
            "</tr>"
            for v in vulns
        )
        vulns_table = (
            "<table><tr><th>Severity</th><th>Confidence</th><th>Type</th><th>URL</th>"
            "<th>Parameter</th><th>Payload</th><th>Evidence</th></tr>" + rows + "</table>"
        )
    else:
        vulns_table = "<p class='safe'>No vulnerabilities found.</p>"

    techs = scan_data.get("technologies", {})
    if techs:
        tech_html = "".join(
            f"<li><b>{_e(cat)}:</b> "
            f"{_e(', '.join(str(t) for t in items))}</li>"
            for cat, items in techs.items()
        )
        techs_html = f"<ul>{tech_html}</ul>"
    else:
        techs_html = "<p>None detected.</p>"

    stats = scan_data.get("statistics", {})
    stats_html = "".join(f"<li><b>{_e(k)}:</b> {_e(v)}</li>" for k, v in stats.items())

    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Web Security Scan Report - {target}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#f4f4f4; color:#222; margin:0; padding:20px; }}
  h1 {{ background:#0078d7; color:#fff; padding:12px; border-radius:6px; }}
  .section {{ background:#fff; margin:20px 0; padding:16px; border-radius:8px; box-shadow:0 2px 6px #ccc; }}
  table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
  th,td {{ border:1px solid #ccc; padding:6px 10px; text-align:left; vertical-align:top; font-size:14px; }}
  th {{ background:#eee; }}
  code {{ background:#f0f0f0; padding:1px 4px; border-radius:3px; word-break:break-all; }}
  .safe {{ color:#080; font-weight:bold; }}
  .sev {{ font-weight:bold; text-transform:capitalize; }}
  .sev-critical {{ color:#b10000; }} .sev-high {{ color:#d35400; }}
  .sev-medium {{ color:#c29d00; }} .sev-low {{ color:#2874a6; }} .sev-info {{ color:#555; }}
  .conf {{ font-weight:bold; }}
  .conf-confirmed {{ color:#b10000; }} .conf-high {{ color:#d35400; }}
  .conf-medium {{ color:#c29d00; }} .conf-low {{ color:#2874a6; }} .conf-na {{ color:#999; }}
</style>
</head>
<body>
<h1>Web Security Scan Report</h1>
<div class="section">
  <p><b>Target:</b> {target}</p>
  <p><b>Profile:</b> {profile}</p>
  <p><b>Generated:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
</div>
<div class="section">
  <h2>Vulnerabilities ({len(vulns)})</h2>
  {vulns_table}
</div>
<div class="section">
  <h2>Technologies</h2>
  {techs_html}
</div>
<div class="section">
  <h2>Statistics</h2>
  <ul>{stats_html or '<li>None</li>'}</ul>
</div>
<div class="section">
  <p><i>Generated by Web Security Scanner. For authorized security testing only.</i></p>
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return str(path)


def generate_reports(scan_data: dict[str, Any], formats: list[str], output_dir: str = "reports") -> dict[str, str]:
    """Generate the requested report formats; returns {format: path}."""
    paths: dict[str, str] = {}
    if "json" in formats:
        paths["json"] = generate_json_report(scan_data, output_dir)
    if "html" in formats:
        paths["html"] = generate_html_report(scan_data, output_dir)
    return paths


async def generate_reports_async(scan_data: dict[str, Any], formats: list[str],
                                 output_dir: str = "reports") -> dict[str, str]:
    """
    Non-blocking version of :func:`generate_reports`.

    Report rendering and the synchronous ``open(..., "w")`` disk writes are run
    in a worker thread via ``asyncio.to_thread`` so calling this from within the
    running event loop (the CLI does) never blocks it.
    """
    return await asyncio.to_thread(generate_reports, scan_data, formats, output_dir)
