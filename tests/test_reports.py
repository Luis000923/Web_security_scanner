"""Report generation hardening tests (Phase 6).

Covers:
* Stored-XSS immunity — a payload injected as a "vulnerability" must land in the
  HTML report as inert, escaped text, never as a live ``<script>`` tag.
* Secret masking — Bearer tokens / cookies / JWTs captured as evidence must be
  redacted from BOTH the JSON and HTML artifacts.
"""

import json
from pathlib import Path

from web_security_scanner.reports import generate_html_report, generate_json_report
from web_security_scanner.utils.validation import mask_secrets

XSS_PAYLOAD = "<script>alert(1)</script>"

SCAN_DATA = {
    "target": "http://target/search?q=<script>alert('t')</script>",
    "profile": "balanced",
    "statistics": {"total_vulnerabilities": 1},
    "technologies": {},
    "vulnerabilities": [
        {
            "type": "XSS",
            "severity": "high",
            "confidence": "HIGH",
            "url": f"http://target/p?x={XSS_PAYLOAD}",
            "parameter": "x\"><img src=x onerror=alert(1)>",
            "payload": XSS_PAYLOAD,
            "evidence": (
                "Reflected in response. Request headers:\n"
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123SECRET\n"
                "Cookie: session=SUPERSECRETVALUE; theme=dark"
            ),
        }
    ],
}


def test_html_report_escapes_xss_payload(tmp_path):
    path = Path(generate_html_report(SCAN_DATA, output_dir=str(tmp_path)))
    html_text = path.read_text(encoding="utf-8")

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text
    # The raw executable tag must never appear anywhere in the document.
    assert "<script>alert(1)</script>" not in html_text
    # Attribute-breakout attempt in the parameter name is neutralised too.
    assert 'onerror=alert(1)>' not in html_text
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_text


def test_reports_mask_bearer_tokens_and_cookies(tmp_path):
    json_path = Path(generate_json_report(SCAN_DATA, output_dir=str(tmp_path)))
    html_path = Path(generate_html_report(SCAN_DATA, output_dir=str(tmp_path)))

    data = json.loads(json_path.read_text(encoding="utf-8"))
    evidence = data["vulnerabilities"][0]["evidence"]
    assert "Authorization: Bearer ***" in evidence
    assert "Cookie: ***" in evidence
    assert "SUPERSECRETVALUE" not in evidence
    assert "abc123SECRET" not in evidence
    assert "***JWT***" in evidence or "Bearer ***" in evidence

    html_text = html_path.read_text(encoding="utf-8")
    assert "SUPERSECRETVALUE" not in html_text
    assert "abc123SECRET" not in html_text


def test_json_structure_is_preserved(tmp_path):
    json_path = Path(generate_json_report(SCAN_DATA, output_dir=str(tmp_path)))
    data = json.loads(json_path.read_text(encoding="utf-8"))
    vuln = data["vulnerabilities"][0]
    for key in ("type", "severity", "confidence", "url", "parameter", "payload", "evidence"):
        assert key in vuln
    # Non-sensitive values are untouched.
    assert vuln["type"] == "XSS"
    assert vuln["payload"] == XSS_PAYLOAD


def test_mask_secrets_is_noop_for_plain_text():
    assert mask_secrets("just a normal evidence string") == "just a normal evidence string"
    assert mask_secrets("") == ""
    assert mask_secrets(None) is None
