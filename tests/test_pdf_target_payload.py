"""Checks that PDF findings keep the affected URL and probe together."""

from reportlab.platypus import Table

from web_security_scanner.report_generator import (
    _pdf_findings,
    _pdf_styles,
    build_structured_report,
    generate_pdf_report,
)


def test_pdf_finding_groups_url_parameter_and_exact_payload(tmp_path):
    scan = {
        "target": "http://example.test/",
        "vulnerabilities": [{
            "type": "Cross-Site Scripting (XSS)",
            "url": "http://example.test/search?q=example&source=web",
            "parameter": "q",
            "payload": "<script>alert('x&y')</script>",
            "severity": "High",
        }],
    }
    report = build_structured_report(scan)
    table = next(item for item in _pdf_findings(report, _pdf_styles()) if isinstance(item, Table))
    label, details = table._cellvalues[0]
    assert label.getPlainText() == "Target and payload"
    text = details.getPlainText()
    assert "http://example.test/search?q=example&source=web (parameter: q)" in text
    assert "<script>alert('x&y')</script>" in text
    assert generate_pdf_report(scan, output_dir=str(tmp_path)).endswith(".pdf")
