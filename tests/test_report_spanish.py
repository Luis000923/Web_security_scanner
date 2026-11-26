"""Spanish reports translate presentation without changing probe data."""

from reportlab.platypus import Table

from web_security_scanner.report_generator import (
    _pdf_cover,
    _pdf_findings,
    _pdf_styles,
    build_structured_report,
    generate_pdf_report,
)
from web_security_scanner.utils.i18n import i18n


def test_spanish_report_keeps_payload_and_translates_finding(tmp_path):
    previous = i18n.current_lang
    i18n.current_lang = "es"
    try:
        payload = "<script>alert('x&y')</script>"
        scan = {"target": "http://example.test", "vulnerabilities": [{
            "type": "Cross-Site Scripting (XSS)", "severity": "High",
            "url": "http://example.test/?q=1", "parameter": "q", "payload": payload,
        }]}
        report = build_structured_report(scan)
        finding = report["vulnerabilities"][0]
        assert finding["payload"] == payload
        assert "navegador" in finding["technical_mechanism"]
        styles = _pdf_styles()
        assert "Evaluación de seguridad" in _pdf_cover(report, styles)[1].getPlainText()
        table = next(item for item in _pdf_findings(report, styles) if isinstance(item, Table))
        label, detail = table._cellvalues[0]
        assert label.getPlainText() == "Objetivo y carga"
        assert "parámetro: q" in detail.getPlainText()
        assert payload in detail.getPlainText()
        assert generate_pdf_report(scan, str(tmp_path)).endswith(".pdf")
    finally:
        i18n.current_lang = previous
