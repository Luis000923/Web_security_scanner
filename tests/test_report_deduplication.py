from web_security_scanner.report_generator import _deduplicate_findings


def test_deduplicate_payloads_per_parameter_and_origin_keeps_strongest():
    base = {'type': 'XSS', 'url': 'http://one.test/search?q=one', 'parameter': 'q'}
    findings = [
        {**base, 'payload': 'one', 'severity': 'medium', 'confidence': 'LOW'},
        {**base, 'payload': 'two', 'severity': 'high', 'confidence': 'HIGH'},
        {**base, 'url': 'http://two.test/search?q=one', 'payload': 'three', 'severity': 'high'},
        {**base, 'parameter': 'other', 'payload': 'four', 'severity': 'high'},
    ]
    result = _deduplicate_findings(findings)
    assert len(result) == 3
    assert any(f['payload'] == 'two' for f in result)
    assert not any(f['payload'] == 'one' for f in result)
