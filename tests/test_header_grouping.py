"""Security-header findings must be grouped per application, not per URL.

CSP / HSTS / X-Frame-Options / X-Content-Type-Options / ``Server`` leakage are
properties of the origin. Emitting one row per crawled URL turned a 200-page
crawl into ~1000 identical Low/Info records — noise in the report and a heavy
class imbalance in the triage-LLM dataset built from these findings.

Covered here:
* the tester emits one finding per (origin, header) however many URLs it sees,
  while keeping an exact ``occurrences`` count and a bounded URL sample;
* two different origins stay separate;
* the report layer regroups anything that still arrives duplicated.
"""

import json
from pathlib import Path

from conftest import MockScanner

from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.header_security_async import (
    HeaderSecurityTester,
)
from web_security_scanner.reports import generate_json_report, group_findings

NO_HEADERS = {"status_code": 200, "text": "<html>ok</html>",
              "headers": {"Server": "nginx/1.25.3"}}


async def _scan_urls(urls):
    """Run the header tester over several URLs of one crawl; return findings."""
    emitter = ScanEventEmitter()
    found = []
    emitter.on(ScanEventType.VULNERABILITY_FOUND,
               lambda **k: found.append(k.get("vulnerability")))
    tester = HeaderSecurityTester(
        MockScanner(lambda m, u, kw: dict(NO_HEADERS)), emitter,
        {"payload_delay": 0},
    )
    for url in urls:
        await tester.run_test(url)
    return found


async def test_headers_reported_once_per_origin():
    urls = [f"http://target/page{i}" for i in range(25)]
    found = await _scan_urls(urls)

    headers = [v["payload"] for v in found]
    assert sorted(headers) == sorted(set(headers)), "one row per header, not per URL"
    # 4 missing security headers + the leaked Server banner.
    assert set(headers) == {
        "X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy",
        "Strict-Transport-Security", "Server",
    }
    for vuln in found:
        assert vuln["scope"] == "site"
        assert vuln["url"] == "http://target"
        assert vuln["occurrences"] == 25
        # The URL sample is bounded even though 25 pages were scanned.
        assert 0 < len(vuln["affected_urls"]) <= 10


async def test_distinct_origins_are_not_merged():
    found = await _scan_urls(["http://a.target/x", "http://b.target/y"])
    csp = [v for v in found if v["payload"] == "Content-Security-Policy"]
    assert len(csp) == 2
    assert {v["host"] for v in csp} == {"http://a.target", "http://b.target"}
    assert all(v["occurrences"] == 1 for v in csp)


def test_group_findings_collapses_duplicates_from_older_runs():
    vulns = [
        {"type": "Missing Security Header", "url": f"http://target/p{i}",
         "payload": "Content-Security-Policy", "severity": "Low",
         "group_key": "header:http://target:Missing Security Header:Content-Security-Policy"}
        for i in range(50)
    ]
    grouped = group_findings(vulns)
    assert len(grouped) == 1
    assert grouped[0]["occurrences"] == 50
    assert grouped[0]["url"] == "http://target"
    assert len(grouped[0]["affected_urls"]) <= 10


def test_group_findings_never_merges_parameter_level_vulns():
    vulns = [
        {"type": "SQL Injection", "url": "http://target/item?id=1",
         "parameter": "id", "severity": "High"},
        {"type": "SQL Injection", "url": "http://target/item?id=2",
         "parameter": "id", "severity": "High"},
    ]
    assert group_findings(vulns) == vulns


async def test_json_report_carries_one_grouped_header_row(tmp_path):
    found = await _scan_urls([f"http://target/page{i}" for i in range(12)])
    path = Path(generate_json_report(
        {"target": "http://target", "vulnerabilities": found},
        output_dir=str(tmp_path),
    ))
    data = json.loads(path.read_text(encoding="utf-8"))
    csp = [v for v in data["vulnerabilities"]
           if v.get("payload") == "Content-Security-Policy"]
    assert len(csp) == 1
    assert csp[0]["occurrences"] == 12
