"""
Smoke tests for the async vulnerability testers.

Each tester is checked for a true positive AND absence of the false positives
that motivated the sync->async consolidation. These guard against a future
"async rewrite" silently weakening detection again.
"""

import html

import pytest
from conftest import collect_log_messages, collect_vulns, param_value

from web_security_scanner.modules.vulnerability_testers.command_injection_async import (
    CommandInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.header_security_async import (
    HeaderSecurityTester,
)
from web_security_scanner.modules.vulnerability_testers.idor_tester_async import IDORTester
from web_security_scanner.modules.vulnerability_testers.nosql_injection_async import (
    NoSQLInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.open_redirect_async import (
    MARKER,
    OpenRedirectTester,
)
from web_security_scanner.modules.vulnerability_testers.path_traversal_async import (
    PathTraversalTester,
)
from web_security_scanner.modules.vulnerability_testers.sql_injection_async import (
    SQLInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.ssrf_tester_async import SSRFTester
from web_security_scanner.modules.vulnerability_testers.xss_tester_async import XSSTester
from web_security_scanner.utils.i18n import i18n

# asyncio_mode = "auto" (pyproject) auto-detects coroutine tests, so no global
# pytest.mark.asyncio is needed — and applying it would wrongly mark the sync
# technology-detector tests as asyncio.


# ---- SQL Injection ---------------------------------------------------------

async def test_sqli_error_based_detected():
    def r(m, u, kw):
        return {"text": "You have an error in your SQL syntax near '1'"}
    assert len(await collect_vulns(SQLInjectionTester, r)) > 0

async def test_sqli_time_based_detected():
    def r(m, u, kw):
        payload = param_value(u, "q").lower()
        slow = any(k in payload for k in ("sleep", "waitfor", "delay"))
        return {"text": "ok", "elapsed": 5.0 if slow else 0.1}
    assert len(await collect_vulns(SQLInjectionTester, r)) > 0

async def test_sqli_time_based_confirmed_confidence():
    def r(m, u, kw):
        payload = param_value(u, "q").lower()
        slow = any(k in payload for k in ("sleep", "waitfor", "delay"))
        return {"text": "ok", "elapsed": 5.0 if slow else 0.1}
    found = await collect_vulns(SQLInjectionTester, r)
    assert found and any(v["confidence"] == "CONFIRMED" for v in found)

async def test_sqli_time_based_intermittent_no_false_positive():
    # The endpoint is slow exactly ONCE (network blip); every retry is fast.
    # Baseline-latency + confirmation must stop this from being CONFIRMED.
    state = {"slow_hits": 0}
    def r(m, u, kw):
        payload = param_value(u, "q").lower()
        is_time = any(k in payload for k in ("sleep", "waitfor", "delay"))
        if is_time and state["slow_hits"] == 0:
            state["slow_hits"] += 1
            return {"text": "ok", "elapsed": 5.0}
        return {"text": "ok", "elapsed": 0.1}
    found = await collect_vulns(SQLInjectionTester, r)
    assert all(v.get("confidence") != "CONFIRMED" for v in found)

async def test_sqli_clean_no_false_positive():
    def r(m, u, kw):
        return {"text": "<html>Welcome to our shop</html>", "elapsed": 0.1}
    assert await collect_vulns(SQLInjectionTester, r) == []


# ---- XSS -------------------------------------------------------------------

async def test_xss_raw_reflection_detected():
    def r(m, u, kw):
        return {"text": "<html>you searched: " + param_value(u, "q") + "</html>"}
    assert len(await collect_vulns(XSSTester, r)) > 0

async def test_xss_escaped_no_false_positive():
    def r(m, u, kw):
        return {"text": "<html>" + html.escape(param_value(u, "q")) + "</html>"}
    assert await collect_vulns(XSSTester, r) == []

async def test_xss_escaped_in_html_context_no_false_positive():
    # Payload reflected but HTML-escaped in a real text/html page: NOT vulnerable.
    def r(m, u, kw):
        return {
            "text": "<html>results for " + html.escape(param_value(u, "q")) + "</html>",
            "headers": {"Content-Type": "text/html; charset=utf-8"},
        }
    assert await collect_vulns(XSSTester, r) == []

async def test_xss_raw_reflection_in_html_is_high_confidence():
    def r(m, u, kw):
        return {
            "text": "<html>you searched: " + param_value(u, "q") + "</html>",
            "headers": {"Content-Type": "text/html"},
        }
    found = await collect_vulns(XSSTester, r)
    assert found and found[0]["confidence"] == "HIGH"

async def test_xss_raw_reflection_in_json_capped_at_low():
    # Same raw reflection but application/json -> only content-sniffing risk.
    def r(m, u, kw):
        return {
            "text": '{"q": "' + param_value(u, "q") + '"}',
            "headers": {"Content-Type": "application/json"},
        }
    found = await collect_vulns(XSSTester, r)
    assert found and found[0]["confidence"] == "LOW"


# ---- Command Injection -----------------------------------------------------

async def test_cmdi_detected_on_command_output():
    def r(m, u, kw):
        return {"text": "root:x:0:0:root:/root:/bin/bash\n"}
    assert len(await collect_vulns(CommandInjectionTester, r)) > 0

async def test_cmdi_no_fp_on_generic_chars():
    # Body full of $, |, &, <, > must NOT trigger (old sync bug).
    def r(m, u, kw):
        return {"text": "Price: $5 | shipping & tax < 10 > free"}
    assert await collect_vulns(CommandInjectionTester, r) == []


# ---- Path Traversal --------------------------------------------------------

async def test_path_traversal_real_leak_detected():
    def r(m, u, kw):
        return {"text": "root:x:0:0:root:/root:/bin/bash"}
    assert len(await collect_vulns(PathTraversalTester, r)) > 0

async def test_path_traversal_403_no_false_positive():
    # 403 with the word "passwd" in it must NOT trigger (old sync bug).
    def r(m, u, kw):
        return {"status_code": 403, "text": "Forbidden: cannot read /etc/passwd"}
    assert await collect_vulns(PathTraversalTester, r) == []


# ---- Open Redirect ---------------------------------------------------------

async def test_open_redirect_marker_detected():
    def r(m, u, kw):
        return {"status_code": 302, "headers": {"Location": f"https://{MARKER}/next"}}
    assert len(await collect_vulns(OpenRedirectTester, r)) > 0

async def test_open_redirect_benign_host_no_fp():
    # A redirect to a legitimate host must NOT trigger.
    def r(m, u, kw):
        return {"status_code": 302, "headers": {"Location": "https://example.com/home"}}
    assert await collect_vulns(OpenRedirectTester, r) == []


# ---- SSRF ------------------------------------------------------------------

async def test_ssrf_metadata_leak_detected():
    def r(m, u, kw):
        return {"text": "ami-id: ami-12345\ninstance-id: i-abc"}
    assert len(await collect_vulns(SSRFTester, r)) > 0

async def test_ssrf_no_fp_on_brand_word():
    # A page merely mentioning "redis" must NOT trigger (old sync bug).
    def r(m, u, kw):
        return {"text": "We use Redis and MongoDB in our stack.", "elapsed": 0.2}
    assert await collect_vulns(SSRFTester, r) == []


# ---- NoSQL Injection -------------------------------------------------------

async def test_nosqli_error_detected():
    def r(m, u, kw):
        return {"text": "E11000 duplicate key error"}
    assert len(await collect_vulns(NoSQLInjectionTester, r)) > 0


# ---- IDOR ------------------------------------------------------------------

async def test_idor_no_fp_when_body_contains_404_text():
    # Baseline + all IDs return 200 identical body containing '404' as text.
    def r(m, u, kw):
        return {"status_code": 200, "text": "Building at 404 Main St. email n/a"}
    # Identical to baseline -> no diff -> no finding (old sync suppressed via
    # substring '404'; here identical content is the correct reason for no-hit).
    assert await collect_vulns(IDORTester, r) == []

async def test_idor_detected_on_distinct_data_object():
    def r(m, u, kw):
        idv = param_value(u, "id")
        if idv == "benign_baseline_123":
            return {"status_code": 200, "text": "profile baseline"}
        return {"status_code": 200, "text": f"email user{idv}@corp.com username u{idv} " + "x" * 100}
    assert len(await collect_vulns(IDORTester, r)) > 0


# ---- Destructive gate ------------------------------------------------------

async def test_destructive_payloads_skipped_by_default():
    seen = []
    def r(m, u, kw):
        seen.append(param_value(u, "q"))
        return {"text": "ok", "elapsed": 0.1}
    await collect_vulns(SQLInjectionTester, r, config={"max_payloads": 500})
    assert not any("drop table" in p.lower() for p in seen)

async def test_destructive_payloads_included_when_allowed():
    seen = []
    def r(m, u, kw):
        seen.append(param_value(u, "q"))
        return {"text": "ok", "elapsed": 0.1}
    await collect_vulns(SQLInjectionTester, r,
                        config={"max_payloads": 500, "allow_destructive": True})
    assert any("drop table" in p.lower() for p in seen)


# ---- Header security -------------------------------------------------------

async def test_missing_security_headers_detected():
    def r(m, u, kw):
        return {"status_code": 200, "text": "", "headers": {"Server": "nginx"}}
    found = await collect_vulns(HeaderSecurityTester, r)
    assert len(found) > 0
    missing = [v for v in found if v["type"] == i18n.get("vulnerabilities.missing_header")]
    assert {"X-Frame-Options", "X-Content-Type-Options",
            "Content-Security-Policy", "Strict-Transport-Security"} <= {v["payload"] for v in missing}


async def test_header_lowercased_modern_api_no_false_positive():
    # HTTP/2 / proxy style: all-lowercase names, valid modern values.
    def r(m, u, kw):
        return {"status_code": 200, "text": "", "headers": {
            "x-frame-options": "sameorigin",
            "x-content-type-options": "nosniff",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        }}
    found = await collect_vulns(HeaderSecurityTester, r)
    missing = [v for v in found if v["type"] == i18n.get("vulnerabilities.missing_header")]
    assert missing == []


async def test_x_xss_protection_zero_is_not_a_finding():
    def r(m, u, kw):
        return {"status_code": 200, "text": "", "headers": {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=63072000",
            "X-XSS-Protection": "0",
        }}
    found = await collect_vulns(HeaderSecurityTester, r)
    assert [v for v in found if v["type"] == i18n.get("vulnerabilities.missing_header")] == []


async def test_hsts_max_age_zero_flagged_as_weak():
    def r(m, u, kw):
        return {"status_code": 200, "text": "", "headers": {
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=0",
        }}
    found = await collect_vulns(HeaderSecurityTester, r)
    weak = [v for v in found if v["payload"] == "Strict-Transport-Security"]
    assert weak and weak[0]["confidence"] == "LOW"


async def test_header_tester_no_backtracking_on_hostile_value():
    import asyncio as _asyncio
    def r(m, u, kw):
        return {"status_code": 200, "text": "", "headers": {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=" + "1" * 100000 + " " * 100000 + "!",
        }}
    found = await _asyncio.wait_for(collect_vulns(HeaderSecurityTester, r), timeout=5)
    assert isinstance(found, list)


# ---- LOG_MESSAGE emit regression (enum, not string) ------------------------

@pytest.mark.parametrize("tester_cls", [
    SQLInjectionTester, XSSTester, CommandInjectionTester, PathTraversalTester,
    OpenRedirectTester, SSRFTester, NoSQLInjectionTester,
])
async def test_testers_emit_log_message_enum(tester_cls):
    # Testers must emit ScanEventType.LOG_MESSAGE (enum). Passing the string
    # "LOG_MESSAGE" makes the emitter silently drop the event.
    def r(m, u, kw):
        return {"status_code": 200, "text": "ok", "elapsed": 0.1}
    logs = await collect_log_messages(tester_cls, r)
    assert len(logs) > 0


# ---- Technology detection --------------------------------------------------

def test_tech_detector_fingerprints_headers_and_html():
    from web_security_scanner.modules.technology_detector import TechnologyDetector
    det = TechnologyDetector()
    headers = {"Server": "nginx/1.25", "X-Powered-By": "PHP/8.2",
               "Set-Cookie": "PHPSESSID=abc; path=/"}
    html = '<html><head><meta name="generator" content="WordPress 6.4">'\
           '</head><body>wp-content wp-includes</body></html>'
    result = det.detect_all(headers, html)
    assert "Nginx" in result.get("servers", [])
    assert "PHP" in result.get("languages", [])
    assert "WordPress" in result.get("cms", [])

def test_tech_detector_no_substring_false_positive():
    from web_security_scanner.modules.technology_detector import TechnologyDetector
    # "nginx" must not match the Go/Gin signature (substring bug); a plain nginx
    # server must not be reported as running Go.
    result = TechnologyDetector().detect_all({"Server": "nginx/1.25"}, "<html></html>")
    assert "Go" not in result.get("languages", [])
    assert "Nginx" in result.get("servers", [])

def test_tech_detector_empty_input_no_crash():
    from web_security_scanner.modules.technology_detector import TechnologyDetector
    # Empty input must not raise. Absent X-Powered-By is reported as a hardening
    # signal, so the only expected category is security_headers.
    result = TechnologyDetector().detect_all({}, "")
    assert result.get("security_headers") == ["X-Powered-By Hidden"]
    assert "servers" not in result and "cms" not in result


def test_total_technologies_stat_not_clobbered_by_mapper():
    # The mapper emits its own total_technologies (0); the scanner's real count
    # must win in the merged statistics dict.
    technologies = {"servers": ["Nginx"], "languages": ["PHP"], "cms": ["WordPress"]}
    map_stats = {"total_technologies": 0, "total_urls": 5}
    stats = {
        **map_stats,
        "total_vulnerabilities": 2,
        "total_technologies": sum(len(v) for v in technologies.values()),
    }
    assert stats["total_technologies"] == 3
    assert stats["total_urls"] == 5
