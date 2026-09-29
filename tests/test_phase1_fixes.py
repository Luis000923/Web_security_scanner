"""Unit tests for the Phase 1 fixes from PLAN_DESARROLLO.md:

* xss_tester_async: javascript:/data: href/src sink detection
* csrf_tester_async: sensitive GET forms + logout links without a token
* path_traversal_async: traversal via URL path segments (no query params)
* idor_tester_async: multi-user data exposure in a feed/listing endpoint
"""

from conftest import collect_vulns, param_value

from web_security_scanner.modules.vulnerability_testers.csrf_tester_async import CSRFTester
from web_security_scanner.modules.vulnerability_testers.idor_tester_async import IDORTester
from web_security_scanner.modules.vulnerability_testers.path_traversal_async import (
    PathTraversalTester,
)
from web_security_scanner.modules.vulnerability_testers.xss_tester_async import XSSTester


# ---- XSS: javascript:/data: href sink --------------------------------------

async def test_xss_javascript_href_sink_detected():
    def r(m, u, kw):
        q = param_value(u, "q")
        return {
            "text": f'<html><a href="{q}">click</a></html>',
            "headers": {"Content-Type": "text/html"},
        }
    found = await collect_vulns(
        XSSTester, r, target="http://target/page?q=javascript:alert(1)")
    assert found and found[0]["confidence"] == "HIGH"


async def test_xss_javascript_not_in_href_context_not_flagged_by_sink_rule():
    """javascript:alert(1) reflected as plain text (not inside href/src) has
    no dangerous chars either -- still not a finding via the sink rule."""
    def r(m, u, kw):
        q = param_value(u, "q")
        if q != "javascript:alert(1)":
            return {"text": "<html>no reflection here</html>",
                     "headers": {"Content-Type": "text/html"}}
        return {
            "text": f"<html>you searched: {q}</html>",
            "headers": {"Content-Type": "text/html"},
        }
    found = await collect_vulns(
        XSSTester, r, target="http://target/page?q=javascript:alert(1)")
    assert found == []


async def test_xss_data_uri_src_sink_capped_low_outside_html():
    def r(m, u, kw):
        q = param_value(u, "q")
        return {
            "text": '{"src": "' + q + '"}',
            "headers": {"Content-Type": "application/json"},
        }
    found = await collect_vulns(
        XSSTester, r, target="http://target/page?q=data:text/html,<script>alert(1)</script>")
    assert found and found[0]["confidence"] == "LOW"


# ---- CSRF: sensitive GET forms + logout links -------------------------------

async def test_csrf_sensitive_get_form_without_token_flagged():
    def r(m, u, kw):
        return {"text": '<form method="GET" action="/logout"><input name="x"></form>'}
    found = await collect_vulns(CSRFTester, r, target="http://target/page")
    assert len(found) == 1
    assert found[0]["confidence"] == "MEDIUM"
    assert found[0]["url"] == "/logout"


async def test_csrf_sensitive_get_form_with_token_not_flagged():
    def r(m, u, kw):
        return {
            "text": ('<form method="GET" action="/logout">'
                     '<input name="csrf_token" value="tok"></form>')
        }
    found = await collect_vulns(CSRFTester, r, target="http://target/page")
    assert found == []


async def test_csrf_content_submitting_get_form_without_sensitive_keyword_flagged():
    """VUL-008 shape: a GET form that creates content (Gruyere's
    newsnippet2?snippet=...) has no 'delete'/'logout'-like action keyword,
    but still submits real data and must be flagged."""
    def r(m, u, kw):
        return {"text": '<form method="GET" action="/newsnippet2">'
                         '<input name="snippet"></form>'}
    found = await collect_vulns(CSRFTester, r, target="http://target/newsnippet.gtl")
    assert len(found) == 1
    assert found[0]["url"] == "/newsnippet2"


async def test_csrf_plain_get_form_not_flagged():
    """A GET form whose action isn't sensitive (search, filter, ...) is not
    inherently a CSRF concern -- must not be reported."""
    def r(m, u, kw):
        return {"text": '<form method="GET" action="/search"><input name="q"></form>'}
    found = await collect_vulns(CSRFTester, r, target="http://target/page")
    assert found == []


async def test_csrf_logout_link_without_token_flagged():
    def r(m, u, kw):
        return {"text": '<a href="/logout">Sign out</a>'}
    found = await collect_vulns(CSRFTester, r, target="http://target/page")
    assert len(found) == 1
    assert found[0]["url"] == "/logout"
    assert found[0]["confidence"] == "MEDIUM"


async def test_csrf_logout_link_with_token_not_flagged():
    def r(m, u, kw):
        return {"text": '<a href="/logout?csrf_token=abc">Sign out</a>'}
    found = await collect_vulns(CSRFTester, r, target="http://target/page")
    assert found == []


# ---- Path Traversal: URL-path-segment injection -----------------------------

async def test_path_traversal_no_query_params_tries_path_segment():
    def r(m, u, kw):
        if "%2f" in u.lower().split("/")[-1] or ".." in u:
            return {"text": "root:x:0:0:root:/root:/bin/bash"}
        return {"text": "normal file contents"}
    found = await collect_vulns(
        PathTraversalTester, r, target="http://target/static/report.pdf")
    assert len(found) == 1
    assert found[0]["parameter"] == "<path>"


async def test_path_traversal_no_query_params_and_no_leak_no_finding():
    def r(m, u, kw):
        return {"text": "just a normal file"}
    found = await collect_vulns(
        PathTraversalTester, r, target="http://target/static/report.pdf")
    assert found == []


async def test_path_traversal_root_url_no_segment_skips_path_test():
    """A bare root path has no file-serving-shaped last segment to
    substitute -- must not crash and must not report anything."""
    def r(m, u, kw):
        return {"text": "root:x:0:0:root:/root:/bin/bash"}
    found = await collect_vulns(PathTraversalTester, r, target="http://target/")
    assert found == []


# ---- IDOR: multi-user feed leak ---------------------------------------------

async def test_idor_feed_multiple_emails_flagged():
    def r(m, u, kw):
        return {
            "status_code": 200,
            "text": "alice@corp.com bob@corp.com carol@corp.com",
        }
    found = await collect_vulns(IDORTester, r, target="http://target/api/users")
    assert len(found) == 1
    assert found[0]["confidence"] == "MEDIUM"


async def test_idor_feed_single_email_not_flagged():
    def r(m, u, kw):
        return {"status_code": 200, "text": "alice@corp.com only, nothing else here"}
    found = await collect_vulns(IDORTester, r, target="http://target/api/profile")
    assert found == []


async def test_idor_feed_check_skipped_when_id_param_present():
    """A URL that already carries an id-like query param goes through the
    alternate-ID heuristic instead; the feed check must not also fire and
    double-report the same endpoint."""
    def r(m, u, kw):
        idv = param_value(u, "id")
        if idv == "benign_baseline_123":
            return {"status_code": 200, "text": "baseline"}
        return {"status_code": 200, "text": "alice@corp.com bob@corp.com carol@corp.com"}
    found = await collect_vulns(IDORTester, r, target="http://target/page?id=1")
    # Only the alternate-ID finding (if any), never a duplicate feed finding.
    assert all(f["parameter"] != "<response-body>" for f in found)
