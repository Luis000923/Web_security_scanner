"""Tests for Architecture Refactor & False Positive Reduction Engine.

Validates:
1. Unified InjectionPoint abstraction across GET, POST (url-encoded), POST (JSON),
   POST (multipart/form-data with fields and file upload headers/filename), and HTTP Headers.
2. Decoupled AsyncHTTPClient with connection pool, semaphore concurrency limits,
   rate limiting, and exponential backoff retries.
3. Three-state differential analysis (R_base, R_noop, R_test) with Levenshtein and DOM SimHash.
4. Response inspection: Soft 404 and fake 200 OK error detection.
5. Syntactic DOM context inspection for Reflected XSS false positive reduction.
"""

import time

import aiohttp
import pytest

from web_security_scanner.core.differential_analyzer import (
    DifferentialAnalyzer,
    dom_simhash_similarity,
    levenshtein_similarity,
)
from web_security_scanner.core.dom_xss_analyzer import DOMContextInspector
from web_security_scanner.core.http_client import (
    AsyncHTTPClient,
    HTTPClientConfig,
    TokenBucket,
)
from web_security_scanner.core.injection_point import (
    InjectionPoint,
    _iter_leaf_paths,
)
from web_security_scanner.core.response_filter import ResponseFilter

# ============================================================================
# 1. UNIFIED INJECTION POINT ABSTRACTION
# ============================================================================


def test_injection_point_get():
    pt = InjectionPoint(base_url="http://test.local/search?q=old&lang=en", param="q", vector="getparam")
    assert pt.http_method == "GET"
    method, url, kwargs = pt.apply_payload("PWN'OR'1=1")
    assert method == "GET"
    assert "q=PWN%27OR%271%3D1" in url
    assert "lang=en" in url
    assert kwargs == {}


def test_injection_point_post_urlencoded():
    pt = InjectionPoint(
        base_url="http://test.local/login",
        param="username",
        vector="formparam",
        template={"username": "alice", "csrf": "tok123"},
    )
    assert pt.http_method == "POST"
    method, url, kwargs = pt.apply_payload("admin'--")
    assert method == "POST"
    assert url == "http://test.local/login"
    assert kwargs["data"] == {"username": "admin'--", "csrf": "tok123"}


def test_injection_point_post_json_nested():
    tpl = {
        "user": {
            "profile": {"name": "Bob", "bio": "hello"},
            "tags": ["dev", "qa"],
        },
        "meta": {"active": True},
    }
    # Test leaf enumeration
    leaves = _iter_leaf_paths(tpl)
    assert "user.profile.name" in leaves
    assert "user.tags.0" in leaves

    # Test targeted leaf injection preserving json structure
    pt = InjectionPoint(
        base_url="http://test.local/api/user",
        param="user.profile.name",
        vector="jsonparam",
        template=tpl,
    )
    assert pt.http_method == "POST"
    method, url, kwargs = pt.apply_payload("<script>alert(1)</script>")
    assert method == "POST"
    assert url == "http://test.local/api/user"
    assert kwargs["json"]["user"]["profile"]["name"] == "<script>alert(1)</script>"
    assert kwargs["json"]["user"]["profile"]["bio"] == "hello"
    assert kwargs["json"]["user"]["tags"] == ["dev", "qa"]
    assert kwargs["json"]["meta"]["active"] is True


def test_injection_point_post_multipart_field():
    tpl = {
        "fields": {"description": "my file", "category": "documents"},
        "files": {
            "attachment": {
                "filename": "report.pdf",
                "content": b"PDF-DATA",
                "content_type": "application/pdf",
            }
        },
    }
    pt = InjectionPoint(
        base_url="http://test.local/upload",
        param="description",
        vector="multipart_field",
        template=tpl,
    )
    assert pt.http_method == "POST"
    method, url, kwargs = pt.apply_payload("PWN_DESC")
    assert method == "POST"
    assert url == "http://test.local/upload"
    form_data = kwargs["data"]
    assert isinstance(form_data, aiohttp.FormData)


def test_injection_point_post_multipart_file_header_and_filename():
    tpl = {
        "fields": {"author": "admin"},
        "files": {
            "avatar": {
                "filename": "photo.jpg",
                "content": b"IMG_BYTES",
                "content_type": "image/jpeg",
            }
        },
    }
    # Injection in filename
    pt_fname = InjectionPoint(
        base_url="http://test.local/profile/photo",
        param="avatar.filename",
        vector="multipart_file",
        template=tpl,
        part_type="filename",
    )
    _, _, kw_fname = pt_fname.apply_payload("../../../etc/passwd")
    assert isinstance(kw_fname["data"], aiohttp.FormData)

    # Injection in file Content-Type header
    pt_ctype = InjectionPoint(
        base_url="http://test.local/profile/photo",
        param="avatar.content_type",
        vector="multipart_header",
        template=tpl,
        part_type="content_type",
    )
    _, _, kw_ctype = pt_ctype.apply_payload("text/html")
    assert isinstance(kw_ctype["data"], aiohttp.FormData)


def test_injection_point_headers():
    pt = InjectionPoint(
        base_url="http://test.local/status",
        param="X-Forwarded-For",
        vector="header",
        template={"X-Forwarded-For": "127.0.0.1", "Accept": "text/html"},
    )
    assert pt.http_method == "GET"
    method, url, kwargs = pt.apply_payload("127.0.0.1' UNION SELECT 1--")
    assert method == "GET"
    assert kwargs["headers"]["X-Forwarded-For"] == "127.0.0.1' UNION SELECT 1--"
    assert kwargs["headers"]["Accept"] == "text/html"


# ============================================================================
# 2. DECOUPLED ASYNC HTTP CLIENT
# ============================================================================


@pytest.mark.asyncio
async def test_token_bucket_rate_pacing():
    bucket = TokenBucket(rate=20.0, capacity=2.0)  # 20 per sec
    start = time.monotonic()
    for _ in range(5):
        await bucket.acquire(1.0)
    elapsed = time.monotonic() - start
    # Burst 2 immediate + 3 paced at 0.05s ~= 0.15s min
    assert elapsed >= 0.10


@pytest.mark.asyncio
async def test_async_http_client_concurrency_gate():
    cfg = HTTPClientConfig(max_concurrency=2, timeout=5)
    client = AsyncHTTPClient(cfg)
    assert client.semaphore._value == 2

    # Verify semaphore dynamically resizes
    client.set_concurrency(10)
    assert client.config.max_concurrency == 10

    await client.close()


@pytest.mark.asyncio
async def test_async_http_client_retry_exponential_backoff(monkeypatch):
    cfg = HTTPClientConfig(
        max_retries=2, retry_backoff_base=0.001, retry_backoff_max=0.005
    )
    client = AsyncHTTPClient(cfg)

    call_count = 0

    async def mock_send(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            return {"status_code": 0, "error": "Connection reset"}
        return {"status_code": 200, "text": "Success"}

    monkeypatch.setattr(client, "send_single_request", mock_send)

    res = await client.execute_with_retry("GET", "http://test.local/flake")
    assert res["status_code"] == 200
    assert call_count == 3
    await client.close()


# ============================================================================
# 3. THREE-STATE DIFFERENTIAL ANALYSIS (R_base, R_noop, R_test)
# ============================================================================


def test_levenshtein_and_dom_simhash():
    html_a = "<html><head><title>Test</title></head><body><h1>Hello</h1><p>World</p></body></html>"
    html_b = "<html><head><title>Test</title></head><body><h1>Hello</h1><p>Universe</p></body></html>"
    html_c = "<html><body><div>Error: Invalid syntax in database query near 'x'</div></body></html>"

    # Same DOM structure, small text change
    assert dom_simhash_similarity(html_a, html_b) > 0.90
    assert levenshtein_similarity(html_a, html_b) > 0.85

    # Completely different structure and content
    assert dom_simhash_similarity(html_a, html_c) < 0.70
    assert levenshtein_similarity(html_a, html_c) < 0.60


def test_differential_analyzer_confirms_causal_finding():
    analyzer = DifferentialAnalyzer(stability_threshold=0.80, deviation_threshold=0.15)

    r_base = {"status_code": 200, "text": "<html><body><div>User Profile: 123</div></body></html>"}
    r_noop = {"status_code": 200, "text": "<html><body><div>User Profile: 123_noop</div></body></html>"}
    r_test = {"status_code": 500, "text": "<html><body><div>SQL Error: syntax error near '</div></body></html>"}

    def detector_sql(r):
        return "SQL Error" in r.get("text", "")

    result = analyzer.evaluate_3state(r_base, r_noop, r_test, detector=detector_sql)
    assert result.is_confirmed is True
    assert result.is_ambient_leak is False
    assert result.confidence == "CONFIRMED"
    assert result.stability_score >= 0.80


def test_differential_analyzer_filters_ambient_false_positive():
    analyzer = DifferentialAnalyzer(stability_threshold=0.80)

    # Ambient error: the page ALWAYS contains "Error" even on benign input!
    r_base = {"status_code": 200, "text": "<html><body><div>Notice: internal query error</div></body></html>"}
    r_noop = {"status_code": 200, "text": "<html><body><div>Notice: internal query error</div></body></html>"}
    r_test = {"status_code": 200, "text": "<html><body><div>Notice: internal query error</div></body></html>"}

    def detector_ambient(r):
        return "query error" in r.get("text", "")

    result = analyzer.evaluate_3state(r_base, r_noop, r_test, detector=detector_ambient)
    assert result.is_confirmed is False
    assert result.is_ambient_leak is True
    assert result.confidence in ("LOW", "NONE")


def test_differential_analyzer_detects_volatile_endpoint():
    analyzer = DifferentialAnalyzer(stability_threshold=0.80)

    # Volatile: base and noop are completely different (random dynamic content)
    r_base = {"status_code": 200, "text": "<html><body><div>Random token: 918237192837</div></body></html>"}
    r_noop = {"status_code": 200, "text": "<html><body><div>Advert banner: Click Here!</div><span>555</span></body></html>"}
    r_test = {"status_code": 200, "text": "<html><body><div>Leaked secret: password123</div></body></html>"}

    def detector_volatile(r):
        return "Leaked secret" in r.get("text", "")

    result = analyzer.evaluate_3state(r_base, r_noop, r_test, detector=detector_volatile)
    assert result.is_volatile_endpoint is True
    assert result.confidence == "MEDIUM"  # Degraded due to baseline volatility


# ============================================================================
# 4. RESPONSE FILTER: SOFT 404 & FAKE 200 OK DETECTION
# ============================================================================


def test_response_filter_detects_soft_404_title():
    resp = {
        "status_code": 200,
        "text": "<html><head><title>404 - Page Not Found</title></head><body><h1>Oops</h1></body></html>",
    }
    assert ResponseFilter.is_soft_404(resp) is True
    assert ResponseFilter.is_fictitious_200(resp) is True
    cls = ResponseFilter.classify(resp)
    assert cls.category == "soft_404"


def test_response_filter_detects_soft_404_spanish():
    resp = {
        "status_code": 200,
        "text": "<html><body><h1>Página no encontrada</h1><p>El recurso solicitado no existe.</p></body></html>",
    }
    assert ResponseFilter.is_soft_404(resp) is True
    assert ResponseFilter.is_fictitious_200(resp) is True


def test_response_filter_detects_disguised_block_page():
    resp = {
        "status_code": 200,
        "text": "<html><body><h1>Access Denied</h1><p>Your request was blocked by security policy.</p></body></html>",
    }
    cls = ResponseFilter.classify(resp)
    assert cls.is_blocked is True
    assert cls.is_fictitious_200 is True
    assert cls.category == "blocked"


def test_response_filter_detects_server_error_in_200():
    resp = {
        "status_code": 200,
        "text": "<html><body><h1>Something went wrong on our end</h1><p>An unexpected error occurred.</p></body></html>",
    }
    cls = ResponseFilter.classify(resp)
    assert cls.is_generic_error is True
    assert cls.is_fictitious_200 is True
    assert cls.category == "server_error"


def test_response_filter_allows_legitimate_200():
    resp = {
        "status_code": 200,
        "text": "<html><head><title>User Dashboard</title></head><body><h1>Welcome Back</h1></body></html>",
    }
    assert ResponseFilter.is_soft_404(resp) is False
    assert ResponseFilter.is_fictitious_200(resp) is False
    assert ResponseFilter.classify(resp).category == "ok"


# ============================================================================
# 5. DOM SYNTACTIC CONTEXT VERIFICATION (REFLECTED XSS)
# ============================================================================


def test_xss_inside_script_string_escaped_quote_is_safe():
    # Reflection inside string literal with quotes escaped with backslash -> NOT EXECUTABLE
    html_page = '<html><script>var user = "alice\\\" onload=\\\"alert(1)";</script></html>'
    payload = '" onload="alert(1)'
    analysis = DOMContextInspector.analyze(html_page, payload)
    assert analysis.is_executable is False
    assert analysis.confidence is None


def test_xss_inside_script_string_unescaped_quote_breakout():
    # Raw unescaped quote breaks out of JS string -> EXECUTABLE
    html_page = '<html><script>var user = ""; alert(1); //";</script></html>'
    payload = '"; alert(1); //'
    analysis = DOMContextInspector.analyze(html_page, payload)
    assert analysis.is_executable is True
    assert analysis.confidence == "HIGH"
    assert "script" in analysis.context


def test_xss_inside_event_handler_attribute():
    html_page = '<button onclick="alert(1)">Click Me</button>'
    payload = "alert(1)"
    analysis = DOMContextInspector.analyze(html_page, payload)
    assert analysis.is_executable is True
    assert analysis.confidence == "HIGH"
    assert analysis.context == "event_handler"


def test_xss_inside_uri_sink():
    html_page = '<a href="javascript:alert(1)">Link</a>'
    payload = "javascript:alert(1)"
    analysis = DOMContextInspector.analyze(html_page, payload)
    assert analysis.is_executable is True
    assert analysis.confidence == "HIGH"
    assert analysis.context == "uri_sink"


def test_xss_inside_html_attribute_safely_enclosed():
    # Reflected in value attribute, but quotes are escaped -> CANNOT BREAK OUT -> SAFE!
    html_page = '<html><input name="q" value="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"></html>'
    payload = '"><script>alert(1)</script>'
    analysis = DOMContextInspector.analyze(html_page, payload)
    assert analysis.is_executable is False
    assert analysis.confidence is None


def test_xss_inside_html_attribute_with_raw_breakout():
    # Reflected in value attribute with raw unescaped quote -> BREAKS OUT -> VULNERABLE!
    html_page = '<html><input name="q" value=""><script>alert(1)</script>"></html>'
    payload = '"><script>alert(1)</script>'
    analysis = DOMContextInspector.analyze(html_page, payload)
    assert analysis.is_executable is True
    assert analysis.confidence == "HIGH"
    assert analysis.context == "attribute_breakout"


def test_xss_inside_textarea_without_breakout_is_safe():
    # Content inside <textarea> is parsed as RCDATA, not executed -> SAFE!
    html_page = '<html><textarea><script>alert(1)</script></textarea></html>'
    payload = '<script>alert(1)</script>'
    analysis = DOMContextInspector.analyze(html_page, payload)
    assert analysis.is_executable is False
    assert analysis.confidence is None


def test_xss_inside_textarea_with_closing_tag_breakout():
    # Payload explicitly closes </textarea> -> BREAKS OUT -> VULNERABLE!
    html_page = '<html><textarea></textarea><script>alert(1)</script></textarea></html>'
    payload = '</textarea><script>alert(1)</script>'
    analysis = DOMContextInspector.analyze(html_page, payload)
    assert analysis.is_executable is True
    assert analysis.confidence == "HIGH"
    assert analysis.context == "rcdata_breakout"


def test_xss_inside_comment_without_breakout_is_safe():
    html_page = '<html><!-- User search: <script>alert(1)</script> --></html>'
    payload = '<script>alert(1)</script>'
    analysis = DOMContextInspector.analyze(html_page, payload)
    assert analysis.is_executable is False
    assert analysis.confidence is None


def test_xss_inside_comment_with_breakout():
    html_page = '<html><!-- User search: --><script>alert(1)</script> --></html>'
    payload = '--><script>alert(1)</script>'
    analysis = DOMContextInspector.analyze(html_page, payload)
    assert analysis.is_executable is True
    assert analysis.confidence == "HIGH"
    assert analysis.context == "html_comment"


def test_xss_in_json_response_capped_at_low():
    json_text = '{"status": "ok", "message": "<script>alert(1)</script>"}'
    payload = '<script>alert(1)</script>'
    analysis = DOMContextInspector.analyze(json_text, payload, content_type="application/json")
    assert analysis.is_executable is True
    assert analysis.confidence == "LOW"
    assert analysis.context == "non_html"
