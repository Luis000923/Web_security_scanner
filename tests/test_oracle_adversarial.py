"""tests/test_oracle_adversarial.py — oracle resilience to evasion/obfuscation.

``tools/eval_oracle.py`` matches scanner findings against ground truth on the
tuple (normalized_url, param, canonical_type). An attacker (or a noisy
scanner tester-id) can pack a "type" label or a URL with obfuscated payload
fragments — encoding tricks, inline comments, mixed case, alternate
operators — hoping to either dodge classification or break the match. These
tests pin down that ``canonicalize_type`` still buckets a label correctly
when real payload noise from common evasion techniques is embedded in it,
that pure noise with no semantic keyword is never mis-bucketed into a real
category, and that ``normalize_url`` strips every URL-side evasion vector
(query, fragment, case, missing scheme) down to the same stable key.
"""

import pytest

from tools.eval_oracle import canonicalize_type, normalize_url

# --------------------------------------------------------------------------
# canonicalize_type — resilience to obfuscated payload noise in the label
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "obfuscated_label, expected_category",
    [
        # Inline SQL comment injection (WAF-bypass technique) noised into an
        # otherwise ordinary SQLi tester label.
        ("SQLInjectionTester: UNiOn/**/SeLeCt bypass", "sql_injection"),
        # URL-encoded traversal sequences noised into a path-traversal label.
        ("PathTraversalTester (..%2f..%2fetc%2fpasswd)", "path_traversal"),
        # Advanced NoSQL operator injection noised into a NoSQLi label.
        ('NoSQLInjectionTester {"$gt": ""}', "nosql_injection"),
        # HTML/attribute-based XSS obfuscation noised into an XSS label.
        ("XSSTester <svg/onload=alert(1)>", "xss"),
        # Double URL-encoding (a classic WAF-evasion technique) noised into
        # a path-traversal label — the fully spelled-out alias still matches
        # even with encoded slashes and dots surrounding it.
        ("Double URL-Encoded Path Traversal (%2e%2e%2f%2e%2e%2fetc%2fpasswd)",
         "path_traversal"),
        # Case-scrambling alone (no other obfuscation) must not defeat the
        # fold-then-match step.
        ("sQlInJeCtIoN", "sql_injection"),
        ("XsS ReFlEcTeD", "xss"),
        # Spanish i18n display strings surviving the same fold-and-match.
        ("Inyeccion de Comando (${IFS}cat${IFS}/etc/passwd)", "command_injection"),
    ],
)
def test_oracle_adversarial_evasion(obfuscated_label, expected_category):
    assert canonicalize_type(obfuscated_label) == expected_category


@pytest.mark.parametrize(
    "raw_payload",
    [
        "%2527%255C",              # double URL-encoded noise, no keyword
        "UNiOn/**/SeLeCt",          # SQLi technique with no "sql" keyword
        '{"$gt": ""}',              # NoSQL operator with no "nosql" keyword
        "<svg/onload=alert(1)>",    # XSS payload with no "xss" keyword
        "..%2f..%2fetc%2fpasswd",   # traversal payload with no keyword
    ],
)
def test_oracle_adversarial_evasion_pure_payload_never_misclassified(raw_payload):
    """A raw obfuscated payload with no semantic keyword must never be
    silently mapped onto one of the real vulnerability categories — that
    would corrupt TP/FP accounting by matching unrelated ground-truth
    entries. It must fall through to the unknown passthrough bucket."""
    result = canonicalize_type(raw_payload)
    known_categories = {
        "nosql_injection", "sql_injection", "xss", "ssrf", "command_injection",
        "path_traversal", "xxe", "csrf", "idor", "open_redirect", "ssti",
        "crlf", "log4shell", "ldap_injection", "deserialization",
        "missing_header", "info_disclosure",
    }
    assert result not in known_categories


# --------------------------------------------------------------------------
# normalize_url — resilience to malformed URLs / fragments / missing scheme
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url, expected",
    [
        # Mixed-case scheme/host + explicit port + query + fragment.
        ("HTTP://Example.COM:80/Path?x=1#frag", "http://example.com:80/Path"),
        # Trailing slash removed on a non-root path.
        ("https://EXAMPLE.com/a/b/c/", "https://example.com/a/b/c"),
        # Root path is preserved as "/", never stripped to "".
        ("https://example.com/", "https://example.com/"),
        # Fragment-only variation still collapses to the bare path.
        ("https://example.com/path#section", "https://example.com/path"),
        # An XSS payload smuggled into the query string cannot survive
        # normalization to break the (url, param, type) match.
        ("https://example.com/path?x=<script>alert(1)</script>#frag",
         "https://example.com/path"),
        # Protocol-relative URL defaults to http.
        ("//example.com/path#frag", "http://example.com/path"),
        # Bare scheme with no path at all defaults to "/".
        ("HTTPS://EXAMPLE.COM", "https://example.com/"),
        # A malformed IPv6 host literal raises inside urlsplit(); the
        # function must degrade gracefully to the raw string rather than
        # crash the whole evaluation run.
        ("http://[::1/broken", "http://[::1/broken"),
    ],
)
def test_oracle_url_normalization_robustness(url, expected):
    assert normalize_url(url) == expected


def test_oracle_url_normalization_neutralizes_query_and_fragment_variants():
    """Multiple syntactic variations of "the same" URL — different query
    strings, different fragments, different casing — must all collapse onto
    one identical normalized key, since that key is what the oracle uses to
    match a scanner finding to its ground-truth record."""
    variants = [
        "HTTPS://Example.com/admin/login?user=alice",
        "https://EXAMPLE.COM/admin/login?user=bob&next=%2f%2fevil.com",
        "https://example.com/admin/login#fragment-noise",
        "https://example.com/admin/login?x=<img src=x onerror=alert(1)>#frag",
    ]
    normalized = {normalize_url(v) for v in variants}
    assert normalized == {"https://example.com/admin/login"}
