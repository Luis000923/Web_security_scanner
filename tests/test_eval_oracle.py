"""tests/test_eval_oracle.py — coverage for tools/eval_oracle.py.

Exercises the three pieces of the oracle that feed the paper's numbers
directly: type canonicalization (so scanner tester-ids and ground-truth
"type" strings collapse onto the same bucket), URL normalization (so a
payload injected into the query string still matches the GT URL), and the
precision/recall/F1/FPR arithmetic (including the FPR-is-N/A-without-traps
case documented in the module docstring).
"""

import importlib.util
import sys
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).parent.parent / "tools" / "eval_oracle.py"
_spec = importlib.util.spec_from_file_location("eval_oracle", _MOD_PATH)
oracle = importlib.util.module_from_spec(_spec)
sys.modules["eval_oracle"] = oracle  # dataclasses needs the module registered
_spec.loader.exec_module(oracle)


# --------------------------------------------------------------------------
# canonicalize_type — one alias per canonical category
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "alias, expected",
    [
        ("NoSQL Injection", "nosql_injection"),
        ("SQLInjectionTester", "sql_injection"),
        ("Cross-Site Scripting", "xss"),
        ("SSRFTester", "ssrf"),
        ("CommandInjectionTester", "command_injection"),
        ("LFI", "path_traversal"),
        ("XXE", "xxe"),
        ("CSRF", "csrf"),
        ("IDOR", "idor"),
        ("Open Redirect", "open_redirect"),
        ("SSTI", "ssti"),
        ("HTTP Response Splitting", "crlf"),
        ("JNDI", "log4shell"),
        ("LDAP Injection", "ldap_injection"),
        ("DeserializationTester", "deserialization"),
        ("Missing Security Header", "missing_header"),
        ("Information Disclosure", "info_disclosure"),
        # i18n (Spanish) display strings.
        ("Inyeccion de Comando", "command_injection"),
        ("Falsificacion de Sitios Cruzados", "csrf"),
    ],
)
def test_canonicalize_type_aliases(alias, expected):
    assert oracle.canonicalize_type(alias) == expected


def test_canonicalize_type_nosql_not_claimed_by_sql():
    # "nosql" is checked before "sql" so it must not fall into sql_injection.
    assert oracle.canonicalize_type("NoSQLi") == "nosql_injection"
    assert oracle.canonicalize_type("SQLi") == "sql_injection"


def test_canonicalize_type_unknown_passthrough():
    assert oracle.canonicalize_type("CustomVulnCategory") == "customvulncategory"


def test_canonicalize_type_empty_and_none():
    assert oracle.canonicalize_type(None) == ""
    assert oracle.canonicalize_type("") == ""


# --------------------------------------------------------------------------
# normalize_url
# --------------------------------------------------------------------------

def test_normalize_url_strips_query_and_lowercases_host():
    assert (oracle.normalize_url("http://Example.COM/Path?a=1&b=2")
            == "http://example.com/Path")


def test_normalize_url_strips_fragment():
    assert (oracle.normalize_url("http://example.com/path#section")
            == "http://example.com/path")


def test_normalize_url_strips_query_and_fragment_together():
    assert (oracle.normalize_url("http://example.com/path?x=1#frag")
            == "http://example.com/path")


def test_normalize_url_trailing_slash_removed_except_root():
    assert oracle.normalize_url("http://example.com/path/") == "http://example.com/path"
    assert oracle.normalize_url("http://example.com/") == "http://example.com/"


def test_normalize_url_defaults_missing_scheme_to_http():
    assert oracle.normalize_url("//example.com/path") == "http://example.com/path"


def test_normalize_url_malformed_falls_back_to_raw():
    # urlsplit() raises ValueError on an unterminated IPv6 host literal.
    raw = "http://[::1/path"
    assert oracle.normalize_url(raw) == raw


# --------------------------------------------------------------------------
# precision / recall / f1 / fpr — synthetic ground truth
# --------------------------------------------------------------------------

def _gt_key(url, param, vtype):
    return oracle._finding_key(url, param, vtype)


def _build_gt(records):
    """records: list of (url, param, type, vulnerable)."""
    gt = oracle.GroundTruth()
    for url, param, vtype, vulnerable in records:
        key = _gt_key(url, param, vtype)
        gt.all_keys[key] = vulnerable
        (gt.positives if vulnerable else gt.traps).add(key)
    return gt


# 15 ground-truth records: 10 real vulnerabilities, 5 explicit traps.
_SYNTHETIC_GT_RECORDS = [
    ("http://t/a", "id", "sql_injection", True),
    ("http://t/b", "q", "xss", True),
    ("http://t/c", "cmd", "command_injection", True),
    ("http://t/d", "path", "path_traversal", True),
    ("http://t/e", "url", "ssrf", True),
    ("http://t/f", "tpl", "ssti", True),
    ("http://t/g", "hdr", "crlf", True),
    ("http://t/h", "id", "idor", True),
    ("http://t/i", "next", "open_redirect", True),
    ("http://t/j", "xml", "xxe", True),
    ("http://t/k", "id", "sql_injection", False),   # trap
    ("http://t/l", "q", "xss", False),               # trap
    ("http://t/m", "cmd", "command_injection", False),  # trap
    ("http://t/n", "path", "path_traversal", False),    # trap
    ("http://t/o", "url", "ssrf", False),                # trap
]


def test_precision_recall_f1_with_traps():
    gt = _build_gt(_SYNTHETIC_GT_RECORDS)
    assert len(gt.positives) == 10
    assert len(gt.traps) == 5

    # Scanner: 8 of the 10 real vulns found (2 missed -> FN), 2 explicit
    # traps incorrectly flagged (FP on traps), plus 1 FP on a URL/type the
    # GT never mentions at all (still counts toward Precision, not FPR).
    findings = {
        _gt_key("http://t/a", "id", "sql_injection"),
        _gt_key("http://t/b", "q", "xss"),
        _gt_key("http://t/c", "cmd", "command_injection"),
        _gt_key("http://t/d", "path", "path_traversal"),
        _gt_key("http://t/e", "url", "ssrf"),
        _gt_key("http://t/f", "tpl", "ssti"),
        _gt_key("http://t/g", "hdr", "crlf"),
        _gt_key("http://t/h", "id", "idor"),
        # i, j (open_redirect, xxe) missed -> 2 FN
        _gt_key("http://t/k", "id", "sql_injection"),   # trap FP
        _gt_key("http://t/l", "q", "xss"),                # trap FP
        _gt_key("http://unrelated/z", "w", "xss"),        # non-trap FP
    }

    m = oracle.evaluate(findings, gt)
    assert len(m.tp) == 8
    assert len(m.fn) == 2
    assert len(m.fp) == 3  # 2 trap FPs + 1 unrelated FP
    assert len(m.fp_on_traps) == 2
    assert m.total_traps == 5

    assert m.precision == pytest.approx(8 / 11)
    assert m.recall == pytest.approx(8 / 10)
    expected_f1 = 2 * (m.precision * m.recall) / (m.precision + m.recall)
    assert m.f1 == pytest.approx(expected_f1)
    assert m.fpr == pytest.approx(2 / 5)


def test_perfect_score_zero_fp_zero_fn():
    gt = _build_gt(_SYNTHETIC_GT_RECORDS)
    findings = set(gt.positives)  # exact match, no traps triggered
    m = oracle.evaluate(findings, gt)
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0
    assert m.fpr == 0.0  # traps exist (5) but none were flagged


def test_fpr_is_none_when_ground_truth_has_no_traps():
    # Same 10 positives, but no explicit traps defined anywhere in the GT.
    no_trap_records = [r for r in _SYNTHETIC_GT_RECORDS if r[3]]
    gt = _build_gt(no_trap_records)
    assert len(gt.traps) == 0

    findings = {
        _gt_key("http://t/a", "id", "sql_injection"),
        _gt_key("http://unrelated/z", "w", "xss"),  # a stray FP, not a trap
    }
    m = oracle.evaluate(findings, gt)
    assert m.total_traps == 0
    assert m.fpr is None  # N/A: no known-negative population to rate against


def test_precision_and_recall_none_on_empty_denominators():
    gt = oracle.GroundTruth()  # no positives, no traps at all
    m = oracle.evaluate(set(), gt)
    assert m.precision is None
    assert m.recall is None
    assert m.f1 is None
    assert m.fpr is None
