"""Schema + invariant validation for PAYLOAD/payloads_v5.json.

Fails CI on any malformed / mis-tagged signature. ``payloads_v5.json`` is the
single committed source of truth; entries tagged ``source:legacy`` were folded
in from the (now removed) historical flat files during the v5.1 migration.
"""

import json
import re
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

REPO = Path(__file__).resolve().parent.parent
PAYLOAD_DIR = REPO / "web_security_scanner" / "PAYLOAD"
SCHEMA_FILE = PAYLOAD_DIR / "schema.json"
V5_FILE = PAYLOAD_DIR / "payloads_v5.json"

CANARY = "WSSc4n4ry7788"
EXPECTED_CATEGORIES = {
    "sql_injection", "xss", "path_traversal", "command_injection", "open_redirect",
    "ssrf", "nosql_injection", "xxe", "idor",
    "ssti", "crlf", "log4shell", "ldap", "deserialization",
}

_TIME_TOKENS = re.compile(
    r"sleep\s*\(|sleep\s+\d|waitfor|pg_sleep|benchmark\(|dbms_(?:lock|pipe)|"
    r"ping\s+-[cn]|timeout\s+/t|start-sleep|randomblob", re.I)
_DESTRUCTIVE_TOKENS = re.compile(
    r"drop\s+(?:table|database)|delete\s+from|truncate\b|insert\s+into|"
    r"update\s+\w+\s+set|shutdown\b|rm\s+-rf|mkfs|\bformat\s+[a-z]:", re.I)


@pytest.fixture(scope="module")
def doc():
    return json.loads(V5_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def entries(doc):
    return [(cat, e) for cat, lst in doc["categories"].items() for e in lst]


def test_schema_is_valid_draft202012():
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)


def test_corpus_validates_against_schema(doc):
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    assert not errors, "\n".join(
        f"{list(e.absolute_path)}: {e.message}" for e in errors[:25]
    )


def test_all_expected_categories_present_and_non_empty(doc):
    cats = doc["categories"]
    missing = EXPECTED_CATEGORIES - cats.keys()
    assert not missing, f"missing categories: {missing}"
    for cat in EXPECTED_CATEGORIES:
        assert cats[cat], f"{cat} is empty"


def test_ids_are_globally_unique(entries):
    seen: dict[str, str] = {}
    for cat, e in entries:
        assert e["id"] not in seen, f"duplicate id {e['id']} ({cat} & {seen.get(e['id'])})"
        seen[e["id"]] = cat


def test_no_duplicate_vector_within_category(doc):
    for cat, lst in doc["categories"].items():
        vectors = [e["vector"] for e in lst]
        dupes = {v for v in vectors if vectors.count(v) > 1}
        assert not dupes, f"{cat} has duplicate vectors: {list(dupes)[:5]}"


def test_id_prefix_matches_category(entries):
    # legacy/auto ids are "<category>.legacy.*" / "<category>.auto.*"; curated ids
    # use a short domain prefix. Only enforce the machine-generated ones.
    for cat, e in entries:
        if ".legacy." in e["id"] or ".auto." in e["id"]:
            assert e["id"].startswith(cat + "."), f"{e['id']} not prefixed with {cat}"


def test_time_based_flag_is_consistent(entries):
    for _cat, e in entries:
        has_token = bool(_TIME_TOKENS.search(e["vector"]))
        if has_token:
            assert e.get("time_based") is True, f"{e['id']} looks time-based but flag unset"
        if e.get("time_based") and not has_token:
            assert re.search(r"sleep|delay|wait", e["vector"], re.I), \
                f"{e['id']} flagged time_based with no delay token"


def test_destructive_flag_is_consistent(entries):
    for _cat, e in entries:
        if _DESTRUCTIVE_TOKENS.search(e["vector"]):
            assert e.get("destructive") is True, f"{e['id']} looks destructive but flag unset"
        if e.get("destructive"):
            assert e.get("min_intrusion_level") in {"medium", "high"}, \
                f"{e['id']} destructive but intrusion level too low"


def test_canary_consistency(entries):
    for _cat, e in entries:
        c = e.get("canary")
        if c is True:
            assert CANARY in e["vector"], f"{e['id']} canary:true but token missing"
        elif isinstance(c, str):
            assert c in e["vector"], f"{e['id']} canary string {c!r} not in vector"


def test_references_are_urls(entries):
    for _cat, e in entries:
        for ref in e.get("references", []):
            assert ref.startswith(("http://", "https://")), f"{e['id']}: bad ref {ref}"


def test_ssti_arithmetic_probes_declare_engines(doc):
    # engine-specific arithmetic / engine-id probes must map to candidate engines;
    # the universal break polyglot legitimately has none.
    for e in doc["categories"]["ssti"]:
        tags = e.get("tags", [])
        if "source:legacy" in tags or "polyglot" in tags:
            continue
        if e["context"] in {"detection", "engine_id"}:
            assert e.get("engines"), f"{e['id']} SSTI probe without engines"


def test_curated_entries_have_cwe(doc):
    for _cat, lst in doc["categories"].items():
        for e in lst:
            if "source:legacy" not in e.get("tags", []):
                assert re.match(r"^CWE-\d+$", e.get("cwe", "")), f"{e['id']} missing CWE"
