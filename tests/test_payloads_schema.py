"""Schema + invariant validation for the PAYLOAD/ signature corpus.

Fails CI on any malformed / mis-tagged signature. The corpus is committed as one
file per category under ``PAYLOAD/data/<category>.json`` (validated against
``PAYLOAD/schema.json``) plus ``PAYLOAD/meta.json`` (validated against
``PAYLOAD/meta.schema.json``). Entries tagged ``source:legacy`` were folded in
from the historical flat files during the v5.1 migration.
"""

import json
import re
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

REPO = Path(__file__).resolve().parent.parent
PAYLOAD_DIR = REPO / "web_security_scanner" / "PAYLOAD"
SCHEMA_FILE = PAYLOAD_DIR / "schema.json"
META_SCHEMA_FILE = PAYLOAD_DIR / "meta.schema.json"
META_FILE = PAYLOAD_DIR / "meta.json"
DATA_DIR = PAYLOAD_DIR / "data"

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
def category_files():
    files = sorted(DATA_DIR.glob("*.json"))
    assert files, f"no category files under {DATA_DIR}"
    return files


@pytest.fixture(scope="module")
def category_docs(category_files):
    return {p: json.loads(p.read_text(encoding="utf-8")) for p in category_files}


@pytest.fixture(scope="module")
def doc(category_docs):
    """Reconstruct the aggregated ``{"categories": {...}}`` view for invariants."""
    cats: dict[str, list] = {}
    for raw in category_docs.values():
        cats[raw["category"]] = raw["payloads"]
    return {"categories": cats}


@pytest.fixture(scope="module")
def meta():
    return json.loads(META_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def entries(doc):
    return [(cat, e) for cat, lst in doc["categories"].items() for e in lst]


def test_schema_is_valid_draft202012():
    for path in (SCHEMA_FILE, META_SCHEMA_FILE):
        jsonschema.Draft202012Validator.check_schema(
            json.loads(path.read_text(encoding="utf-8"))
        )


def test_every_category_file_validates_against_schema(category_docs):
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for path, raw in category_docs.items():
        errors = sorted(validator.iter_errors(raw), key=lambda e: list(e.absolute_path))
        assert not errors, f"{path.name}:\n" + "\n".join(
            f"  {list(e.absolute_path)}: {e.message}" for e in errors[:25]
        )


def test_meta_validates_and_matches_data_dir(meta, category_docs):
    schema = json.loads(META_SCHEMA_FILE.read_text(encoding="utf-8"))
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(meta))
    assert not errors, "\n".join(e.message for e in errors)
    assert meta["canary_token"] == CANARY
    on_disk = {raw["category"] for raw in category_docs.values()}
    assert set(meta["categories"]) == on_disk


def test_category_field_matches_filename(category_docs):
    for path, raw in category_docs.items():
        assert raw["category"] == path.stem, f"{path.name}: category != filename"


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


MIN_SIGNATURES_PER_CATEGORY = 30


def test_no_category_falls_below_minimum_signature_count(doc):
    # Guards against corpus asymmetry silently regressing (e.g. deserialization/idor
    # historically had only 6-7 signatures against sql_injection's 500+).
    thin = {
        cat: len(lst) for cat, lst in doc["categories"].items()
        if len(lst) < MIN_SIGNATURES_PER_CATEGORY
    }
    assert not thin, (
        f"categories below the {MIN_SIGNATURES_PER_CATEGORY}-signature floor: {thin}"
    )
