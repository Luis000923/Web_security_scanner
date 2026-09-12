"""build_ground_truth.py — multi-vector support + backward compatibility."""

import importlib.util
from pathlib import Path

_MOD_PATH = Path(__file__).parent.parent / "testbed" / "build_ground_truth.py"
_spec = importlib.util.spec_from_file_location("build_ground_truth", _MOD_PATH)
bgt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bgt)


_EXPECTED = {
    "BenchmarkTest00001": ("sqli", True, 89),
    "BenchmarkTest00002": ("sqli", False, 89),
    "BenchmarkTest00003": ("xss", True, 79),
}
_CRAWLER = {
    "BenchmarkTest00001": ("https://localhost:8443/benchmark/sqli-00/BenchmarkTest00001",
                           "getparam", "BenchmarkTest00001"),
    "BenchmarkTest00002": ("https://localhost:8443/benchmark/sqli-01/BenchmarkTest00002",
                           "jsonparam", "BenchmarkTest00002"),
    "BenchmarkTest00003": ("https://localhost:8443/benchmark/xss-00/BenchmarkTest00003",
                           "formparam", "BenchmarkTest00003"),
}


def _build(**kw):
    opts = dict(categories={"sqli", "xss"},
                vectors={"getparam", "formparam", "jsonparam"},
                base_url="https://127.0.0.1:8443", keep_traps=True)
    opts.update(kw)
    return bgt.build_records(_EXPECTED, _CRAWLER, **opts)


def test_jsonparam_is_a_valid_vector():
    assert "jsonparam" in bgt._VALID_VECTORS


def test_records_carry_method_derived_from_vector():
    records, _ = _build()
    by_tc = {r["tc"]: r for r in records}
    assert by_tc["BenchmarkTest00001"]["method"] == "GET"     # getparam
    assert by_tc["BenchmarkTest00002"]["method"] == "POST"    # jsonparam
    assert by_tc["BenchmarkTest00003"]["method"] == "POST"    # formparam


def test_record_schema_stays_backward_compatible():
    records, _ = _build()
    r = records[0]
    for key in ("url", "param", "type", "vulnerable", "vector", "cwe", "tc"):
        assert key in r


def test_jsonparam_vector_filtered_out_by_default_vector_set():
    records, stats = _build(vectors={"getparam", "formparam"})
    assert all(r["vector"] != "jsonparam" for r in records)
    assert stats["vector_filtered"] >= 1
