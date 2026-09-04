"""Tests for the async, typed payload loader and its tester integration."""

import inspect

import pytest
from conftest import collect_vulns, param_value

from web_security_scanner.core.payload_loader import (
    CONFIDENCE_LEVELS,
    WSS_CANARY,
    Payload,
    PayloadLoader,
    get_payload_loader,
)
from web_security_scanner.modules.vulnerability_testers.xss_tester_async import XSSTester

EXPECTED_CATEGORIES = {
    "sql_injection", "xss", "path_traversal", "command_injection",
    "open_redirect", "ssrf", "nosql_injection", "xxe", "idor",
    "ssti", "crlf", "log4shell", "ldap", "deserialization",
}


# ---- Loading & structure -------------------------------------------------

async def test_all_categories_load_and_validate_schema():
    loader = get_payload_loader()
    assert EXPECTED_CATEGORIES <= set(loader.available_categories())
    for category in EXPECTED_CATEGORIES:
        payloads = await loader.get_payloads(category, include_destructive=True)
        assert payloads, f"no payloads for {category}"
        for p in payloads:
            assert isinstance(p, Payload)
            assert p.vector and isinstance(p.vector, str)
            assert p.category == category
            assert p.confidence in CONFIDENCE_LEVELS
            assert p.severity in {"Info", "Low", "Medium", "High", "Critical"}
            assert isinstance(p.tags, tuple)


async def test_get_payloads_is_async():
    assert inspect.iscoroutinefunction(PayloadLoader.get_payloads)


# ---- v5.1 extended schema fields ----------------------------------------

async def test_extended_payload_fields_are_typed():
    loader = get_payload_loader()
    curated = [
        p for p in await loader.get_payloads("sql_injection", include_destructive=True)
        if "source:legacy" not in p.tags
    ]
    assert curated
    sample = curated[0]
    assert sample.id and "." in sample.id
    assert sample.cwe.startswith("CWE-")
    assert sample.min_intrusion_level in {"safe", "low", "medium", "high"}
    assert isinstance(sample.engines, tuple)
    assert isinstance(sample.references, tuple)
    assert isinstance(sample.expected_evidence, tuple)
    # every id in the corpus is unique
    all_ids = [p.id for c in loader.available_categories()
              for p in loader._ensure_loaded()[c]]
    assert len(all_ids) == len(set(all_ids))


async def test_engine_filter():
    loader = get_payload_loader()
    jinja = await loader.get_payloads("ssti", engine="jinja2")
    assert jinja
    # entries with an engine list must include jinja2; engine-less entries pass through
    for p in jinja:
        assert not p.engines or "jinja2" in p.engines
    freemarker_only = {
        p.id for p in await loader.get_payloads("ssti", engine="freemarker")
    }
    jinja_only = {p.id for p in jinja if p.engines == ("jinja2",)}
    assert jinja_only.isdisjoint(freemarker_only)


async def test_waf_bypass_filter():
    loader = get_payload_loader()
    waf = await loader.get_payloads("xss", waf_bypass=True, include_destructive=True)
    assert waf and all(p.waf_bypass for p in waf)
    non_waf = await loader.get_payloads("xss", waf_bypass=False, include_destructive=True)
    assert non_waf and not any(p.waf_bypass for p in non_waf)


async def test_max_intrusion_filter_excludes_loud_vectors():
    loader = get_payload_loader()
    safe = await loader.get_payloads("ssti", max_intrusion="safe", include_destructive=True)
    everything = await loader.get_payloads("ssti", include_destructive=True)
    assert 0 < len(safe) < len(everything)
    assert all(p.min_intrusion_level == "safe" for p in safe)
    assert any(p.min_intrusion_level == "high" for p in everything)


async def test_legacy_import_folded_in():
    loader = get_payload_loader()
    sqli = await loader.get_payloads("sql_injection", include_destructive=True)
    legacy = [p for p in sqli if "source:legacy" in p.tags]
    assert legacy, "expected imported legacy SQLi signatures"
    assert len(sqli) > 200


async def test_cache_is_shared_and_immutable():
    loader = get_payload_loader()
    first = await loader.get_payloads("xss")
    second = await loader.get_payloads("xss")
    assert first == second
    assert isinstance(first, tuple)
    with pytest.raises(AttributeError):
        first[0].vector = "mutated"  # type: ignore[misc]


# ---- Context handling --------------------------------------------------

async def test_context_filter_returns_only_requested_context():
    loader = get_payload_loader()
    time_based = await loader.get_payloads("sql_injection", context="time_based_blind")
    assert time_based
    assert all(p.context == "time_based_blind" for p in time_based)
    assert all(p.time_based for p in time_based)
    union = await loader.get_payloads("sql_injection", context="union_based")
    assert {p.vector for p in time_based}.isdisjoint({p.vector for p in union})


async def test_min_confidence_floor():
    loader = get_payload_loader()
    medium = await loader.get_payloads("xss", min_confidence="MEDIUM", include_destructive=True)
    assert medium
    assert all(p.confidence in {"MEDIUM", "HIGH", "CONFIRMED"} for p in medium)


# ---- Destructive gate -------------------------------------------------

async def test_destructive_excluded_by_default_included_on_request():
    loader = get_payload_loader()
    safe = await loader.get_payloads("sql_injection")
    unsafe = await loader.get_payloads("sql_injection", include_destructive=True)
    assert all(not p.destructive for p in safe)
    assert any(p.destructive for p in unsafe)
    assert any("drop table" in p.vector.lower() for p in unsafe)


# ---- Canary ---------------------------------------------------------------

async def test_xss_payloads_carry_shared_canary():
    loader = get_payload_loader()
    xss = await loader.get_payloads("xss")
    canaried = [p for p in xss if p.canary == WSS_CANARY]
    assert canaried
    assert all(WSS_CANARY in p.vector for p in canaried)


async def test_open_redirect_curated_entries_carry_marker_canary():
    loader = get_payload_loader()
    curated = [p for p in await loader.get_payloads("open_redirect")
               if "source:legacy" not in p.tags]
    assert curated
    for p in curated:
        assert p.canary and p.canary in p.vector


# ---- Tester integration (simulated vulnerable server) --------------------

async def test_xss_tester_confirms_with_canary_on_vulnerable_server():
    def responder(method, url, kwargs):
        reflected = param_value(url, "q")
        return {"text": f"<html>results: {reflected}</html>",
                "headers": {"Content-Type": "text/html"}}

    found = await collect_vulns(XSSTester, responder)
    assert found
    assert any(WSS_CANARY in v["payload"] and v["confidence"] == "HIGH" for v in found)


async def test_tester_falls_back_when_category_unknown():
    loader = PayloadLoader()
    assert await loader.get_payloads("does_not_exist") == ()
