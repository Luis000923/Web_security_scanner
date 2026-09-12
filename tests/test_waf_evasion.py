"""Unit tests for the perimeter-evasion module (``modules.waf_evasion``).

Covers: the new ``sql_comment_injection`` transform (keyword-splitting,
``binary_safe`` classification), the standalone ``WafEvasionEngine`` adaptive
retry loop against 403/406 perimeter blocks (not-blocked / bypassed /
confirmed-blocked outcomes, ``max_retries`` capping, graceful skip of an
unsafe transform for a sensitive payload category), and its wiring into
:class:`~web_security_scanner.modules.exploit_engine.ExploitEngine` via
``--enable-waf-evasion``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from conftest import MockScanner

from web_security_scanner.core.payload_loader import Payload
from web_security_scanner.core.transforms.base import get_transform
from web_security_scanner.events.event_emitter import ScanEventEmitter
from web_security_scanner.modules.exploit_engine import ExploitClassification, ExploitEngine
from web_security_scanner.modules.waf_evasion import (
    DEFAULT_EVASION_TRANSFORMS,
    PERIMETER_BLOCK_STATUSES,
    WafEvasionEngine,
    WafEvasionOutcome,
    WafEvasionResult,
)

# ---------------------------------------------------------------------------
# sql_comment_injection transform
# ---------------------------------------------------------------------------


def test_sql_comment_injection_splits_a_keyword_with_inline_comment():
    out = get_transform("sql_comment_injection").transform("UNION SELECT password FROM users")
    assert "/**/" in out
    # the literal keyword no longer appears unbroken -- that's the point.
    assert "UNION" not in out or "SELECT" not in out or "FROM" not in out


def test_sql_comment_injection_is_not_binary_safe():
    assert get_transform("sql_comment_injection").binary_safe is False


def test_sql_comment_injection_registry_default_is_seeded_and_stable():
    a = get_transform("sql_comment_injection").transform("UNION SELECT 1,2,3--")
    b = get_transform("sql_comment_injection").transform("UNION SELECT 1,2,3--")
    assert a == b


def test_sql_comment_injection_noop_on_short_words_and_non_keywords():
    out = get_transform("sql_comment_injection").transform("id=1")
    assert out.startswith("id=1")


def test_sql_comment_injection_from_common_transforms_import():
    from web_security_scanner.core.transforms import SqlCommentInjectionTransform

    out = SqlCommentInjectionTransform(rate=1.0, seed=1).transform("SELECT")
    assert "/**/" in out


# ---------------------------------------------------------------------------
# WafEvasionEngine.is_perimeter_block
# ---------------------------------------------------------------------------


def test_perimeter_block_statuses_are_403_and_406():
    assert PERIMETER_BLOCK_STATUSES == {403, 406}


@pytest.mark.parametrize("status", [403, 406])
def test_is_perimeter_block_true_for_block_statuses(status):
    assert WafEvasionEngine.is_perimeter_block({"status_code": status}) is True


@pytest.mark.parametrize("status", [200, 301, 404, 429, 500])
def test_is_perimeter_block_false_for_other_statuses(status):
    assert WafEvasionEngine.is_perimeter_block({"status_code": status}) is False


def test_is_perimeter_block_false_for_missing_or_empty_response():
    assert WafEvasionEngine.is_perimeter_block(None) is False
    assert WafEvasionEngine.is_perimeter_block({}) is False


def test_is_perimeter_block_false_for_non_int_status():
    assert WafEvasionEngine.is_perimeter_block({"status_code": "403"}) is False


def test_is_perimeter_block_honors_custom_block_statuses():
    assert WafEvasionEngine.is_perimeter_block(
        {"status_code": 401}, block_statuses=frozenset({401})
    ) is True


# ---------------------------------------------------------------------------
# WafEvasionEngine.send_with_evasion -- adaptive retry loop
# ---------------------------------------------------------------------------

ProbeFn = Callable[[str], Awaitable[dict[str, Any]]]


def _make_probe(blocked_vectors: set[str], *, status: int = 403) -> ProbeFn:
    """A fake perimeter: blocks any vector in ``blocked_vectors``, else 200s."""

    async def _probe(vector: str) -> dict[str, Any]:
        if vector in blocked_vectors:
            return {"status_code": status, "text": "blocked by perimeter"}
        return {"status_code": 200, "text": f"ok:{vector}"}

    return _probe


@pytest.mark.asyncio
async def test_not_blocked_on_first_attempt_short_circuits():
    engine = WafEvasionEngine()
    probe = _make_probe(blocked_vectors=set())  # never blocks

    result = await engine.send_with_evasion(probe, "ALERT(1)")

    assert result.outcome is WafEvasionOutcome.NOT_BLOCKED
    assert result.attempts == 1
    assert result.final_vector == "ALERT(1)"
    assert result.transform_chain == ()
    assert result.blocked_statuses == ()


@pytest.mark.asyncio
async def test_bypassed_after_one_mutation():
    original = "ALERT(1)"
    engine = WafEvasionEngine()
    probe = _make_probe(blocked_vectors={original})

    result = await engine.send_with_evasion(probe, original, category="xss")

    assert result.outcome is WafEvasionOutcome.BYPASSED
    assert result.attempts == 2  # original (blocked) + first successful mutation
    assert result.final_vector != original
    assert result.transform_chain == ("random_case",)  # first entry in the default chain
    assert result.blocked_statuses == (403,)
    assert result.final_response["status_code"] == 200


@pytest.mark.asyncio
async def test_confirmed_blocked_when_every_mutation_also_blocked():
    original = "PAYLOAD"

    async def always_blocked(vector: str) -> dict[str, Any]:
        return {"status_code": 403, "text": "blocked"}

    engine = WafEvasionEngine()
    result = await engine.send_with_evasion(always_blocked, original, category="generic")

    assert result.outcome is WafEvasionOutcome.CONFIRMED_BLOCKED
    # 1 initial probe + one per configured transform (none skipped for a
    # non-sensitive category).
    assert result.attempts == 1 + len(DEFAULT_EVASION_TRANSFORMS)
    assert result.transform_chain == DEFAULT_EVASION_TRANSFORMS
    assert len(result.blocked_statuses) == result.attempts
    assert all(s == 403 for s in result.blocked_statuses)


@pytest.mark.asyncio
async def test_406_is_also_treated_as_a_perimeter_block():
    async def always_406(vector: str) -> dict[str, Any]:
        return {"status_code": 406, "text": "not acceptable"}

    engine = WafEvasionEngine(max_retries=1)
    result = await engine.send_with_evasion(always_406, "PAYLOAD")

    assert result.outcome is WafEvasionOutcome.CONFIRMED_BLOCKED
    assert result.blocked_statuses[0] == 406


@pytest.mark.asyncio
async def test_max_retries_caps_the_mutation_attempts():
    async def always_blocked(vector: str) -> dict[str, Any]:
        return {"status_code": 403, "text": "blocked"}

    engine = WafEvasionEngine(max_retries=2)
    result = await engine.send_with_evasion(always_blocked, "PAYLOAD")

    assert result.outcome is WafEvasionOutcome.CONFIRMED_BLOCKED
    assert result.attempts == 1 + 2
    assert result.transform_chain == DEFAULT_EVASION_TRANSFORMS[:2]


@pytest.mark.asyncio
async def test_unsafe_transforms_are_skipped_for_sensitive_categories():
    """``random_case`` and ``sql_comment_injection`` (binary_safe=False) must
    be skipped -- not raised -- when mutating an ``idor``-category vector, so
    only the binary-safe members of the default chain are actually tried."""

    async def always_blocked(vector: str) -> dict[str, Any]:
        return {"status_code": 403, "text": "blocked"}

    engine = WafEvasionEngine()
    result = await engine.send_with_evasion(always_blocked, "42", category="idor")

    assert result.outcome is WafEvasionOutcome.CONFIRMED_BLOCKED
    assert result.transform_chain == ("partial_percent_encode", "double_url_encode")
    assert result.attempts == 1 + 2


@pytest.mark.asyncio
async def test_custom_transform_chain_is_respected():
    original = "<script>alert(1)</script>"
    engine = WafEvasionEngine(transforms=("double_url_encode",), max_retries=5)
    probe = _make_probe(blocked_vectors={original})

    result = await engine.send_with_evasion(probe, original)

    assert result.outcome is WafEvasionOutcome.BYPASSED
    assert result.transform_chain == ("double_url_encode",)


@pytest.mark.asyncio
async def test_unknown_transform_name_is_skipped_gracefully():
    async def always_blocked(vector: str) -> dict[str, Any]:
        return {"status_code": 403, "text": "blocked"}

    engine = WafEvasionEngine(transforms=("not_a_real_transform",))
    result = await engine.send_with_evasion(always_blocked, "PAYLOAD")

    assert result.outcome is WafEvasionOutcome.CONFIRMED_BLOCKED
    assert result.attempts == 1  # the only configured transform was skipped
    assert result.transform_chain == ()


def test_result_to_dict_shape():
    result = WafEvasionResult(
        outcome=WafEvasionOutcome.BYPASSED,
        attempts=2,
        final_vector="mutated",
        final_response={"status_code": 200},
        transform_chain=("random_case",),
        blocked_statuses=(403,),
    )
    d = result.to_dict()
    assert d == {
        "outcome": "BYPASSED",
        "attempts": 2,
        "final_vector": "mutated",
        "final_status": 200,
        "transform_chain": ["random_case"],
        "blocked_statuses": [403],
    }


# ---------------------------------------------------------------------------
# ExploitEngine integration (--enable-waf-evasion)
# ---------------------------------------------------------------------------


def _make_exploit_engine(responder, config):
    em = ScanEventEmitter()
    return ExploitEngine(MockScanner(responder), em, config)


def _make_payload(**overrides):
    base = dict(
        vector="PAYLOAD_X", category="test", context="generic",
        confidence="LOW", severity="Medium",
        expected_evidence=("MARKER_HIT",),
    )
    base.update(overrides)
    return Payload(**base)


def test_exploit_engine_waf_evasion_disabled_by_default():
    engine = _make_exploit_engine(lambda m, u, k: {"text": ""}, config={})
    assert engine._waf_evasion is None


def test_exploit_engine_waf_evasion_enabled_via_config_flag():
    engine = _make_exploit_engine(
        lambda m, u, k: {"text": ""}, config={"enable_waf_evasion": True}
    )
    assert engine._waf_evasion is not None
    assert engine._waf_evasion._max_retries == 4


def test_exploit_engine_waf_evasion_respects_custom_max_retries():
    engine = _make_exploit_engine(
        lambda m, u, k: {"text": ""},
        config={"enable_waf_evasion": True, "waf_evasion_max_retries": 1},
    )
    assert engine._waf_evasion._max_retries == 1


@pytest.mark.asyncio
async def test_probe_with_evasion_noop_when_disabled():
    def responder(method, url, kwargs):
        return {"status_code": 403, "text": "blocked"}

    engine = _make_exploit_engine(responder, config={})
    point = engine._probe.as_injection_point("id", base_url="http://t/x?id=1")
    payload = _make_payload()

    response, vector, note, technique, bypassed = await engine._probe_with_evasion(
        "http://t/x?id=1", point, payload, "test"
    )

    assert response["status_code"] == 403
    assert vector == payload.vector
    assert note == ""
    assert technique is None
    assert bypassed is False


@pytest.mark.asyncio
async def test_probe_with_evasion_bypasses_a_literal_signature_block():
    """A naive perimeter WAF blocking on the exact-case literal payload
    string should be defeated by the case-randomization mutation, and the
    resulting attempt should carry the mutated vector plus an evasion note."""

    def responder(method, url, kwargs):
        if "PAYLOAD_X" in url:  # exact-case literal signature match
            return {"status_code": 403, "text": "blocked"}
        return {"status_code": 200, "text": "reflected MARKER_HIT here"}

    engine = _make_exploit_engine(
        responder, config={"enable_waf_evasion": True}
    )
    point = engine._probe.as_injection_point("id", base_url="http://t/x?id=1")
    payload = _make_payload()

    response, vector, note, technique, bypassed = await engine._probe_with_evasion(
        "http://t/x?id=1", point, payload, "test"
    )

    assert response["status_code"] == 200
    assert vector != payload.vector
    assert "[WAF evasion]" in note
    assert "bypassed" in note
    assert bypassed is True
    assert technique is not None


@pytest.mark.asyncio
async def test_probe_with_evasion_reports_confirmed_block():
    def responder(method, url, kwargs):
        return {"status_code": 403, "text": "blocked"}

    engine = _make_exploit_engine(
        responder, config={"enable_waf_evasion": True, "waf_evasion_max_retries": 1}
    )
    point = engine._probe.as_injection_point("id", base_url="http://t/x?id=1")
    payload = _make_payload()

    response, vector, note, technique, bypassed = await engine._probe_with_evasion(
        "http://t/x?id=1", point, payload, "test"
    )

    assert response["status_code"] == 403
    assert "[WAF evasion]" in note
    assert "confirmed" in note
    assert technique is None
    assert bypassed is False


@pytest.mark.asyncio
async def test_classify_by_evidence_replays_the_mutated_vector_not_the_original():
    """``_classify_by_evidence``'s corroboration replay must use whatever
    vector the evasion retry actually sent -- replaying the original,
    still-blocked vector would wrongly fail to reproduce the marker."""
    replayed_vectors: list[str] = []

    def responder(method, url, kwargs):
        if "PAYLOAD_X" in url:
            return {"status_code": 403, "text": "blocked"}
        replayed_vectors.append(url)
        return {"status_code": 200, "text": "before MARKER_HIT after"}

    engine = _make_exploit_engine(responder, config={})
    point = engine._probe.as_injection_point("id", base_url="http://t/x?id=1")
    baseline = {"status_code": 200, "length": 5, "text": "clean"}
    payload = _make_payload()
    response = {"status_code": 200, "text": "before MARKER_HIT after"}

    classification, evidence, marker = await engine._classify_by_evidence(
        "http://t/x?id=1", point, payload, response, baseline, vector="MUTATED_VECTOR",
    )

    assert classification is ExploitClassification.CONFIRMED_EXPLOITABLE
    assert marker is not None
    assert any("MUTATED_VECTOR" in v for v in replayed_vectors)
