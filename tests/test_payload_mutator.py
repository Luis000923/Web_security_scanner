"""Unit tests for the payload transform primitives and PayloadMutator."""

import dataclasses

import pytest

from web_security_scanner.core.payload_loader import Payload
from web_security_scanner.core.payload_mutator import PayloadMutator
from web_security_scanner.core.transforms import (
    DoubleUrlEncodeTransform,
    HexEntityTransform,
    HtmlEntityTransform,
    RandomCaseTransform,
    UrlEncodeTransform,
    available_transforms,
    build_default_registry,
    get_transform,
)
from web_security_scanner.core.transforms.base import BaseTransform, UnknownTransformError


@pytest.fixture
def sample_payload() -> Payload:
    return Payload(
        vector="<script>alert(1)</script>",
        category="xss",
        context="html_body",
        canary=None,
        confidence="HIGH",
        severity="High",
        tags=("technique:reflection", "source:curated"),
        id="xss.reflect.basic",
        description="basic reflection probe",
        cwe="CWE-79",
        owasp="A03:2021",
        min_intrusion_level="low",
        engines=("generic",),
        expected_evidence=("<script>alert(1)</script>",),
        references=("https://example.test/xss",),
    )


# ---- individual transforms -------------------------------------------------


def test_url_encode():
    assert UrlEncodeTransform().transform("<a href>") == "%3Ca%20href%3E"
    # '/', '&', '=' are encoded too (safe="")
    assert UrlEncodeTransform().transform("a=b&c/d") == "a%3Db%26c%2Fd"


def test_double_url_encode_is_url_encode_twice():
    raw = "<x>"
    once = UrlEncodeTransform().transform(raw)
    twice = DoubleUrlEncodeTransform().transform(raw)
    assert once == "%3Cx%3E"
    assert twice == "%253Cx%253E"
    assert twice == UrlEncodeTransform().transform(once)


def test_hex_entity():
    assert HexEntityTransform().transform("<A>") == "&#x3c;&#x41;&#x3e;"


def test_html_entity_is_decimal():
    assert HtmlEntityTransform().transform("<A>") == "&#60;&#65;&#62;"


def test_entity_transforms_are_the_same_codepoints_in_different_bases():
    value = "'; DROP--"
    hexed = HexEntityTransform().transform(value)
    decs = HtmlEntityTransform().transform(value)
    hex_points = [int(p, 16) for p in hexed.replace("&#x", " ").replace(";", "").split()]
    dec_points = [int(p) for p in decs.replace("&#", " ").replace(";", "").split()]
    assert hex_points == dec_points == [ord(c) for c in value]


def test_random_case_only_flips_letters_and_preserves_length_and_semantics():
    value = "SELECT * FROM t WHERE id=1"
    out = RandomCaseTransform(seed=12345).transform(value)
    assert out != value
    assert len(out) == len(value)
    assert out.lower() == value.lower()
    # non-letters untouched at the same positions
    for a, b in zip(value, out, strict=True):
        if not a.isalpha():
            assert a == b


def test_random_case_is_deterministic_with_a_seed():
    a = RandomCaseTransform(seed=7).transform("alertOrigin")
    b = RandomCaseTransform(seed=7).transform("alertOrigin")
    assert a == b


def test_random_case_registry_default_is_seeded_and_stable():
    first = get_transform("random_case").transform("javascript")
    second = get_transform("random_case").transform("javascript")
    assert first == second  # fixed seed baked into the registry entry


# ---- registry ------------------------------------------------------------


def test_registry_exposes_all_builtins():
    assert set(available_transforms()) == {
        "url_encode",
        "double_url_encode",
        "hex_entity",
        "html_entity",
        "random_case",
    }
    for name in available_transforms():
        assert isinstance(get_transform(name), BaseTransform)


def test_get_transform_unknown_raises():
    with pytest.raises(UnknownTransformError):
        get_transform("does_not_exist")


def test_custom_transform_registers_and_runs():
    from web_security_scanner.core.transforms.base import register

    @register("suffix_bang")
    class _Bang(BaseTransform):
        def transform(self, value: str) -> str:
            return value + "!"

    try:
        assert get_transform("suffix_bang").transform("x") == "x!"
        assert PayloadMutator().apply("x", ["suffix_bang"]) == "x!"
    finally:
        from web_security_scanner.core.transforms.base import _REGISTRY

        _REGISTRY.pop("suffix_bang", None)


# ---- PayloadMutator ----------------------------------------------------


def test_mutate_rewrites_vector_and_preserves_all_other_metadata(sample_payload):
    mut = PayloadMutator()
    out = mut.mutate(sample_payload, ["url_encode"])

    assert out.vector == "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    assert out is not sample_payload
    # every field except `vector` is carried over untouched
    for f in dataclasses.fields(Payload):
        if f.name == "vector":
            continue
        assert getattr(out, f.name) == getattr(sample_payload, f.name), f.name


def test_mutate_applies_transforms_in_order(sample_payload):
    mut = PayloadMutator()
    chained = mut.mutate(sample_payload, ["random_case", "url_encode"])
    manual = UrlEncodeTransform().transform(
        get_transform("random_case").transform(sample_payload.vector)
    )
    assert chained.vector == manual


def test_mutate_empty_chain_returns_a_fresh_equal_instance(sample_payload):
    mut = PayloadMutator()
    out = mut.mutate(sample_payload, [])
    assert out == sample_payload
    assert out is not sample_payload


def test_mutate_unknown_transform_raises_and_leaves_input_untouched(sample_payload):
    mut = PayloadMutator()
    with pytest.raises(UnknownTransformError):
        mut.mutate(sample_payload, ["url_encode", "nope"])
    assert sample_payload.vector == "<script>alert(1)</script>"


def test_mutated_payload_is_immutable(sample_payload):
    out = PayloadMutator().mutate(sample_payload, ["hex_entity"])
    with pytest.raises(dataclasses.FrozenInstanceError):
        out.vector = "tampered"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        out.confidence = "LOW"  # type: ignore[misc]


def test_mutator_accepts_a_restricted_registry(sample_payload):
    only_url = {"url_encode": UrlEncodeTransform()}
    mut = PayloadMutator(registry=only_url)
    assert mut.available() == ("url_encode",)
    assert mut.mutate(sample_payload, ["url_encode"]).vector.startswith("%3C")
    with pytest.raises(UnknownTransformError):
        mut.mutate(sample_payload, ["hex_entity"])


def test_mutator_registry_snapshot_is_isolated():
    reg = build_default_registry()
    reg.clear()
    # clearing the returned copy must not affect a fresh mutator
    assert PayloadMutator().available()
