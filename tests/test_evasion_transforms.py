"""Tests for the entropy-driven evasion transforms and the binary_safe gate.

Covers: the new transforms decode back to the original vector (structural
integrity), ``binary_safe`` is classified correctly on old and new
transforms, and ``PayloadMutator`` refuses an unsafe transform against a
deserialization/idor payload instead of silently corrupting it.
"""

import urllib.parse

import pytest

from web_security_scanner.core.payload_loader import Payload
from web_security_scanner.core.payload_mutator import SENSITIVE_CATEGORIES, PayloadMutator
from web_security_scanner.core.transforms import (
    AdaptiveEntropyTransform,
    FullwidthUnicodeTransform,
    PartialPercentEncodeTransform,
    WhitespaceDelimiterTransform,
    binary_safe_transforms,
    get_transform,
)
from web_security_scanner.core.transforms.base import UnsafeTransformError

# ---- PartialPercentEncodeTransform ----------------------------------------


def test_partial_percent_encode_round_trips_to_the_original_bytes():
    raw = "'; DROP TABLE users;--"
    out = PartialPercentEncodeTransform(rate=0.7, seed=1).transform(raw)
    assert urllib.parse.unquote(out) == raw


def test_partial_percent_encode_never_touches_alphanumerics():
    raw = "abcXYZ019 <script>"
    out = PartialPercentEncodeTransform(rate=1.0, seed=2).transform(raw)
    assert "abcXYZ019" in out  # alnum run survives untouched even at rate=1.0


def test_partial_percent_encode_rate_zero_is_identity():
    raw = "<script>alert(1)</script>"
    assert PartialPercentEncodeTransform(rate=0.0).transform(raw) == raw


def test_partial_percent_encode_rate_one_is_fully_encoded_like_url_encode():
    raw = "<script>"
    partial = PartialPercentEncodeTransform(rate=1.0, seed=3).transform(raw)
    # Same bytes encoded, case of hex digits may differ -> compare case-insensitively.
    assert partial.lower() == urllib.parse.quote(raw, safe="").lower()


def test_registry_default_partial_percent_encode_is_seeded_and_stable():
    a = get_transform("partial_percent_encode").transform("<img src=x onerror=alert(1)>")
    b = get_transform("partial_percent_encode").transform("<img src=x onerror=alert(1)>")
    assert a == b


def test_partial_percent_encode_is_binary_safe():
    assert get_transform("partial_percent_encode").binary_safe is True
    assert "partial_percent_encode" in binary_safe_transforms()


# ---- WhitespaceDelimiterTransform ------------------------------------------


def test_whitespace_delimiter_replaces_every_space():
    out = WhitespaceDelimiterTransform(seed=5).transform("SELECT * FROM t WHERE id=1")
    assert " " not in out


def test_whitespace_delimiter_is_a_noop_without_spaces():
    raw = "rO0ABXQADldTU2M0bjRyeTc3ODg="  # base64, no literal spaces
    assert WhitespaceDelimiterTransform(seed=5).transform(raw) == raw


def test_whitespace_delimiter_is_binary_safe():
    assert get_transform("whitespace_delimiter").binary_safe is True


# ---- FullwidthUnicodeTransform ---------------------------------------------


def test_fullwidth_unicode_maps_ascii_to_fullwidth_block():
    out = FullwidthUnicodeTransform().transform("<A>")
    assert out == "＜Ａ＞"


def test_fullwidth_unicode_is_not_binary_safe():
    assert get_transform("fullwidth_unicode").binary_safe is False
    assert "fullwidth_unicode" not in binary_safe_transforms()


# ---- AdaptiveEntropyTransform -----------------------------------------------


def test_adaptive_entropy_default_pool_is_binary_safe():
    t = AdaptiveEntropyTransform()
    assert t.binary_safe is True


def test_adaptive_entropy_with_unsafe_member_reports_unsafe():
    t = AdaptiveEntropyTransform(pool=("hex_entity",), binary_safe_only=False)
    assert t.binary_safe is False


def test_adaptive_entropy_binary_safe_only_drops_unsafe_pool_members():
    t = AdaptiveEntropyTransform(pool=("hex_entity", "url_encode"), binary_safe_only=True)
    assert t.binary_safe is True
    assert t._pool == ("url_encode",)


def test_adaptive_entropy_transform_is_reversible_by_url_decode():
    # every member of the default pool is percent-encoding-based -> chained
    # output always decodes back to the original with enough unquote() passes.
    raw = "<script>alert(document.cookie)</script>"
    out = AdaptiveEntropyTransform(seed=9).transform(raw)
    decoded = out
    for _ in range(4):  # unwind up to 4 encoding layers (double_url_encode = 2)
        decoded = urllib.parse.unquote(decoded)
    assert decoded == raw


def test_adaptive_entropy_registry_default_is_seeded_and_stable():
    a = get_transform("adaptive_entropy").transform("' OR 1=1--")
    b = get_transform("adaptive_entropy").transform("' OR 1=1--")
    assert a == b


def test_adaptive_entropy_unseeded_varies_across_instances():
    raw = "' OR 1=1-- " * 3  # long enough that at least one variant differs
    outputs = {AdaptiveEntropyTransform().transform(raw) for _ in range(20)}
    assert len(outputs) > 1


# ---- PayloadMutator safety gate --------------------------------------------


def _payload(category: str, vector: str) -> Payload:
    return Payload(
        vector=vector, category=category, context="detection",
        confidence="LOW", severity="High", id=f"{category}.test",
    )


def test_sensitive_categories_are_deserialization_and_idor():
    assert SENSITIVE_CATEGORIES == {"deserialization", "idor"}


def test_mutate_blocks_unsafe_transform_on_deserialization_payload():
    mut = PayloadMutator()
    gadget = _payload("deserialization", "rO0ABXQADldTU2M0bjRyeTc3ODg=")
    with pytest.raises(UnsafeTransformError):
        mut.mutate(gadget, ["random_case"])
    # the base64 payload is untouched
    assert gadget.vector == "rO0ABXQADldTU2M0bjRyeTc3ODg="


def test_mutate_blocks_unsafe_transform_on_idor_payload():
    mut = PayloadMutator()
    idor = _payload("idor", "2")
    with pytest.raises(UnsafeTransformError):
        mut.mutate(idor, ["hex_entity"])


def test_mutate_allows_binary_safe_transform_on_sensitive_categories():
    mut = PayloadMutator()
    gadget = _payload("deserialization", "rO0ABXQADldTU2M0bjRyeTc3ODg=")
    out = mut.mutate(gadget, ["url_encode"])
    assert urllib.parse.unquote(out.vector) == gadget.vector


def test_mutate_enforce_safety_false_opts_out_explicitly():
    mut = PayloadMutator()
    idor = _payload("idor", "2")
    out = mut.mutate(idor, ["hex_entity"], enforce_safety=False)
    assert out.vector == "&#x32;"


def test_mutate_unsafe_transform_is_fine_on_non_sensitive_categories():
    mut = PayloadMutator()
    xss = _payload("xss", "<script>")
    out = mut.mutate(xss, ["random_case", "hex_entity"])
    assert out.vector != "<script>"


def test_safe_transforms_for_restricts_to_binary_safe_for_sensitive_categories():
    mut = PayloadMutator()
    gadget = _payload("deserialization", "AAA=")
    safe = set(mut.safe_transforms_for(gadget))
    assert "random_case" not in safe
    assert "hex_entity" not in safe
    assert "fullwidth_unicode" not in safe
    assert "url_encode" in safe
    assert "partial_percent_encode" in safe


def test_safe_transforms_for_returns_everything_for_ordinary_categories():
    mut = PayloadMutator()
    xss = _payload("xss", "<script>")
    assert set(mut.safe_transforms_for(xss)) == set(mut.available())
