"""WAF-evasion payload synthesis corpus (ai_module/redteam_corpus.py).

Covers: every encoder is a pure, safe transformation of a base payload drawn
from the scanner's own curated corpus; every generated training sample is
valid against the same PayloadOut schema synthesize_payloads() must produce;
and the dataset_generator CLI wiring (--enable-redteam-corpus) actually
merges the corpus into the 'payload' task.
"""
import json

from ai_module import redteam_corpus as rc
from ai_module.structured_inference import PayloadOut


def test_encoders_are_pure_and_non_empty():
    sample = "' OR '1'='1"
    for vclass, techniques in rc.EVASION_TECHNIQUES.items():
        for technique in techniques:
            out = technique(sample)
            assert isinstance(out, str) and out, f"{vclass}/{technique.__name__} produced nothing"


def test_nested_url_encode_is_double_encoded():
    encoded = rc.nested_url_encode("' OR 1=1")
    assert "%2527" in encoded or "%25" in encoded  # '%' re-encoded to %25


def test_overlong_utf8_traversal_replaces_dots_and_slashes():
    encoded = rc.overlong_utf8_traversal("../../etc/passwd")
    assert ".." not in encoded
    assert "%c0%ae" in encoded and "%c0%af" in encoded


def test_hex_literal_sqli_produces_valid_hex():
    encoded = rc.hex_literal_sqli("admin")
    assert encoded.startswith("0x")
    bytes.fromhex(encoded[2:])  # must not raise


def test_ifs_substitution_removes_spaces():
    encoded = rc.ifs_substitution("cat /etc/passwd")
    assert " " not in encoded
    assert "${IFS}" in encoded


def test_base64_shell_wrap_roundtrips():
    import base64

    encoded = rc.base64_shell_wrap("; id")
    b64_part = encoded.split("echo ", 1)[1].split("|", 1)[0]
    assert base64.b64decode(b64_part).decode() == "id"


def test_iter_redteam_seeds_covers_all_four_classes():
    seeds = list(rc.iter_redteam_seeds())
    classes = {s.vclass for s in seeds}
    assert classes == {"sqli", "xss", "cmdi", "pathtraver"}
    assert len(seeds) > 0


def test_sql_char_concat_is_valid_char_call():
    encoded = rc.sql_char_concat("admin")
    assert encoded.startswith("CHAR(") and encoded.endswith(")")
    codes = [int(n) for n in encoded[5:-1].split(",")]
    assert "".join(chr(c) for c in codes) == "admin"


def test_versioned_comment_wrap_is_balanced():
    encoded = rc.versioned_comment_wrap("UNION SELECT 1")
    assert encoded.startswith("/*!") and encoded.endswith("*/")
    assert "UNION SELECT 1" in encoded


def test_svg_tag_vector_wraps_js_call():
    encoded = rc.svg_tag_vector("<script>alert('x')</script>")
    assert encoded.startswith("<svg/onload=") and encoded.endswith(">")
    assert "alert(" in encoded


def test_whitespace_tag_split_breaks_script_literal():
    encoded = rc.whitespace_tag_split("<script>alert(1)</script>")
    assert "<script" not in encoded
    assert "<scr\tipt" in encoded


def test_backslash_traversal_mix_alternates_separators():
    encoded = rc.backslash_traversal_mix("../../etc/passwd")
    assert "\\" in encoded and "/" in encoded


def test_null_byte_truncate_appends_encoded_nul():
    assert rc.null_byte_truncate("shell.php").endswith("%00")


def test_newline_command_split_removes_common_separators():
    encoded = rc.newline_command_split("; cat /etc/passwd && id")
    assert ";" not in encoded and "&&" not in encoded
    assert "%0a" in encoded


def test_backtick_substitution_wraps_in_backticks():
    encoded = rc.backtick_substitution("$(id)")
    assert encoded == "`id`"


def test_chain_composes_left_to_right():
    doubled = rc.chain(str.upper, str.lower)
    assert doubled("AbC") == "abc"  # upper() then lower() -> lower wins
    combo = rc.chain(rc.hex_literal_sqli, rc.nested_url_encode)
    assert combo("a") == rc.nested_url_encode(rc.hex_literal_sqli("a"))


def test_every_technique_has_a_note():
    for techniques in rc.EVASION_TECHNIQUES.values():
        for technique in techniques:
            assert technique in rc._TECHNIQUE_NOTE, (
                f"{technique} is wired into EVASION_TECHNIQUES but has no "
                f"_TECHNIQUE_NOTE entry -- the generated sample's rationale "
                f"would silently fall back to a generic phrase"
            )


def test_build_redteam_corpus_samples_valid_against_payload_schema():
    samples = list(rc.build_redteam_corpus_samples(multiplier=1))
    assert samples
    for s in samples:
        obj = json.loads(s.assistant)
        PayloadOut.model_validate(obj)  # raises on schema violation
        assert s.meta["redteam_seed"] is True
        assert s.meta["label"] in {"sqli", "xss", "cmdi", "pathtraver"}


def test_build_redteam_corpus_samples_is_deterministic():
    a = [s.assistant for s in rc.build_redteam_corpus_samples(seed=42)]
    b = [s.assistant for s in rc.build_redteam_corpus_samples(seed=42)]
    assert a == b


def test_multiplier_varies_surface_text_not_just_duplicates():
    reps1 = list(rc.build_redteam_corpus_samples(seed=1, multiplier=1))
    reps3 = list(rc.build_redteam_corpus_samples(seed=1, multiplier=3))
    assert len(reps3) == 3 * len(reps1)
    # dedup keys should not all collapse to the same handful of values
    keys = {s.meta["_dedup"] for s in reps3}
    assert len(keys) > len(reps1)


# --------------------------------------------------------------------------- #
# dataset_generator CLI wiring
# --------------------------------------------------------------------------- #

def test_dataset_generator_cli_has_redteam_flags():
    import contextlib
    import io

    from ai_module.dataset_generator import main as dg_main

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            dg_main(["--help"])
        except SystemExit:
            pass
    assert "--enable-redteam-corpus" in buf.getvalue()
    assert "--redteam-corpus-multiplier" in buf.getvalue()


def test_run_task_merges_redteam_corpus_into_payload_task(tmp_path):
    import argparse

    from ai_module.dataset_generator import Oracle, _run_task

    args = argparse.Namespace(
        synthetic_multiplier=0, no_standalone_seeds=False, standalone_all_seeds=False,
        enable_redteam_corpus=True, redteam_corpus_multiplier=1,
        no_dedup=False, balance=False, balance_ratio=1.0, limit=0,
        seed=1337, out=tmp_path / "out.jsonl", task_list=["payload"], format="alpaca",
        split=1.0,
    )
    result = _run_task("payload", [], Oracle(), args, weak=True)
    assert result["redteam_corpus"]["built"] > 0
    assert result["samples_with_redteam_corpus"] >= result["redteam_corpus"]["built"]
