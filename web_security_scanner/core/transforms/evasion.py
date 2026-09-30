"""Entropy-driven WAF/IDS evasion transforms.

These extend :mod:`.common` with techniques aimed specifically at *modern*
edge WAFs (Cloudflare, AWS WAF managed rules, ModSecurity CRS) rather than
naive substring filters:

- :class:`PartialPercentEncodeTransform` -- selective, case-randomized
  percent-encoding. CRS-style regexes are usually written against either the
  raw token or the fully percent-encoded token; encoding a *random subset* of
  the special characters (and randomizing the hex-digit case, which RFC 3986
  makes case-insensitive) produces a string that matches neither anchor while
  still decoding byte-for-byte to the original vector.
- :class:`WhitespaceDelimiterTransform` -- swaps literal spaces for an
  inline-equivalent delimiter (tab, newline, SQL block comment, ``%0a``/``%09``)
  the target's tokenizer treats identically. Directly targets the
  whitespace-anchored patterns common in SQLi/LDAP/SSTI CRS rules.
- :class:`FullwidthUnicodeTransform` -- maps ASCII to the Unicode Fullwidth
  Forms block. A long-documented bypass against ASCII-only WAF regexes for
  stacks that Unicode-normalize (NFKC) before the vulnerable sink runs.
- :class:`AdaptiveEntropyTransform` -- polymorphic composite: draws a random
  *subset and order* of other registered transforms per call, so repeated
  probes in one sweep don't all carry the one lexical signature a WAF could
  learn and start blocking mid-scan.
- :class:`SqlCommentInjectionTransform` -- splits SQL keywords with an inline
  block comment (``SEL/**/ECT``) and, some of the time, appends a trailing
  line comment (``-- ``) to truncate the rest of the query. Targets
  keyword-anchored CRS signatures (e.g. ``\\bUNION\\b``) that a plain
  whitespace swap does not touch.

Every transform here declares :attr:`~.base.BaseTransform.binary_safe`
accurately (see that attribute's docstring) so
:meth:`~web_security_scanner.core.payload_mutator.PayloadMutator.mutate` can
refuse to run an unsafe one against a deserialization gadget chain or an IDOR
identifier instead of silently corrupting it.
"""

from __future__ import annotations

import random
import re

from .base import BaseTransform, get_transform, register

__all__ = [
    "PartialPercentEncodeTransform",
    "WhitespaceDelimiterTransform",
    "FullwidthUnicodeTransform",
    "AdaptiveEntropyTransform",
    "SqlCommentInjectionTransform",
]

# Characters left alone by PartialPercentEncodeTransform even at rate=1.0:
# encoding alphanumerics buys no evasion value (no WAF signature keys off a
# bare letter/digit) and only bloats the vector.
_ALWAYS_LITERAL = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

# Inline-whitespace equivalents a SQL/LDAP/SSTI tokenizer treats the same as
# a literal space. "/**/" is SQL-specific (works in MySQL/Postgres/MSSQL as
# an inline comment); the others are generic control/URL-encoded whitespace.
_WS_POOL: tuple[str, ...] = ("\t", "\n", "\r", "/**/", "%0a", "%09", "+")

# Registered `adaptive_entropy` composes from this pool by default -- every
# member is binary_safe, so the seeded registry instance stays safe even
# when SENSITIVE_CATEGORIES routes a deserialization/idor payload through it.
_DEFAULT_ADAPTIVE_POOL: tuple[str, ...] = (
    "url_encode", "double_url_encode", "partial_percent_encode", "whitespace_delimiter",
)


def _rng(seed: int | None) -> random.Random:
    return random.Random(seed) if seed is not None else random.Random()


class PartialPercentEncodeTransform(BaseTransform):
    """Percent-encode a random subset of special characters, hex-case-mixed.

    Every encoded byte still round-trips through one standard URL-decode
    pass (``binary_safe = True``) -- only *which* characters get encoded,
    and the case of their hex digits, varies. ``rate`` (0..1) is the
    per-eligible-character encoding probability; ``None`` (default) draws a
    fresh rate in ``[0.35, 0.85]`` per call from the same RNG, so even two
    calls with the same seed-less instance rarely look alike.
    """

    binary_safe = True

    def __init__(self, rate: float | None = None, seed: int | None = None) -> None:
        self._rate = rate
        self._seed = seed

    def transform(self, value: str) -> str:
        rng = _rng(self._seed)
        rate = self._rate if self._rate is not None else rng.uniform(0.35, 0.85)
        rate = min(1.0, max(0.0, rate))
        out: list[str] = []
        for ch in value:
            if ch in _ALWAYS_LITERAL or rng.random() >= rate:
                out.append(ch)
                continue
            for b in ch.encode("utf-8"):
                digits = f"{b:02x}"
                if rng.random() < 0.5:
                    digits = digits.upper()
                out.append(f"%{digits}")
        return "".join(out)


@register("partial_percent_encode")
class _SeededPartialPercentEncodeTransform(PartialPercentEncodeTransform):
    """Registry default: fixed seed keeps the mutator reproducible run-to-run.

    Callers running a live engagement who want a fresh encoding shape on
    every probe should instantiate ``PartialPercentEncodeTransform()``
    directly (no seed) instead of pulling ``"partial_percent_encode"`` from
    the registry -- same convention as :class:`~.common.RandomCaseTransform`.
    """

    def __init__(self) -> None:
        super().__init__(seed=0xE7ADE)


class WhitespaceDelimiterTransform(BaseTransform):
    """Replace literal spaces with a randomly chosen inline-whitespace peer.

    A no-op on any vector without a literal space -- including every
    base64-encoded gadget-chain vector and every IDOR identifier in the
    corpus -- so it is safe there by construction, not just by declaration.
    """

    binary_safe = True

    def __init__(self, pool: tuple[str, ...] | None = None, seed: int | None = None) -> None:
        self._pool = pool or _WS_POOL
        self._seed = seed

    def transform(self, value: str) -> str:
        if " " not in value:
            return value
        rng = _rng(self._seed)
        return "".join(rng.choice(self._pool) if ch == " " else ch for ch in value)


@register("whitespace_delimiter")
class _SeededWhitespaceDelimiterTransform(WhitespaceDelimiterTransform):
    """Registry default: fixed seed, see :class:`_SeededPartialPercentEncodeTransform`."""

    def __init__(self) -> None:
        super().__init__(seed=0x5FACE)


@register("fullwidth_unicode")
class FullwidthUnicodeTransform(BaseTransform):
    """Map printable ASCII to the Unicode Fullwidth Forms block (U+FF01..FF5E).

    ``<`` (U+003C) -> ``＜`` (U+FF1C); space -> U+3000 (ideographic space).
    Documented bypass for stacks that Unicode-normalize (NFKC) request data
    *after* an ASCII-only WAF regex has already let it through, collapsing
    the fullwidth text back to the original ASCII right before the sink
    sees it. ``binary_safe = False``: nothing about a base64 gadget-chain
    byte stream or a numeric IDOR id relies on -- or survives -- Unicode
    normalization, so this only makes sense for text/HTML/script contexts.
    """

    binary_safe = False

    def transform(self, value: str) -> str:
        out: list[str] = []
        for ch in value:
            cp = ord(ch)
            if ch == " ":
                out.append("　")
            elif 0x21 <= cp <= 0x7E:
                out.append(chr(cp + 0xFEE0))
            else:
                out.append(ch)
        return "".join(out)


_SQL_KEYWORD_PATTERN = re.compile(
    r"\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|WHERE|FROM|AND|OR|EXEC|EXECUTE)\b",
    re.IGNORECASE,
)


class SqlCommentInjectionTransform(BaseTransform):
    """Split SQL keywords with ``/**/`` and randomly append a ``-- `` comment.

    ``UNION SELECT`` -> ``UNI/**/ON SEL/**/ECT`` -- every mainstream SQL
    engine's tokenizer treats an inline block comment as whitespace *inside*
    a token boundary, so the statement parses identically while a
    keyword-anchored regex (``\\bUNION\\b``) no longer matches the literal
    substring. ``rate`` (0..1) is the per-keyword split probability and the
    trailing-comment probability; ``None`` (default) draws both independently
    per call from ``[0.35, 0.85]``, so a fixed-seed instance still varies
    keyword-to-keyword.

    ``binary_safe = False``: this rewrites the payload's actual SQL syntax,
    not just its transport encoding -- meaningless (and potentially
    corrupting) for a deserialization gadget chain or a bare IDOR identifier.
    """

    binary_safe = False

    def __init__(self, rate: float | None = None, seed: int | None = None) -> None:
        self._rate = rate
        self._seed = seed

    def transform(self, value: str) -> str:
        rng = _rng(self._seed)
        rate = self._rate if self._rate is not None else rng.uniform(0.35, 0.85)
        rate = min(1.0, max(0.0, rate))

        def _split(match: re.Match[str]) -> str:
            word = match.group(0)
            if len(word) < 2 or rng.random() >= rate:
                return word
            idx = rng.randint(1, len(word) - 1)
            return word[:idx] + "/**/" + word[idx:]

        out = _SQL_KEYWORD_PATTERN.sub(_split, value)
        if rng.random() < rate:
            out = f"{out} -- "
        return out


@register("sql_comment_injection")
class _SeededSqlCommentInjectionTransform(SqlCommentInjectionTransform):
    """Registry default: fixed seed, see :class:`_SeededPartialPercentEncodeTransform`."""

    def __init__(self) -> None:
        super().__init__(seed=0x5901)


class AdaptiveEntropyTransform(BaseTransform):
    """Polymorphic composite: a random sub-chain of other transforms per call.

    The single-shot transforms above each rewrite a payload through one fixed
    lens; a WAF given enough probes from one sweep can still learn *that*
    lens (e.g. cache "this client always partial-percent-encodes at ~60%").
    This composes ``k`` transforms (``min_steps..max_steps``) drawn *without
    replacement* from ``pool`` in random order on every call, so the lexical
    shape of the mutated vector varies probe-to-probe within a single scan,
    not just across scans.

    ``binary_safe`` is computed in ``__init__`` from the resolved pool (and
    forced by ``binary_safe_only=True``, the default, which drops any
    non-safe member from the pool before drawing) -- so a custom pool that
    happens to include only safe transforms still reports correctly, and
    :data:`SENSITIVE_CATEGORIES` payloads get a composite instance that is
    provably safe rather than safe "by convention".
    """

    def __init__(
        self,
        pool: tuple[str, ...] | None = None,
        *,
        min_steps: int = 1,
        max_steps: int = 2,
        seed: int | None = None,
        binary_safe_only: bool = True,
    ) -> None:
        candidates = pool or _DEFAULT_ADAPTIVE_POOL
        if binary_safe_only:
            candidates = tuple(n for n in candidates if get_transform(n).binary_safe)
        self._pool = candidates
        self._min_steps = max(1, min_steps)
        self._max_steps = max(self._min_steps, max_steps)
        self._seed = seed
        # Instance-level override of the class default: true only when every
        # transform this instance can possibly draw is itself binary_safe.
        self.binary_safe = bool(self._pool) and all(
            get_transform(n).binary_safe for n in self._pool
        )

    def transform(self, value: str) -> str:
        if not self._pool:
            return value
        rng = _rng(self._seed)
        k = rng.randint(self._min_steps, min(self._max_steps, len(self._pool)))
        chosen = rng.sample(self._pool, k)
        out = value
        for name in chosen:
            out = get_transform(name).transform(out)
        return out


@register("adaptive_entropy")
class _SeededAdaptiveEntropyTransform(AdaptiveEntropyTransform):
    """Registry default: fixed seed, see :class:`_SeededPartialPercentEncodeTransform`.

    For a live engagement, prefer ``AdaptiveEntropyTransform()`` (no seed) in
    a custom registry passed to ``PayloadMutator`` -- every probe then draws
    fresh randomness, so a signature the WAF learns from one probe's shape
    does not carry over to the next.
    """

    def __init__(self) -> None:
        super().__init__(seed=0xADAF7)
