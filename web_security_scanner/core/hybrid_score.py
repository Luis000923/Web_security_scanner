"""Hybrid differential decision engine: structural + content + categorical.

Why the old single score could not carry recall
----------------------------------------------
:func:`web_security_scanner.core.differential_analyzer.calculate_structural_similarity`
returned ``0.4 * dom_simhash + 0.4 * levenshtein + 0.2 * status``. On any site
with a rigid template -- i.e. most real applications -- two of those three
terms are *constants*:

* ``dom_simhash`` compares only the tag *skeleton*, so two responses whose
  markup has the same shape but whose content differs measure exactly ``1.0``
  -- measured: ``dom_simhash_similarity`` on two pages sharing a template and
  differing only in their text returns ``1.0000``;
* ``status_sim`` is ``1.0`` whenever the status code did not change, which is
  the overwhelmingly common case.

Measured on the OWASP Benchmark corpus, a genuine boolean SQLi (``OR 1=1``,
one row returned against a full result set) scored a deviation of ``0.0882``
against a ``0.15`` threshold. **The structural path alone cannot detect a real
injection inside a template**, because a large share of what it measures is
guaranteed not to move. Re-weighting the same three terms does not fix that:
the constant mass is still constant, only smaller.

The second level is not a re-scaling of the first. Levenshtein over a raw 4 KB
page dilutes a 3-byte reflected value to ``0.999``, and token *sets* cancel a
row-count collapse completely -- a one-row and a thirty-row rendering have
identical tag and word sets. Both failure modes are fixed by comparing token
*multisets* over the visible text only.

What this module changes
------------------------
Three levels, each measuring something that can actually differ:

============  ======  ==========================================================
level         weight  what it measures
============  ======  ==========================================================
``dom``       0.20    tag skeleton (3-gram simhash) **and** the tag-frequency
                      histogram, averaged. The histogram is the half that
                      tracks repetition, which the skeleton cannot see: 1 vs
                      30 table rows move the histogram a long way
                      (measured 0.52) while leaving the skeleton's shingle
                      set nearly unchanged.
``content``   0.40    a text/content AST -- word tokens, HTML/JS comments,
                      visible text nodes and numeric literals, compared as
                      **multisets** over visible text only.
``categorical`` 0.40  a per-vulnerability oracle (see below) that asks whether
                      the observed difference is *attributable to this
                      vulnerability class*, with a p-value.
============  ======  ==========================================================

Missing levels are handled by **renormalisation over the available levels**,
not by a neutral constant. This is a deliberate choice with a consequence worth
stating: a comparison with no categorical oracle available is scored
``0.333 * dom + 0.667 * content``, which is *not* on the same scale as a
comparison that has one. Scores are therefore only comparable across pairs
with the same set of available levels. Using ``1.0`` as the neutral value for
an unavailable level would have preserved the original defect verbatim --
a constant term that never moves is exactly the bug.

The categorical oracles
-----------------------
Each returns a :class:`CategoricalVerdict` whose ``similarity`` follows the same
convention as the other two levels (``1.0`` = the test response is
indistinguishable from the benign one in this dimension) and whose
``attributable`` flag is the decision gate.

* :class:`SqlBooleanOracle` -- the boolean double-inversion test. Given
  ``R_base``, ``R_true`` (``AND 1=1``) and ``R_false`` (``AND 1=2``) it
  requires ``R_true ~ R_base`` **and** ``R_false != R_base``, and it decides
  significance with a paired t-test over per-replicate differences
  (:mod:`web_security_scanner.core.differential_stats`), reporting an exact
  sign test alongside as a distribution-free second opinion.
* :class:`XssContextOracle` -- reflection plus DOM syntactic context, delegating
  to :class:`~web_security_scanner.core.dom_xss_analyzer.DOMContextInspector`,
  so a payload reflected but neutralised (escaped ``<``/``>``/quotes) does not
  score as an execution context.
* :class:`TimeBasedOracle` -- a *plateau* test rather than a threshold test. A
  server hiccup produces one slow sample; a ``SLEEP`` produces all of them. It
  requires every probe over the robust upper bound of the baseline **and** a
  bounded relative spread across the probes.

Probe status
------------
:func:`evaluate_probe_pipeline` enforces the order

    content filter / soft-404 -> categorical verification -> differential -> score

and returns early with ``probe_status`` for responses the scan never actually
measured. This is the fix for a concrete measured defect: a Soft 404 served with
HTTP 200 used to score ``HIGH confirmed`` if it ever reached the differential
analyzer, because nothing compared it against the baseline -- the *order of
function calls* was the only thing standing between a Soft 404 and a published
false positive. Both the perimeter-block and the soft-404 checks here are
**relative to the baseline**, which matters in the other direction too: a
``200 ok -> 200 "404 not found"`` transition is precisely what an error-based
SQLi looks like, and it must still reach the categorical stage instead of being
discarded as noise.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .differential_analyzer import (
    dom_simhash_similarity,
    extract_dom_tags,
    levenshtein_similarity,
)
from .differential_stats import MIN_PROBES, SignTestResult, paired_t_test, sign_test
from .dom_xss_analyzer import DOMContextInspector
from .response_filter import ResponseFilter

__all__ = [
    "LEVEL_WEIGHTS",
    "ContentProfile",
    "content_profile",
    "content_ast_similarity",
    "dom_tag_histogram_similarity",
    "dom_similarity",
    "CategoricalVerdict",
    "Oracle",
    "SqlBooleanOracle",
    "XssContextOracle",
    "TimeBasedOracle",
    "get_oracle",
    "HybridScore",
    "hybrid_similarity",
    "ProbeStatus",
    "ProbeVerdict",
    "evaluate_probe_pipeline",
    "UntestableResponseError",
]


# --------------------------------------------------------------------------- #
# Weights
# --------------------------------------------------------------------------- #

#: Relative weight of each level when all three are available. Sums to 1.0.
LEVEL_WEIGHTS: dict[str, float] = {
    "dom": 0.20,
    "content": 0.40,
    "categorical": 0.40,
}


# --------------------------------------------------------------------------- #
# Level 1 -- DOM tree (structural)
# --------------------------------------------------------------------------- #


def dom_tag_histogram_similarity(html1: str, html2: str) -> float:
    """Similarity of the tag-*frequency* profile of two documents.

    This is the structural measure that is *not* frozen on a rigid template.
    ``dom_simhash_similarity`` only sees the tag sequence, so a page rendering
    one table row and a page rendering thirty have the same skeleton and a
    simhash distance of 0. Their histograms, however, differ by ~29 ``tr``
    tags, which is exactly the signal a boolean-based SQLi produces.

    Uses total-variation distance on the L1-normalised histograms: 1.0 for
    identical tag mixes, 0.0 for disjoint ones.
    """
    tags1 = Counter(extract_dom_tags(html1))
    tags2 = Counter(extract_dom_tags(html2))
    if not tags1 and not tags2:
        return 1.0
    if not tags1 or not tags2:
        return 0.0
    total1 = sum(tags1.values())
    total2 = sum(tags2.values())
    keys = set(tags1) | set(tags2)
    tv = 0.5 * sum(
        abs(tags1.get(k, 0) / total1 - tags2.get(k, 0) / total2) for k in keys
    )
    return max(0.0, 1.0 - tv)


def dom_similarity(text1: str, text2: str) -> float:
    """Level-1 structural similarity: skeleton simhash averaged with the histogram.

    The two measures are complementary rather than redundant. The simhash
    catches reordering and nesting changes; the histogram catches repetition
    changes (row counts, list lengths). Averaging them is what makes the level
    informative on templated pages instead of returning a constant.
    """
    shingle_sim = dom_simhash_similarity(text1, text2)
    hist_sim = dom_tag_histogram_similarity(text1, text2)
    return 0.5 * shingle_sim + 0.5 * hist_sim


# --------------------------------------------------------------------------- #
# Level 2 -- content AST
# --------------------------------------------------------------------------- #

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")
_NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_SCRIPT_COMMENT_RE = re.compile(r"(?://|/\*)(.*?)(?:\n|-->|\*/)", re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_ENTITY_RE = re.compile(r"&[a-zA-Z#0-9]{2,8};")


def _visible_text(html: str) -> str:
    """Strip tags/entities, leaving the text a user would actually see."""
    without_scripts = re.sub(
        r"<(script|style)\b[^>]*>.*?</\1>", " ", html, flags=re.DOTALL | re.IGNORECASE
    )
    return _ENTITY_RE.sub(" ", _TAG_RE.sub(" ", without_scripts))


@dataclass(frozen=True)
class ContentProfile:
    """The dynamic content of a response body, split by the kind of node.

    Counts, not sets. A set profile of a one-row and a thirty-row rendering of
    the same page is *identical* -- every tag name and every word is present in
    both -- so a set-based comparison returns 1.0 and is blind to precisely the
    difference a boolean SQLi produces. Multiplicity is the signal, so it is
    preserved.
    """

    tokens: Counter[str]
    comments: tuple[str, ...]
    text_nodes: Counter[str]
    numbers: Counter[str]
    is_html: bool
    raw: str

    @property
    def is_empty(self) -> bool:
        return not (self.tokens or self.comments or self.text_nodes or self.numbers)


def content_profile(body: str) -> ContentProfile:
    """Extract the content AST of ``body``.

    For a non-HTML body (JSON, plain text, XML payloads) there is no template
    to strip, so the whole body is kept as the single text node and
    ``is_html`` is False -- callers then fall back to raw similarity.
    """
    body = body or ""
    is_html = "<" in body and ">" in body
    if not is_html:
        return ContentProfile(
            tokens=Counter(_TOKEN_RE.findall(body)),
            comments=(),
            text_nodes=Counter([body]) if body else Counter(),
            numbers=Counter(_NUMBER_RE.findall(body)),
            is_html=False,
            raw=body,
        )

    comments = tuple(
        c.strip() for c in _COMMENT_RE.findall(body) if c.strip()
    ) + tuple(c.strip() for c in _SCRIPT_COMMENT_RE.findall(body) if c.strip())

    text = _visible_text(body)
    # Text nodes: runs of non-whitespace, which is how a browser would see them.
    text_nodes = Counter(t for t in text.split() if t)

    return ContentProfile(
        tokens=Counter(_TOKEN_RE.findall(text)),
        comments=comments,
        text_nodes=text_nodes,
        numbers=Counter(_NUMBER_RE.findall(body)),
        is_html=True,
        raw=body,
    )


def _multiset_jaccard(a: Counter[str], b: Counter[str]) -> float:
    """Jaccard over multisets: ``sum(min) / sum(max)``.

    Equals set-Jaccard when no element repeats, and degrades gracefully to
    multiplicity once it does -- which is the behaviour needed here. A token
    appearing 1 time against 30 times contributes ``1/30``, so a row-count
    collapse registers instead of cancelling out.
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    keys = set(a) | set(b)
    intersection = sum(min(a[k], b[k]) for k in keys)
    union = sum(max(a[k], b[k]) for k in keys)
    return intersection / union if union else 1.0


def _sequence_similarity(a: Sequence[str], b: Sequence[str]) -> float:
    """Normalised edit similarity over short node sequences."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    if len(a) == len(b) and a == b:
        return 1.0
    return levenshtein_similarity(" ".join(a), " ".join(b), max_len=4000)


def content_ast_similarity(body1: str, body2: str) -> float:
    """Level-2 content similarity over tokens, comments, text nodes and numbers.

    Non-HTML bodies fall back to whole-body edit similarity, because tokenising
    a JSON document and comparing token *sets* would discard exactly the
    ordering information that distinguishes ``{"a":1,"b":2}`` from
    ``{"b":2,"a":1}`` -- which is all a JSON-reflecting endpoint varies.
    """
    p1, p2 = content_profile(body1), content_profile(body2)
    if not p1.is_html or not p2.is_html:
        return levenshtein_similarity(body1 or "", body2 or "")

    token_sim = _multiset_jaccard(p1.tokens, p2.tokens)
    comment_sim = _sequence_similarity(p1.comments, p2.comments)
    node_sim = _multiset_jaccard(p1.text_nodes, p2.text_nodes)
    number_sim = _multiset_jaccard(p1.numbers, p2.numbers)

    # Comments and numbers are the high-information components when they are
    # present at all (a version string or a row id moving is strong evidence);
    # an empty-vs-empty comparison is uninformative and must not dilute.
    parts: list[tuple[float, float]] = [
        (token_sim, 0.45),
        (node_sim, 0.35),
    ]
    if p1.comments or p2.comments:
        parts.append((comment_sim, 0.10))
    if p1.numbers or p2.numbers:
        parts.append((number_sim, 0.10))

    total_w = sum(w for _, w in parts)
    return sum(sim * w for sim, w in parts) / total_w


# --------------------------------------------------------------------------- #
# Level 3 -- categorical oracles
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CategoricalVerdict:
    """Outcome of a per-vulnerability-class oracle.

    ``similarity`` uses the same direction as the other two levels: ``1.0``
    means the test response is indistinguishable from the benign one *in this
    dimension*. ``attributable`` is the boolean decision gate -- whether the
    observed difference can be explained by the vulnerability class rather than
    by the site's normal dynamism.

    ``similarity`` is graded rather than binary because it carries 40 % of the
    hybrid score: a switch would make that 40 % either fully on or fully off.
    """

    similarity: float
    attributable: bool
    reason: str
    detail: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def inert(cls, reason: str, **detail: Any) -> CategoricalVerdict:
        """No evidence either way -- the level should be excluded, not scored 0."""
        return cls(similarity=1.0, attributable=False, reason=reason, detail=detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "similarity": self.similarity,
            "attributable": self.attributable,
            "reason": self.reason,
            "detail": dict(self.detail),
        }


class Oracle:
    """Base class for the categorical oracles."""

    #: Free-form vulnerability-type labels this oracle answers to (lowercase).
    labels: tuple[str, ...] = ()

    def evaluate(self, **kwargs: Any) -> CategoricalVerdict:
        raise NotImplementedError


# ---- SQL injection: boolean double inversion --------------------------------


class SqlBooleanOracle(Oracle):
    """Boolean double-inversion oracle for SQL injection.

    The hypothesis under test is that the response depends on the injected
    boolean clause. The test is a *paired* comparison, because the benign and
    the false-clause responses are both measured against the same baseline at
    the same endpoint, which is the textbook paired design:

        d_i = sim(R_true_i, R_base_i) - sim(R_false_i, R_base_i)

    ``H0: mean(d) == 0`` -- the clause does not matter, the endpoint is
    returning the same page for both. ``H1: mean(d) > 0`` -- the true clause
    behaves like the benign value and the false clause does not, which is the
    signature of a boolean injection.

    Significance comes from the paired t-test over ``d_i``; an exact sign test
    over the same differences is reported alongside as a distribution-free
    second opinion. ``min_probes`` defaults to
    :data:`~web_security_scanner.core.differential_stats.MIN_PROBES` (3).

    Both halves of the stated criterion are enforced separately: the p-value
    says the separation is *real*, while ``similarity_floor`` /
    ``deviation_floor`` say it is *large enough to mean anything*. A
    statistically significant difference of 0.001 is still not a vulnerability.
    """

    labels = ("sqli", "sql_injection", "sql injection", "sqlinjection")

    def __init__(
        self,
        *,
        alpha: float = 0.05,
        min_probes: int = MIN_PROBES,
        similarity_floor: float = 0.80,
        deviation_floor: float = 0.15,
        min_mean_difference: float = 0.10,
        stability_floor: float = 0.60,
    ) -> None:
        self.alpha = alpha
        self.min_probes = min_probes
        self.similarity_floor = similarity_floor
        self.deviation_floor = deviation_floor
        self.min_mean_difference = min_mean_difference
        self.stability_floor = stability_floor

    @staticmethod
    def _replicate_stability(responses: Sequence[dict[str, Any]]) -> float:
        """Mean pairwise similarity among replicates of the *same* logical state.

        This is the volatility guard. A t-test on differences uses magnitude,
        which is exactly what a page whose content shifts on every request can
        fake: with three draws from a volatile page the differences can be
        large, consistently signed, and significant, while nothing about the
        boolean clause caused it. If the replicates of one state do not agree
        with each other, no comparison between states means anything.
        """
        n = len(responses)
        if n < 2:
            return 1.0
        sims = [
            hybrid_similarity(responses[i], responses[j]).similarity
            for i in range(n)
            for j in range(i + 1, n)
        ]
        return sum(sims) / len(sims) if sims else 1.0

    def evaluate(
        self,
        *,
        base: Sequence[dict[str, Any]] | None = None,
        true: Sequence[dict[str, Any]] | None = None,
        false: Sequence[dict[str, Any]] | None = None,
        **_: Any,
    ) -> CategoricalVerdict:
        base, true, false = list(base or []), list(true or []), list(false or [])
        if len(base) < self.min_probes or len(true) < self.min_probes \
                or len(false) < self.min_probes:
            return CategoricalVerdict.inert(
                "not enough boolean states to test: need "
                f"{self.min_probes} each of base/true/false, got "
                f"{len(base)}/{len(true)}/{len(false)}",
                base=len(base), true=len(true), false=len(false),
            )

        n = min(len(base), len(true), len(false))
        true_sims: list[float] = []
        false_sims: list[float] = []
        for i in range(n):
            true_sims.append(hybrid_similarity(base[i], true[i]).similarity)
            false_sims.append(hybrid_similarity(base[i], false[i]).similarity)

        differences = [t - f for t, f in zip(true_sims, false_sims, strict=True)]
        t_res: Any = paired_t_test(
            differences, alpha=self.alpha, min_probes=self.min_probes
        )
        s_res: SignTestResult = sign_test(differences, alpha=self.alpha)

        mean_true = sum(true_sims) / n
        mean_false = sum(false_sims) / n
        true_stability = self._replicate_stability(true[:n])
        false_stability = self._replicate_stability(false[:n])
        detail = {
            "replicates": n,
            "mean_sim_true_vs_base": mean_true,
            "mean_sim_false_vs_base": mean_false,
            "mean_difference": t_res.mean_difference,
            "true_replicate_stability": true_stability,
            "false_replicate_stability": false_stability,
            "t_test": t_res.to_dict(),
            "sign_test": {
                "n": s_res.n, "positives": s_res.positives, "p_value": s_res.p_value,
                "underpowered": s_res.underpowered, "reason": s_res.reason,
            },
            "similarity_floor": self.similarity_floor,
            "deviation_floor": self.deviation_floor,
            "stability_floor": self.stability_floor,
        }

        # --- guard 1: volatility -------------------------------------
        # Checked before the significance test, because significance computed
        # over unstable replicates is not evidence of anything.
        if min(true_stability, false_stability) < self.stability_floor:
            unstable = "true" if true_stability < false_stability else "false"
            got = true_stability if unstable == "true" else false_stability
            return CategoricalVerdict(
                similarity=1.0,
                attributable=False,
                reason=(
                    f"replicates of the {unstable} clause disagree with each other "
                    f"(stability {got:.3f} < {self.stability_floor}); the endpoint is "
                    "volatile, so no cross-state comparison is reliable"
                ),
                detail=detail,
            )

        if not t_res.significant:
            return CategoricalVerdict(
                similarity=1.0,
                attributable=False,
                reason=f"boolean clause produced no significant separation. {t_res.reason}",
                detail=detail,
            )
        # --- guard 2: the sign test disagrees -------------------------
        # Only binding when it had the power to disagree. At n=3 the exact
        # two-sided sign test floors at p=0.25 and cannot reject anything, so
        # blocking on it there would discard every real finding; it is reported
        # but not enforced. From n=5 it can, and then a magnitude-driven t-test
        # that the distribution-free view contradicts is not trustworthy.
        if not s_res.underpowered and not s_res.significant:
            return CategoricalVerdict(
                similarity=1.0,
                attributable=False,
                reason=(
                    f"paired t-test and exact sign test disagree: {t_res.reason}, "
                    f"but {s_res.reason}"
                ),
                detail=detail,
            )
        if mean_true < self.similarity_floor:
            return CategoricalVerdict(
                similarity=min(1.0, mean_true),
                attributable=False,
                reason=(
                    f"true clause does not resemble the baseline "
                    f"(sim {mean_true:.3f} < {self.similarity_floor}); the endpoint "
                    "changes for the benign value too, so this is not a boolean oracle"
                ),
                detail=detail,
            )
        if mean_false > 1.0 - self.deviation_floor:
            return CategoricalVerdict(
                similarity=mean_false,
                attributable=False,
                reason=(
                    f"false clause is indistinguishable from the baseline "
                    f"(sim {mean_false:.3f}); the clause had no effect"
                ),
                detail=detail,
            )
        if t_res.mean_difference < self.min_mean_difference:
            return CategoricalVerdict(
                similarity=1.0 - min(1.0, t_res.mean_difference / self.min_mean_difference),
                attributable=False,
                reason=(
                    f"separation is significant but small "
                    f"(mean difference {t_res.mean_difference:.4f} < "
                    f"{self.min_mean_difference})"
                ),
                detail=detail,
            )

        # Significant, large, and in the predicted direction. Grade the level by
        # how far past the floors the separation reaches, so the 40 % weight is
        # not all-or-nothing.
        effect = (1.0 - mean_false) - (1.0 - mean_true)   # == mean_true - mean_false
        strength = min(1.0, effect / max(1e-9, 2.0 * self.deviation_floor))
        return CategoricalVerdict(
            similarity=max(0.0, 1.0 - strength),
            attributable=True,
            reason=(
                f"boolean oracle verified: R_true~R_base (sim {mean_true:.3f}), "
                f"R_false deviates (sim {mean_false:.3f}), {t_res.reason}"
            ),
            detail=detail,
        )


# ---- Reflected XSS: DOM syntactic context -----------------------------------


class XssContextOracle(Oracle):
    """Reflected-XSS oracle: reflection plus DOM syntactic context.

    Reflection alone is not a vulnerability, and neither is reflection into a
    context that cannot execute. This oracle delegates the syntactic analysis to
    :class:`~web_security_scanner.core.dom_xss_analyzer.DOMContextInspector`,
    which already distinguishes ``SCRIPT_TAG`` / ``ATTRIBUTE_VALUE`` /
    ``HTML_BODY`` / ``RCDATA`` / ``HTML_COMMENT`` breakouts from
    ``rcdata_enclosed`` and from a payload that was escaped before being
    rendered.

    The level is graded by the inspector's own confidence tier rather than
    switching on ``is_executable``: a ``CONFIRMED`` script-tag breakout and a
    ``LOW`` MIME-sniffing reflection are not the same claim.
    """

    labels = ("xss", "reflected_xss", "xss_reflected", "dom_xss", "cross_site_scripting")

    #: similarity assigned per inspector confidence tier.
    _TIER_SIMILARITY = {
        "CONFIRMED": 0.00,
        "HIGH": 0.15,
        "LOW": 0.55,
    }

    @staticmethod
    def _content_type(test: dict[str, Any] | None, explicit: str) -> str:
        """Resolve the response content type: explicit argument, then headers."""
        if explicit:
            return explicit
        headers = (test or {}).get("headers")
        if isinstance(headers, dict):
            for key, value in headers.items():
                if str(key).lower() == "content-type" and value:
                    return str(value)
        return "text/html"

    def evaluate(
        self,
        *,
        test: dict[str, Any] | None = None,
        payload: str = "",
        content_type: str = "",
        **_: Any,
    ) -> CategoricalVerdict:
        text = (test or {}).get("text", "") or ""
        if not payload:
            return CategoricalVerdict.inert("no payload to locate in the response")
        if payload not in text:
            return CategoricalVerdict(
                similarity=1.0,
                attributable=False,
                reason="payload was not reflected; no XSS context to analyse.",
                detail={"reflected": False},
            )

        analysis = DOMContextInspector.analyze(text, payload, self._content_type(test, content_type))
        detail = {
            "reflected": True,
            "context": analysis.context,
            "tag_name": analysis.tag_name,
            "attribute_name": analysis.attribute_name,
            "executable": analysis.is_executable,
            "inspector_confidence": analysis.confidence,
        }
        if not analysis.is_executable:
            return CategoricalVerdict(
                similarity=0.90,
                attributable=False,
                reason=(
                    f"payload reflected into a non-executing context "
                    f"({analysis.context}): {analysis.reason}"
                ),
                detail=detail,
            )
        similarity = self._TIER_SIMILARITY.get(analysis.confidence or "LOW", 0.55)
        return CategoricalVerdict(
            similarity=similarity,
            attributable=True,
            reason=f"executable reflection in {analysis.context}: {analysis.reason}",
            detail=detail,
        )


# ---- Time-based: plateau + jitter control -----------------------------------


class TimeBasedOracle(Oracle):
    """Time-based oracle: a plateau test, not a threshold test.

    The failure this replaces is the classic one: a single slow response (JVM
    GC pause, a cold cache, a contended thread pool) clears any fixed latency
    threshold and is reported as a confirmed injection.

    Two conditions, both required:

    1. **every** probe over the robust upper bound of the baseline;
    2. a bounded *relative spread* across the probes
       (``(max - min) / median <= plateau_tol``).

    Condition 2 is what makes this a plateau: a real ``SLEEP`` delays every
    probe by roughly the same amount, so the spread is small. A hiccup delays
    one of three probes, so the spread is large even when the mean is above the
    bound. No number of extra probes fixes a threshold test; only this
    statistic does.

    When a reduced-delay variant is supplied (``reduced_delays``, the
    ``SLEEP(5) -> SLEEP(2)`` probe), the oracle additionally requires the
    delays to *shrink by roughly the expected amount*, which is the only
    evidence that ties the latency to the attacker's value rather than to the
    endpoint being slow.
    """

    labels = ("time_based", "sqli_time", "blind_sqli", "command_injection_time",
              "rce_time", "timing")

    def __init__(
        self,
        *,
        min_probes: int = MIN_PROBES,
        plateau_tol: float = 0.34,
        scale_tolerance: float = 1.0,
    ) -> None:
        self.min_probes = min_probes
        self.plateau_tol = plateau_tol
        self.scale_tolerance = scale_tolerance

    def evaluate(
        self,
        *,
        baseline_delays: Sequence[float] | None = None,
        test_delays: Sequence[float] | None = None,
        upper_bound: float | None = None,
        reduced_delays: Sequence[float] | None = None,
        expected_reduction: float | None = None,
        **_: Any,
    ) -> CategoricalVerdict:
        baseline_delays = [d for d in (baseline_delays or [])]
        test_delays = [d for d in (test_delays or [])]
        detail: dict[str, Any] = {
            "baseline_delays": baseline_delays,
            "test_delays": test_delays,
            "upper_bound": upper_bound,
            "plateau_tolerance": self.plateau_tol,
            "min_probes": self.min_probes,
        }

        if len(test_delays) < self.min_probes:
            return CategoricalVerdict.inert(
                f"need at least {self.min_probes} test probes to tell a plateau "
                f"from a spike, got {len(test_delays)}",
                **detail,
            )
        if upper_bound is None:
            return CategoricalVerdict.inert(
                "no baseline upper bound supplied; cannot attribute latency",
                **detail,
            )

        bound = float(upper_bound)
        detail["bound_exceeded_by"] = [
            i for i, d in enumerate(test_delays) if d <= bound
        ]
        if any(d <= bound for d in test_delays):
            return CategoricalVerdict(
                similarity=1.0,
                attributable=False,
                reason=(
                    f"only {len(test_delays) - len(detail['bound_exceeded_by'])}/"
                    f"{len(test_delays)} probes exceeded the baseline bound "
                    f"{bound:.3f}s: not a plateau, this is jitter"
                ),
                detail=detail,
            )

        ordered = sorted(test_delays)
        med = ordered[len(ordered) // 2] if len(ordered) % 2 else (
            ordered[len(ordered) // 2 - 1] + ordered[len(ordered) // 2]
        ) / 2.0
        spread = (ordered[-1] - ordered[0]) / med if med > 0 else float("inf")
        detail["median_test_delay"] = med
        detail["relative_spread"] = spread
        if spread > self.plateau_tol:
            return CategoricalVerdict(
                similarity=max(0.0, 1.0 - spread),
                attributable=False,
                reason=(
                    f"all probes exceeded the bound but the relative spread is "
                    f"{spread:.2f} (> {self.plateau_tol}); a constant delay would "
                    f"be flat, this is an unstable server"
                ),
                detail=detail,
            )

        if reduced_delays and expected_reduction:
            detail["reduced_delays"] = list(reduced_delays)
            detail["expected_reduction"] = expected_reduction
            expected_reduced = med - expected_reduction
            lo = expected_reduced - self.scale_tolerance
            hi = expected_reduced + self.scale_tolerance
            if not all(lo <= d <= hi for d in reduced_delays):
                return CategoricalVerdict(
                    similarity=0.5,
                    attributable=False,
                    reason=(
                        f"delays did not scale with the attacker's value: expected "
                        f"~{expected_reduced:.2f}s, observed {list(reduced_delays)}"
                    ),
                    detail=detail,
                )
            return CategoricalVerdict(
                similarity=0.0,
                attributable=True,
                reason=(
                    f"latency is a plateau ({med:.2f}s +/-{spread:.0%}) and scales "
                    f"down to ~{expected_reduced:.2f}s with the reduced payload: "
                    "attributable to the injected delay"
                ),
                detail=detail,
            )

        # No reduced variant available: the plateau is necessary but not
        # sufficient, because a genuinely slow endpoint also produces one.
        return CategoricalVerdict(
            similarity=0.45,
            attributable=False,
            reason=(
                f"latency is a flat plateau over the bound ({med:.2f}s, spread "
                f"{spread:.0%}) but no reduced-delay probe was available to prove "
                "the delay tracks the attacker's value"
            ),
            detail=detail,
        )


# ---- registry ---------------------------------------------------------------

_ORACLES: tuple[Oracle, ...] = (
    SqlBooleanOracle(),
    XssContextOracle(),
    TimeBasedOracle(),
)


def get_oracle(vuln_type: str | None) -> Oracle | None:
    """Return the oracle for ``vuln_type``, or ``None`` when the class has none.

    Matching is on the exact label or on substring containment, so
    ``"sqli_time_based"`` resolves to the time-based oracle. A type with no
    oracle means the categorical level is *excluded* from the hybrid score and
    renormalised away -- not scored as "no evidence" (which would silently
    lower every similarity and inflate every deviation).
    """
    label = str(vuln_type or "").strip().lower()
    if not label:
        return None
    for oracle in _ORACLES:
        if label in oracle.labels:
            return oracle
    for oracle in _ORACLES:
        if any(oracle_label in label for oracle_label in oracle.labels):
            return oracle
    return None


# --------------------------------------------------------------------------- #
# Hybrid combination
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class HybridScore:
    """The combined score plus every level that produced it."""

    similarity: float
    levels: dict[str, float | None]
    weights: dict[str, float]

    @property
    def deviation(self) -> float:
        """``1 - similarity``, in ``[0, 1]``."""
        return max(0.0, 1.0 - self.similarity)

    @property
    def level_coverage(self) -> float:
        """Share of the total weight that was actually computable, in ``[0, 1]``.

        A score built from fewer levels is a weaker measurement, and a caller
        that cares should be able to see that without re-deriving the weights.
        """
        total = sum(self.weights.values()) or 1.0
        used = sum(w for k, w in self.weights.items() if self.levels.get(k) is not None)
        return used / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "similarity": self.similarity,
            "deviation": self.deviation,
            "levels": dict(self.levels),
            "weights": dict(self.weights),
            "level_coverage": self.level_coverage,
        }


def hybrid_similarity(
    resp1: dict[str, Any],
    resp2: dict[str, Any],
    *,
    categorical: CategoricalVerdict | None = None,
    weights: dict[str, float] | None = None,
) -> HybridScore:
    """Combine the three levels into one similarity in ``[0, 1]``.

    A level whose value is ``None`` was **not computable** and is dropped from
    the weighted mean; the remaining weights are renormalised. See the module
    docstring for why a constant placeholder would reintroduce the original
    defect.

    ``categorical=None`` means "no oracle ran", which is different from an
    oracle returning :meth:`CategoricalVerdict.inert`. To contribute an
    explicit "no evidence" at that level, pass the inert verdict (similarity
    1.0) rather than ``None``.
    """
    w = dict(weights or LEVEL_WEIGHTS)
    text1 = resp1.get("text", "") or ""
    text2 = resp2.get("text", "") or ""

    dom_sim = dom_similarity(text1, text2)
    content_sim = content_ast_similarity(text1, text2)

    levels: dict[str, float | None] = {
        "dom": dom_sim,
        "content": content_sim,
        "categorical": None if categorical is None else categorical.similarity,
    }

    num = sum(w[k] * v for k, v in levels.items() if v is not None and k in w)
    den = sum(w[k] for k, v in levels.items() if v is not None and k in w)
    similarity = num / den if den > 0 else 1.0
    return HybridScore(
        similarity=max(0.0, min(1.0, similarity)),
        levels=levels,
        weights=w,
    )


# --------------------------------------------------------------------------- #
# Probe pipeline
# --------------------------------------------------------------------------- #


class ProbeStatus(str, Enum):
    """Whether a probe actually measured the target.

    ``TESTED``
        The response was scored. Nothing prevents it from being a finding.
    ``BLOCKED_UNTESTED``
        A perimeter (WAF / edge) block. The payload never reached the
        application, so the response says nothing about the vulnerability --
        in either direction. This is the Track A / WAF case.
    ``SOFT404_UNTESTED``
        The endpoint served a not-found or error page **for the benign value
        too**. The injection had no observable effect because the point was
        never really exercised.
    ``PROBE_ABORTED``
        The probe could not be constructed or sent (e.g. a payload byte the
        HTTP client refuses). The point was never tested.

    The last three matter for the metrics: an untested point is neither a true
    positive nor a false negative, and counting it as an FN makes recall a
    measurement of the perimeter's configuration instead of the scanner's
    fidelity. See :mod:`web_security_scanner.core.ieee_metrics`.
    """

    TESTED = "tested"
    BLOCKED_UNTESTED = "blocked_untested"
    SOFT404_UNTESTED = "soft404_untested"
    PROBE_ABORTED = "probe_aborted"

    @property
    def is_untested(self) -> bool:
        return self is not ProbeStatus.TESTED


_UNTESTED_CONFIDENCE = {
    ProbeStatus.BLOCKED_UNTESTED: "BLOCKED",
    ProbeStatus.SOFT404_UNTESTED: "UNTESTED",
    ProbeStatus.PROBE_ABORTED: "UNTESTED",
}


@dataclass(frozen=True)
class ProbeVerdict:
    """Full outcome of scoring one probe through the ordered pipeline."""

    probe_status: ProbeStatus
    scored: bool
    confidence: str
    reason: str
    score: HybridScore | None = None
    categorical: CategoricalVerdict | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def deviation(self) -> float | None:
        return None if self.score is None else self.score.deviation

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_status": self.probe_status.value,
            "scored": self.scored,
            "confidence": self.confidence,
            "reason": self.reason,
            "score": None if self.score is None else self.score.to_dict(),
            "categorical": None if self.categorical is None else self.categorical.to_dict(),
            "detail": dict(self.detail),
        }


class UntestableResponseError(RuntimeError):
    """Raised by :func:`evaluate_probe_pipeline` in ``strict`` mode.

    Gives callers that would rather branch than inspect a verdict an exception
    to catch, with the verdict attached as ``verdict``.
    """

    def __init__(self, verdict: ProbeVerdict) -> None:
        super().__init__(verdict.reason)
        self.verdict = verdict


# Deviation thresholds for the structural path, applied only when no categorical
# oracle claimed the finding.
_DEVIATION_HIGH = 0.15
_DEVIATION_MEDIUM = 0.08


def evaluate_probe_pipeline(
    test: dict[str, Any] | None,
    *,
    base: dict[str, Any] | None = None,
    vuln_type: str = "",
    payload: str = "",
    oracle: Oracle | None = None,
    oracle_evidence: dict[str, Any] | None = None,
    high_threshold: float = _DEVIATION_HIGH,
    medium_threshold: float = _DEVIATION_MEDIUM,
    strict: bool = False,
) -> ProbeVerdict:
    """Score one probe, enforcing the evaluation order.

    ``content filter -> categorical verification -> differential score -> final scoring``

    Returns early, with ``scored=False``, for any response the scan never
    measured. See :class:`ProbeStatus` for why those must not be silently
    folded into the FP or FN buckets.

    The content filter is applied **relative to the baseline**, not in
    absolute terms. That distinction is the whole point: a Soft 404 served for
    the benign value is an untested point, while a ``200 ok -> 200 "not found"``
    transition is precisely what an error-based SQLi looks like and must reach
    the categorical stage.
    """
    if not test:
        verdict = ProbeVerdict(
            probe_status=ProbeStatus.PROBE_ABORTED,
            scored=False,
            confidence="UNTESTED",
            reason="no response captured for the probe",
        )
        if strict:
            raise UntestableResponseError(verdict)
        return verdict

    test_cls = ResponseFilter.classify(test)
    base_cls = ResponseFilter.classify(base) if base else None

    # ---- stage 1: content filter / soft-404 ----------------------------
    # Perimeter block: the payload never reached the application, whether or
    # not the baseline was blocked too (both cases are unmeasured).
    if test_cls.is_blocked:
        verdict = ProbeVerdict(
            probe_status=ProbeStatus.BLOCKED_UNTESTED,
            scored=False,
            confidence=_UNTESTED_CONFIDENCE[ProbeStatus.BLOCKED_UNTESTED],
            reason=(
                f"response classified as a perimeter block "
                f"(category={test_cls.category}): {test_cls.reason}. The payload "
                "was not evaluated by the application."
            ),
            detail={"classification": test_cls.category, "filter_reason": test_cls.reason},
        )
        if strict:
            raise UntestableResponseError(verdict)
        return verdict

    # Soft 404 / generic error on the test response. Untested only when the
    # benign baseline behaves the same way; otherwise it is a real behavioural
    # change and falls through to the categorical stage.
    test_is_noise = test_cls.category in ("soft_404", "server_error", "http_error")
    base_is_noise = base_cls is not None and base_cls.category in (
        "soft_404", "server_error", "http_error"
    )
    if test_is_noise and base_is_noise:
        verdict = ProbeVerdict(
            probe_status=ProbeStatus.SOFT404_UNTESTED,
            scored=False,
            confidence=_UNTESTED_CONFIDENCE[ProbeStatus.SOFT404_UNTESTED],
            reason=(
                f"endpoint returns '{base_cls.category if base_cls else '?'}' for the "
                f"benign baseline too; the injection point was never really "
                f"exercised. test={test_cls.reason}"
            ),
            detail={
                "test_classification": test_cls.category,
                "base_classification": base_cls.category if base_cls else None,
            },
        )
        if strict:
            raise UntestableResponseError(verdict)
        return verdict

    # ---- stage 2: categorical verification -----------------------------
    cat_verdict: CategoricalVerdict | None = None
    oracle = oracle if oracle is not None else get_oracle(vuln_type)
    if oracle is not None:
        kwargs: dict[str, Any] = {
            "test": test,
            "base": base,
            "payload": payload,
            "vuln_type": vuln_type,
        }
        kwargs.update(oracle_evidence or {})
        cat_verdict = oracle.evaluate(**kwargs)

    # ---- stage 3: differential score ------------------------------------
    score = hybrid_similarity(base or test, test, categorical=cat_verdict)

    # ---- stage 4: final scoring ----------------------------------------
    return _final_scoring(
        score,
        cat_verdict,
        test_cls=test_cls,
        base_cls=base_cls,
        vuln_type=vuln_type,
        oracle_used=oracle,
        high_threshold=high_threshold,
        medium_threshold=medium_threshold,
    )


def _final_scoring(
    score: HybridScore,
    cat_verdict: CategoricalVerdict | None,
    *,
    test_cls: Any,
    base_cls: Any,
    vuln_type: str,
    oracle_used: Oracle | None,
    high_threshold: float,
    medium_threshold: float,
) -> ProbeVerdict:
    """Combine the hybrid score and the categorical verdict into a confidence."""
    deviation = score.deviation
    detail: dict[str, Any] = {
        "vuln_type": vuln_type,
        "oracle": type(oracle_used).__name__ if oracle_used else None,
        "test_classification": test_cls.category,
        "base_classification": base_cls.category if base_cls else None,
    }

    # Class-attributable evidence outranks the structural score. This is what
    # recovers the templated-page case the structural path provably cannot see:
    # the oracle does not need the similarity to move much, because it is
    # asking a different question.
    if cat_verdict is not None and cat_verdict.attributable:
        confidence = "CONFIRMED" if cat_verdict.similarity <= 0.25 else "HIGH"
        return ProbeVerdict(
            probe_status=ProbeStatus.TESTED,
            scored=True,
            confidence=confidence,
            reason=cat_verdict.reason,
            score=score,
            categorical=cat_verdict,
            detail=detail,
        )

    # An oracle ran and found nothing attributable while the structural levels
    # say the response moved. That is exactly the Soft-404 / template-dynamics
    # false-positive shape: a difference with no class to explain it. Cap it.
    if cat_verdict is not None and deviation >= high_threshold:
        return ProbeVerdict(
            probe_status=ProbeStatus.TESTED,
            scored=True,
            confidence="LOW",
            reason=(
                f"structural deviation {deviation:.4f} without class-attributable "
                f"evidence: {cat_verdict.reason}"
            ),
            score=score,
            categorical=cat_verdict,
            detail=detail,
        )

    if deviation >= high_threshold:
        confidence = "HIGH"
        reason = f"structural deviation {deviation:.4f} >= {high_threshold}."
    elif deviation >= medium_threshold:
        confidence = "MEDIUM"
        reason = f"structural deviation {deviation:.4f} >= {medium_threshold}."
    else:
        confidence = "NONE"
        reason = (
            f"structural deviation {deviation:.4f} < {medium_threshold}: "
            "indistinguishable from the baseline."
        )

    if cat_verdict is not None:
        reason = f"{reason} {cat_verdict.reason}"

    return ProbeVerdict(
        probe_status=ProbeStatus.TESTED,
        scored=True,
        confidence=confidence,
        reason=reason,
        score=score,
        categorical=cat_verdict,
        detail=detail,
    )
