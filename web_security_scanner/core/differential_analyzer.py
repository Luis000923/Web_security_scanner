"""Three-state differential response analysis engine for false positive reduction.

Implements a 3-state evaluation:
- R_base: Original benign baseline response.
- R_noop: Benign no-op mutation response (semantically neutral).
- R_test: Test payload response.

Uses structural similarity metrics:
- Levenshtein distance and normalized string edit similarity.
- DOM tree structural extraction and 64-bit SimHash hamming similarity.
- Combined structural deviation analysis.
"""

from __future__ import annotations

import difflib
import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any

from .injection_point import BENIGN_MARKER, InjectionPoint


class DOMStructureParser(HTMLParser):
    """Fast HTML parser that extracts the structural sequence of tags.

    Ignores dynamic text content and dynamic attribute values to capture
    pure DOM skeleton/topology.
    """

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag.lower())

    def handle_endtag(self, tag: str) -> None:
        self.tags.append(f"/{tag.lower()}")


def extract_dom_tags(html_text: str) -> list[str]:
    """Extract ordered tag skeleton from HTML string."""
    if not html_text:
        return []
    parser = DOMStructureParser()
    try:
        parser.feed(html_text)
    except Exception:
        pass
    return parser.tags


def compute_simhash(tokens: Sequence[str], bit_size: int = 64) -> int:
    """Compute an N-bit SimHash fingerprint from a sequence of tokens."""
    if not tokens:
        return 0

    v = [0] * bit_size
    for token in tokens:
        token_hash = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
        for i in range(bit_size):
            bit = (token_hash >> i) & 1
            v[i] += 1 if bit else -1

    fingerprint = 0
    for i in range(bit_size):
        if v[i] > 0:
            fingerprint |= 1 << i
    return fingerprint


def simhash_similarity(hash1: int, hash2: int, bit_size: int = 64) -> float:
    """Return normalized similarity [0.0, 1.0] from the Hamming distance between two SimHashes."""
    if hash1 == hash2:
        return 1.0
    diff = bin(hash1 ^ hash2).count("1")
    return max(0.0, 1.0 - (diff / bit_size))


def dom_simhash_similarity(html1: str, html2: str) -> float:
    """Calculate structural DOM similarity between two HTML documents using SimHash."""
    tags1 = extract_dom_tags(html1)
    tags2 = extract_dom_tags(html2)
    if not tags1 and not tags2:
        return 1.0
    if not tags1 or not tags2:
        return 0.0

    # Build 3-gram tag shingles for contextual structure
    shingles1 = [":".join(tags1[i : i + 3]) for i in range(max(1, len(tags1) - 2))]
    shingles2 = [":".join(tags2[i : i + 3]) for i in range(max(1, len(tags2) - 2))]

    h1 = compute_simhash(shingles1)
    h2 = compute_simhash(shingles2)
    return simhash_similarity(h1, h2)


def levenshtein_similarity(s1: str, s2: str, max_len: int = 10000) -> float:
    """Calculate normalized string similarity [0.0, 1.0] using edit sequence matching."""
    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0

    # Truncate strings to max_len to protect against CPU denial of service on huge bodies
    sub1 = s1[:max_len]
    sub2 = s2[:max_len]
    return difflib.SequenceMatcher(None, sub1, sub2).ratio()


def calculate_structural_similarity(resp1: dict[str, Any], resp2: dict[str, Any]) -> float:
    """Calculate combined structural similarity [0.0, 1.0] between two HTTP response dicts."""
    status1 = resp1.get("status_code", 0)
    status2 = resp2.get("status_code", 0)
    if status1 != status2:
        status_sim = 0.5 if (status1 // 100 == status2 // 100) else 0.0
    else:
        status_sim = 1.0

    text1 = resp1.get("text", "") or ""
    text2 = resp2.get("text", "") or ""

    # DOM SimHash similarity (tag structure)
    dom_sim = dom_simhash_similarity(text1, text2)

    # String edit similarity
    text_sim = levenshtein_similarity(text1, text2)

    # Weighted combination: 40% DOM structure, 40% text similarity, 20% status code
    return (0.4 * dom_sim) + (0.4 * text_sim) + (0.2 * status_sim)


def generate_noop_payload(point: InjectionPoint | str, original_val: str = "") -> str:
    """Generate an innocuous / neutral mutation for an injection point."""
    val = original_val or BENIGN_MARKER

    # Numeric parameter: neutral arithmetic identity or same number
    if val.isdigit():
        return val

    # Boolean parameter
    if val.lower() in ("true", "false", "1", "0"):
        return val

    # Default neutral string mutation that preserves server logic
    return f"{val}_noop"


@dataclass(frozen=True)
class DifferentialResult:
    """Outcome of a three-state differential response analysis."""

    stability_score: float  # Sim(R_base, R_noop)
    deviation_score: float  # 1.0 - Sim(R_noop, R_test)
    base_noop_sim: float
    noop_test_sim: float
    base_test_sim: float
    dom_simhash_sim: float
    levenshtein_sim: float
    is_confirmed: bool
    is_ambient_leak: bool
    is_volatile_endpoint: bool
    confidence: str  # CONFIRMED, HIGH, MEDIUM, LOW, NONE
    reason: str


class DifferentialAnalyzer:
    """Performs 3-state differential analysis (R_base, R_noop, R_test) to weed out false positives."""

    def __init__(
        self,
        stability_threshold: float = 0.80,
        deviation_threshold: float = 0.15,
    ) -> None:
        self.stability_threshold = stability_threshold
        self.deviation_threshold = deviation_threshold

    def evaluate_3state(
        self,
        r_base: dict[str, Any],
        r_noop: dict[str, Any],
        r_test: dict[str, Any],
        *,
        detector: Callable[[dict[str, Any]], bool] | None = None,
    ) -> DifferentialResult:
        """Evaluate R_base, R_noop, and R_test to determine causal validity."""
        base_noop_sim = calculate_structural_similarity(r_base, r_noop)
        noop_test_sim = calculate_structural_similarity(r_noop, r_test)
        base_test_sim = calculate_structural_similarity(r_base, r_test)

        text_noop = r_noop.get("text", "") or ""
        text_test = r_test.get("text", "") or ""

        dom_sim = dom_simhash_similarity(text_noop, text_test)
        lev_sim = levenshtein_similarity(text_noop, text_test)

        stability_score = base_noop_sim
        deviation_score = max(0.0, 1.0 - noop_test_sim)

        is_volatile = stability_score < self.stability_threshold

        # If a detector callable is provided, check for ambient signal presence
        base_hit = bool(detector(r_base)) if detector else False
        noop_hit = bool(detector(r_noop)) if detector else False
        test_hit = bool(detector(r_test)) if detector else False

        is_ambient = base_hit or noop_hit

        if is_ambient:
            # Finding already exists in benign traffic -> False Positive!
            return DifferentialResult(
                stability_score=stability_score,
                deviation_score=deviation_score,
                base_noop_sim=base_noop_sim,
                noop_test_sim=noop_test_sim,
                base_test_sim=base_test_sim,
                dom_simhash_sim=dom_sim,
                levenshtein_sim=lev_sim,
                is_confirmed=False,
                is_ambient_leak=True,
                is_volatile_endpoint=is_volatile,
                confidence="LOW" if test_hit else "NONE",
                reason="Ambient signal: pattern already present in benign base/noop response.",
            )

        if detector:
            if not test_hit:
                return DifferentialResult(
                    stability_score=stability_score,
                    deviation_score=deviation_score,
                    base_noop_sim=base_noop_sim,
                    noop_test_sim=noop_test_sim,
                    base_test_sim=base_test_sim,
                    dom_simhash_sim=dom_sim,
                    levenshtein_sim=lev_sim,
                    is_confirmed=False,
                    is_ambient_leak=False,
                    is_volatile_endpoint=is_volatile,
                    confidence="NONE",
                    reason="Detector did not trigger on test response.",
                )

            # Detector tripped on test_hit and was clean on base/noop
            if not is_volatile:
                confidence = "CONFIRMED"
                reason = "Causally verified: clean benign baseline, reproducible test deviation."
            else:
                confidence = "MEDIUM"
                reason = "Attributable to test payload, but baseline shows ambient volatility."

            return DifferentialResult(
                stability_score=stability_score,
                deviation_score=deviation_score,
                base_noop_sim=base_noop_sim,
                noop_test_sim=noop_test_sim,
                base_test_sim=base_test_sim,
                dom_simhash_sim=dom_sim,
                levenshtein_sim=lev_sim,
                is_confirmed=True,
                is_ambient_leak=False,
                is_volatile_endpoint=is_volatile,
                confidence=confidence,
                reason=reason,
            )

        # Without an explicit detector, evaluate pure structural deviation
        has_significant_deviation = (
            deviation_score >= self.deviation_threshold
            or r_noop.get("status_code") != r_test.get("status_code")
        )

        if has_significant_deviation and not is_volatile:
            confidence = "HIGH"
            reason = "Significant structural deviation detected over stable baseline."
            is_confirmed = True
        elif has_significant_deviation and is_volatile:
            confidence = "LOW"
            reason = "Deviation detected, but endpoint exhibits baseline volatility."
            is_confirmed = False
        else:
            confidence = "NONE"
            reason = "No significant structural deviation between noop and test."
            is_confirmed = False

        return DifferentialResult(
            stability_score=stability_score,
            deviation_score=deviation_score,
            base_noop_sim=base_noop_sim,
            noop_test_sim=noop_test_sim,
            base_test_sim=base_test_sim,
            dom_simhash_sim=dom_sim,
            levenshtein_sim=lev_sim,
            is_confirmed=is_confirmed,
            is_ambient_leak=False,
            is_volatile_endpoint=is_volatile,
            confidence=confidence,
            reason=reason,
        )
