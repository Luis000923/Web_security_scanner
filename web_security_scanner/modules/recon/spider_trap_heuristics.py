"""Heuristic spider-trap detection.

``WebMapperAsync`` and ``BrowserRecon`` already enforce hard numeric ceilings
(``max_urls``/``max_depth`` and the per-signature ``MAX_URLS_PER_SIGNATURE``
cap - see ``web_mapper_async.py``). Those are a necessary backstop, but they
are reactive: the crawler only notices a trap once it has already burned a
chunk of its budget descending into it, and a well-tuned trap can still stay
just under the numeric cap while wasting most of the crawl on garbage.

This module adds a *proactive*, purely structural classifier that looks at a
single candidate URL - no crawl history required - and flags the three
classic infinite-generator shapes:

* **Cyclic paths** - a short segment sequence repeating itself
  (``/cat/sub/cat/sub/cat/sub``), the signature of a breadcrumb/calendar
  walker that re-links its own ancestors.
* **Excessively repeated segment values** - the same path component recurring
  many times anywhere in the path (``/page/page/page/page/page``), typically
  a "load more" / "deeper" link generator that never terminates.
* **High-entropy path tokens** - a long, non-separated alphanumeric run with
  near-random character distribution (a minted session id, signed token or
  hash embedded in the path), which the server re-generates on every
  response so the crawler can never revisit the same URL twice.
* **Repetitive query parameters** - many query-string parameters (by name or
  by value) recurring beyond a small threshold within a single URL, e.g. a
  faceted-search page that echoes the same filter back under N different
  parameter names.

Any one of these is enough to flag a candidate as trap-shaped; the caller
(``WebMapperAsync._crawl_structure`` / ``BrowserRecon``) is expected to log a
warning and discard that branch of the exploration tree instead of queuing
it, independent of whether the numeric caps have been hit yet.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlparse

_ALNUM_RUN_RE = re.compile(r"[0-9a-zA-Z]+")


@dataclass(frozen=True)
class TrapVerdict:
    """Result of :func:`evaluate_url_for_trap`."""

    is_trap: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.is_trap


def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def has_cyclic_segments(path: str, *, min_repeats: int = 3, max_cycle_len: int = 4) -> bool:
    """True when the tail of ``path`` is a short cycle repeated ``min_repeats``
    times or more, e.g. ``/a/b/a/b/a/b`` (cycle ``[a, b]``, repeated 3x).
    """
    segs = _segments(path)
    if len(segs) < min_repeats * 2:
        return False
    for cycle_len in range(1, min(max_cycle_len, len(segs) // min_repeats) + 1):
        window_len = cycle_len * min_repeats
        if window_len > len(segs):
            continue
        window = segs[-window_len:]
        cycle = window[:cycle_len]
        if all(window[i:i + cycle_len] == cycle for i in range(0, window_len, cycle_len)):
            return True
    return False


def has_repeated_segment_value(path: str, *, max_occurrences: int = 4) -> bool:
    """True when one path segment value recurs beyond ``max_occurrences`` times
    anywhere in the path, regardless of position (catches non-adjacent
    repeats a strict cycle check would miss, e.g. ``/x/page/y/page/z/page``).
    """
    segs = _segments(path)
    if not segs:
        return False
    counts = Counter(s.lower() for s in segs)
    return max(counts.values()) > max_occurrences


def segment_entropy(text: str) -> float:
    """Shannon entropy (bits/char) of ``text``."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _longest_alnum_run_entropy(segment: str) -> tuple[int, float]:
    """Length and entropy of the longest unbroken alphanumeric run in ``segment``.

    Splitting on separators (``-``, ``_``, ``.``) first means a prefixed token
    like ``session_9f3ac71e4b2d8a0f7c6e5d4b3a291807`` is still evaluated on
    its random suffix alone, while ordinary hyphenated SEO slugs (whose runs
    are all short, dictionary-word fragments) stay well under the threshold.
    """
    best_len, best_entropy = 0, 0.0
    for run in _ALNUM_RUN_RE.findall(segment):
        if len(run) >= best_len:
            best_len = len(run)
            best_entropy = max(best_entropy, segment_entropy(run))
    return best_len, best_entropy


def has_high_entropy_segment(path: str, *, min_len: int = 16, min_entropy: float = 3.0) -> bool:
    """True when the path contains a long, high-entropy alphanumeric run -
    e.g. a per-response session/signed token minted dynamically by the
    server, which a crawler can never revisit and will therefore expand
    without bound.
    """
    for seg in _segments(path):
        run_len, run_entropy = _longest_alnum_run_entropy(seg)
        if run_len >= min_len and run_entropy >= min_entropy:
            return True
    return False


def has_repetitive_query_params(query: str, *, min_repeats: int = 4) -> bool:
    """True when the query string repeats a param name or value beyond
    ``min_repeats`` times - a faceted-search / cache-buster trap that
    re-encodes the same state under many different keys.
    """
    pairs = parse_qsl(query, keep_blank_values=True)
    if len(pairs) < min_repeats:
        return False
    name_counts = Counter(k for k, _ in pairs)
    if max(name_counts.values(), default=0) >= min_repeats:
        return True
    value_counts = Counter(v for _, v in pairs if v)
    if value_counts and max(value_counts.values()) >= min_repeats:
        return True
    return False


def evaluate_url_for_trap(url: str) -> TrapVerdict:
    """Classify a single candidate URL as trap-shaped or not.

    Pure function of the URL string - no crawl history needed - so it can be
    called uniformly from the HTTP crawler (``WebMapperAsync``) and the
    headless-browser recon pass (``BrowserRecon``) alike.
    """
    parsed = urlparse(url)
    path = parsed.path

    if has_cyclic_segments(path):
        return TrapVerdict(True, "cyclic path segments")
    if has_repeated_segment_value(path):
        return TrapVerdict(True, "path segment repeated excessively")
    if has_high_entropy_segment(path):
        return TrapVerdict(True, "high-entropy path token (likely per-request generator)")
    if has_repetitive_query_params(parsed.query):
        return TrapVerdict(True, "repetitive query parameters")
    return TrapVerdict(False)
