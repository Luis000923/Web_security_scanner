"""Derive the WAF-evasion A/B counters from already-collected telemetry.

Why this module exists
----------------------
:class:`~web_security_scanner.core.adaptive_metrics.EvasionCounters` is the
paper-facing A/B metric for *Track A* (does lexical mutation actually recover
blocked probes?). It has been dead code since it was written: nothing in the
production path ever constructed one, so ``effectiveness()`` was never computed
from a real scan.

The missing piece turned out to be **not** more plumbing at the probe site. By
the time an adaptive-retry cycle finishes,
:class:`~web_security_scanner.core.telemetry_engine.WafEvasionMetrics` has
already accumulated every number the A/B metric needs -- the raw
per-cycle ``blocked``/``success``/``attempts`` triple is recorded at
``modules/exploit_engine.py`` via
:meth:`TelemetryEngine.record_waf_evasion`. All that was lacking was the
algebra that folds those totals into the A/B shape, and that algebra is exactly
what lives here, isolated and unit-tested instead of inlined at six call sites.

The algebra
-----------
One adaptive-retry cycle contributes to
:class:`WafEvasionMetrics` as::

    probes                 += 1                      # one baseline probe per cycle
    total_mutation_attempts += max(0, attempts - 1)  # the mutated retries
    perimeter_blocks       += 1  if blocked
    bypassed               += 1  if success

The three outcomes a cycle can have, and what each therefore contributes:

===================  ==================  ==========  ==========
outcome              mutated_total       bypassed    mutated_blocked
===================  ==================  ==========  ==========
``NOT_BLOCKED``      0                   0           0
``BYPASSED`` (k>=1)  k                   1           k - 1
``CONFIRMED_BLOCKED``  m (== attempts-1) 0           m
===================  ==================  ==========  ==========

Reading the last two columns together, ``mutated_blocked`` is simply
``total_mutation_attempts - bypassed``: every mutated retry was blocked except
the single one that got through, and a bypassed cycle contributes exactly one
such success. Hence::

    baseline_total  = probes
    baseline_blocked = perimeter_blocks_encountered
    mutated_total   = total_mutation_attempts
    mutated_blocked = total_mutation_attempts - bypassed

Invariant relied upon
---------------------
A ``BYPASSED`` verdict implies at least one mutation was actually sent (the
engine can only report it after retrying), so ``bypassed <= total_mutation_attempts``
and ``mutated_blocked`` cannot go negative. :func:`evasion_counters_from_snapshot`
clamp-guards anyway rather than emit a negative rate, because a silently negative
``mutated_blocked`` would invert the sign of ``effectiveness()`` and produce a
plausible-looking but wrong paper number. If the clamp ever actually fires, the
retry engine's accounting changed and the derivation needs revisiting.

Scope note: these are *perimeter-block* rates, not detection rates. A blocked
probe says the WAF rejected the request; it does not say the target was or was
not vulnerable. Ground-truth recall/precision lives in
``tools/eval_oracle.py`` + ``tools/analyze_results.py``.
"""

from __future__ import annotations

from typing import Any

from .adaptive_metrics import EvasionCounters

__all__ = ["evasion_counters_from_snapshot", "evasion_counters_from_metrics"]


def evasion_counters_from_metrics(
    probes: int,
    perimeter_blocks: int,
    total_mutation_attempts: int,
    bypassed: int,
) -> EvasionCounters:
    """Build :class:`EvasionCounters` from the four raw totals.

    The algebra and its invariant are documented at module level. All four
    inputs are the cumulative totals as tracked by ``WafEvasionMetrics``; they
    are passed explicitly rather than read from a dict so the function is usable
    with either a live metrics object or a stored snapshot.
    """
    probes = max(0, int(probes))
    perimeter_blocks = max(0, int(perimeter_blocks))
    total_mutation_attempts = max(0, int(total_mutation_attempts))
    bypassed = max(0, int(bypassed))

    mutated_blocked = total_mutation_attempts - bypassed
    if mutated_blocked < 0:
        # Invariant violated (see module docstring). Clamp rather than emit a
        # negative count, which would flip the sign of effectiveness().
        mutated_blocked = 0

    return EvasionCounters(
        baseline_total=probes,
        baseline_blocked=perimeter_blocks,
        mutated_total=total_mutation_attempts,
        mutated_blocked=mutated_blocked,
    )


def evasion_counters_from_snapshot(snapshot: Any) -> EvasionCounters:
    """Build :class:`EvasionCounters` from a telemetry snapshot or sub-dict.

    Accepts either the full ``TelemetryEngine.snapshot()`` (in which case the
    ``waf_evasion`` sub-dict is used) or the ``waf_evasion`` sub-dict directly.
    Returns an all-zero counter set -- which renders as an *omitted* evasion
    block, not a misleading ``0.0`` effectiveness -- when the input is missing,
    empty, or malformed.
    """
    if not isinstance(snapshot, dict):
        return EvasionCounters()

    waf = snapshot.get("waf_evasion")
    if not isinstance(waf, dict):
        waf = snapshot if "probes" in snapshot else {}

    def _int(key: str) -> int:
        try:
            return int(waf.get(key, 0) or 0)
        except (TypeError, ValueError):
            return 0

    return evasion_counters_from_metrics(
        probes=_int("probes"),
        perimeter_blocks=_int("perimeter_blocks_encountered"),
        total_mutation_attempts=_int("total_mutation_attempts"),
        bypassed=_int("bypassed"),
    )
