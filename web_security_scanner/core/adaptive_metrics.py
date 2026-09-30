"""IEEE-paper-ready export of the Phase 3 adaptive anomaly engine's own metrics.

Scope, deliberately narrow: this reports on the *scoring engine itself* --
how much of what :func:`assess_anomaly
<web_security_scanner.modules.vulnerability_testers.base_tester_async.assess_anomaly>`
flags as "interesting" is WAF/load-balancer noise it correctly down-weights,
how often an edge WAF's block codes were observed, how often a family's
accumulated score crossed the adaptive-reorder threshold. It does **not**
compute classical precision/recall/false-positive-rate against ground truth
-- that requires labeled vulnerable/benign instances and already lives in
``tools/analyze_results.py`` + ``tools/eval_oracle.py`` (the testbed's paired
telemetry-vs-``ground_truth.json`` pipeline; see that module's docstring).
Conflating the two would misrepresent an internal noise-filtering rate as a
detector accuracy figure, which is not defensible in a paper. Every field
below is named and documented for exactly what it measures so it can be cited
correctly.

Usage, end of a scan::

    from web_security_scanner.core.adaptive_metrics import aggregate_ieee_metrics

    snapshots = [tester.adaptive_metrics_snapshot() for tester in testers]
    metrics = aggregate_ieee_metrics(snapshots, run_id=run_id)
    export_ieee_metrics_json(metrics, "reports/metrics/adaptive_engine.json")

``evasion`` is optional and supplied by the caller (this module has no way to
know, from ``EndpointFeedback`` alone, which probes carried a WAF-bypass
transform) -- see :class:`EvasionCounters`.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "EvasionCounters",
    "IEEEAdaptiveMetrics",
    "aggregate_ieee_metrics",
    "export_ieee_metrics_json",
]

# Reason tags that AnomalySignal / EndpointFeedback.reason_tags can carry.
# Kept here (not re-derived from base_tester_async) so this module has no
# import-time dependency on the tester package -- it only consumes the plain
# dicts VulnerabilityTester.adaptive_metrics_snapshot() already produces.
_NOISE_TAGS = ("throttled", "infra-noise")
_SIGNAL_TAGS = (
    "server-error", "waf-block", "status", "length-shift",
    "full-reflection", "partial-reflection", "latency",
)


@dataclass(frozen=True)
class EvasionCounters:
    """Caller-supplied WAF-bypass A/B counts (this module cannot infer them).

    ``baseline_*`` are probes sent with no ``waf_bypass_transforms`` chain;
    ``mutated_*`` are probes sent through one (``random_case``,
    ``adaptive_entropy``, ...). "Blocked" means the response carried a
    ``waf-block`` (401/403/406) or ``throttled`` (429/503) reason -- i.e. the
    edge rejected the request outright, not that the target turned out
    non-vulnerable. Leave everything at 0 to omit the evasion block from the
    export (``effectiveness`` is then ``None``, not a misleading 0.0).
    """

    baseline_total: int = 0
    baseline_blocked: int = 0
    mutated_total: int = 0
    mutated_blocked: int = 0

    def baseline_block_rate(self) -> float | None:
        return self.baseline_blocked / self.baseline_total if self.baseline_total else None

    def mutated_block_rate(self) -> float | None:
        return self.mutated_blocked / self.mutated_total if self.mutated_total else None

    def effectiveness(self) -> float | None:
        """Relative drop in block rate from applying a WAF-bypass transform.

        ``1.0`` = mutated probes were never blocked where baseline probes
        were; ``0.0`` = the transform made no difference; negative = the
        mutation made things *worse* (a real, useful outcome to report --
        some WAF rules trigger specifically on double-encoding). ``None``
        when there isn't enough data on either arm to compare.
        """
        base = self.baseline_block_rate()
        mut = self.mutated_block_rate()
        if base is None or mut is None or base == 0:
            return None
        return (base - mut) / base


@dataclass(frozen=True)
class IEEEAdaptiveMetrics:
    """Structured, paper-citable snapshot of the adaptive engine's behaviour.

    Every rate is documented with exactly what it divides by; none of them
    are a substitute for ground-truth-based precision/recall (see module
    docstring). ``testers`` retains the per-tester breakdown so a table can
    show XSS vs SQLi vs ... separately as well as the aggregate row.
    """

    run_id: str
    total_probes: int
    points_tracked: int
    points_boosted: int
    reason_counts: dict[str, int]
    testers: tuple[dict[str, Any], ...]
    evasion: EvasionCounters = field(default_factory=EvasionCounters)

    # ---- derived rates, each documented with its exact denominator --------

    def noise_suppression_rate(self) -> float:
        """(throttled + infra-noise signals) / (every non-empty-reason signal).

        The fraction of "the response looked different from baseline" events
        that the WAF/LB-aware scoring in ``assess_anomaly`` recognises as
        target-infrastructure noise rather than payload evidence, and so
        keeps out of the adaptive-reorder budget. Higher = more noise
        correctly filtered *before* it could bias which payloads get
        re-prioritised or inflate an apparent finding rate. This is an
        internal filtering-effectiveness measure, not a false-positive rate
        against labeled vulnerabilities.
        """
        noise = sum(self.reason_counts.get(t, 0) for t in _NOISE_TAGS)
        signal = noise + sum(self.reason_counts.get(t, 0) for t in _SIGNAL_TAGS)
        return noise / signal if signal else 0.0

    def waf_block_rate(self) -> float:
        """waf-block (401/403/406) signals / total probes across all testers."""
        return self.reason_counts.get("waf-block", 0) / self.total_probes if self.total_probes else 0.0

    def hot_boost_rate(self) -> float:
        """Injection points whose adaptive-reorder threshold was crossed / all points tracked."""
        return self.points_boosted / self.points_tracked if self.points_tracked else 0.0

    def reflection_rate(self) -> float:
        """(full + partial reflection signals) / total probes."""
        refl = self.reason_counts.get("full-reflection", 0) + self.reason_counts.get(
            "partial-reflection", 0)
        return refl / self.total_probes if self.total_probes else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Flat, JSON-safe dict -- the actual export payload."""
        return {
            "run_id": self.run_id,
            "total_probes": self.total_probes,
            "points_tracked": self.points_tracked,
            "points_boosted": self.points_boosted,
            "reason_counts": dict(self.reason_counts),
            "rates": {
                "noise_suppression_rate": round(self.noise_suppression_rate(), 6),
                "waf_block_rate": round(self.waf_block_rate(), 6),
                "hot_boost_rate": round(self.hot_boost_rate(), 6),
                "reflection_rate": round(self.reflection_rate(), 6),
            },
            "evasion": {
                "baseline_total": self.evasion.baseline_total,
                "baseline_blocked": self.evasion.baseline_blocked,
                "baseline_block_rate": self.evasion.baseline_block_rate(),
                "mutated_total": self.evasion.mutated_total,
                "mutated_blocked": self.evasion.mutated_blocked,
                "mutated_block_rate": self.evasion.mutated_block_rate(),
                "effectiveness": self.evasion.effectiveness(),
            },
            "testers": [dict(t) for t in self.testers],
            "note": (
                "Operational metrics of the anomaly-scoring engine itself "
                "(noise filtering, WAF-block observation, reorder activity). "
                "NOT ground-truth precision/recall/FPR -- see "
                "tools/analyze_results.py + tools/eval_oracle.py for those."
            ),
        }


def aggregate_ieee_metrics(
    snapshots: list[dict[str, Any]],
    *,
    run_id: str = "unknown",
    evasion: EvasionCounters | None = None,
) -> IEEEAdaptiveMetrics:
    """Combine one :meth:`VulnerabilityTester.adaptive_metrics_snapshot` per
    tester into one run-level :class:`IEEEAdaptiveMetrics`.
    """
    total_probes = 0
    points_tracked = 0
    points_boosted = 0
    reason_counts: dict[str, int] = {}
    for snap in snapshots:
        total_probes += int(snap.get("total_probes", 0))
        points_tracked += int(snap.get("points_tracked", 0))
        points_boosted += int(snap.get("points_boosted", 0))
        for tag, n in dict(snap.get("reason_counts", {})).items():
            reason_counts[tag] = reason_counts.get(tag, 0) + int(n)
    return IEEEAdaptiveMetrics(
        run_id=run_id,
        total_probes=total_probes,
        points_tracked=points_tracked,
        points_boosted=points_boosted,
        reason_counts=reason_counts,
        testers=tuple(snapshots),
        evasion=evasion or EvasionCounters(),
    )


def export_ieee_metrics_json(metrics: IEEEAdaptiveMetrics, path: str | Path) -> Path:
    """Write ``metrics.to_dict()`` as pretty JSON to ``path``; returns the path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(metrics.to_dict(), indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return out


# Keep `asdict` importable-and-used for anyone wanting the raw dataclass shape
# (e.g. to hand EvasionCounters straight to a DataFrame) without re-deriving it.
def evasion_counters_as_dict(counters: EvasionCounters) -> dict[str, Any]:
    return asdict(counters)
