"""Ground-truth metric computation and IEEE-ready export.

Pure stdlib. No pandas, no numpy, no scipy: the pipeline that produces the
numbers in the paper must run with the same dependency set as the scanner, so a
reviewer can reproduce it without a scientific-Python install.

What this module does
---------------------
Takes (a) the findings a scan reported and (b) a ground-truth table of
vulnerable / benign instances, and produces the confusion matrix plus the derived
rates, then renders them as Markdown and LaTeX tables.

The counting rule, stated explicitly because it is the thing most easily got
wrong
------------------------------------------------------------------------------
Every ground-truth instance lands in exactly one of four buckets:

======================  ====================================================
bucket                  rule
======================  ====================================================
``TP``                  a reported finding matched a vulnerable instance
``FN``                  a vulnerable instance with no matching finding
``FP``                  a reported finding matched a benign instance
``TN``                  a benign instance with no matching finding
======================  ====================================================

Plus one bucket the standard matrix has no slot for:

``FP_OUTSIDE_GT``
    a reported finding whose (url, parameter) matched **nothing** in the ground
    truth. It is a real reported finding, so it counts against precision, but it
    is not a "false positive on a known-benign point" and mixing the two is how
    an FPR comes out looking implausibly good.

Why that distinction is not academic
-----------------------------------
A reported finding that falls outside the ground truth is either (a) a false
positive on a point the ground truth does not cover, or (b) a *true* positive on
a vulnerability the ground truth missed. The ground truth cannot tell us which.
Collapsing both into one number hides the ambiguity instead of measuring it, so
this module reports the bucket separately and never lets it silently inflate a
rate. ``FPR`` is computed **only** against ground-truth benign instances and is
named ``fpr_on_ground_truth`` so that reading it as a general false-positive
rate would be a visible category error rather than an easy accident.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .vuln_classes import canonical_class, class_matches

__all__ = [
    "GroundTruth",
    "MetricResult",
    "Finding",
    "KeyResolver",
    "compute_metrics",
    "render_markdown",
    "render_latex",
    "render_console_summary",
    "write_results",
]


# ---- inputs ----------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One claim the scan makes about a point.

    A :class:`Finding` is either a reported vulnerability or a record that the
    point could not be measured. The two are the same shape because they are
    keyed the same way, and keeping them in one list means the ingest path
    cannot accidentally drop the unmeasured ones -- dropping them is exactly
    what would silently inflate recall.

    Attributes:
        url: The full request URL the finding was reported against.
        parameter: The injected parameter name, or "" when the finding is
            about the URL as a whole (path traversal, open redirect, ...).
        vulnerability_type: Free-form category label.
        severity: Free-form severity label.
        confidence: The tool's own confidence tier, when it emitted one.
        untested: True when this record is a "could not measure" marker rather
            than a vulnerability claim. Carries the
            :class:`~web_security_scanner.core.hybrid_score.ProbeStatus` value in
            ``vulnerability_type`` (``blocked_untested``, ``soft404_untested``,
            ``probe_aborted``).
    """

    url: str
    parameter: str = ""
    vulnerability_type: str = "unknown"
    severity: str = "unknown"
    confidence: str = ""
    untested: bool = False

    @property
    def key(self) -> tuple[str, str]:
        """The matching key: (url, parameter)."""
        return (self.url, self.parameter)

    @property
    def is_untested(self) -> bool:
        """True when the scan recorded this point as unmeasured."""
        return self.untested


# A callable mapping one finding to every ground-truth key it could legitimately
# be recorded under. Supplied explicitly by the caller (see compute_metrics).
KeyResolver = Callable[[Finding], "list[tuple[str, str]]"]


@dataclass(frozen=True)
class GroundTruth:
    """Labelled instances to score the scan against.

    Attributes:
        instances: ``(key, vulnerable, category)`` triples. ``category`` is a
            free-form label used only for per-slice breakdowns.
        name: Identifier of the ground-truth source, recorded in the export so
            a number can always be traced back to the table it came from.
        expected_class: Optional ``key -> vulnerability class`` map, used to
            score *class agreement* as well as detection.

            OWASP Benchmark labels each test case with the class it is supposed
            to be vulnerable to (``sqli``, ``xss``, ``pathtraver``, ...) and the
            vulnerability flag separately. Scoring only the flag treats an LDAP
            filter finding on a path-traversal endpoint as a hit, which is how a
            scanner that reports the wrong class everywhere can show 0.94 recall.
            Measured on the 338-instance subset: 182 vulnerable instances
            detected, but only 143 had the expected class reported.

            Empty means the source carries no class information, in which case
            the class-agreement rates are ``None`` -- not 1.0. A source that
            cannot answer a question must not appear to have answered it well.
    """

    instances: Sequence[tuple[tuple[str, str], bool, str]] = field(default_factory=tuple)
    name: str = "ground_truth"
    expected_class: Mapping[tuple[str, str], str] = field(default_factory=dict)


# ---- results ---------------------------------------------------------------


@dataclass(frozen=True)
class MetricResult:
    """Confusion matrix plus every derived rate, with its denominators.

    Counts are stored raw so the export can recompute and verify; ``rates()``
    returns the derived values. Every rate carries ``None`` rather than ``0.0``
    when its denominator is zero, so "no data" is never published as "zero
    performance".
    """

    # ---- claim counts (unit: one reported finding) --------------------------
    tp: int
    fn: int
    fp: int
    tn: int
    fp_outside_gt: int
    total_findings: int
    total_instances: int

    # ---- instance counts (unit: one labelled ground-truth instance) ---------
    #: Distinct vulnerable instances a finding landed on. ``tp`` counts *claims*
    #: and can therefore exceed the number of vulnerable instances: three
    #: testers reporting three different vulnerabilities on one endpoint are
    #: three correct claims but one detected vulnerability. Every rate whose
    #: denominator is a population of ground-truth instances -- recall,
    #: specificity, accuracy -- must use these, never the claim counts. Mixing
    #: the two units is what produced an accuracy of 1.64 on a 338-instance
    #: benchmark.
    tp_instances: int = 0
    #: Distinct benign instances at least one finding landed on. ``fp`` may be
    #: several times larger when several testers fire on one endpoint.
    fp_instances: int = 0
    #: Claims that landed on a vulnerable instance *and* named the class the
    #: ground truth expects for it. Zero when the ground truth carries no class
    #: labels, and :attr:`precision_class_matched` then returns ``None`` rather
    #: than falling back to ``precision``: "no class labels" and "every class
    #: matched" are different facts about a report.
    tp_class_matched: int = 0
    #: The same, counted per *instance*. A class-matched claim does not stop the
    #: next one from being class-matched too, so the two counters differ
    #: whenever several findings on one instance all name the right class.
    tp_class_matched_instances: int = 0
    #: How many vulnerable instances carry an expected-class label at all. The
    #: denominator restriction for the class-agreement rates: instances the
    #: source does not label by class cannot be scored on class agreement, and
    #: including them would let an unlabelled source look fully matched.
    class_labelled_instances: int = 0
    #: Claims that landed on a class-labelled vulnerable instance but whose
    #: reported type is not in the vocabulary of
    #: :mod:`web_security_scanner.core.vuln_classes`. They count as
    #: class-*mismatched*, never as matches, and the count is exported so a
    #: reviewer can see how much of the gap is a label nobody can normalise
    #: rather than a genuinely wrong class.
    claims_unknown_class: int = 0
    #: Claims that landed on a vulnerable instance the source does not label by
    #: class. Excluded from the class-agreement numerator *and* denominator, and
    #: reported so the difference between :attr:`recall` and
    #: :attr:`recall_class_matched` can be attributed.
    claims_unlabelled_class: int = 0

    # Provenance, so a published number is traceable to what produced it
    ground_truth_name: str = "ground_truth"
    per_category: dict[str, dict[str, int]] = field(default_factory=dict)
    unmatched_findings: list[str] = field(default_factory=list)
    #: Ground-truth keys the scan could not measure (perimeter block, soft 404,
    #: aborted probe). Held out of the tp/fp/fn/tn buckets entirely -- see
    #: :func:`compute_metrics`. Exposed because a recall figure whose meaning
    #: depends on how many points were skipped is not interpretable without it.
    untested_points: list[tuple[str, str]] = field(default_factory=list)
    #: How many of ``untested_points`` were vulnerable instances. Passed in by
    #: :func:`compute_metrics` (the only place that has the ground truth) rather
    #: than recomputed from a stored table, so it cannot drift from the list.
    untested_vulnerable: int = 0

    def with_vulnerable_untested(self, vulnerable_keys: set[tuple[str, str]]) -> MetricResult:
        """Return a copy with the vulnerable subset of the untested points counted.

        :func:`compute_metrics` calls this once it knows which untested keys
        were vulnerable.
        """
        import dataclasses

        return dataclasses.replace(
            self,
            untested_vulnerable=len(vulnerable_keys & set(self.untested_points)),
        )

    # ---- derived rates ----------------------------------------------------

    @property
    def precision(self) -> float | None:
        """TP / (TP + FP + FP_OUTSIDE_GT).

        Denominator is every reported finding, because every one of them is a
        claim the tool made. Restricting precision to findings that landed on
        labelled ground truth would silently forgive findings at unlabelled
        points -- which is exactly the behaviour that makes a precision number
        impossible to audit.
        """
        predicted = self.tp + self.fp + self.fp_outside_gt
        return self.tp / predicted if predicted else None

    @property
    def recall(self) -> float | None:
        """Detected vulnerable *instances* / measured vulnerable instances.

        The denominator is instances, not claims: a vulnerability cannot be
        recalled twice. Three testers reporting three distinct problems on one
        vulnerable endpoint are one detected instance, and counting them as
        three would let a scanner buy recall by overlapping its own detectors.

        Untested points are already excluded from ``fn`` by
        :func:`compute_metrics`, so this is a conditional recall: "of the
        vulnerabilities the scan was actually able to measure, how many did it
        find". Read it together with :attr:`recall_lower_bound` and
        :attr:`untested_points` -- a high recall bought by skipping points is
        not a better scanner, and this number alone cannot tell the two apart.
        """
        actual = self.tp_instances + self.fn
        return self.tp_instances / actual if actual else None

    @property
    def recall_lower_bound(self) -> float | None:
        """Recall if every untested *vulnerable* point had actually been missed.

        The pessimistic companion to :attr:`recall`: the same scan, scored with
        the skipped vulnerable points charged to it as false negatives. A gap
        between the two is exactly the credit the conditional recall is being
        given for points that were never measured, so publishing one without
        the other is how a perimeter-blocked scan gets mistaken for a
        high-recall scanner.
        """
        actual = self.tp_instances + self.fn + self.untested_vulnerable
        return self.tp_instances / actual if actual else None

    @property
    def precision_class_matched(self) -> float | None:
        """Claims that named the right class / every claim made.

        ``None`` when the ground truth carries no class labels, which is the
        honest answer for a source that cannot answer. The companion
        :attr:`recall_class_matched` is the number a reviewer will actually
        compute by hand on an OWASP Benchmark table, so a paper that publishes
        only :attr:`recall` is publishing the flattering half.
        """
        if not self.has_class_labels:
            return None
        predicted = self.tp + self.fp + self.fp_outside_gt
        return self.tp_class_matched / predicted if predicted else None

    @property
    def recall_class_matched(self) -> float | None:
        """Class-labelled vulnerable instances reported with the expected class.

        The denominator is the **class-labelled** population, not the whole
        vulnerable one. An instance the source does not label by class cannot be
        scored for class agreement -- and charging it here would conflate two
        unrelated gaps, "the scanner named the wrong vulnerability" and "the
        labels never said which vulnerability to expect", making a partially
        labelled table look worse than a correctly-labelled one.

        Per *instance*, and requiring the right class: an endpoint is recalled
        only if the tool reported what the ground truth says is there. This is
        strictly below :attr:`recall` -- recall counts any finding on the
        instance -- and the gap is the scanner reporting the wrong vulnerability
        class on an endpoint it did in fact detect.
        """
        if not self.has_class_labels:
            return None
        return self.tp_class_matched_instances / self.class_labelled_instances

    @property
    def has_class_labels(self) -> bool:
        """Whether the ground truth source names a vulnerability class.

        Derived from the count rather than stored as a flag, so it cannot go
        stale against the labels it claims to have counted.
        """
        return self.class_labelled_instances > 0

    @property
    def f1_class_matched(self) -> float | None:
        """Harmonic mean of the class-matched precision and recall.

        The same mixed-unit rule as :attr:`f1`, tightened by requiring the right
        class on both sides. ``None`` when the source carries no class labels,
        for the same reason as :attr:`precision_class_matched`.
        """
        p, r = self.precision_class_matched, self.recall_class_matched
        if p is None or r is None:
            return None
        if (p + r) == 0:
            return 0.0
        return 2 * p * r / (p + r)

    @property
    def duplicate_claims(self) -> int:
        """Claims made in excess of one per instance.

        ``total_findings - (tp_instances + fp_instances)`` over the claims that
        landed on a labelled instance. Reported rather than discarded: it is
        the visible price of multi-tester overlap, and it is why the claim
        counts and the instance counts differ.
        """
        return max(0, self.tp + self.fp - self.tp_instances - self.fp_instances)

    @property
    def untested_vulnerable_count(self) -> int:
        """How many of the untested points were vulnerable instances.

        :attr:`untested_points` is a flat list of keys; this is the subset that
        counts against the scanner. A benign untested point (a soft 404 on a
        non-vulnerable endpoint) is not the scanner's problem and is not
        counted.
        """
        return self.untested_vulnerable

    @property
    def coverage(self) -> float | None:
        """Share of labelled instances the scan was able to measure at all.

        ``(total_instances - untested) / total_instances``. Reported because
        precision and recall are both conditional on it, and a coverage figure
        in the low 0.8s changes what a 0.9 F1 actually means.
        """
        if not self.total_instances:
            return None
        return (self.total_instances - len(self.untested_points)) / self.total_instances

    @property
    def f1(self) -> float | None:
        """Harmonic mean of precision and recall.

        Deliberately a *mixed* metric: precision is over claims (every reported
        finding is a claim the tool made and can be wrong about) while recall is
        over instances (a vulnerability cannot be detected twice). Both
        conventions are defensible on their own; mixing them is the stricter of
        the two combinations, because it charges the scanner for every extra
        claim it made while refusing to let overlapping detectors inflate
        recall.

        ``None`` when either input is undefined (no findings to score, or no
        labelled instances to score them against). ``0.0`` when both are
        defined and zero -- the tool reported findings and every one was wrong,
        which is a measurement, not an absence of data.
        """
        p, r = self.precision, self.recall
        if p is None or r is None:
            return None
        if (p + r) == 0:
            return 0.0
        return 2 * p * r / (p + r)

    @property
    def specificity(self) -> float | None:
        """Clean benign instances / all benign instances -- ``TN/(TN+FP_inst)``.

        The denominator is the *labelled* population, so this is a property of
        the instance set. Using the claim-level ``fp`` here instead is what made
        specificity read 0.75 while the scanner actually flagged only 15 of 144
        benign endpoints (0.90): three testers firing on one endpoint is one
        contaminated instance, not three.
        """
        actual = self.tn + self.fp_instances
        return self.tn / actual if actual else None

    @property
    def fpr_on_ground_truth(self) -> float | None:
        """Contaminated benign instances / all benign instances -- ``FP_inst/(FP_inst+TN)``.

        Named to make the restriction impossible to miss. This is *not* the
        tool's false-positive rate over everything it said; use
        ``fp_rate_over_findings`` for that. Reporting this number alone as "FPR"
        understates the observed FP count whenever the scanner also reports
        findings at unlabelled points.
        """
        actual = self.fp_instances + self.tn
        return self.fp_instances / actual if actual else None

    @property
    def fp_rate_over_findings(self) -> float | None:
        """Share of reported findings that did not match a vulnerable instance.

        The honest headline false-positive rate: every reported finding is in
        the denominator, whether or not the ground truth covers its location.
        """
        return 1.0 - self.precision if self.precision is not None else None

    @property
    def accuracy(self) -> float | None:
        """(TP_inst + TN) / total instances.

        Instance units throughout. It is a rate over the labelled population,
        so it is bounded by 1 -- a value above 1 is not a weak scanner, it is a
        units bug (claim counts in a numerator whose denominator counts
        instances), and it is exactly what this property used to report.
        """
        total = self.total_instances
        return (self.tp_instances + self.tn) / total if total else None

    def rates(self) -> dict[str, float | None]:
        """Every derived rate in one dict, for JSON export.

        ``recall`` and ``f1`` are conditional on coverage. ``coverage``,
        ``recall_lower_bound`` and the ``untested_*`` counts travel with them so
        an exported figure cannot be read without the context that qualifies it.
        ``duplicate_claims`` travels too, because the claim counts and the
        instance counts that feed these rates differ whenever several testers
        land on one instance.

        The class-agreement rates are the strictest reading of the same run: a
        detection counts only if the reported class is the one the labels
        expect. They are always ``<=`` their unqualified counterparts and are
        ``None`` -- not 0.0 and not 1.0 -- when the source carries no class
        labels, so "unanswerable" can never be mistaken for "answered".
        """
        return {
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "recall_lower_bound": self.recall_lower_bound,
            "specificity": self.specificity,
            "fpr_on_ground_truth": self.fpr_on_ground_truth,
            "fp_rate_over_findings": self.fp_rate_over_findings,
            "accuracy": self.accuracy,
            "coverage": self.coverage,
            "duplicate_claims": float(self.duplicate_claims),
            "untested_points": float(len(self.untested_points)),
            "untested_vulnerable": float(self.untested_vulnerable),
            "precision_class_matched": self.precision_class_matched,
            "recall_class_matched": self.recall_class_matched,
            "f1_class_matched": self.f1_class_matched,
        }

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable form."""
        return {
            "ground_truth": self.ground_truth_name,
            "counts": {
                # Claims: one per reported finding.
                "tp": self.tp,
                "fp": self.fp,
                "fp_outside_ground_truth": self.fp_outside_gt,
                "total_findings": self.total_findings,
                # Instances: one per labelled ground-truth point.
                "tp_instances": self.tp_instances,
                "fp_instances": self.fp_instances,
                "fn": self.fn,
                "tn": self.tn,
                "total_instances": self.total_instances,
                # Class agreement, same claim/instance split.
                "has_class_labels": self.has_class_labels,
                "tp_class_matched": self.tp_class_matched,
                "tp_class_matched_instances": self.tp_class_matched_instances,
                "class_labelled_instances": self.class_labelled_instances,
                "claims_unknown_class": self.claims_unknown_class,
                "claims_unlabelled_class": self.claims_unlabelled_class,
            },
            "rates": self.rates(),
            "per_category": self.per_category,
            "unmatched_findings": list(self.unmatched_findings),
            # The skipped points, listed rather than only counted: a reader who
            # questions a recall figure has to be able to see which instances it
            # rests on being unmeasured.
            "untested_points": [list(k) for k in self.untested_points],
        }


# ---- computation -----------------------------------------------------------


def compute_metrics(
    findings: Iterable[Finding],
    ground_truth: GroundTruth,
    *,
    key_resolver: KeyResolver | None = None,
) -> MetricResult:
    """Score ``findings`` against ``ground_truth``.

    Matching
    --------
    A finding matches a ground-truth instance when the instance's key is among
    the keys the finding resolves to. By default a finding resolves to exactly
    one key -- its own ``(url, parameter)`` -- so matching is **exact**, with no
    fuzzy fallback. That default is deliberate: normalisation belongs to the
    caller that built the keys, because only it knows whether its source encodes
    the target as ``http://host/path?a=1`` or ``/path?a=1``. A heuristic here
    would silently convert unmatched findings into false negatives and quietly
    change every number.

    Pass ``key_resolver`` when the two sides genuinely encode an instance
    differently and an explicit, auditable mapping is available -- e.g. the OWASP
    Benchmark, whose ground truth is keyed by test-case id while findings carry
    the concrete probed URL. See
    :func:`benchmark_ground_truth.candidate_keys`. The resolver is *only* ever
    supplied by the caller that understands both encodings; it is never guessed.

    Duplicates
    ----------
    Duplicate findings for the same instance are counted once. A scanner that
    reports the same SQL injection from three testers has still made one claim;
    counting it three times would inflate recall in effect and make TP depend on
    how many testers happen to overlap.
    """
    truth_map: dict[tuple[str, str], tuple[bool, str]] = {
        key: (vulnerable, category) for key, vulnerable, category in ground_truth.instances
    }

    # One claim per instance: dedupe on the primary key, but remember which
    # truth keys each claim would satisfy so the resolver still applies.
    unique: dict[tuple[str, str], Finding] = {}
    for f in findings:
        # An untested record must never be shadowed by a real finding at the same
        # key: ``setdefault`` keeps whichever came first, and if the untested
        # marker arrived first the genuine detection would be discarded --
        # turning a true positive into an untested point. A vulnerability claim
        # therefore always wins the slot.
        prior = unique.get(f.key)
        if prior is None or (prior.is_untested and not f.is_untested):
            unique[f.key] = f

    tp = fn = fp = tn = fp_outside = 0
    tp_class_matched = 0
    claims_unknown_class = 0
    claims_unlabelled_class = 0
    matched_keys: set[tuple[str, str]] = set()
    matched_class_keys: set[tuple[str, str]] = set()
    class_labels = {
        key: label
        for key, label in (ground_truth.expected_class or {}).items()
        if canonical_class(label) is not None
    }
    # Only labels the shared vocabulary can actually resolve are kept, so a
    # typo in a hand-written ground truth removes an instance from the
    # class-scored population instead of silently scoring it as a class miss.
    # Such an instance is then indistinguishable from an unlabelled one -- which
    # is the honest reading: the source never told us the class.
    class_labelled = sum(
        1 for key, (vulnerable, _category) in truth_map.items()
        if vulnerable and key in class_labels
    )
    # Ground-truth keys the scan could not measure. See ``_untested_keys``.
    untested_keys: set[tuple[str, str]] = set()
    per_category: dict[str, dict[str, int]] = {}
    unmatched: list[str] = []

    for f in unique.values():
        # Resolve against the raw key as well as the resolver's candidates. An
        # untested marker is emitted by the scanner itself and its URL is
        # already the probed one; running it through a benchmark-style resolver
        # (which expects a test-case id) would fail to match and silently drop
        # the exclusion.
        candidates = list(key_resolver(f)) if key_resolver else []
        if f.key not in candidates:
            candidates.append(f.key)
        hit = next((c for c in candidates if c in truth_map), None)

        if f.is_untested:
            # Not a vulnerability claim: it must not reach tp/fp. Its only job
            # is to mark the point unmeasured, so the silence below is not read
            # as a miss. Unlabelled points are ignored -- there is nothing to
            # exclude from, and excluding them would hide scanner silence.
            if hit is not None:
                untested_keys.add(hit)
            continue

        if hit is not None:
            # The claim counter moves for every finding; the instance counter
            # and the per-category matrix only the first time this instance is
            # touched. Both are kept because they answer different questions --
            # "was the tool right?" (claims) and "did the tool find it?"
            # (instances). Keeping claims in the per-category table too would
            # make the breakdown disagree with the recall it sits next to.
            vulnerable, category = truth_map[hit]
            bucket = per_category.setdefault(
                category, {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
            )
            if vulnerable:
                tp += 1
                if hit not in matched_keys:
                    bucket["tp"] += 1
                expected = class_labels.get(hit)
                if expected is None:
                    # The source does not say which class to expect here, so
                    # this claim cannot be credited or blamed on class. Counted
                    # apart from an unknown class: "unlabelled" and "labelled
                    # but unrepresentable" need different fixes.
                    claims_unlabelled_class += 1
                elif class_matches(f.vulnerability_type, expected):
                    tp_class_matched += 1
                    matched_class_keys.add(hit)
                elif canonical_class(f.vulnerability_type) is None:
                    claims_unknown_class += 1
            else:
                fp += 1
                if hit not in matched_keys:
                    bucket["fp"] += 1
            matched_keys.add(hit)
        else:
            fp_outside += 1
            unmatched.append(f"{f.vulnerability_type} {f.url}"
                             + (f"?{f.parameter}" if f.parameter else ""))

    tp_instances = sum(1 for k in matched_keys if truth_map[k][0])
    fp_instances = len(matched_keys) - tp_instances

    # Everything the scanner stayed silent about.
    for key, (vulnerable, category) in truth_map.items():
        if key in matched_keys:
            continue
        if key in untested_keys:
            # The scan recorded the point as unmeasurable (perimeter block, soft
            # 404, aborted probe). Counting it as FN would make recall a
            # measurement of the perimeter's configuration instead of the
            # scanner's fidelity -- the exact defect ProbeStatus exists to
            # prevent. Reported separately, never folded into a rate.
            continue
        bucket = per_category.setdefault(category, {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
        if vulnerable:
            fn += 1
            bucket["fn"] += 1
        else:
            tn += 1
            bucket["tn"] += 1

    result = MetricResult(
        tp=tp,
        fn=fn,
        fp=fp,
        tn=tn,
        fp_outside_gt=fp_outside,
        total_findings=len(unique),
        total_instances=len(truth_map),
        tp_instances=tp_instances,
        fp_instances=fp_instances,
        tp_class_matched=tp_class_matched,
        tp_class_matched_instances=len(matched_class_keys),
        class_labelled_instances=class_labelled,
        claims_unknown_class=claims_unknown_class,
        claims_unlabelled_class=claims_unlabelled_class,
        ground_truth_name=ground_truth.name,
        per_category=per_category,
        unmatched_findings=sorted(unmatched),
        untested_points=sorted(untested_keys),
    )
    return result.with_vulnerable_untested(
        {key for key in untested_keys if truth_map[key][0]}
    )


# ---- rendering -------------------------------------------------------------

# (field, markdown label, LaTeX label). The two label sets are kept separate on
# purpose: sharing one string leaked LaTeX markup into the Markdown tables.
_RATE_LABELS: tuple[tuple[str, str, str], ...] = (
    ("precision", "Precision", "$\\mathrm{Precision}$"),
    ("recall", "Recall", "$\\mathrm{Recall}$"),
    ("f1", "F1", "$F_1$"),
    ("specificity", "Specificity", "$\\mathrm{Specificity}$"),
    ("fpr_on_ground_truth", "FPR (ground truth only)", "$\\mathrm{FPR}_{GT}$"),
    ("fp_rate_over_findings", "FP rate (over findings)", "$\\mathrm{FPR}_{find}$"),
    ("accuracy", "Accuracy", "$\\mathrm{Accuracy}$"),
)

#: Rendered only when something was untested. Precision and recall are
#: conditional on coverage, so a table that omits the skipped points would let
#: a reader take a conditional recall for an unconditional one.
_QUALIFIER_LABELS: tuple[tuple[str, str, str], ...] = (
    ("coverage", "Coverage (measured)", "$\\mathrm{Coverage}$"),
    ("recall_lower_bound", "Recall lower bound", "$\\mathrm{Recall}_{LB}$"),
    ("untested_points", "Untested points", "$\\#\\mathrm{Untested}$"),
    ("untested_vulnerable", "...of those, vulnerable", "$\\#\\mathrm{Untested}_{vuln}$"),
)

#: Rendered only when the ground truth actually names a class. A class-agreement
#: row printed against an unlabelled source would read as a measurement of
#: something, and there is nothing to measure.
_CLASS_LABELS: tuple[tuple[str, str, str], ...] = (
    ("precision_class_matched", "Precision (class-matched)",
     "$\\mathrm{Precision}_{class}$"),
    ("recall_class_matched", "Recall (class-matched)", "$\\mathrm{Recall}_{class}$"),
    ("f1_class_matched", "F1 (class-matched)", "$F_1^{class}$"),
)

_CLASS_NOTE: dict[str, str] = {
    "precision_class_matched":
        "class-matched claims / every claim; None when the labels carry no class",
    "recall_class_matched":
        "class-matched instances / *class-labelled* vulnerable instances",
    "f1_class_matched": "harmonic mean of the two class-matched rates",
}

_RATE_NOTE: dict[str, str] = {
    "fpr_on_ground_truth": "FP_inst/(FP_inst+TN) over labelled benign instances",
    "fp_rate_over_findings": "1 - precision; every reported finding in the denominator",
    "recall": "TP_inst/(TP_inst+FN) over *measured* vulnerable instances; untested excluded",
    "recall_lower_bound": "recall charging every untested vulnerable point as FN",
    "specificity": "TN/(TN+FP_inst) over labelled benign instances",
    "accuracy": "(TP_inst+TN)/total instances",
}

#: Always printed under the matrix. TP and FP are claim counts and routinely
#: exceed the instance population (several testers land on one endpoint), so a
#: bare ``TP 426 / 194 vulnerable instances`` reads as a contradiction.
_UNITS_NOTE = (
    "TP/FP count *claims* (one per reported finding); FN/TN count *instances*. "
    "Rates whose denominator is a ground-truth population use the instance counts."
)


def _fmt(value: float | None, spec: str = ".4f") -> str:
    return "n/a" if value is None else format(value, spec)


def render_markdown(result: MetricResult) -> str:
    """Markdown tables: confusion matrix, rates, per-category breakdown."""
    lines: list[str] = []

    lines.append("### Confusion matrix")
    lines.append("")
    lines.append("| Outcome | Claims | Instances |")
    lines.append("| --- | ---: | ---: |")
    lines.append(f"| True positive (TP) | {result.tp} | {result.tp_instances} |")
    lines.append(
        f"| False negative (FN) | {result.fn} | {result.fn} |"
    )
    lines.append(f"| False positive (FP) | {result.fp} | {result.fp_instances} |")
    lines.append(f"| True negative (TN) | {result.tn} | {result.tn} |")
    lines.append(
        f"| Reported, outside ground truth | {result.fp_outside_gt} | -- |"
    )
    lines.append(
        f"| **Total** | **{result.total_findings}** |"
        f" **{result.total_instances}** |"
    )
    lines.append("")
    lines.append(f"*{_UNITS_NOTE}*")
    if result.duplicate_claims:
        lines.append("")
        lines.append(
            f"`{result.duplicate_claims}` claim(s) landed on an instance that was"
            " already counted -- multi-tester overlap on the same endpoint."
        )
    if result.untested_points:
        lines.append(
            f"*Untested (held out of TP/FP/FN/TN):"
            f" {len(result.untested_points)}.*"
        )

    lines.append("")
    lines.append("### Rates")
    lines.append("")
    rates = result.rates()
    lines.append("| Metric | Value |")
    lines.append("| --- | ---: |")
    for field_name, label, _ in _RATE_LABELS:
        lines.append(f"| {label} | {_fmt(rates[field_name])} |")
    for field_name, _, _ in _RATE_LABELS:
        if field_name in _RATE_NOTE:
            lines.append(f"| *{_RATE_NOTE[field_name]}* | |")

    if result.untested_points:
        lines.append("")
        lines.append("| Coverage qualifier | Value |")
        lines.append("| --- | ---: |")
        for field_name, label, _ in _QUALIFIER_LABELS:
            lines.append(f"| {label} | {_fmt(rates[field_name])} |")
        lines.append(
            f"| *{_RATE_NOTE['recall_lower_bound']}* | |"
        )

    lines.append("")
    if result.has_class_labels:
        lines.append("### Class agreement")
        lines.append("")
        lines.append(
            "The strictest reading of the same run: a detection counts only if"
            " the reported class is the one the labels expect. Every rate here"
            " is at or below its unqualified counterpart."
        )
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("| --- | ---: |")
        for field_name, label, _ in _CLASS_LABELS:
            lines.append(f"| {label} | {_fmt(rates[field_name])} |")
        for field_name, _, _ in _CLASS_LABELS:
            lines.append(f"| *{_CLASS_NOTE[field_name]}* | |")
        if result.claims_unknown_class:
            lines.append("")
            lines.append(
                f"`{result.claims_unknown_class}` claim(s) landed on a"
                " class-labelled vulnerable instance with a reported type"
                " outside the shared vocabulary, so they are counted as"
                " mismatches rather than matches."
            )
    else:
        lines.append(
            "*Class agreement: n/a -- the ground truth source carries no"
            " expected-class labels, so the question cannot be answered. The"
            " rates above therefore count a detection on any vulnerability"
            " class as a hit.*"
        )

    if result.per_category:
        lines.append("")
        lines.append("### Per-category breakdown")
        lines.append("")
        lines.append("| Category | TP | FN | FP | TN |")
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        for category in sorted(result.per_category):
            b = result.per_category[category]
            lines.append(
                f"| {category} | {b['tp']} | {b['fn']} | {b['fp']} | {b['tn']} |"
            )

    if result.unmatched_findings:
        lines.append("")
        lines.append(
            f"<details><summary>{len(result.unmatched_findings)} finding(s) "
            "reported outside the ground truth (auditable list)</summary>"
        )
        lines.append("")
        for item in result.unmatched_findings:
            lines.append(f"- `{item}`")
        lines.append("</details>")

    return "\n".join(lines) + "\n"


def render_latex(
    result: MetricResult,
    *,
    caption: str = "Detection metrics",
    label: str = "tab:metrics",
) -> str:
    """LaTeX booktabs table, ready to \\input from a paper section."""
    lines: list[str] = []
    lines.append("% Generated by web_security_scanner.core.ieee_metrics -- do not edit")
    lines.append("\\begin{table}[t]")
    lines.append("\\centering")
    lines.append("\\begin{tabular}{lrr}")
    lines.append("\\toprule")
    lines.append("\\textbf{Outcome} & \\textbf{Claims} & \\textbf{Instances} \\\\")
    lines.append("\\midrule")
    lines.append(f"True positive (TP) & {result.tp} & {result.tp_instances} \\\\")
    lines.append(f"False negative (FN) & {result.fn} & {result.fn} \\\\")
    lines.append(f"False positive (FP) & {result.fp} & {result.fp_instances} \\\\")
    lines.append(f"True negative (TN) & {result.tn} & {result.tn} \\\\")
    lines.append(
        f"Reported, outside ground truth & {result.fp_outside_gt} & n/a \\\\"
    )
    lines.append("\\midrule")
    lines.append(f"Total & {result.total_findings} & {result.total_instances} \\\\")
    if result.untested_points:
        lines.append(
            f"Untested (excluded from TP/FP/FN/TN) & -- &"
            f" {len(result.untested_points)} \\\\"
        )
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append(
        f"\\caption{{{caption}. TP and FP count claims (one per reported"
        " finding); FN and TN count instances. Rates whose denominator is a"
        " ground-truth population use the instance column.}"
    )
    lines.append(f"\\label{{{label}}}")
    lines.append("\\end{table}")

    lines.append("")
    lines.append("% Rates (as a macro block, for \\MetricFone etc.)")
    lines.append("\\begin{table}[t]")
    lines.append("\\centering")
    lines.append("\\begin{tabular}{lr}")
    lines.append("\\toprule")
    lines.append("\\textbf{Metric} & \\textbf{Value} \\\\")
    lines.append("\\midrule")
    rates = result.rates()
    for field_name, _, latex_name in _RATE_LABELS:
        value = rates[field_name]
        rendered = "n/a" if value is None else f"{value:.4f}"
        lines.append(f"{latex_name} & {rendered} \\\\")
    if result.untested_points:
        # Emitted as its own block so the conditional recall in the table above
        # cannot be lifted into a paper without the qualifiers that bound it.
        lines.append("\\midrule")
        for field_name, _, latex_name in _QUALIFIER_LABELS:
            value = rates[field_name]
            rendered = "n/a" if value is None else f"{value:.4f}"
            lines.append(f"{latex_name} & {rendered} \\\\")
    if result.has_class_labels:
        # Same reasoning: the class-matched figures are always at or below the
        # ones above, and a table carrying only the flattering pair would let a
        # reader quote a detection rate for a class-agreement claim.
        lines.append("\\midrule")
        for field_name, _, latex_name in _CLASS_LABELS:
            value = rates[field_name]
            rendered = "n/a" if value is None else f"{value:.4f}"
            lines.append(f"{latex_name} & {rendered} \\\\")
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    caption = (
        "Derived rates. FPR is reported over labelled ground-truth benign"
        " points only; FP rate is over all reported findings."
    )
    if result.has_class_labels:
        caption += (
            " The $class$-subscripted rates are the strict reading: a"
            " detection counts only when the reported class matches the class"
            " the labels expect, over the class-labelled instances only, and are"
            " therefore never above the unqualified rates."
        )
    else:
        caption += (
            " The ground truth carries no expected-class labels, so class"
            " agreement is undefined: a detection on any vulnerability class"
            " counts as a hit in the rates above."
        )
    if result.untested_points:
        caption += (
            " Recall and $F_1$ are conditional on coverage: untested points"
            " (perimeter block, soft 404, aborted probe) are held out of the"
            " confusion matrix, and the coverage row plus the recall lower"
            " bound state what that costs."
        )
    lines.append(f"\\caption{{{caption}}}")
    lines.append(f"\\\\label{{{label}-rates}}")
    lines.append("\\end{table}")

    if result.per_category:
        lines.append("")
        lines.append("\\begin{table}[t]")
        lines.append("\\centering")
        lines.append("\\begin{tabular}{lrrrr}")
        lines.append("\\toprule")
        lines.append("\\textbf{Category} & \\textbf{TP} & \\textbf{FN} & "
                     "\\textbf{FP} & \\textbf{TN} \\\\")
        lines.append("\\midrule")
        for category in sorted(result.per_category):
            b = result.per_category[category]
            safe = category.replace("_", "\\_")
            lines.append(
                f"{safe} & {b['tp']} & {b['fn']} & {b['fp']} & {b['tn']} \\\\"
            )
        lines.append("\\bottomrule")
        lines.append("\\end{tabular}")
        lines.append("\\caption{Per-category counts.}")
        lines.append(f"\\label{{{label}-per-category}}")
        lines.append("\\end{table}")

    return "\n".join(lines) + "\n"


def write_results(
    result: MetricResult,
    out_dir: str | Path,
    *,
    basename: str = "results",
) -> dict[str, str]:
    """Write ``results.json``, ``metrics.md`` and ``metrics.tex``. Returns paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    json_path = out / f"{basename}.json"
    md_path = out / f"{basename}.md"
    tex_path = out / f"{basename}.tex"

    json_path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(result), encoding="utf-8")
    tex_path.write_text(render_latex(result), encoding="utf-8")

    return {"json": str(json_path), "markdown": str(md_path), "latex": str(tex_path)}


def render_console_summary(result: MetricResult) -> str:
    """Human-readable summary for a terminal or CI log."""
    r = result.rates()
    lines = [
        "=" * 62,
        " DETECTION METRICS",
        "=" * 62,
        f" ground truth        : {result.ground_truth_name}",
        f" instances labelled  : {result.total_instances}",
        f" findings reported   : {result.total_findings}",
        "-" * 62,
        " claims  TP/FP       : "
        f"{result.tp} / {result.fp}   (one per reported finding)",
        f" instances TP/FN/FP/TN: {result.tp_instances} / {result.fn}"
        f" / {result.fp_instances} / {result.tn}",
        f" outside ground truth: {result.fp_outside_gt}",
        "-" * 62,
        f" Precision           : {_fmt(r['precision'])}",
        f" Recall              : {_fmt(r['recall'])}",
        f" F1                  : {_fmt(r['f1'])}",
        f" Specificity         : {_fmt(r['specificity'])}",
        f" FPR (GT only)       : {_fmt(r['fpr_on_ground_truth'])}",
        f" FP rate (findings)  : {_fmt(r['fp_rate_over_findings'])}",
        f" Accuracy            : {_fmt(r['accuracy'])}",
    ]
    if result.duplicate_claims:
        lines.append(
            f" duplicate claims    : {result.duplicate_claims}"
            "   (extra findings on an instance already counted)"
        )
    if result.untested_points:
        # Printed inline with the rates, not as a footnote: recall above is a
        # conditional figure and the reader has to see the condition in the
        # same breath.
        lines += [
            "-" * 62,
            f" Untested points     : {len(result.untested_points)}"
            f" ({result.untested_vulnerable} vulnerable) -- excluded from"
            " TP/FP/FN/TN",
            f" Coverage            : {_fmt(r['coverage'])}",
            f" Recall lower bound  : {_fmt(r['recall_lower_bound'])}"
            "   (untested vulnerable charged as FN)",
        ]
    if result.has_class_labels:
        # Also inline: the class-matched pair is the number a reviewer
        # recomputes by hand on a benchmark table, and the gap between it and
        # the pair above is the whole point of reporting it.
        lines += [
            "-" * 62,
            " class agreement (reported class == expected class):",
            f"   Precision         : {_fmt(r['precision_class_matched'])}"
            f"   (vs {_fmt(r['precision'])} on any class)",
            f"   Recall            : {_fmt(r['recall_class_matched'])}"
            f"   (vs {_fmt(r['recall'])} on any class)",
            f"   F1                : {_fmt(r['f1_class_matched'])}"
            f"   (vs {_fmt(r['f1'])} on any class)",
            f"   class-labelled    : {result.class_labelled_instances}"
            f" vulnerable instances,"
            f" {result.tp_class_matched_instances} matched",
        ]
        if result.claims_unknown_class:
            lines.append(
                f"   unknown classes   : {result.claims_unknown_class} claim(s)"
                " with a reported type outside the shared vocabulary; counted"
                " as mismatches"
            )
    else:
        lines.append(
            " class agreement     : n/a -- the ground truth carries no"
            " expected-class labels, so the rates above count a detection on"
            " any vulnerability class as a hit."
        )
    lines.append("=" * 62)
    if result.unmatched_findings:
        lines.append(
            f" note: {result.fp_outside_gt} finding(s) fell outside the ground"
            " truth; FPR (GT only) does not account for them."
        )
        lines.append("=" * 62)
    return "\n".join(lines)
