"""TP claims and TP instances are not the same unit, and mixing them breaks rates.

Defect found on the live OWASP Benchmark run (338 instances, 471 findings):
the confusion matrix counted TP/FP **per reported finding** while FN/TN counted
**per labelled instance**. One endpoint routinely receives several findings --
three testers each reporting a different vulnerability class -- so the claim
counts exceeded the instance population:

    claims     TP/FP      : 426 / 44
    instances  TP/FN/FP/TN: 182 / 12 / 15 / 129

The rates that divide an instance population then inherited the claim count,
and the exported table shipped:

    Specificity  0.7457   (129 / (129 + 44))   -> should be 129/144 = 0.8958
    Recall       0.9726   (426 / (426 + 12))   -> should be 182/194 = 0.9381
    Accuracy     1.6420   (426 + 129) / 338    -> **greater than one**

Accuracy above 1 is the tell: not a weak scanner, a units bug. It is also the
kind of number a reviewer checks first, because it is arithmetically free to
verify against the confusion matrix printed above it.

The convention kept here, and why:

* precision is over **claims** -- every reported finding is a claim the tool
  made and can be wrong about, so forgiving the extra ones would make
  precision unauditable;
* recall, specificity and accuracy are over **instances** -- a vulnerability
  cannot be detected twice, so overlapping detectors must not buy recall, and
  a rate over a population must divide by that population.

Docstrings and comments are English (house rule). Research findings
(statements about the tool's measured behaviour, not mechanics) are Spanish.
"""

import json

from web_security_scanner.core.benchmark_ground_truth import candidate_keys
from web_security_scanner.core.ieee_metrics import (
    Finding,
    GroundTruth,
    compute_metrics,
    render_console_summary,
    render_latex,
    render_markdown,
)

# ---- fixtures ---------------------------------------------------------------

#: Two vulnerable instances, two benign ones, keyed by the bare endpoint.
_INSTANCES = [
    (("/a", "q"), True, "sqli"),
    (("/b", "q"), True, "sqli"),
    (("/c", "q"), False, "sqli"),
    (("/d", "q"), False, "sqli"),
]


def _gt(instances=_INSTANCES) -> GroundTruth:
    return GroundTruth(instances=tuple(instances), name="synthetic")


def _resolver(finding: Finding) -> list[tuple[str, str]]:
    """Ground truth keyed by bare endpoint, findings carrying the payload.

    This is the shape every DAST report has: the label names the injection
    point, the finding names the concrete request that was sent. The gap between
    the two encodings is where multi-tester overlap becomes visible -- three
    testers probing one endpoint produce three findings at three different
    concrete URLs, and they are three claims about one instance.
    """
    return candidate_keys(finding.url, finding.parameter)


def _overlap_result():
    """Three testers fire on each of the two vulnerable instances; one on /c.

    Seven findings, four instances. This is the shape the benchmark produces on
    essentially every endpoint, so it is the shape the rates have to survive.
    """
    findings = [
        Finding("/a?p=1", "q", "sqli"),
        Finding("/a?p=2", "q", "cmdi"),
        Finding("/a?p=3", "q", "xss"),
        Finding("/b?p=1", "q", "sqli"),
        Finding("/b?p=2", "q", "cmdi"),
        Finding("/b?p=3", "q", "xss"),
        Finding("/c?p=1", "q", "nosql"),
    ]
    return compute_metrics(findings, _gt(), key_resolver=_resolver)


# ---- counts -----------------------------------------------------------------


def test_claim_and_instance_counts_are_reported_separately():
    r = _overlap_result()

    # Claims: one per reported finding, nothing deduped away -- each finding is
    # a distinct claim with a distinct payload and evidence.
    assert (r.tp, r.fp, r.total_findings) == (6, 1, 7)
    # Instances: one per labelled point. Both vulnerable ones detected, one
    # benign one flagged, one benign instance clean.
    assert (r.tp_instances, r.fp_instances, r.fn, r.tn) == (2, 1, 0, 1)
    assert r.duplicate_claims == 4


def test_confusion_matrix_balances_over_instances():
    """TP_inst + FN must be the vulnerable population and FP_inst + TN the benign.

    This is the invariant that caught the defect: the claim counts do not close
    the matrix, the instance counts do.
    """
    r = _overlap_result()

    assert r.tp_instances + r.fn + r.fp_instances + r.tn == r.total_instances


# ---- rates ------------------------------------------------------------------


def test_recall_is_over_instances_not_claims():
    """Three findings on one endpoint is one detected vulnerability, not three."""
    r = _overlap_result()

    # 6/6 = 1.0 is the claim-level reading; 2/2 = 1.0 here, so use a sample
    # that separates the two: /b detected once out of two claims is still a
    # detected instance.
    assert r.recall == 1.0

    partial = compute_metrics(
        [Finding("/a?p=1", "q", "sqli"), Finding("/a?p=2", "q", "cmdi")], _gt(),
        key_resolver=_resolver,
    )
    assert partial.tp == 2, "two claims"
    assert partial.tp_instances == 1, "one detected instance"
    assert partial.recall == 0.5, "1 of 2 vulnerable instances, not 2 of 2"


def test_specificity_denominator_is_the_benign_population():
    r = _overlap_result()

    assert r.specificity == 0.5, "1 clean benign instance of 2"
    assert r.fpr_on_ground_truth == 0.5, "1 contaminated benign instance of 2"


def test_accuracy_can_never_exceed_one():
    """The exported table shipped accuracy=1.642 on this very shape.

    Any accuracy above 1 means a claim count reached an instance denominator.
    The property is asserted rather than the value so the invariant survives
    whatever the input shape is.
    """
    assert _overlap_result().accuracy == 0.75, "(2 + 2) / 4"

    heavy = compute_metrics(
        [Finding(f"/a?p={i}", "q", "sqli") for i in range(9)],
        _gt(),
        key_resolver=_resolver,
    )
    assert heavy.tp == 9 and heavy.tp_instances == 1
    assert 0.0 <= heavy.accuracy <= 1.0


def test_precision_still_charges_every_claim():
    """Precision keeps the conservative unit: three claims on one endpoint.

    The dedupe in ``compute_metrics`` collapses findings sharing a
    ``(url, parameter)`` key -- the same claim reported twice by two testers.
    It does not collapse findings that a resolver maps to one instance, because
    each of those made its own claim on the wire.
    """
    r = _overlap_result()

    assert r.precision == 6 / 7


def test_duplicate_findings_at_one_key_still_count_once():
    """The pre-existing per-(url, parameter) dedupe is unchanged by this fix.

    Two identical claims are one claim: same URL, same parameter, same
    instance. This is a different question from "three testers on one endpoint
    reported three different problems", and it must not be lost.
    """
    r = compute_metrics(
        [
            Finding("/a", "q", "sqli"),
            Finding("/a", "q", "sqli"),
        ],
        _gt(),
    )

    assert (r.tp, r.tp_instances, r.total_findings) == (1, 1, 1)


def test_per_category_is_a_matrix_over_instances():
    """The breakdown must agree with the recall printed next to it.

    A category table that counts claims while the headline counts instances
    would let a reader recompute a different number from the same report.
    """
    r = _overlap_result()

    buckets = r.per_category["sqli"]
    assert (buckets["tp"], buckets["fn"], buckets["fp"], buckets["tn"]) == (2, 0, 1, 1)
    assert sum(buckets.values()) == 4 == r.total_instances


def test_untested_holds_out_of_both_units():
    """An untested marker still removes the instance without claiming anything.

    One vulnerable instance is measured and flagged twice, the other is marked
    unmeasurable. Recall is conditional on the one that could be measured, and
    the lower bound charges the skipped one.
    """
    instances = [(("/a", "q"), True, "sqli"), (("/b", "q"), True, "sqli")]
    r = compute_metrics(
        [
            Finding("/a?p=1", "q", "sqli"),
            Finding("/a?p=2", "q", "cmdi"),
            Finding("/b?p=1", "q", "blocked_un_tested", untested=True),
        ],
        _gt(instances),
        key_resolver=_resolver,
    )

    assert (r.tp, r.tp_instances) == (2, 1)
    assert r.fn == 0, "the unmeasured point is not a miss"
    assert len(r.untested_points) == 1
    assert r.recall == 1.0
    assert r.recall_lower_bound == 0.5


# ---- export -----------------------------------------------------------------


def test_rates_export_carries_both_units_and_the_duplicate_count():
    payload = json.loads(json.dumps(_overlap_result().to_dict()))

    assert payload["counts"]["tp"] == 6
    assert payload["counts"]["tp_instances"] == 2
    assert payload["rates"]["duplicate_claims"] == 4.0


#: The proportion-valued entries of ``rates()``. The remaining keys are counts
#: (``untested_*``, ``duplicate_claims``) and are legitimately unbounded above 1.
_PROPORTIONS = (
    "precision", "recall", "f1", "recall_lower_bound", "specificity",
    "fpr_on_ground_truth", "fp_rate_over_findings", "accuracy", "coverage",
)


def test_every_rendered_rate_is_a_real_proportion():
    """Nothing in the exported table may exceed 1.0.

    Applied to all three renderers rather than one property: the defect escaped
    because the console table was read but the JSON was not.
    """
    r = compute_metrics(
        [Finding(f"/a?p={i}", "q", "sqli") for i in range(6)],
        _gt(),
        key_resolver=_resolver,
    )
    rates = r.rates()

    for name in _PROPORTIONS:
        assert 0.0 <= rates[name] <= 1.0, name

    for rendered in (
        render_console_summary(r), render_markdown(r), render_latex(r)
    ):
        assert "1.642" not in rendered


def test_rendered_tables_state_the_units():
    """A reader of the table alone must be able to tell 426 from 182."""
    r = _overlap_result()

    md = render_markdown(r)
    assert "claims" in md and "instances" in md
    assert "| True positive (TP) | 6 | 2 |" in md

    tex = render_latex(r)
    assert "\\textbf{Claims}" in tex and "\\textbf{Instances}" in tex

    console = render_console_summary(r)
    assert "claims" in console and "instances" in console
    assert "duplicate claims" in console
