"""Tests for the metric computation and the ground-truth loaders.

The properties under test are the ones that decide whether a published number is
honest:

* every ground-truth instance lands in exactly one bucket;
* a reported finding that matches nothing is counted *separately* and still
  counts against precision;
* a zero denominator yields ``None`` ("no data"), never ``0.0`` ("zero
  performance");
* duplicate findings for one instance do not inflate TP;
* the benchmark's per-case schema reconciles with per-(url, parameter) findings.

Docstrings and comments are English (house rule). Research findings
(i.e. statements about the tool's behaviour, not mechanics) are Spanish.
"""

import json
import re

import pytest

from web_security_scanner.core.benchmark_ground_truth import (
    benchmark_key_resolver,
    candidate_keys,
    canonical_path,
    exact_key_resolver,
    json_key_resolver,
    load_findings_from_report,
    load_json_ground_truth,
    load_owasp_benchmark,
)
from web_security_scanner.core.ieee_metrics import (
    Finding,
    GroundTruth,
    compute_metrics,
    render_console_summary,
    render_latex,
    render_markdown,
    write_results,
)


def _gt(rows):
    """Ground truth from (url, param, vulnerable, category) tuples."""
    return GroundTruth(
        instances=tuple(((u, p), bool(v), c) for u, p, v, c in rows),
        name="synthetic",
    )


# ---- bucket arithmetic -----------------------------------------------------


def test_every_instance_lands_in_exactly_one_bucket():
    gt = _gt([
        ("/a", "q", 1, "sqli"), ("/b", "q", 1, "sqli"),
        ("/c", "q", 0, "sqli"), ("/d", "q", 0, "sqli"),
    ])
    result = compute_metrics(
        [Finding("/a", "q"), Finding("/c", "q")], gt
    )

    assert (result.tp, result.fn, result.fp, result.tn) == (1, 1, 1, 1)
    assert result.tp + result.fn + result.fp + result.tn == result.total_instances


def test_no_findings_gives_perfect_specificity_and_null_recall():
    """Nothing reported means nothing to be wrong about on the benign side, but
    every vulnerable instance is a miss."""
    gt = _gt([("/a", "q", 1, "sqli"), ("/b", "q", 0, "sqli")])
    result = compute_metrics([], gt)

    assert (result.tp, result.fn, result.fp, result.tn) == (0, 1, 0, 1)
    assert result.recall == 0.0
    assert result.specificity == 1.0
    assert result.precision is None, "no findings -> no precision to report"


def test_all_findings_correct_gives_perfect_precision():
    gt = _gt([("/a", "q", 1, "sqli"), ("/b", "q", 1, "sqli")])
    result = compute_metrics([Finding("/a", "q"), Finding("/b", "q")], gt)

    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.f1 == 1.0


# ---- the FP-outside-ground-truth bucket -----------------------------------


def test_finding_outside_ground_truth_is_separate_but_still_hurts_precision():
    """The case the standard matrix has no slot for. A reported finding at an
    unlabelled point is still a claim the tool made, so it must count against
    precision -- while staying distinguishable from an FP on a known-benign
    point."""
    gt = _gt([("/a", "q", 1, "sqli"), ("/b", "q", 0, "sqli")])
    result = compute_metrics(
        [Finding("/a", "q"), Finding("/unknown", "z")], gt
    )

    assert result.tp == 1
    assert result.fp == 0, "the unlabelled point is not a labelled false positive"
    assert result.fp_outside_gt == 1
    assert result.total_findings == 2
    # precision counts it: 1 TP out of 2 claims
    assert result.precision == pytest.approx(0.5)
    # but FPR over labelled benign points stays clean
    assert result.fpr_on_ground_truth == 0.0
    assert result.fp_rate_over_findings == pytest.approx(0.5)


def test_the_two_fp_rates_can_diverge_and_they_do():
    """FINDING (the reason both rates exist): the two false-positive rates are
    not redundant and can disagree by a wide margin.

    With 93 false positives, only 2 of which landed on the 144 labelled decoys,
    a ground-truth-restricted FPR reads 0.0139 while 91 reported findings go
    unaccounted for. Reporting only the former would understate the observed
    false positives by a factor of ~45. A paper that quotes one number without
    naming the denominator is therefore not auditable.
    """
    gt = _gt([(f"/safe{i}", "q", 0, "safe") for i in range(144)])
    findings = [Finding(f"/vuln{i}", "q") for i in range(125)]  # outside GT
    findings += [Finding("/safe0", "q"), Finding("/safe1", "q")]  # on decoys
    result = compute_metrics(findings, gt)

    assert result.tn == 142
    assert result.fp == 2
    assert result.fp_outside_gt == 125
    assert result.fpr_on_ground_truth == pytest.approx(2 / 144, rel=1e-3)
    assert result.precision is not None and result.precision < 0.05


def test_unmatched_findings_are_listed_for_audit():
    gt = _gt([("/a", "q", 1, "sqli")])
    result = compute_metrics([Finding("/x", "z", "sqli"), Finding("/y", "", "xss")], gt)

    assert result.fp_outside_gt == 2
    assert len(result.unmatched_findings) == 2
    assert any("sqli /x" in item for item in result.unmatched_findings)
    assert result.unmatched_findings == sorted(result.unmatched_findings), \
        "stable order so two runs diff cleanly"


# ---- duplicates ------------------------------------------------------------


def test_duplicate_findings_for_one_instance_count_once():
    """Three testers reporting the same SQL injection is one claim, not three.
    Counting them separately would make TP depend on tester overlap."""
    gt = _gt([("/a", "q", 1, "sqli")])
    findings = [
        Finding("/a", "q", "sqli"),
        Finding("/a", "q", "sqli", confidence="HIGH"),
        Finding("/a", "q", "sql_injection"),
    ]
    result = compute_metrics(findings, gt)

    assert result.tp == 1
    assert result.total_findings == 1
    assert result.recall == 1.0


def test_duplicate_findings_do_not_create_extra_precision_mass():
    gt = _gt([("/a", "q", 1, "sqli")])
    result = compute_metrics([Finding("/a", "q")] * 10, gt)

    assert result.precision == 1.0, "repeats must not dilute the denominator"


# ---- zero denominators -----------------------------------------------------


def test_no_ground_truth_yields_nulls_not_zeros():
    """A run with nothing labelled must not be published as a tool that scores
    zero on everything."""
    result = compute_metrics([Finding("/a", "q")], GroundTruth(instances=()))

    assert result.total_instances == 0
    assert result.precision == 0.0, "one finding, zero labelled TP -> precision 0"
    assert result.recall is None, "no labelled instances -> no recall"
    assert result.f1 is None
    assert result.specificity is None
    assert result.accuracy is None
    assert result.fpr_on_ground_truth is None


def test_f1_is_none_when_there_are_no_findings_at_all():
    result = compute_metrics([], _gt([("/a", "q", 1, "sqli")]))

    assert result.precision is None
    assert result.f1 is None, "F1 must not be 0.0 when precision is undefined"


def test_f1_is_zero_when_precision_and_recall_both_zero():
    gt = _gt([("/a", "q", 1, "sqli")])
    result = compute_metrics([Finding("/b", "q")], gt)

    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1 == 0.0


# ---- per-category ----------------------------------------------------------


def test_per_category_split_sums_to_the_totals():
    gt = _gt([
        ("/a", "q", 1, "sqli"), ("/b", "q", 1, "sqli"),
        ("/c", "x", 1, "xss"), ("/d", "x", 0, "xss"),
    ])
    result = compute_metrics(
        [Finding("/a", "q"), Finding("/b", "q"), Finding("/d", "x")], gt
    )

    assert result.per_category["sqli"] == {"tp": 2, "fn": 0, "fp": 0, "tn": 0}
    assert result.per_category["xss"] == {"tp": 0, "fn": 1, "fp": 1, "tn": 0}
    assert sum(b["tp"] for b in result.per_category.values()) == result.tp


# ---- matching is exact -----------------------------------------------------


def test_parameter_must_match_too():
    """Same URL, different parameter -> different instance."""
    gt = _gt([("/a", "q", 1, "sqli"), ("/a", "id", 0, "sqli")])
    result = compute_metrics([Finding("/a", "id")], gt)

    assert result.tp == 0
    assert result.fp == 1
    assert result.fn == 1


def test_url_matching_is_exact_not_fuzzy():
    """A near-miss URL is not silently credited. Normalisation is the caller's
    job (see benchmark_ground_truth.canonical_path); a fuzzy fallback here would
    convert unmatched findings into false negatives without trace."""
    gt = _gt([("/api/search", "q", 1, "sqli")])
    result = compute_metrics([Finding("/api/search2", "q")], gt)

    assert result.fp_outside_gt == 1
    assert result.fn == 1


# ---- URL normalisation -----------------------------------------------------


@pytest.mark.parametrize("a,b", [
    ("http://127.0.0.1:8443/benchmark/BenchmarkTest00001?foo=1&bar=2",
     "http://owasp-benchmark:8080/benchmark/BenchmarkTest00001?bar=2&foo=1"),
    ("/x?a=1&b=2", "/x?b=2&a=1"),
    ("http://h/x", "/x"),
])
def test_canonical_path_collapses_host_and_query_order(a, b):
    assert canonical_path(a) == canonical_path(b)


def test_canonical_path_keeps_differing_query_values_apart():
    assert canonical_path("/x?a=1") != canonical_path("/x?a=2")


def test_candidate_keys_include_the_benchmark_case_id():
    keys = candidate_keys("http://127.0.0.1:8443/benchmark/BenchmarkTest00042?foo=bar")

    assert ("/BenchmarkTest00042", "") in keys


def test_candidate_keys_reconcile_an_injected_value_against_a_bare_endpoint():
    """The ground truth names the endpoint; the scanner names the attack.

    ``/search?q=1 OR 1=1`` reported against a ``/search`` + ``q`` label is the
    same instance. Without the query-stripped variant the keys never intersect
    and a genuine detection is booked as "outside the ground truth" -- a run
    that finds real vulnerabilities and reports precision 0.0.
    """
    keys = candidate_keys("/search?q=1%20OR%201=1", "q")

    assert ("/search", "q") in keys


def test_candidate_keys_still_separate_two_query_values_on_one_path():
    """Dropping the query must not merge two distinct labelled instances.

    They stay distinct through the parameter, which is what the table names.
    """
    gt_keys = {
        ("/x", "a"),
        ("/x", "b"),
    }
    resolved = {
        key for url, param in (("/x?a=1", "a"), ("/x?b=2", "b"))
        for key in candidate_keys(url, param)
    }

    assert gt_keys <= resolved
    assert len(gt_keys & resolved) == 2


def test_json_resolver_reconciles_a_payload_bearing_finding():
    """End to end: a JSON table plus a real finding yields a true positive."""
    gt = GroundTruth(instances=((("/search", "q"), True, "sqli"),), name="t")
    findings = [Finding("/search?q=1%20OR%201=1", "q", "sqli")]

    result = compute_metrics(findings, gt, key_resolver=json_key_resolver())

    assert result.tp == 1
    assert result.fp_outside_gt == 0
    assert result.precision == 1.0


def test_json_resolver_still_scores_a_true_negative_when_silent():
    """Reconciliation must not manufacture matches out of nothing."""
    gt = GroundTruth(instances=((("/search", "q"), True, "sqli"),), name="t")

    result = compute_metrics([], gt, key_resolver=json_key_resolver())

    assert result.tp == 0
    assert result.fn == 1


# ---- OWASP Benchmark loader ------------------------------------------------

_CSV_HEADER = "# onemore line,real vulnerability,vulnerability name,category\n"


def test_benchmark_loader_marks_vulnerable_and_safe(tmp_path):
    csv_path = tmp_path / "expectedresults.csv"
    csv_path.write_text(
        _CSV_HEADER + "BenchmarkTest00001,true,Blind SQL Injection,sqli\n"
        "BenchmarkTest00002,false,Cross-site Scripting,xss\n",
        encoding="utf-8",
    )

    gt, index = load_owasp_benchmark(csv_path)

    assert len(gt.instances) == 2
    vulnerable = {key: flag for key, flag, _ in gt.instances}
    assert vulnerable[("/BenchmarkTest00001", "")] is True
    assert vulnerable[("/BenchmarkTest00002", "")] is False
    assert index["BenchmarkTest00001"] == "/BenchmarkTest00001"


def test_benchmark_findings_match_by_case_id(tmp_path):
    csv_path = tmp_path / "expectedresults.csv"
    csv_path.write_text(
        _CSV_HEADER + "BenchmarkTest00001,true,Blind SQL Injection,sqli\n"
        "BenchmarkTest00002,false,Cross-site Scripting,xss\n",
        encoding="utf-8",
    )
    gt, _ = load_owasp_benchmark(csv_path, base_url="http://127.0.0.1:8443")

    # A scanner reports the concrete probed URL, not the case id.
    result = compute_metrics(
        [Finding("/benchmark/BenchmarkTest00001?foo=bar&baz=1", "")],
        gt,
    )
    # Unmatched here on purpose: the case id has to be reconciled first.
    assert result.fp_outside_gt == 1


def test_benchmark_findings_match_after_case_id_reconciliation(tmp_path):
    """The reconciliation the benchmark format actually needs: the scan reports
    a concrete URL, the ground truth is keyed by case id."""
    csv_path = tmp_path / "expectedresults.csv"
    csv_path.write_text(
        _CSV_HEADER + "BenchmarkTest00001,true,Blind SQL Injection,sqli\n"
        "BenchmarkTest00002,false,Cross-site Scripting,xss\n",
        encoding="utf-8",
    )
    gt, _ = load_owasp_benchmark(csv_path)

    result = compute_metrics(
        [Finding("/BenchmarkTest00001", ""), Finding("/BenchmarkTest00002", "")],
        gt,
        key_resolver=benchmark_key_resolver(),
    )

    assert (result.tp, result.fp) == (1, 1)


def test_benchmark_reconciliation_survives_a_concrete_probed_url(tmp_path):
    """The real shape of a benchmark finding: the case id embedded in a path that
    also carries the injected query string.

    Without the resolver this run scores recall 0.0 while having detected a real
    blind SQL injection -- and it still prints a full, plausible table. That is
    the failure mode this test guards.
    """
    csv_path = tmp_path / "expectedresults.csv"
    csv_path.write_text(
        _CSV_HEADER + "BenchmarkTest00001,true,Blind SQL Injection,sqli\n"
        "BenchmarkTest00002,false,Cross-site Scripting,xss\n",
        encoding="utf-8",
    )
    gt, _ = load_owasp_benchmark(csv_path)

    findings = [
        Finding("/benchmark/BenchmarkTest00001?foo=1&bar=2", "", "sql_injection"),
        Finding("/benchmark/BenchmarkTest00002?foo=1", "", "xss"),
    ]

    unrescored = compute_metrics(findings, gt)
    resolved = compute_metrics(findings, gt, key_resolver=benchmark_key_resolver())

    assert unrescored.tp == 0 and unrescored.recall == 0.0, "documents the trap"
    assert resolved.tp == 1 and resolved.fp == 1
    assert resolved.recall == 1.0
    assert resolved.fp_outside_gt == 0


def test_a_benchmark_finding_on_an_unlabelled_case_stays_outside(tmp_path):
    """The resolver must not invent matches: an unknown case id is still a
    finding the ground truth does not cover."""
    csv_path = tmp_path / "expectedresults.csv"
    csv_path.write_text(
        _CSV_HEADER + "BenchmarkTest00001,true,Blind SQL Injection,sqli\n",
        encoding="utf-8",
    )
    gt, _ = load_owasp_benchmark(csv_path)

    result = compute_metrics(
        [Finding("/benchmark/BenchmarkTest09999?foo=1", "")],
        gt,
        key_resolver=benchmark_key_resolver(),
    )

    assert result.fp_outside_gt == 1
    assert result.tp == 0


def test_the_resolver_cannot_credit_a_vulnerable_case_as_benign(tmp_path):
    """A finding on a *safe* case must stay an FP even through the resolver."""
    csv_path = tmp_path / "expectedresults.csv"
    csv_path.write_text(
        _CSV_HEADER + "BenchmarkTest00002,false,Cross-site Scripting,xss\n",
        encoding="utf-8",
    )
    gt, _ = load_owasp_benchmark(csv_path)

    result = compute_metrics(
        [Finding("/benchmark/BenchmarkTest00002?foo=1", "")],
        gt,
        key_resolver=benchmark_key_resolver(),
    )

    assert result.fp == 1
    assert result.fp_outside_gt == 0


def test_exact_resolver_is_the_identity():
    """The default must stay strict; the resolver is opt-in, never inferred."""
    gt = _gt([("/a", "q", 1, "sqli")])
    findings = [Finding("/a", "q")]

    assert compute_metrics(findings, gt).tp == 1
    assert compute_metrics(findings, gt, key_resolver=exact_key_resolver()).tp == 1


def test_exact_resolver_does_not_match_a_different_url():
    gt = _gt([("/a", "q", 1, "sqli")])

    result = compute_metrics(
        [Finding("/a?extra=1", "q")], gt, key_resolver=exact_key_resolver()
    )

    assert result.tp == 0
    assert result.fp_outside_gt == 1


def test_a_resolver_that_returns_several_keys_credits_at_most_one_instance():
    """One finding is one claim: a broad resolver must not let it satisfy two
    ground-truth instances and manufacture recall."""
    gt = _gt([("/BenchmarkTest00001", "", 1, "sqli"),
              ("/BenchmarkTest00002", "", 1, "sqli")])

    def greedy(finding):
        return [("/BenchmarkTest00001", ""), ("/BenchmarkTest00002", "")]

    result = compute_metrics([Finding("/anything", "")], gt, key_resolver=greedy)

    assert result.tp == 1
    assert result.fn == 1


def test_benchmark_loader_accepts_alternative_column_names(tmp_path):
    csv_path = tmp_path / "expectedresults.csv"
    csv_path.write_text(
        "test_case,is_vulnerable\nBenchmarkTest00009,y\n", encoding="utf-8"
    )

    gt, _ = load_owasp_benchmark(csv_path)

    assert gt.instances[0][1] is True


def test_benchmark_loader_rejects_an_unrecognised_header(tmp_path):
    csv_path = tmp_path / "expectedresults.csv"
    csv_path.write_text("alpha,beta\n1,2\n", encoding="utf-8")

    with pytest.raises(ValueError, match="could not locate"):
        load_owasp_benchmark(csv_path)


def test_benchmark_loader_rejects_an_empty_truth_column(tmp_path):
    """Zero usable instances must fail loudly. Silently returning an empty
    ground truth would produce a run that reports recall 0.0 as if it were a
    measurement."""
    csv_path = tmp_path / "expectedresults.csv"
    csv_path.write_text(
        _CSV_HEADER + "BenchmarkTest00001,maybe,?,?\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="parsed 0 usable instances"):
        load_owasp_benchmark(csv_path)


def test_benchmark_loader_reports_a_missing_file():
    with pytest.raises(FileNotFoundError):
        load_owasp_benchmark("/nonexistent/expectedresults.csv")


def test_benchmark_loader_deduplicates_repeated_cases(tmp_path):
    csv_path = tmp_path / "expectedresults.csv"
    csv_path.write_text(
        _CSV_HEADER + "BenchmarkTest00001,true,a,sqli\n"
        "BenchmarkTest00001,true,a,sqli\n",
        encoding="utf-8",
    )

    gt, _ = load_owasp_benchmark(csv_path)

    assert len(gt.instances) == 1


# ---- generic JSON loader (the out-of-benchmark door) ----------------------


def test_json_ground_truth_round_trip(tmp_path):
    path = tmp_path / "gt.json"
    path.write_text(json.dumps({
        "name": "defect-injected-app",
        "instances": [
            {"url": "/search?q=1", "parameter": "q", "vulnerable": True, "category": "sqli"},
            {"url": "/about", "parameter": "", "vulnerable": False},
        ],
    }), encoding="utf-8")

    gt = load_json_ground_truth(path)
    result = compute_metrics([Finding("/search?q=1", "q")], gt)

    assert gt.name == "defect-injected-app"
    assert result.tp == 1
    assert result.tn == 1


def test_json_ground_truth_accepts_a_bare_list(tmp_path):
    path = tmp_path / "gt.json"
    path.write_text(json.dumps([
        {"url": "/a", "parameter": "q", "vulnerable": "y"},
    ]), encoding="utf-8")

    gt = load_json_ground_truth(path)

    assert gt.instances[0][1] is True


def test_json_ground_truth_rejects_an_ambiguous_truth_value(tmp_path):
    path = tmp_path / "gt.json"
    path.write_text(json.dumps([
        {"url": "/a", "parameter": "q", "vulnerable": "probably"},
    ]), encoding="utf-8")

    with pytest.raises(ValueError, match="unrecognised 'vulnerable'"):
        load_json_ground_truth(path)


def test_json_ground_truth_requires_a_url(tmp_path):
    path = tmp_path / "gt.json"
    path.write_text(json.dumps([{"parameter": "q", "vulnerable": True}]), encoding="utf-8")

    with pytest.raises(ValueError, match="has no 'url'"):
        load_json_ground_truth(path)


# ---- report ingestion ------------------------------------------------------


def test_findings_load_from_an_enriched_report():
    report = {"vulnerabilities": [
        {"url": "/a", "parameter": "q", "type": "sql_injection",
         "severity": "high", "confidence": "CONFIRMED"},
        {"url": "/b", "type": "xss"},
    ]}

    findings, warnings = load_findings_from_report(report)

    assert warnings == []
    assert len(findings) == 2
    assert findings[0].vulnerability_type == "sql_injection"
    assert findings[1].parameter == ""


def test_findings_load_accepts_the_param_alias():
    report = {"vulnerabilities": [{"url": "/a", "param": "id", "name": "sqli"}]}

    findings, _ = load_findings_from_report(report)

    assert findings[0].parameter == "id"
    assert findings[0].vulnerability_type == "sqli"


def test_a_finding_without_a_url_is_warned_not_dropped_silently():
    """Dropping it would deflate recall with no trace in the output."""
    findings, warnings = load_findings_from_report(
        {"vulnerabilities": [{"parameter": "q"}, {"url": "/a"}]}
    )

    assert len(findings) == 1
    assert len(warnings) == 1
    assert "no 'url'" in warnings[0]


def test_an_empty_report_warns_explicitly():
    findings, warnings = load_findings_from_report({})

    assert findings == []
    assert warnings and "no 'vulnerabilities' key" in warnings[0]


def test_report_urls_are_normalised_against_the_base_url():
    report = {"vulnerabilities": [
        {"url": "http://127.0.0.1:8443/benchmark/BenchmarkTest00001?b=2&a=1"},
    ]}

    findings, _ = load_findings_from_report(report, base_url="http://127.0.0.1:8443")

    assert findings[0].url == "/benchmark/BenchmarkTest00001?a=1&b=2"


# ---- rendering and export --------------------------------------------------


def _sample_result():
    gt = _gt([
        ("/a", "q", 1, "sqli"), ("/b", "q", 1, "sqli"),
        ("/c", "q", 0, "sqli"), ("/d", "q", 0, "sqli"),
    ])
    return compute_metrics([Finding("/a", "q"), Finding("/c", "q"), Finding("/zz", "w")], gt)


def test_results_json_is_serialisable_and_complete():
    payload = json.loads(json.dumps(_sample_result().to_dict()))

    assert payload["counts"] == {
        # Claims: one per reported finding.
        "tp": 1, "fp": 1, "fp_outside_ground_truth": 1,
        "total_findings": 3,
        # Instances: one per labelled point. A sample with no multi-claim
        # instance cannot tell the two units apart, so they are equal here;
        # the divergence is covered in tests/differential/test_metric_units.py.
        "tp_instances": 1, "fp_instances": 1, "fn": 1, "tn": 1,
        "total_instances": 4,
        # Class agreement. This fixture's ground truth carries no expected-class
        # labels, so there is nothing to score and the flag says so -- a reader
        # must not read the absence of class figures as a perfect score.
        "has_class_labels": False,
        "tp_class_matched": 0, "tp_class_matched_instances": 0,
        "class_labelled_instances": 0,
        "claims_unknown_class": 0,
        # The one TP claim landed on a vulnerable instance this source does not
        # name a class for, so it is excluded from the class population.
        "claims_unlabelled_class": 1,
    }
    # The coverage qualifiers ship with the rates by construction: recall and
    # f1 are conditional on what the scan could measure, so a consumer that
    # receives them without those keys cannot tell a conditional figure from an
    # unconditional one. See tests/differential/test_probe_abort.py.
    assert set(payload["rates"]) == {
        "precision", "recall", "f1", "specificity",
        "fpr_on_ground_truth", "fp_rate_over_findings", "accuracy",
        "coverage", "recall_lower_bound", "duplicate_claims",
        "untested_points", "untested_vulnerable",
        "precision_class_matched", "recall_class_matched", "f1_class_matched",
    }
    assert payload["ground_truth"] == "synthetic"
    assert payload["untested_points"] == []


def test_markdown_has_both_fp_rates_labelled():
    md = render_markdown(_sample_result())

    assert "Precision" in md
    assert "F1" in md
    assert "FPR (ground truth only)" in md
    assert "FP rate (over findings)" in md
    # "n/a" is scoped to the rate *rows* of the rates table, which is what the
    # original assertion was about: every rate in it has a value in this sample.
    # The document also carries prose that says class agreement is n/a, and that
    # sentence is required -- see the class-agreement note below.
    rates_rows = [
        line for line in _section(md, "### Rates").splitlines()
        if line.startswith("|")
    ]
    assert rates_rows, "the rates table rendered no rows"
    assert not [r for r in rates_rows if "n/a" in r], (
        f"this sample has data for every rate: {[r for r in rates_rows if 'n/a' in r]}"
    )


def _section(document: str, heading: str) -> str:
    """The body of a markdown section, up to the next heading of the same level."""
    body = document.split(heading, 1)[1]
    return re.split(r"^#{1,3} ", body, maxsplit=1, flags=re.M)[0]


def test_markdown_says_when_class_agreement_is_unanswerable():
    """El silencio se lee como un 1.0; la frase explícita no."""
    md = render_markdown(_sample_result())

    assert "Class agreement: n/a" in md
    assert "no expected-class labels" in md


def test_markdown_renders_none_as_not_applicable():
    md = render_markdown(compute_metrics([], _gt([("/a", "q", 1, "sqli")])))

    assert "| Recall | 0.0000 |" in md
    assert "| Precision | n/a |" in md


def test_markdown_lists_unmatched_findings_for_audit():
    md = render_markdown(_sample_result())

    assert "outside the ground truth" in md
    assert "/zz" in md


def test_latex_table_is_well_formed():
    tex = render_latex(_sample_result())

    assert "\\begin{table}" in tex and "\\end{table}" in tex
    assert tex.count("\\begin{tabular}") == tex.count("\\end{tabular}")
    assert tex.count("{") == tex.count("}"), "unbalanced braces break pdflatex"
    assert "\\toprule" in tex and "\\bottomrule" in tex
    assert "\\label{tab:metrics}" in tex


def test_latex_escapes_underscores_in_category_names():
    result = compute_metrics([], _gt([("/a", "q", 1, "sqli_injection")]))

    tex = render_latex(result)

    assert "sqli\\_injection" in tex
    assert "sql_injection &" not in tex


def test_latex_renders_null_rates_without_crashing():
    tex = render_latex(compute_metrics([], GroundTruth(instances=())))

    assert "n/a" in tex
    assert tex.count("{") == tex.count("}")


def test_write_results_emits_all_three_formats(tmp_path):
    paths = write_results(_sample_result(), tmp_path / "out")

    for key in ("json", "markdown", "latex"):
        assert (tmp_path / "out").exists()
        assert paths[key].endswith((".json", ".md", ".tex"))

    assert json.loads((tmp_path / "out" / "results.json").read_text())["counts"]["tp"] == 1


def test_console_summary_reports_the_three_headline_numbers():
    out = render_console_summary(_sample_result())

    assert "Precision" in out and "Recall" in out and "F1" in out
    assert "outside the ground truth" in out
    assert "does not account for them" in out, "must flag the FPR caveat"
