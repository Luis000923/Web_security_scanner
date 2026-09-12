"""tests/test_analyze_results.py — smoke test for tools/analyze_results.py.

Runs the full analysis pipeline (TASK 1 per-run metrics, TASK 2 significance
tests, TASK 2b First-TP/early-recall, TASK 2c AI-triage audit) end-to-end
over a small synthetic ``experiment_results.csv`` + matching telemetry
directories + ground truth, and asserts it completes without raising and
produces the expected output files/columns. Figures are skipped
(``--no-figures``) since they only exercise matplotlib rendering, not the
statistics this test is meant to validate.
"""

import csv
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).parent.parent / "tools" / "analyze_results.py"
_spec = importlib.util.spec_from_file_location("analyze_results", _MOD_PATH)
analyze_results = importlib.util.module_from_spec(_spec)
sys.modules["analyze_results"] = analyze_results
_spec.loader.exec_module(analyze_results)

CSV_COLUMNS = ["budget", "condition", "TP", "FP", "FN",
               "Precision", "Recall", "F1", "FPR",
               "AI_Triaged", "AI_Suppressed", "AI_FP_Suppressed",
               "AI_FN_Introduced", "AI_Recall_NoAgent",
               "run_dir", "status", "timestamp"]

_GT = [
    {"url": "http://t/a", "param": "id", "type": "sql_injection", "vulnerable": True},
    {"url": "http://t/b", "param": "q", "type": "xss", "vulnerable": True},
    {"url": "http://t/c", "param": "cmd", "type": "command_injection", "vulnerable": True},
    {"url": "http://t/d", "param": "id", "type": "sql_injection", "vulnerable": False},  # trap
]

# (budget, condition) -> list of (request_index, decision, url, param, tester_id)
_TELEMETRY = {
    (10, "baseline"): [
        (1, True, "http://t/a", "id", "sql_injection"),
        (2, True, "http://t/b", "q", "xss"),
        (3, True, "http://t/c", "cmd", "command_injection"),
    ],
    (10, "no-interleave"): [
        (2, True, "http://t/a", "id", "sql_injection"),
        (4, True, "http://t/b", "q", "xss"),
        (6, False, "http://t/c", "cmd", "command_injection"),
    ],
    (10, "no-priority"): [
        (3, True, "http://t/a", "id", "sql_injection"),
        (5, True, "http://t/b", "q", "xss"),
        (7, True, "http://t/c", "cmd", "command_injection"),
    ],
    (10, "no-runtime-confirm"): [
        (1, True, "http://t/a", "id", "sql_injection"),
        (2, True, "http://t/d", "id", "sql_injection"),  # FP on the explicit trap
        (5, False, "http://t/c", "cmd", "command_injection"),
    ],
    (10, "no-adaptive-sorting"): [
        (5, True, "http://t/a", "id", "sql_injection"),
        (6, True, "http://t/b", "q", "xss"),
        (7, True, "http://t/c", "cmd", "command_injection"),
    ],
    (20, "baseline"): [
        (1, True, "http://t/a", "id", "sql_injection"),
        (2, True, "http://t/b", "q", "xss"),
        (3, True, "http://t/c", "cmd", "command_injection"),
    ],
}

# Extra graded rows with no telemetry dir on disk (orphan-free but still
# widen the CSV to the requested 10-20 row smoke size and exercise the
# AI-triage branch of TASK 2c).
_EXTRA_CSV_ROWS = [
    {"budget": 20, "condition": "no-interleave", "TP": 2, "FP": 0, "FN": 1,
     "Precision": 1.0, "Recall": 0.6667, "F1": 0.8, "FPR": 0.0},
    {"budget": 20, "condition": "no-priority", "TP": 3, "FP": 0, "FN": 0,
     "Precision": 1.0, "Recall": 1.0, "F1": 1.0, "FPR": 0.0},
    {"budget": 20, "condition": "no-runtime-confirm", "TP": 1, "FP": 1, "FN": 2,
     "Precision": 0.5, "Recall": 0.3333, "F1": 0.4, "FPR": 1.0},
    {"budget": 50, "condition": "baseline", "TP": 3, "FP": 0, "FN": 0,
     "Precision": 1.0, "Recall": 1.0, "F1": 1.0, "FPR": 0.0},
    {"budget": 10, "condition": "ai-triage", "TP": 3, "FP": 0, "FN": 0,
     "Precision": 1.0, "Recall": 1.0, "F1": 1.0, "FPR": 0.0,
     "AI_Triaged": 5, "AI_Suppressed": 2, "AI_FP_Suppressed": 2,
     "AI_FN_Introduced": 0, "AI_Recall_NoAgent": 1.0},
    {"budget": 20, "condition": "ai-triage", "TP": 3, "FP": 0, "FN": 0,
     "Precision": 1.0, "Recall": 1.0, "F1": 1.0, "FPR": 0.0,
     "AI_Triaged": 5, "AI_Suppressed": 1, "AI_FP_Suppressed": 1,
     "AI_FN_Introduced": 0, "AI_Recall_NoAgent": 1.0},
]


def _write_jsonl(path: Path, rows) -> None:
    lines = []
    for i, (idx, decision, url, param, tester_id) in enumerate(rows):
        lines.append(json.dumps({
            "run_id": "r", "timestamp": f"2026-01-01T00:00:{i:02d}+00:00",
            "tester_id": tester_id, "payload_id": f"p{i}", "context": "query",
            "confidence_apriori": 0.5, "url": url, "method": "GET",
            "elapsed_time": 0.01, "decision": decision,
            "confidence_final": 0.9 if decision else 0.1,
            "request_index": idx, "param": param,
        }))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _build_testbed(tmp_path: Path):
    results_dir = tmp_path / "results"
    for (budget, condition), rows in _TELEMETRY.items():
        run_dir = results_dir / f"budget{budget}_{condition.replace('-', '')}"
        run_dir.mkdir(parents=True)
        _write_jsonl(run_dir / "telemetry_1.jsonl", rows)

    gt_path = tmp_path / "ground_truth.json"
    gt_path.write_text(json.dumps(_GT), encoding="utf-8")

    csv_path = tmp_path / "experiment_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for (budget, condition), rows in _TELEMETRY.items():
            decided = [r for r in rows if r[1]]
            tp = sum(1 for r in decided if (r[2], r[3], r[4]) != ("http://t/d", "id", "sql_injection"))
            fp = sum(1 for r in decided if (r[2], r[3], r[4]) == ("http://t/d", "id", "sql_injection"))
            total_positive = 3
            fn = total_positive - tp
            precision = tp / (tp + fp) if (tp + fp) else ""
            recall = tp / total_positive
            f1 = (2 * precision * recall / (precision + recall)
                  if precision and recall else "")
            fpr = fp / 1  # one explicit trap in the GT
            w.writerow({
                "budget": budget, "condition": condition, "TP": tp, "FP": fp,
                "FN": fn, "Precision": precision, "Recall": recall, "F1": f1,
                "FPR": fpr, "AI_Triaged": "", "AI_Suppressed": "",
                "AI_FP_Suppressed": "", "AI_FN_Introduced": "",
                "AI_Recall_NoAgent": "", "run_dir": f"budget{budget}_{condition}",
                "status": "ok", "timestamp": "2026-01-01T00:00:00+00:00",
            })
        for extra in _EXTRA_CSV_ROWS:
            row = {col: extra.get(col, "") for col in CSV_COLUMNS}
            row["run_dir"] = f"budget{extra['budget']}_{extra['condition']}"
            row["status"] = "ok"
            row["timestamp"] = "2026-01-01T00:00:00+00:00"
            w.writerow(row)

    return results_dir, gt_path, csv_path


def test_pipeline_handles_missing_telemetry_dirs(tmp_path):
    """testbed/results/ is gitignored (multi-GB per-run telemetry) while
    testbed/experiment_results.csv and testbed/ground_truth.json are
    checked into the repo — so a fresh clone has a graded CSV but zero
    discoverable run directories. That must not crash ``build_summary``'s
    merge with a column-less empty DataFrame (regression: see
    _SUMMARY_BASE_COLUMNS in analyze_results.py)."""
    _, gt_path, csv_path = _build_testbed(tmp_path)
    empty_results_dir = tmp_path / "no_telemetry_here"
    empty_results_dir.mkdir()
    analysis_dir = tmp_path / "analysis"

    rc = analyze_results.main([
        "--results-dir", str(empty_results_dir),
        "--ground-truth", str(gt_path),
        "--csv", str(csv_path),
        "--analysis-dir", str(analysis_dir),
        "--fig-dir", str(tmp_path / "figures"),
        "--no-figures",
    ])
    assert rc == 0

    summary_path = analysis_dir / "summary_by_run.csv"
    assert summary_path.exists()
    with summary_path.open(newline="", encoding="utf-8") as fh:
        header = next(csv.reader(fh))
    assert set(analyze_results._SUMMARY_BASE_COLUMNS).issubset(header)
    assert (analysis_dir / "stats.json").exists()


def test_analyze_results_pipeline_smoke(tmp_path):
    results_dir, gt_path, csv_path = _build_testbed(tmp_path)
    analysis_dir = tmp_path / "analysis"
    fig_dir = tmp_path / "figures"

    rc = analyze_results.main([
        "--results-dir", str(results_dir),
        "--ground-truth", str(gt_path),
        "--csv", str(csv_path),
        "--analysis-dir", str(analysis_dir),
        "--fig-dir", str(fig_dir),
        "--no-figures",
    ])
    assert rc == 0

    # TASK 1
    summary_path = analysis_dir / "summary_by_run.csv"
    assert summary_path.exists()
    with summary_path.open(newline="", encoding="utf-8") as fh:
        summary_rows = list(csv.DictReader(fh))
    expected_cols = {"budget", "condition", "n_requests", "tp_unique",
                     "trap_hits", "recall", "fpr", "auc", "first_tp",
                     "mean_first_tp"}
    assert expected_cols.issubset(summary_rows[0].keys())
    # Every telemetry-backed run we fixtured should have produced a row.
    assert len(summary_rows) == len(_TELEMETRY)

    # TASK 2
    stats_path = analysis_dir / "stats.json"
    assert stats_path.exists()
    stats = json.loads(stats_path.read_text(encoding="utf-8"))
    assert "per_budget" in stats and "pooled" in stats and "bias_mitigations" in stats
    # budget=10 has all four ablation conditions -> a complete Friedman block.
    assert "10" in stats["per_budget"]
    assert "friedman" in stats["per_budget"]["10"]

    # TASK 2b
    early_path = analysis_dir / "early_recall.json"
    assert early_path.exists()
    early = json.loads(early_path.read_text(encoding="utf-8"))
    # budget=10 has both baseline and no-adaptive-sorting -> a paired block.
    assert "10" in early["per_budget"]
    assert early["per_budget"]["10"]["n_instances"] == 3

    # TASK 2c
    ai_path = analysis_dir / "ai_triage.json"
    assert ai_path.exists()
    ai = json.loads(ai_path.read_text(encoding="utf-8"))
    assert ai["available"] is True
    assert "ai-triage" in ai["arms"]

    # TASK 2c (strategy Friedman) — written inline into stats.json. This
    # fixture only grades a complete static/adaptive/ai-triage triple at
    # budget=10, so the test is correctly reported unavailable rather than
    # crashing on too few blocks.
    friedman = stats["strategy_f1_friedman"]
    assert friedman["available"] is False
    assert "found 1 complete budget" in friedman["reason"]

    # No figures were requested, so the fig dir should stay untouched.
    assert not fig_dir.exists() or not any(fig_dir.iterdir())


def _write_f1_only_csv(csv_path: Path, rows: list[dict]) -> None:
    fieldnames = ["budget", "condition", "F1", "status"]
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow({**{"status": "ok"}, **row})


def test_strategy_f1_friedman_available_with_complete_budgets(tmp_path):
    csv_path = tmp_path / "experiment_results.csv"
    # 4 budgets x 3 strategies, matched F1 triples per budget.
    rows = []
    f1_by_strategy = {
        "no-adaptive-sorting": [0.70, 0.72, 0.75, 0.74],  # static
        "baseline": [0.85, 0.86, 0.88, 0.87],               # adaptive
        "ai-triage": [0.90, 0.91, 0.93, 0.92],               # ai_triage
    }
    for budget_idx, budget in enumerate((10, 20, 50, 0)):
        for condition, values in f1_by_strategy.items():
            rows.append({"budget": budget, "condition": condition,
                         "F1": values[budget_idx]})
    _write_f1_only_csv(csv_path, rows)

    result = analyze_results.strategy_f1_friedman(csv_path)

    assert result["available"] is True
    assert result["n_blocks"] == 4
    assert result["budgets_used"] == [0, 10, 20, 50]
    assert result["alpha"] == 0.05
    assert isinstance(result["statistic"], float)
    assert isinstance(result["p_value"], float)
    assert isinstance(result["reject_null"], bool)
    assert set(result["mean_f1"]) == {"static", "adaptive", "ai_triage"}
    # ai_triage strictly dominates adaptive which strictly dominates static
    # in every block, so the mean ranking must reflect that.
    assert (result["mean_f1"]["static"]
            < result["mean_f1"]["adaptive"]
            < result["mean_f1"]["ai_triage"])

    from scipy.stats import friedmanchisquare
    expected_stat, expected_p = friedmanchisquare(*f1_by_strategy.values())
    assert result["statistic"] == pytest.approx(float(expected_stat))
    assert result["p_value"] == pytest.approx(float(expected_p))


def test_strategy_f1_friedman_unavailable_with_too_few_budgets(tmp_path):
    csv_path = tmp_path / "experiment_results.csv"
    rows = [
        {"budget": 10, "condition": "no-adaptive-sorting", "F1": 0.70},
        {"budget": 10, "condition": "baseline", "F1": 0.85},
        {"budget": 10, "condition": "ai-triage", "F1": 0.90},
    ]
    _write_f1_only_csv(csv_path, rows)

    result = analyze_results.strategy_f1_friedman(csv_path)

    assert result["available"] is False
    assert "found 1 complete budget" in result["reason"]


def test_strategy_f1_friedman_unavailable_missing_csv(tmp_path):
    result = analyze_results.strategy_f1_friedman(tmp_path / "does_not_exist.csv")
    assert result == {"available": False, "reason": "no graded CSV"}


def test_strategy_f1_friedman_unavailable_missing_columns(tmp_path):
    csv_path = tmp_path / "experiment_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["budget", "condition"])
        w.writeheader()
        w.writerow({"budget": 10, "condition": "baseline"})

    result = analyze_results.strategy_f1_friedman(csv_path)
    assert result["available"] is False
    assert "missing budget/condition/f1" in result["reason"]
