"""tests/test_run_experiments.py — CSV schema-migration hardening.

``append_csv`` rewrites testbed/experiment_results.csv in place whenever it
finds a stale header from an older CSV_COLUMNS schema. Rows are decoded
positionally by their own field count (12-column legacy schema vs. the
current 17-column one) since the on-disk header can't be trusted. A row
matching neither known width is a corrupt/truncated write feeding the
paper's numbers — it must raise loudly (with the offending file + line
number) instead of being dropped with a warning.
"""

import csv
import importlib.util
import sys
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).parent.parent / "tools" / "run_experiments.py"
_spec = importlib.util.spec_from_file_location("run_experiments", _MOD_PATH)
run_experiments = importlib.util.module_from_spec(_spec)
sys.modules["run_experiments"] = run_experiments
_spec.loader.exec_module(run_experiments)


def _write_raw_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def test_migrate_csv_schema_handles_legacy_and_current_rows(tmp_path):
    csv_path = tmp_path / "experiment_results.csv"
    legacy_row = ["10", "baseline", "5", "1", "2",
                  "0.8333", "0.7143", "0.7692", "0.1",
                  "run1", "ok", "2026-01-01T00:00:00+00:00"]
    current_row = ["20", "no-priority", "6", "0", "1",
                   "1.0", "0.8571", "0.9231", "0.0",
                   "3", "1", "1", "0", "0.9",
                   "run2", "ok", "2026-01-01T00:01:00+00:00"]
    # Stale on-disk header (legacy width) even though row 2 already has the
    # current (wider) schema — this is the exact real-world case the
    # migration exists for (see run_experiments._migrate_csv_schema).
    _write_raw_csv(csv_path, run_experiments._LEGACY_CSV_COLUMNS,
                   [legacy_row, current_row])

    run_experiments._migrate_csv_schema(csv_path)

    with csv_path.open(newline="", encoding="utf-8") as fh:
        reader = list(csv.DictReader(fh))
    assert [r["run_dir"] for r in reader] == ["run1", "run2"]
    assert reader[0]["AI_Triaged"] == ""  # backfilled empty for the legacy row
    assert reader[1]["AI_Triaged"] == "3"


def test_migrate_csv_schema_raises_on_corrupt_row(tmp_path):
    csv_path = tmp_path / "experiment_results.csv"
    good_row = ["10", "baseline", "5", "1", "2",
                "0.8333", "0.7143", "0.7692", "0.1",
                "run1", "ok", "2026-01-01T00:00:00+00:00"]
    # Synthetic corruption: a truncated write (e.g. crash mid-flush) leaves a
    # row with neither the legacy (12) nor current (17) field count.
    corrupt_row = ["20", "no-priority", "6", "0", "1", "1.0"]
    _write_raw_csv(csv_path, run_experiments._LEGACY_CSV_COLUMNS,
                   [good_row, corrupt_row])

    with pytest.raises(ValueError, match=r"line 3") as excinfo:
        run_experiments._migrate_csv_schema(csv_path)

    msg = str(excinfo.value)
    assert "6 field(s)" in msg
    assert str(csv_path) in msg


def test_append_csv_migrates_stale_header_before_appending(tmp_path):
    csv_path = tmp_path / "experiment_results.csv"
    legacy_row = ["10", "baseline", "5", "1", "2",
                  "0.8333", "0.7143", "0.7692", "0.1",
                  "run1", "ok", "2026-01-01T00:00:00+00:00"]
    _write_raw_csv(csv_path, run_experiments._LEGACY_CSV_COLUMNS, [legacy_row])

    new_row = {col: "" for col in run_experiments.CSV_COLUMNS}
    new_row.update(budget="20", condition="baseline", run_dir="run2", status="ok")
    run_experiments.append_csv(csv_path, new_row)

    with csv_path.open(newline="", encoding="utf-8") as fh:
        header = next(csv.reader(fh))
    assert header == run_experiments.CSV_COLUMNS
    with csv_path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["run_dir"] for r in rows] == ["run1", "run2"]


def test_append_csv_propagates_corrupt_row_failure(tmp_path):
    csv_path = tmp_path / "experiment_results.csv"
    corrupt_row = ["20", "no-priority", "6", "0", "1", "1.0"]
    _write_raw_csv(csv_path, run_experiments._LEGACY_CSV_COLUMNS, [corrupt_row])

    new_row = {col: "" for col in run_experiments.CSV_COLUMNS}
    with pytest.raises(ValueError, match=r"line 2"):
        run_experiments.append_csv(csv_path, new_row)
