"""Golden equivalence tests for ``scripts/evaluate.py`` (single-run scoring).

Pins the exact output of the scoring path on a **real** OWASP Benchmark run so
any later refactor of ``scripts/evaluate.py``, ``core.ieee_metrics`` or
``core.benchmark_ground_truth`` (e.g. sharing the matching core with
``tools/eval_oracle.py``) must reproduce the published numbers byte for byte.

Inputs (``tests/fixtures/eval_golden/``, provenance in ``MANIFEST.json``):

* ``owasp_b20_baseline.report.json`` — budget=20 / baseline report of the
  reviewer re-run (``feat/ai-triage-mainline`` 8c23116), trimmed to the fields
  ``load_findings_from_report`` reads.
* ``ground_truth.json`` — ``testbed/ground_truth.json`` (338 instances).

Regenerate the expected outputs only for an *intended* change of the numbers::

    UPDATE_EVAL_GOLDEN=1 .venv/bin/python -m pytest tests/test_eval_golden.py

Assertion messages are in Spanish by repo convention (``tests/``).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "eval_golden"
EXPECTED = FIXTURES / "expected"
UPDATE = os.environ.get("UPDATE_EVAL_GOLDEN") == "1"

CASES = {
    "from_report": [
        "--from-report",
        str(FIXTURES / "owasp_b20_baseline.report.json"),
        "--ground-truth",
        str(FIXTURES / "ground_truth.json"),
    ],
    "synthetic": ["--synthetic", "--ground-truth", str(FIXTURES / "ground_truth.json")],
}
OUTPUTS = ("golden.json", "golden.md", "golden.tex", "stdout.txt")


def _load_evaluate() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "evaluate_script", ROOT / "scripts" / "evaluate.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["evaluate_script"] = module
    spec.loader.exec_module(module)
    return module


def _run(case: str, out_dir: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, str]:
    evaluate = _load_evaluate()
    code = evaluate.main([*CASES[case], "--out", str(out_dir), "--basename", "golden"])
    assert code == 0
    stdout = capsys.readouterr().out.replace(str(out_dir), "<OUT>")
    produced = {name: (out_dir / name).read_text(encoding="utf-8") for name in OUTPUTS[:3]}
    produced["stdout.txt"] = stdout
    return produced


def test_fixtures_coinciden_con_el_manifiesto() -> None:
    manifest = json.loads((FIXTURES / "MANIFEST.json").read_text(encoding="utf-8"))
    for name, digest in manifest["sha256"].items():
        actual = hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest()
        assert actual == digest, f"el fixture {name} cambió: regenera el golden a propósito"


@pytest.mark.parametrize("case", sorted(CASES))
def test_salida_identica_al_golden(
    case: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    produced = _run(case, tmp_path, capsys)
    target = EXPECTED / case
    if UPDATE:
        target.mkdir(parents=True, exist_ok=True)
        for name, text in produced.items():
            (target / name).write_text(text, encoding="utf-8")
        pytest.skip("golden regenerado (UPDATE_EVAL_GOLDEN=1)")
    for name in OUTPUTS:
        expected = (target / name).read_text(encoding="utf-8")
        assert produced[name] == expected, f"{case}/{name} difiere del golden"


def test_cifras_publicables_del_run_real(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Las cifras legibles del golden, para que un cambio se vea en el diff del test."""
    _run("from_report", tmp_path, capsys)
    data = json.loads((tmp_path / "golden.json").read_text(encoding="utf-8"))
    counts, rates = data["counts"], data["rates"]
    assert (counts["tp_instances"], counts["fp_instances"], counts["fn"], counts["tn"]) == (
        182,
        15,
        12,
        129,
    )
    assert counts["total_instances"] == 338 and counts["fp_outside_ground_truth"] == 1
    assert rates["recall"] == pytest.approx(182 / 194, abs=0)
    assert rates["specificity"] == pytest.approx(129 / 144, abs=0)


def test_dos_ejecuciones_identicas(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    first = _run("from_report", tmp_path / "a", capsys)
    second = _run("from_report", tmp_path / "b", capsys)
    assert first == second, "evaluate.py debe ser determinista sobre el mismo informe"
