"""Golden equivalence test for tools/analyze_results.py on the real sweep.

The sweep telemetry (``testbed/results``, ~1.4 GB) is not versioned, so this
test only runs when ``WSS_SWEEP_DIR`` points at a ``testbed/`` directory that
holds ``results/``, ``ground_truth.json`` and ``experiment_results.csv``::

    WSS_SWEEP_DIR=testbed .venv/bin/python -m pytest tests/test_analyze_results_golden.py

It pins the sha256 of every ``--no-figures`` artefact so a refactor (shared
grading core, deprecation wrappers, reanalysis merge) must reproduce the
analysis byte for byte. Digests were captured on 2026-11-26 from the sweep at
8c23116 (two identical runs, ~4.5 min each) with the library versions in
``PINNED_VERSIONS``; float formatting can legitimately move with those
versions, so a mismatch reports the installed versions next to the pinned ones.

Assertion messages are in Spanish by repo convention (``tests/``).
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import os
import sys
from pathlib import Path

import pytest

SWEEP = os.environ.get("WSS_SWEEP_DIR")
pytestmark = pytest.mark.skipif(
    not SWEEP, reason="WSS_SWEEP_DIR no definido (telemetría no versionada)"
)

EXPECTED_SHA256 = {
    "ai_triage.json": "19d0ed87dddd9aa47ade07fe1b66c7ef688699a4488055eba6747b5cf68a49d2",
    "average_ranks.csv": "2b58c1fa210845e06f5441de95ab4e80367a55da7d9cbb8cefd2eb8e695c33d0",
    "detection_cost_matrix.csv": "328d9620cc2d2c2f63764fed2250f2a1a94fd70ec18c479e829b6d44661cfabf",
    "early_recall.json": "62b7828b452c874fb45b7bb06b37f498120d9ba2a7cea6bba743cf43dfc03fc3",
    "stats.json": "48ca673978cf7b39eeaf1b2cd7f32406cd3d8ae73b89188a8019ff4fc4115ea3",
    "summary_by_run.csv": "99a1b1d4a2089c5303a458d03897e9b9219f2e5b932d7f37929711be40c681dd",
}
PINNED_VERSIONS = {
    "numpy": "2.5.5",
    "pandas": "3.1.1",
    "scipy": "1.18.1",
    "statsmodels": "0.15.0",
    "scikit-posthocs": "0.18.0",
}


def _load():
    path = Path(__file__).parent.parent / "tools" / "analyze_results.py"
    spec = importlib.util.spec_from_file_location("analyze_results_golden", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["analyze_results_golden"] = module
    spec.loader.exec_module(module)
    return module


def _installed() -> dict[str, str]:
    out = {}
    for name in PINNED_VERSIONS:
        try:
            out[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            out[name] = "missing"
    return out


def test_artefactos_identicos_al_golden(tmp_path: Path) -> None:
    sweep = Path(SWEEP or ".").resolve()
    rc = _load().main([
        "--results-dir", str(sweep / "results"),
        "--ground-truth", str(sweep / "ground_truth.json"),
        "--csv", str(sweep / "experiment_results.csv"),
        "--analysis-dir", str(tmp_path),
        "--fig-dir", str(tmp_path / "fig"),
        "--no-figures",
    ])
    assert rc == 0
    produced = {
        name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        for name in EXPECTED_SHA256
        if (tmp_path / name).is_file()
    }
    mismatched = sorted(n for n in EXPECTED_SHA256 if produced.get(n) != EXPECTED_SHA256[n])
    assert not mismatched, (
        f"artefactos distintos del golden: {mismatched}; "
        f"versiones instaladas {_installed()} vs fijadas {PINNED_VERSIONS}"
    )
