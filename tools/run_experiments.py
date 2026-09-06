#!/usr/bin/env python3
"""run_experiments.py — DAST grid-search orchestrator for the paper testbed.

Runs the async scanner against OWASP Benchmark across a grid of payload
budgets x ablation conditions, grades every run with tools/eval_oracle.py,
and consolidates the metrics into testbed/experiment_results.csv.

Stdlib only. Designed to be re-run: an existing run directory is skipped
unless --force is given, so an interrupted sweep resumes cheaply.

--------------------------------------------------------------------------
GRID
--------------------------------------------------------------------------

    budgets     : 10, 20, 50, 0            (--max-payloads; 0 = unlimited)
    conditions  : baseline                 (all optimizations on)
                  no-interleave            (--no-interleave only)
                  no-priority              (--no-priority only)
                  no-runtime-confirm       (--no-runtime-confirm only)

    => 4 budgets x 4 conditions = 16 runs.

Each run gets its own telemetry dir:  testbed/results/budget<B>_<condition>/
containing the scanner's JSONL telemetry, its JSON report, and metrics.json
(the oracle's --json-out). One CSV row per run is appended to
testbed/experiment_results.csv with columns:

    budget, condition, TP, FP, FN, Precision, Recall, F1, FPR

--------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------

    # Full 16-run sweep (containers must be up):
    python tools/run_experiments.py

    # See the exact commands without running anything:
    python tools/run_experiments.py --dry-run

    # A slice of the grid, forcing re-run of existing dirs:
    python tools/run_experiments.py --budgets 10,50 --conditions baseline,no-priority --force

Options:
    --target URL          Scan target. Default https://127.0.0.1:8443/benchmark/
    --ground-truth PATH   Default testbed/ground_truth.json
    --results-dir DIR     Default testbed/results
    --csv PATH            Default testbed/experiment_results.csv
    --budgets LIST        Comma list overriding the default 10,20,50,0
    --conditions LIST     Comma list from: baseline,no-interleave,no-priority,
                          no-runtime-confirm
    --compose-file PATH   docker-compose.yml for the precondition check.
                          Default testbed/docker-compose.yml
    --skip-precondition   Don't probe the target / docker before starting.
    --scan-timeout SECS   Hard wall-clock cap per scan (default 3600).
    --extra-args "..."    Extra flags appended verbatim to every scan command.
    --force               Re-run conditions whose results dir already exists.
    --dry-run             Print commands only.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import ssl
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_BUDGETS = [10, 20, 50, 0]

# condition -> the ablation flags that condition adds. Everything not listed
# stays at the scanner's optimized default (interleave / priority /
# runtime-confirm all ON).
CONDITIONS: dict[str, list[str]] = {
    "baseline": [],
    "no-interleave": ["--no-interleave"],
    "no-priority": ["--no-priority"],
    "no-runtime-confirm": ["--no-runtime-confirm"],
}

CSV_COLUMNS = ["budget", "condition", "TP", "FP", "FN",
               "Precision", "Recall", "F1", "FPR", "run_dir", "status", "timestamp"]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _log(msg: str) -> None:
    print(f"[run_experiments] {msg}", flush=True)


def scanner_cmd() -> list[str]:
    """Invoke the scanner with the *same* interpreter running this script.

    Deliberately NOT `shutil.which("webscanner")`: on this box the console
    script lives in a system Python 3.14 without the project's deps. Running
    `tools/run_experiments.py` with `.venv/bin/python` keeps everything on
    the 3.12 venv.
    """
    return [sys.executable, "-m", "web_security_scanner.cli"]


def check_precondition(target: str, compose_file: Path) -> bool:
    ok = True

    if compose_file.exists() and shutil.which("docker"):
        try:
            out = subprocess.run(
                ["docker", "compose", "-f", str(compose_file), "ps", "--format", "json"],
                capture_output=True, text=True, timeout=30,
            )
            running = out.stdout.count('"State":"running"') or out.stdout.lower().count("running")
            _log(f"docker compose ps: {running or 'no'} running service(s)")
            if not running:
                ok = False
        except (subprocess.SubprocessError, OSError) as e:
            _log(f"docker compose ps failed ({e}); relying on the HTTP probe")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "run_experiments/1.0"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:  # noqa: S310
            _log(f"HTTP probe {target} -> {resp.status}")
            if resp.status >= 500:
                ok = False
    except Exception as e:  # noqa: BLE001 - any failure means "not reachable"
        _log(f"HTTP probe {target} FAILED: {e}")
        ok = False

    return ok


def build_scan_command(
    target: str, budget: int, condition: str, run_dir: Path, extra: list[str],
) -> list[str]:
    cmd = [
        *scanner_cmd(), "scan", target,
        "--no-verify-ssl",
        "--allow-private-redirects",
        "--max-payloads", str(budget),
        "--telemetry-dir", str(run_dir),
        "--output", str(run_dir / "report"),
        "--format", "json",
        "--lang", "en",
    ]
    cmd += CONDITIONS[condition]
    cmd += extra
    return cmd


def newest_jsonl(run_dir: Path) -> Path | None:
    candidates = sorted(run_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
    return candidates[-1] if candidates else None


def run_oracle(jsonl: Path, ground_truth: Path, run_dir: Path) -> dict:
    metrics_path = run_dir / "metrics.json"
    cmd = [
        sys.executable, str(REPO_ROOT / "tools" / "eval_oracle.py"),
        "--results", str(jsonl),
        "--ground-truth", str(ground_truth),
        "--json-out", str(metrics_path),
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(metrics_path.read_text(encoding="utf-8"))


def metrics_to_row(budget: int, condition: str, run_dir: Path,
                   m: dict, status: str) -> dict:
    def num(x: object) -> str:
        return "" if x is None else (f"{x:.4f}" if isinstance(x, float) else str(x))

    return {
        "budget": budget,
        "condition": condition,
        "TP": m.get("tp", ""),
        "FP": m.get("fp", ""),
        "FN": m.get("fn", ""),
        "Precision": num(m.get("precision")),
        "Recall": num(m.get("recall")),
        "F1": num(m.get("f1_score")),
        "FPR": num(m.get("fpr")),
        "run_dir": str(run_dir.relative_to(REPO_ROOT)),
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def append_csv(csv_path: Path, row: dict) -> None:
    new_file = not csv_path.exists()
    with csv_path.open("a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        if new_file:
            w.writeheader()
        w.writerow(row)


# --------------------------------------------------------------------------
# main loop
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="run_experiments.py",
                                 description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="https://127.0.0.1:8443/benchmark/")
    ap.add_argument("--ground-truth", default=str(REPO_ROOT / "testbed" / "ground_truth.json"))
    ap.add_argument("--results-dir", default=str(REPO_ROOT / "testbed" / "results"))
    ap.add_argument("--csv", default=str(REPO_ROOT / "testbed" / "experiment_results.csv"))
    ap.add_argument("--budgets", default=",".join(map(str, DEFAULT_BUDGETS)))
    ap.add_argument("--conditions", default=",".join(CONDITIONS))
    ap.add_argument("--compose-file", default=str(REPO_ROOT / "testbed" / "docker-compose.yml"))
    ap.add_argument("--skip-precondition", action="store_true")
    ap.add_argument("--scan-timeout", type=int, default=3600)
    ap.add_argument("--extra-args", default="")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    budgets = [int(b) for b in args.budgets.split(",") if b.strip() != ""]
    conditions = [c.strip() for c in args.conditions.split(",") if c.strip()]
    unknown = set(conditions) - set(CONDITIONS)
    if unknown:
        sys.exit(f"[ERROR] unknown --conditions: {sorted(unknown)}; "
                 f"valid: {sorted(CONDITIONS)}")

    ground_truth = Path(args.ground_truth)
    if not ground_truth.exists():
        sys.exit(f"[ERROR] ground truth not found: {ground_truth}\n"
                 f"        run: python testbed/build_ground_truth.py --download "
                 f"--base-url https://127.0.0.1:8443")

    results_dir = Path(args.results_dir)
    csv_path = Path(args.csv)
    extra = args.extra_args.split() if args.extra_args else []

    _log(f"grid: budgets={budgets} x conditions={conditions} "
         f"=> {len(budgets) * len(conditions)} run(s)")

    if not args.dry_run and not args.skip_precondition:
        if not check_precondition(args.target, Path(args.compose_file)):
            sys.exit("[ERROR] precondition failed — is the testbed up?\n"
                     "        docker compose -f testbed/docker-compose.yml up -d")

    failures: list[str] = []

    for budget in budgets:
        for condition in conditions:
            tag = f"budget{budget}_{condition.replace('-', '')}"
            run_dir = results_dir / tag
            scan_cmd = build_scan_command(args.target, budget, condition, run_dir, extra)

            if args.dry_run:
                _log(f"DRY {tag}")
                print("   ", " ".join(scan_cmd))
                continue

            if run_dir.exists() and not args.force:
                _log(f"SKIP {tag} (dir exists; --force to redo)")
                continue

            run_dir.mkdir(parents=True, exist_ok=True)
            _log(f"RUN  {tag}")
            _log("     " + " ".join(scan_cmd))

            status = "ok"
            metrics: dict = {}
            try:
                proc = subprocess.run(
                    scan_cmd, cwd=REPO_ROOT, timeout=args.scan_timeout,
                    capture_output=True, text=True,
                )
                (run_dir / "scanner.stdout.log").write_text(proc.stdout, encoding="utf-8")
                (run_dir / "scanner.stderr.log").write_text(proc.stderr, encoding="utf-8")
                if proc.returncode != 0:
                    status = f"scan-exit-{proc.returncode}"
                    _log(f"     scanner exited {proc.returncode} — see scanner.stderr.log")

                jsonl = newest_jsonl(run_dir)
                if jsonl is None:
                    status = "no-telemetry"
                    _log("     no *.jsonl telemetry produced")
                else:
                    metrics = run_oracle(jsonl, ground_truth, run_dir)
                    _log(f"     TP={metrics.get('tp')} FP={metrics.get('fp')} "
                         f"FN={metrics.get('fn')} P={metrics.get('precision')} "
                         f"R={metrics.get('recall')} F1={metrics.get('f1_score')} "
                         f"FPR={metrics.get('fpr')}")
            except subprocess.TimeoutExpired:
                status = "scan-timeout"
                _log(f"     scan exceeded {args.scan_timeout}s — killed")
            except subprocess.CalledProcessError as e:
                status = "oracle-error"
                _log(f"     eval_oracle failed: {e.stderr}")
            except Exception as e:  # noqa: BLE001
                status = f"error:{type(e).__name__}"
                _log(f"     unexpected: {e}")

            if status != "ok":
                failures.append(tag)
            append_csv(csv_path, metrics_to_row(budget, condition, run_dir, metrics, status))

    if args.dry_run:
        return 0

    _log(f"done. CSV -> {csv_path}")
    if failures:
        _log(f"{len(failures)} run(s) with a non-ok status: {failures}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
