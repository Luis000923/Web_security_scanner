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
    conditions  : baseline                 (all optimizations on, incl. Phase 3
                                             adaptive live sorting)
                  no-interleave            (--no-interleave only)
                  no-priority              (--no-priority only)
                  no-runtime-confirm       (--no-runtime-confirm only)
                  no-adaptive-sorting      (--no-adaptive-sorting only; the
                                             Phase 3 static-vs-adaptive contrast)

    => 4 budgets x 5 conditions = 20 runs.

Each run gets its own telemetry dir:  testbed/results/budget<B>_<condition>/
containing the scanner's JSONL telemetry, its JSON report, and metrics.json
(the oracle's --json-out). One CSV row per run is appended to
testbed/experiment_results.csv with columns:

    budget, condition, TP, FP, FN, Precision, Recall, F1, FPR

--------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------

    # Full 20-run sweep (containers must be up):
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
                          no-runtime-confirm,no-adaptive-sorting
    --compose-file PATH   docker-compose.yml for the precondition check.
                          Default testbed/docker-compose.yml
    --skip-precondition   Don't probe the target / docker before starting.
    --scan-timeout SECS   Hard wall-clock cap per scan (default 3600).
    --extra-args "..."    Extra flags appended verbatim to every scan command.
    --force               Re-run conditions whose results dir already exists.
    --dry-run             Print commands only.
    --no-progress         Disable the live progress bar (plain line logging).

A live progress bar (current run / total, budget, condition, ETA) is shown when
``rich`` or ``tqdm`` is importable and stderr is a TTY; otherwise the script
falls back to plain prefixed line logging. Neither library is a hard dependency.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_BUDGETS = [10, 20, 50, 0]
SMOKE_BUDGETS = [10]
SMOKE_TARGET_CAP = 100

# condition -> the ablation flags that condition adds. Everything not listed
# stays at the scanner's optimized default (interleave / priority /
# runtime-confirm all ON).
CONDITIONS: dict[str, list[str]] = {
    "baseline": [],
    "no-interleave": ["--no-interleave"],
    "no-priority": ["--no-priority"],
    "no-runtime-confirm": ["--no-runtime-confirm"],
    # Phase 3.3: pin the a-priori order (disable the live feedback loop) so the
    # graded run is directly comparable to `baseline` (adaptive ON).
    "no-adaptive-sorting": ["--no-adaptive-sorting"],
}

# Mandatory keys on every per-probe telemetry JSONL row (see
# core/telemetry_async.py). Used by :func:`validate_jsonl` to prove the adaptive
# reordering runs did not perturb the on-disk schema.
TELEMETRY_REQUIRED_KEYS = (
    "run_id", "timestamp", "tester_id", "payload_id", "context",
    "confidence_apriori", "url", "method", "elapsed_time", "decision",
    "confidence_final", "request_index",
)

CSV_COLUMNS = ["budget", "condition", "TP", "FP", "FN",
               "Precision", "Recall", "F1", "FPR", "run_dir", "status", "timestamp"]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

# Set to the live ProgressReporter for the duration of the sweep so that every
# _log() call is routed through the bar-safe writer instead of a bare print()
# that would tear a redrawing progress bar.
_REPORTER: ProgressReporter | None = None


def _log(msg: str) -> None:
    line = f"[run_experiments] {msg}"
    if _REPORTER is not None:
        _REPORTER.log(line)
    else:
        print(line, flush=True)


class ProgressReporter:
    """Bar-safe progress + log output for the experiment sweep.

    Backend is picked at construction, best first:

    * ``rich``  — a :class:`rich.progress.Progress` bar; logs go through
      ``progress.console.print`` so they scroll *above* the live bar.
    * ``tqdm``  — a ``tqdm`` bar; logs go through ``tqdm.write``.
    * ``plain`` — no live bar; every log line is a plain ``print`` with an
      ``[k/N]`` prefix. Used when neither lib is importable, stderr is not a
      TTY, or ``--no-progress`` was passed.

    The public surface (:meth:`start_run`, :meth:`log`, :meth:`advance`,
    :meth:`summary`) is identical across backends, so the main loop never
    branches on which one is active.
    """

    def __init__(self, total: int, *, enabled: bool = True) -> None:
        self.total = max(0, total)
        self.done = 0
        self._current = ""
        self._start = time.monotonic()
        self.backend = "plain"
        self._progress = None
        self._task = None
        self._tqdm = None
        self._console = None

        want_bar = enabled and total > 0 and sys.stderr.isatty()
        if want_bar and self._init_rich():
            self.backend = "rich"
        elif want_bar and self._init_tqdm():
            self.backend = "tqdm"

    # ---- backend bootstrap ------------------------------------------------

    def _init_rich(self) -> bool:
        try:
            from rich.console import Console
            from rich.progress import (
                BarColumn,
                MofNCompleteColumn,
                Progress,
                SpinnerColumn,
                TextColumn,
                TimeElapsedColumn,
                TimeRemainingColumn,
            )
        except ImportError:
            return False
        self._console = Console(stderr=True)
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("• ETA"),
            TimeRemainingColumn(),
            console=self._console,
            transient=False,
        )
        self._progress.start()
        self._task = self._progress.add_task("starting…", total=self.total)
        return True

    def _init_tqdm(self) -> bool:
        try:
            from tqdm import tqdm
        except ImportError:
            return False
        self._tqdm = tqdm(
            total=self.total, unit="run", dynamic_ncols=True,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
        )
        return True

    # ---- lifecycle -------------------------------------------------------

    def __enter__(self) -> ProgressReporter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._progress is not None:
            self._progress.stop()
            self._progress = None
        if self._tqdm is not None:
            self._tqdm.close()
            self._tqdm = None

    # ---- public API ----------------------------------------------------

    def start_run(self, idx: int, budget: int, condition: str) -> None:
        """Announce run ``idx`` of ``total`` (1-based) before it launches."""
        b = "unlimited" if budget == 0 else str(budget)
        self._current = f"Corrida {idx}/{self.total} · budget={b} · {condition}"
        if self.backend == "rich":
            self._progress.update(self._task, description=self._current)
        elif self.backend == "tqdm":
            self._tqdm.set_description(self._current)
        else:
            print(f"[run_experiments] ==> {self._current}", flush=True)

    def advance(self) -> None:
        """Mark the current run finished and step the bar."""
        self.done += 1
        if self.backend == "rich":
            self._progress.update(self._task, advance=1)
        elif self.backend == "tqdm":
            self._tqdm.update(1)

    def log(self, line: str) -> None:
        """Emit a log line without corrupting a live bar."""
        if self.backend == "rich":
            self._console.print(line, highlight=False, markup=False)
        elif self.backend == "tqdm":
            from tqdm import tqdm
            tqdm.write(line)
        else:
            prefix = f"[{self.done}/{self.total}] " if self.total else ""
            print(prefix + line, flush=True)

    def summary(self, csv_path: Path, rows: list[dict], failures: list[str]) -> None:
        """Pretty end-of-sweep summary (rich table when available)."""
        elapsed = time.monotonic() - self._start
        mins, secs = divmod(int(elapsed), 60)
        self.close()

        if self.backend == "rich":
            self._rich_summary(csv_path, rows, failures, f"{mins}m{secs:02d}s")
            return

        width = 62
        print()
        print("=" * width)
        print(f" Experiment sweep complete — {len(rows)} run(s) in {mins}m{secs:02d}s")
        print("=" * width)
        hdr = f" {'budget':>9} │ {'condition':<20} │ {'F1':>7} │ status"
        print(hdr)
        print(f" {'─' * 9}─┼─{'─' * 20}─┼─{'─' * 7}─┼───────")
        for r in rows:
            b = "unlimited" if str(r.get("budget")) == "0" else str(r.get("budget"))
            print(f" {b:>9} │ {str(r.get('condition','')):<20} │ "
                  f"{str(r.get('F1','') or '—'):>7} │ {r.get('status','')}")
        print("=" * width)
        if failures:
            print(f" ⚠  {len(failures)} run(s) with a non-ok status: {', '.join(failures)}")
        else:
            print(" ✓  every run completed with status=ok")
        print(f" ✓  CSV written to {csv_path}")
        print("=" * width)

    def _rich_summary(self, csv_path: Path, rows: list[dict],
                      failures: list[str], elapsed: str) -> None:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console()
        table = Table(title=f"Experiment sweep — {len(rows)} run(s) in {elapsed}")
        table.add_column("Budget", justify="right", style="cyan")
        table.add_column("Condition", style="magenta")
        table.add_column("TP", justify="right")
        table.add_column("FP", justify="right")
        table.add_column("FN", justify="right")
        table.add_column("F1", justify="right", style="bold")
        table.add_column("Status")
        for r in rows:
            b = "unlimited" if str(r.get("budget")) == "0" else str(r.get("budget"))
            ok = r.get("status") == "ok"
            table.add_row(
                b, str(r.get("condition", "")),
                str(r.get("TP", "")), str(r.get("FP", "")), str(r.get("FN", "")),
                str(r.get("F1", "") or "—"),
                f"[green]{r.get('status')}[/green]" if ok
                else f"[red]{r.get('status')}[/red]",
            )
        console.print(table)
        if failures:
            console.print(Panel.fit(
                f"[yellow]⚠ {len(failures)} run(s) with a non-ok status:[/yellow]\n"
                + "\n".join(f"  • {f}" for f in failures),
                border_style="yellow",
            ))
        console.print(Panel.fit(
            f"[green]✓ CSV written to[/green] [bold]{csv_path}[/bold]",
            border_style="green",
        ))


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


def load_target_list(path: Path) -> list[dict]:
    """Read + validate the --target-list JSON before the sweep starts.

    A malformed or param-less target list is the single most common reason a
    calibrated run silently scores 0 TP: `_targets_from_list()` only injects an
    injectable query parameter (`?BenchmarkTest00026=1`) for entries that carry
    a ``param`` key, and the GET-oriented testers skip any URL with no query
    string. Fail loudly here instead of after a multi-hour sweep.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"[ERROR] --target-list {path}: {e}")
    if not isinstance(raw, list) or not raw:
        sys.exit(f"[ERROR] --target-list {path}: expected a non-empty JSON array")
    missing_url = [i for i, e in enumerate(raw)
                   if not isinstance(e, dict) or not e.get("url")]
    if missing_url:
        sys.exit(f"[ERROR] --target-list {path}: entries {missing_url[:10]} "
                 f"have no 'url' field")
    no_param = [e["url"] for e in raw if not e.get("param")]
    if no_param:
        pct = 100 * len(no_param) / len(raw)
        _log(f"WARNING: {len(no_param)}/{len(raw)} ({pct:.0f}%) target-list "
             f"entries have no 'param' — those URLs carry no injectable query "
             f"string and every tester will skip them. First few: {no_param[:3]}")
        if len(no_param) == len(raw):
            sys.exit("[ERROR] no target-list entry has a 'param'; the scan would "
                     "fire zero payloads. Regenerate with "
                     "build_ground_truth.py --emit-targets ... --vectors getparam")
    return raw


def build_scan_command(
    target: str, target_list: Path, budget: int, condition: str,
    run_dir: Path, extra: list[str],
) -> list[str]:
    # --target-list makes the scanner enqueue exactly this set (recon skipped)
    # and fold each entry's `param` into the URL as `?<param>=1`.
    # --no-verify-ssl is mandatory: the OWASP Benchmark container serves HTTPS
    # on :8443 with a self-signed cert; without it every probe returns
    # status_code=0 and the run scores 0 TP.
    cmd = [
        *scanner_cmd(), "scan", target,
        "--target-list", str(target_list),
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
    # Defensive: these three flags are load-bearing for a calibrated run.
    for required in ("--target-list", "--no-verify-ssl", "--allow-private-redirects"):
        assert required in cmd, f"scan command lost {required}"
    return cmd


def newest_jsonl(run_dir: Path) -> Path | None:
    candidates = sorted(run_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
    return candidates[-1] if candidates else None


def validate_jsonl(jsonl: Path) -> tuple[bool, str]:
    """Confirm a telemetry file is still well-formed line-delimited JSON.

    Phase 3.3 check: the adaptive feedback loop only *reorders* probes — it emits
    no new event type and adds no field — so every row must still parse as a
    standalone JSON object carrying the full :data:`TELEMETRY_REQUIRED_KEYS`
    schema, and ``request_index`` must be a strictly increasing 1-based run.
    Returns ``(ok, detail)``; ``detail`` is a short human summary either way.
    """
    lines = [ln for ln in jsonl.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        return False, "empty telemetry file"
    prev = 0
    seen_ctx: set[str] = set()
    for n, ln in enumerate(lines, 1):
        try:
            row = json.loads(ln)
        except json.JSONDecodeError as e:
            return False, f"line {n}: not valid JSON ({e})"
        missing = [k for k in TELEMETRY_REQUIRED_KEYS if k not in row]
        if missing:
            return False, f"line {n}: missing keys {missing}"
        idx = row["request_index"]
        if not isinstance(idx, int) or idx <= prev:
            return False, f"line {n}: request_index {idx!r} not strictly increasing"
        prev = idx
        if row.get("context"):
            seen_ctx.add(str(row["context"]))
    return True, (f"{len(lines)} rows, request_index 1..{prev}, "
                  f"{len(seen_ctx)} payload families")


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

    try:
        run_dir_str = str(run_dir.relative_to(REPO_ROOT))
    except ValueError:
        run_dir_str = str(run_dir)   # results dir lives outside the repo tree

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
        "run_dir": run_dir_str,
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
    ap.add_argument("--target-list", default=str(REPO_ROOT / "testbed" / "benchmark_targets.json"))
    ap.add_argument("--budgets", default=",".join(map(str, DEFAULT_BUDGETS)))
    ap.add_argument("--conditions", default=",".join(CONDITIONS))
    ap.add_argument("--compose-file", default=str(REPO_ROOT / "testbed" / "docker-compose.yml"))
    ap.add_argument("--skip-precondition", action="store_true")
    ap.add_argument("--scan-timeout", type=int, default=7200)
    ap.add_argument("--extra-args", default="")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-progress", action="store_true",
                    help="Disable the live progress bar; use plain line logging.")
    ap.add_argument("--smoke", action="store_true",
                    help=f"Validation run: budgets={SMOKE_BUDGETS}, target list "
                         f"truncated to the first {SMOKE_TARGET_CAP} endpoints.")
    args = ap.parse_args(argv)

    budgets = [int(b) for b in args.budgets.split(",") if b.strip() != ""]
    if args.smoke:
        budgets = list(SMOKE_BUDGETS)
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

    results_dir = Path(args.results_dir).resolve()
    csv_path = Path(args.csv)
    extra = args.extra_args.split() if args.extra_args else []

    target_list = Path(args.target_list)
    if not target_list.exists():
        sys.exit(f"[ERROR] target list not found: {target_list}\n"
                 f"        run: python testbed/build_ground_truth.py --download "
                 f"--base-url https://127.0.0.1:8443 --vectors getparam "
                 f"--emit-targets testbed/benchmark_targets.json")

    entries = load_target_list(target_list)

    if args.smoke:
        smoke_list = results_dir / "benchmark_targets.smoke.json"
        results_dir.mkdir(parents=True, exist_ok=True)
        smoke_list.write_text(json.dumps(entries[:SMOKE_TARGET_CAP], indent=2) + "\n",
                              encoding="utf-8")
        _log(f"smoke: {len(entries[:SMOKE_TARGET_CAP])}/{len(entries)} targets -> {smoke_list}")
        target_list = smoke_list
        entries = load_target_list(target_list)

    _log(f"target-list: {len(entries)} endpoint(s), "
         f"{sum(1 for e in entries if e.get('param'))} with an injectable param "
         f"-> {target_list}")

    _log(f"grid: budgets={budgets} x conditions={conditions} "
         f"=> {len(budgets) * len(conditions)} run(s)")

    if not args.dry_run and not args.skip_precondition:
        if not check_precondition(args.target, Path(args.compose_file)):
            sys.exit("[ERROR] precondition failed — is the testbed up?\n"
                     "        docker compose -f testbed/docker-compose.yml up -d")

    global _REPORTER

    failures: list[str] = []
    summary_rows: list[dict] = []
    grid = [(b, c) for b in budgets for c in conditions]
    total = len(grid)

    reporter = ProgressReporter(
        total, enabled=not args.dry_run and not args.no_progress
    )
    if not args.dry_run:
        _REPORTER = reporter

    try:
        for idx, (budget, condition) in enumerate(grid, 1):
            tag = f"budget{budget}_{condition.replace('-', '')}"
            run_dir = results_dir / tag
            scan_cmd = build_scan_command(args.target, target_list, budget,
                                          condition, run_dir, extra)

            if args.dry_run:
                _log(f"DRY {tag}")
                print("   ", " ".join(scan_cmd))
                continue

            reporter.start_run(idx, budget, condition)

            if run_dir.exists() and not args.force:
                _log(f"SKIP {tag} (dir exists; --force to redo)")
                reporter.advance()
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
                # exit 1 == "vulnerabilities found" (CI convention), still a
                # successful scan. Only >1 is a real failure.
                if proc.returncode > 1:
                    status = f"scan-exit-{proc.returncode}"
                    _log(f"     scanner exited {proc.returncode} — see scanner.stderr.log")

                jsonl = newest_jsonl(run_dir)
                if jsonl is None:
                    status = "no-telemetry"
                    _log("     no *.jsonl telemetry produced")
                else:
                    ok_jsonl, detail = validate_jsonl(jsonl)
                    _log(f"     telemetry {'OK' if ok_jsonl else 'CORRUPT'}: {detail}")
                    if not ok_jsonl:
                        status = "telemetry-corrupt"
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
            row = metrics_to_row(budget, condition, run_dir, metrics, status)
            append_csv(csv_path, row)
            summary_rows.append(row)
            reporter.advance()
    finally:
        _REPORTER = None
        if not args.dry_run:
            reporter.close()

    if args.dry_run:
        return 0

    reporter.summary(csv_path, summary_rows, failures)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
