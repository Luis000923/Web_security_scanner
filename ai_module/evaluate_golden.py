#!/usr/bin/env python3
"""
evaluate_golden.py — empirical evaluation harness for the lobotomised DAST
triage agent, against a curated "golden" dataset of polyglot vulnerabilities
and extreme false-positive scenarios.

Unlike ``security_metrics.SecurityMetricsCallback`` (which greedily generates
over the *training* eval split, in-process, mid-training) this script drives
the real ``AgentClient`` — the same async client the scanner calls in
production — over any configured backend (``echo`` / ``openai`` / an
OpenAI-compatible vLLM server / ``transformers`` in-process). It is meant to
run standalone, after training, as an acceptance gate.

Golden dataset schema (JSONL, one object per line)::

    {
      "id": "poly-sqli-001",
      "category": "sqli",                 # free-form; drives the breakdown table
      "expected": "TRUE_POSITIVE",        # TRUE_POSITIVE | FALSE_POSITIVE | UNCERTAIN
      "finding": { ... }                  # arbitrary dict, passed verbatim to
                                           # AgentClient.triage_finding()
    }

See ``data/golden_dataset.example.jsonl`` for a worked set of polyglot
SQLi/XSS/cmdi/path-traversal true positives and adversarial false-positive
scenarios (WAF block pages, output-encoded reflection, latency jitter, cached
404s, input-independent error pages).

Metrics
-------
  * ``fnr``              — False-Negative Rate: P(pred=FALSE_POSITIVE | expected
                            =TRUE_POSITIVE). The strict, security-critical miss.
  * ``degradation_rate``  — P(pred=UNCERTAIN | expected=TRUE_POSITIVE): a TP the
                            model hedges on instead of confirming outright.
  * ``fp_recall``         — P(pred=FALSE_POSITIVE | expected=FALSE_POSITIVE):
                            how well the model suppresses curated noise.
  * ``accuracy``          — plain 3-class accuracy, for reference.
  * ``error_rate``        — share of rows where inference itself failed
                            (timeout / connection / malformed response) after
                            retries. Reported separately, never folded into
                            the classification metrics above, so a flaky
                            backend cannot masquerade as a good FNR.

Robustness
----------
A single row's timeout or backend error never aborts the run: each row is
retried (``--retries``, linear backoff) and, on final failure, recorded as an
``ERROR`` pseudo-verdict with a captured error message, excluded from the
classification metrics and surfaced in the report and JSON export instead.

Usage
-----
    python -m ai_module.evaluate_golden \\
        --dataset data/golden_dataset.jsonl \\
        --backend openai --base-url http://127.0.0.1:8000/v1 \\
        --model runs/triage-qlora/adapter \\
        --out metrics/golden_eval_results.json

    # wiring smoke test, no live server needed:
    python -m ai_module.evaluate_golden \\
        --dataset data/golden_dataset.example.jsonl --backend echo
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ai_module.agent_inference import AgentClient

VALID_LABELS = ("TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN")
# Pseudo-verdict for a row whose inference failed after all retries. Kept out
# of VALID_LABELS so it can never silently participate in confusion-matrix
# cells meant for real verdicts.
ERROR_LABEL = "ERROR"


@dataclass
class GoldenRow:
    id: str
    finding: dict[str, Any]
    expected: str
    category: str = "uncategorized"


@dataclass
class EvalResult:
    row: GoldenRow
    predicted: str
    confidence: float = 0.0
    reasoning: str = ""
    latency_s: float = 0.0
    error: str = ""


# --------------------------------------------------------------------------- #
# dataset loading
# --------------------------------------------------------------------------- #

def load_golden_dataset(path: Path) -> list[GoldenRow]:
    """Parse the golden JSONL, skipping (with a warning) any malformed line
    rather than aborting the whole load on one bad row."""
    rows: list[GoldenRow] = []
    skipped = 0
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"warn: {path}:{lineno} invalid JSON ({exc}); skipping",
                      file=sys.stderr)
                skipped += 1
                continue
            expected = str(obj.get("expected", "")).upper()
            finding = obj.get("finding")
            if expected not in VALID_LABELS:
                print(f"warn: {path}:{lineno} missing/invalid 'expected' "
                      f"({expected!r}); skipping", file=sys.stderr)
                skipped += 1
                continue
            if not isinstance(finding, dict):
                print(f"warn: {path}:{lineno} missing 'finding' object; skipping",
                      file=sys.stderr)
                skipped += 1
                continue
            rows.append(GoldenRow(
                id=str(obj.get("id", f"row-{lineno}")),
                finding=finding,
                expected=expected,
                category=str(obj.get("category", "uncategorized")),
            ))
    if skipped:
        print(f"loaded {len(rows)} row(s), skipped {skipped} malformed line(s)",
              file=sys.stderr)
    return rows


# --------------------------------------------------------------------------- #
# evaluation loop — bounded concurrency, per-row timeout + retry, no throws
# --------------------------------------------------------------------------- #

async def _evaluate_one(
    client: AgentClient, row: GoldenRow, *, timeout: float, retries: int,
) -> EvalResult:
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        start = time.monotonic()
        try:
            result = await asyncio.wait_for(
                client.triage_finding(row.finding), timeout=timeout
            )
            return EvalResult(
                row=row, predicted=result.verdict, confidence=result.confidence,
                reasoning=result.reasoning, latency_s=time.monotonic() - start,
            )
        except Exception as exc:  # noqa: BLE001 - timeout / connection / parse / anything
            last_exc = exc
            if attempt < retries:
                await asyncio.sleep(0.5 * (attempt + 1))
    return EvalResult(
        row=row, predicted=ERROR_LABEL, latency_s=timeout,
        error=f"{type(last_exc).__name__}: {last_exc}",
    )


async def run_eval(
    rows: list[GoldenRow], client: AgentClient, *,
    concurrency: int, timeout: float, retries: int, progress: bool = True,
) -> list[EvalResult]:
    sem = asyncio.Semaphore(max(1, concurrency))
    total = len(rows)
    done = 0

    async def _one(row: GoldenRow) -> EvalResult:
        nonlocal done
        async with sem:
            res = await _evaluate_one(client, row, timeout=timeout, retries=retries)
        done += 1
        if progress:
            step = max(1, total // 20)
            if done % step == 0 or done == total:
                print(f"\r  {done}/{total} evaluated", end="", file=sys.stderr, flush=True)
        return res

    results = await asyncio.gather(*(_one(r) for r in rows))
    if progress:
        print(file=sys.stderr)
    return list(results)


# --------------------------------------------------------------------------- #
# metrics — pure function over results, independent of I/O for testability
# --------------------------------------------------------------------------- #

def _ratio(num: int, den: int) -> float | None:
    """None (not 0.0) when the denominator is empty — "no examples of this
    class" must never render as a deceptive 0% / 100%."""
    return (num / den) if den else None


def compute_metrics(results: list[EvalResult]) -> dict[str, Any]:
    scored = [r for r in results if r.predicted != ERROR_LABEL]
    errors = [r for r in results if r.predicted == ERROR_LABEL]

    confusion: dict[str, dict[str, int]] = {
        e: {p: 0 for p in VALID_LABELS} for e in VALID_LABELS
    }
    for r in scored:
        confusion[r.row.expected][r.predicted] += 1

    tp_total = sum(confusion["TRUE_POSITIVE"].values())
    fp_total = sum(confusion["FALSE_POSITIVE"].values())

    fn = confusion["TRUE_POSITIVE"]["FALSE_POSITIVE"]     # strict miss
    degraded = confusion["TRUE_POSITIVE"]["UNCERTAIN"]     # hedged miss
    fp_caught = confusion["FALSE_POSITIVE"]["FALSE_POSITIVE"]
    correct = sum(confusion[e][e] for e in VALID_LABELS)

    by_cat: dict[str, list[EvalResult]] = {}
    for r in scored:
        by_cat.setdefault(r.row.category, []).append(r)
    categories: dict[str, dict[str, Any]] = {}
    for cat, rs in sorted(by_cat.items()):
        cat_tp = sum(1 for r in rs if r.row.expected == "TRUE_POSITIVE")
        cat_fn = sum(1 for r in rs if r.row.expected == "TRUE_POSITIVE"
                     and r.predicted == "FALSE_POSITIVE")
        cat_fp = sum(1 for r in rs if r.row.expected == "FALSE_POSITIVE")
        cat_fp_hit = sum(1 for r in rs if r.row.expected == "FALSE_POSITIVE"
                          and r.predicted == "FALSE_POSITIVE")
        cat_correct = sum(1 for r in rs if r.row.expected == r.predicted)
        categories[cat] = {
            "n": len(rs),
            "fnr": _ratio(cat_fn, cat_tp),
            "fp_recall": _ratio(cat_fp_hit, cat_fp),
            "accuracy": _ratio(cat_correct, len(rs)),
        }

    return {
        "total_rows": len(results),
        "scored_rows": len(scored),
        "error_rows": len(errors),
        "error_rate": _ratio(len(errors), len(results)) or 0.0,
        "fnr": _ratio(fn, tp_total),
        "fnr_count": fn,
        "tp_total": tp_total,
        "degradation_rate": _ratio(degraded, tp_total),
        "degradation_count": degraded,
        "fp_recall": _ratio(fp_caught, fp_total),
        "fp_recall_count": fp_caught,
        "fp_total": fp_total,
        "accuracy": _ratio(correct, len(scored)),
        "confusion_matrix": confusion,
        "by_category": categories,
        "errors": [{"id": r.row.id, "error": r.error} for r in errors],
    }


# --------------------------------------------------------------------------- #
# report rendering — dependency-free fixed-width table
# --------------------------------------------------------------------------- #

def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.2%}"


def format_table(metrics: dict[str, Any], *, dataset: str, backend: str, model: str) -> str:
    W = 78
    lines = ["=" * W,
             f"Golden Dataset Evaluation — {dataset}",
             f"backend={backend}  model={model}",
             "=" * W]

    def row(label: str, value: str) -> None:
        lines.append(f"{label:<46}{value:>32}")

    row("Total rows", str(metrics["total_rows"]))
    row("Scored (no inference error)", str(metrics["scored_rows"]))
    row("Inference errors", f"{metrics['error_rows']} ({metrics['error_rate']:.1%})")
    lines.append("-" * W)
    row("FNR  (expected TP -> predicted FP)",
        f"{_pct(metrics['fnr'])}  ({metrics['fnr_count']}/{metrics['tp_total']})")
    row("TP degradation (expected TP -> UNCERTAIN)",
        f"{_pct(metrics['degradation_rate'])}  "
        f"({metrics['degradation_count']}/{metrics['tp_total']})")
    row("FP recall (expected FP caught correctly)",
        f"{_pct(metrics['fp_recall'])}  "
        f"({metrics['fp_recall_count']}/{metrics['fp_total']})")
    row("Overall accuracy (3-class)", _pct(metrics["accuracy"]))
    lines.append("=" * W)

    lines.append("Confusion matrix (rows=expected, cols=predicted)")
    lines.append(f"{'':16}" + "".join(f"{p:>16}" for p in VALID_LABELS))
    cm = metrics["confusion_matrix"]
    for e in VALID_LABELS:
        lines.append(f"{e:<16}" + "".join(f"{cm[e][p]:>16}" for p in VALID_LABELS))
    lines.append("=" * W)

    if metrics["by_category"]:
        lines.append("By category:")
        lines.append(f"{'category':<20}{'n':>6}{'FNR':>12}{'FP recall':>14}{'accuracy':>12}")
        for cat, c in metrics["by_category"].items():
            lines.append(f"{cat:<20}{c['n']:>6}{_pct(c['fnr']):>12}"
                          f"{_pct(c['fp_recall']):>14}{_pct(c['accuracy']):>12}")
        lines.append("=" * W)

    if metrics["errors"]:
        shown = metrics["errors"][:10]
        lines.append(f"{len(metrics['errors'])} inference error(s):")
        for e in shown:
            lines.append(f"  {e['id']}: {e['error']}")
        if len(metrics["errors"]) > len(shown):
            lines.append(f"  ... and {len(metrics['errors']) - len(shown)} more "
                          f"(full list in the JSON export)")
        lines.append("=" * W)

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

async def _amain(args: argparse.Namespace, rows: list[GoldenRow]) -> int:
    client_kwargs: dict[str, Any] = {}
    if args.backend:
        client_kwargs["backend"] = args.backend
    if args.base_url:
        client_kwargs["base_url"] = args.base_url
    if args.model:
        client_kwargs["model"] = args.model
    client = AgentClient(**client_kwargs)

    print(f"evaluating {len(rows)} row(s) — backend={client.backend} "
          f"model={client.model}", file=sys.stderr)

    if client.backend not in ("echo", "transformers") and not args.skip_healthcheck:
        if not await client.healthcheck():
            print(f"error: backend '{client.backend}' at {client.base_url} failed "
                  f"the pre-flight healthcheck — is the server running? "
                  f"(bypass with --skip-healthcheck)", file=sys.stderr)
            return 2

    results = await run_eval(
        rows, client, concurrency=args.concurrency, timeout=args.timeout,
        retries=args.retries, progress=not args.quiet,
    )

    metrics = compute_metrics(results)
    print()
    print(format_table(metrics, dataset=str(args.dataset), backend=client.backend,
                        model=client.model))

    dump_rows = args.dump_rows or len(rows) <= 500
    export: dict[str, Any] = {
        "dataset": str(args.dataset),
        "backend": client.backend,
        "model": client.model,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "metrics": metrics,
    }
    if dump_rows:
        export["rows"] = [
            {
                "id": r.row.id, "category": r.row.category, "expected": r.row.expected,
                "predicted": r.predicted, "confidence": r.confidence,
                "reasoning": r.reasoning, "latency_s": round(r.latency_s, 3),
                "error": r.error,
            }
            for r in results
        ]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(export, indent=2, ensure_ascii=False))
    print(f"\nresults -> {args.out}", file=sys.stderr)

    if metrics["error_rate"] >= 0.5:
        print("error: >=50% of rows failed inference after retries — treating "
              "the run as a hard failure", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--dataset", type=Path, default=Path("data/golden_dataset.jsonl"),
                    help="golden JSONL: {id, category, expected, finding} per line")
    ap.add_argument("--backend", default=None,
                    help="override AI_AGENT_BACKEND (echo|openai|transformers)")
    ap.add_argument("--base-url", default=None, help="OpenAI-compatible server URL")
    ap.add_argument("--model", default=None, help="model id / adapter path")
    ap.add_argument("--concurrency", type=int, default=4,
                    help="parallel in-flight requests (default: 4)")
    ap.add_argument("--timeout", type=float, default=60.0,
                    help="per-row inference timeout in seconds (default: 60)")
    ap.add_argument("--retries", type=int, default=1,
                    help="extra attempts after a failed/timed-out row (default: 1)")
    ap.add_argument("--out", type=Path, default=Path("metrics/golden_eval_results.json"),
                    help="JSON export path")
    ap.add_argument("--skip-healthcheck", action="store_true",
                    help="skip the pre-flight server healthcheck")
    ap.add_argument("--dump-rows", action="store_true",
                    help="force per-row predictions into the JSON export "
                         "(on by default for datasets of <= 500 rows)")
    ap.add_argument("--quiet", action="store_true", help="suppress the progress counter")
    args = ap.parse_args(argv)

    if not args.dataset.exists():
        print(f"error: golden dataset not found: {args.dataset}\n"
              f"       see data/golden_dataset.example.jsonl for the expected schema",
              file=sys.stderr)
        return 2

    rows = load_golden_dataset(args.dataset)
    if not rows:
        print("error: no usable rows in the golden dataset", file=sys.stderr)
        return 2

    return asyncio.run(_amain(args, rows))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
