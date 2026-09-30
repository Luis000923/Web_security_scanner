#!/usr/bin/env python3
"""
evaluate_model.py — base model vs fine-tuned model, side by side.

Runs the same golden triage dataset (see ``ai_module/evaluate_golden.py`` for
the schema and the 3-class TP/FP/UNCERTAIN harness this reuses rather than
duplicates) through two configured :class:`~ai_module.agent_inference.
AgentClient` instances — "base" and "tuned" — and reports:

* ``evaluate_golden``'s own metrics for each side (FNR, TP-degradation rate,
  FP recall, 3-class accuracy, per-category breakdown) — unchanged, reused
  verbatim so this script can never drift from that harness's definitions;
* the :mod:`web_security_scanner.core.ieee_metrics` metrics the task asks for
  by name — Accuracy, Recall, F1 and **Precision (class-matched)** — computed
  by bridging each side's golden-eval results into that module's
  ``Finding``/``GroundTruth`` shape (see :func:`_to_ieee_inputs`) and calling
  its battle-tested ``compute_metrics()`` rather than re-deriving the same
  arithmetic a second time;
* the delta (tuned − base) for every numeric metric on both sides, which is
  the actual question this script answers: did fine-tuning help, and on
  which axis.

``category``/``suspected_class`` in the golden dataset map directly onto
:mod:`core.vuln_classes`' canonical names (``sqli``/``xss``/``pathtraver``/
``cmdi``/...), so ``precision_class_matched`` is scoreable out of the box
against ``data/golden_dataset.example.jsonl`` and any golden set that follows
its schema.

UNCERTAIN-as-absence
---------------------
``core.ieee_metrics`` has no "hedged" bucket — only a claim or its absence.
An ``UNCERTAIN`` verdict is mapped to *no claim reported*, the same as
``FALSE_POSITIVE``: the model was not confident enough to confirm the
finding, which is exactly what "absence of a claim" means to a detection
metric, and it correctly costs recall on a genuinely vulnerable instance
without misusing ieee_metrics' separate ``untested`` channel (reserved for
points the scan infrastructure itself could not measure — a perimeter block,
a soft 404 — which is a different failure mode than a model hedging on a
point it *did* see).

Usage
-----
    # base model (e.g. the stock instruct checkpoint) vs the fine-tuned adapter,
    # both served OpenAI-compatible:
    python -m ai_module.evaluate_model \\
        --dataset data/golden_dataset.jsonl \\
        --base-backend openai --base-endpoint http://127.0.0.1:8001/v1 \\
            --base-model Qwen2.5-1.5B-Instruct \\
        --tuned-backend openai --tuned-endpoint http://127.0.0.1:8000/v1 \\
            --tuned-model runs/triage-qlora/merged \\
        --out metrics/model_comparison.json

    # wiring smoke test, no live servers needed:
    python -m ai_module.evaluate_model --dataset data/golden_dataset.example.jsonl \\
        --base-backend echo --tuned-backend echo
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from ai_module.agent_inference import AgentClient
from ai_module.evaluate_golden import (
    ERROR_LABEL,
    EvalResult,
    GoldenRow,
    load_golden_dataset,
    run_eval,
)
from ai_module.evaluate_golden import compute_metrics as compute_golden_metrics
from ai_module.evaluate_golden import format_table as format_golden_table
from web_security_scanner.core.ieee_metrics import Finding, GroundTruth
from web_security_scanner.core.ieee_metrics import compute_metrics as compute_ieee_metrics
from web_security_scanner.core.vuln_classes import canonical_class

# The ieee_metrics rates this script surfaces, in report order. Each is a
# MetricResult property returning float | None.
_IEEE_RATE_NAMES = (
    "accuracy", "recall", "precision", "f1",
    "precision_class_matched", "recall_class_matched", "f1_class_matched",
)


# --------------------------------------------------------------------------- #
# bridge: evaluate_golden's EvalResult rows -> core.ieee_metrics inputs
# --------------------------------------------------------------------------- #

def _to_ieee_inputs(results: list[EvalResult]) -> tuple[list[Finding], GroundTruth]:
    """Reshape a golden-eval run into ``(findings, ground_truth)``.

    Key: ``(endpoint, parameter)`` from ``row.finding`` when present, else
    ``(row.id, "")`` -- the golden dataset's worked examples always carry
    ``endpoint``/``parameter``, but a minimal hand-written row need not.

    Only a ``TRUE_POSITIVE`` verdict produces a :class:`Finding` (a claim);
    ``FALSE_POSITIVE`` and ``UNCERTAIN`` are both "no claim reported" -- see
    the module docstring for why ``UNCERTAIN`` is folded into absence rather
    than ``untested``. Inference errors (``ERROR_LABEL``) are dropped
    entirely, matching ``evaluate_golden.compute_metrics``'s own convention
    of excluding them from the classification metrics.
    """
    findings: list[Finding] = []
    instances: list[tuple[tuple[str, str], bool, str]] = []
    expected_class: dict[tuple[str, str], str] = {}

    for r in results:
        if r.predicted == ERROR_LABEL:
            continue
        url = str(r.row.finding.get("endpoint") or r.row.id)
        parameter = str(r.row.finding.get("parameter") or "")
        key = (url, parameter)
        vulnerable = r.row.expected == "TRUE_POSITIVE"
        instances.append((key, vulnerable, r.row.category))
        if canonical_class(r.row.category) is not None:
            expected_class[key] = r.row.category

        if r.predicted == "TRUE_POSITIVE":
            reported_class = str(
                r.row.finding.get("suspected_class") or r.row.category
            )
            confidence_tier = (
                "HIGH" if r.confidence >= 0.75 else
                "MEDIUM" if r.confidence >= 0.4 else "LOW"
            )
            findings.append(Finding(
                url=url, parameter=parameter,
                vulnerability_type=reported_class,
                confidence=confidence_tier,
            ))

    gt = GroundTruth(instances=instances, name="golden_dataset",
                      expected_class=expected_class)
    return findings, gt


def _ieee_rates(results: list[EvalResult]) -> dict[str, float | None]:
    findings, gt = _to_ieee_inputs(results)
    metric_result = compute_ieee_metrics(findings, gt)
    return {name: getattr(metric_result, name) for name in _IEEE_RATE_NAMES}


# --------------------------------------------------------------------------- #
# per-model evaluation
# --------------------------------------------------------------------------- #

async def evaluate_one(
    rows: list[GoldenRow], client: AgentClient, *,
    label: str, concurrency: int, timeout: float, retries: int, quiet: bool,
) -> dict[str, Any]:
    healthy = await client.healthcheck()
    if not healthy:
        print(f"warn: {label} backend ({client.backend}) failed its healthcheck; "
              f"every row will record an inference error", file=sys.stderr)
    results = await run_eval(
        rows, client, concurrency=concurrency, timeout=timeout, retries=retries,
        progress=not quiet,
    )
    return {
        "label": label,
        "backend": client.backend,
        "base_url": client.base_url if client.backend == "openai" else "",
        "model": client.model,
        "healthy": healthy,
        "golden": compute_golden_metrics(results),
        "ieee": _ieee_rates(results),
    }


def _delta(base: dict[str, Any], tuned: dict[str, Any]) -> dict[str, Any]:
    """``tuned - base`` for every numeric metric both sides report.

    ``None`` on either side propagates to ``None`` in the delta (e.g. neither
    model's golden set carries class labels) rather than being silently
    treated as ``0.0``, which would fabricate a comparison that was never
    actually measured on one of the two sides.
    """
    def _sub(b: Any, t: Any) -> Any:
        if isinstance(b, dict) and isinstance(t, dict):
            return {k: _sub(b.get(k), t.get(k)) for k in set(b) | set(t)}
        if isinstance(b, (int, float)) and isinstance(t, (int, float)) \
                and not isinstance(b, bool) and not isinstance(t, bool):
            return t - b
        return None

    return {
        "golden": _sub(base["golden"], tuned["golden"]),
        "ieee": _sub(base["ieee"], tuned["ieee"]),
    }


# --------------------------------------------------------------------------- #
# report rendering
# --------------------------------------------------------------------------- #

def _fmt_rate(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.1%}"


def _fmt_delta(v: float | None) -> str:
    if v is None:
        return "n/a"
    sign = "+" if v >= 0 else ""
    return f"{sign}{v:.1%}"


def format_comparison(base: dict[str, Any], tuned: dict[str, Any],
                       delta: dict[str, Any], *, dataset: str) -> str:
    w = 78
    lines = ["=" * w, f"Model comparison — {dataset}", "=" * w,
             f"base:  backend={base['backend']}  model={base['model']}"
             f"{'  (healthcheck FAILED)' if not base['healthy'] else ''}",
             f"tuned: backend={tuned['backend']}  model={tuned['model']}"
             f"{'  (healthcheck FAILED)' if not tuned['healthy'] else ''}",
             "=" * w]

    lines.append(f"{'metric (core.ieee_metrics)':<34}{'base':>12}{'tuned':>12}{'delta':>14}")
    for name in _IEEE_RATE_NAMES:
        b, t, d = base["ieee"][name], tuned["ieee"][name], delta["ieee"][name]
        lines.append(f"{name:<34}{_fmt_rate(b):>12}{_fmt_rate(t):>12}{_fmt_delta(d):>14}")
    lines.append("-" * w)

    lines.append(f"{'metric (evaluate_golden)':<34}{'base':>12}{'tuned':>12}{'delta':>14}")
    for key, label in (("fnr", "FNR"), ("degradation_rate", "TP degradation"),
                        ("fp_recall", "FP recall"), ("accuracy", "3-class accuracy")):
        b, t, d = base["golden"][key], tuned["golden"][key], delta["golden"][key]
        lines.append(f"{label:<34}{_fmt_rate(b):>12}{_fmt_rate(t):>12}{_fmt_delta(d):>14}")
    lines.append("=" * w)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _agent_client(args: argparse.Namespace, prefix: str) -> AgentClient:
    kwargs: dict[str, Any] = {}
    backend = getattr(args, f"{prefix}_backend")
    if backend:
        kwargs["backend"] = backend
    endpoint = getattr(args, f"{prefix}_endpoint")
    if endpoint:
        kwargs["base_url"] = endpoint
    model = getattr(args, f"{prefix}_model")
    if model:
        kwargs["model"] = model
    return AgentClient(**kwargs)


def _add_model_args(ap: argparse.ArgumentParser, prefix: str, label: str) -> None:
    ap.add_argument(f"--{prefix}-backend", default=None,
                    help=f"{label} model backend (echo|openai|transformers)")
    ap.add_argument(f"--{prefix}-endpoint", default=None,
                    help=f"{label} model OpenAI-compatible server URL (backend=openai)")
    ap.add_argument(f"--{prefix}-model", default=None,
                    help=f"{label} model id / adapter path")


async def _amain(args: argparse.Namespace, rows: list[GoldenRow]) -> int:
    base_client = _agent_client(args, "base")
    tuned_client = _agent_client(args, "tuned")

    base = await evaluate_one(
        rows, base_client, label="base",
        concurrency=args.concurrency, timeout=args.timeout, retries=args.retries,
        quiet=args.quiet,
    )
    tuned = await evaluate_one(
        rows, tuned_client, label="tuned",
        concurrency=args.concurrency, timeout=args.timeout, retries=args.retries,
        quiet=args.quiet,
    )
    delta = _delta(base, tuned)

    print(format_comparison(base, tuned, delta, dataset=str(args.dataset)))
    if args.verbose:
        print()
        print(format_golden_table(base["golden"], dataset=str(args.dataset),
                                  backend=base["backend"], model=base["model"]))
        print()
        print(format_golden_table(tuned["golden"], dataset=str(args.dataset),
                                  backend=tuned["backend"], model=tuned["model"]))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(
        {"dataset": str(args.dataset), "n_rows": len(rows),
         "base": base, "tuned": tuned, "delta": delta},
        indent=2, default=str,
    ))
    print(f"\nwrote {args.out}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--dataset", type=Path, default=Path("data/golden_dataset.jsonl"),
                    help="golden JSONL: {id, category, expected, finding} per line")
    _add_model_args(ap, "base", "base")
    _add_model_args(ap, "tuned", "fine-tuned")
    ap.add_argument("--concurrency", type=int, default=4,
                    help="parallel in-flight requests per model (default: 4)")
    ap.add_argument("--timeout", type=float, default=60.0,
                    help="per-row inference timeout in seconds (default: 60)")
    ap.add_argument("--retries", type=int, default=1,
                    help="extra attempts after a failed/timed-out row (default: 1)")
    ap.add_argument("--out", type=Path, default=Path("metrics/model_comparison.json"),
                    help="JSON export path")
    ap.add_argument("--verbose", action="store_true",
                    help="also print evaluate_golden's full per-model table "
                         "(confusion matrix, by-category breakdown)")
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
