#!/usr/bin/env python3
"""
dataset_generator.py — Telemetry JSONL  ->  LLM fine-tuning dataset.

The async scanner, when run with ``--telemetry-dir PATH``, writes one
newline-delimited JSON row per payload probe (see
``web_security_scanner/core/telemetry_async.py``). Our testbed sweep leaves
those files at ``testbed/results/<run>/telemetry_*.jsonl``. This script folds
the raw probe rows into supervised samples the fine-tuning pipeline consumes:

  * ``triage``   — given a candidate finding + evidence, label it TP / FP.
  * ``payload``  — given an endpoint/param probe history, propose the next payload.

Ground truth
------------
Two interchangeable sources (either, both, or neither):

  * ``--benchmark-csv testbed/.cache/benchmark/expectedresults-1.2.csv``
    The OWASP Benchmark oracle. Rows are joined to probes by the
    ``BenchmarkTestNNNNN`` id embedded in the request URL path.
  * ``--ground-truth file.json`` — ``{"vulnerabilities": [{"url","param","type"}]}``
    or a bare list of the same; joined on ``(url, param, vuln_class)``.

With no oracle the script falls back to *weak labels*: the scanner's own
``decision`` / ``confidence_final`` columns become the training target
(``--weak-labels`` is then implied). Useful for bootstrapping, noisier.

Real telemetry rows carry no response body, so ``triage`` evidence is built
from the columns that *are* present (a-priori confidence, context, latency vs.
the run's benign baseline, the scanner's verdict). The literal payload string
is reconstructed from the URL query component.

Output formats
--------------
- ``alpaca``   : ``{"instruction","input","output"}`` per line (+ ``meta``)
- ``sharegpt`` : ``{"conversations": [{"from","value"}, ...]}`` per line
- ``chatml``   : ``{"messages": [{"role","content"}, ...]}`` per line

Usage
-----
    python -m ai_module.dataset_generator \
        --telemetry testbed/results \
        --benchmark-csv testbed/.cache/benchmark/expectedresults-1.2.csv \
        --task triage --format alpaca \
        --out data/triage.jsonl --split 0.9
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from ai_module.prompts import load_prompt

# --------------------------------------------------------------------------- #
# Telemetry loading
# --------------------------------------------------------------------------- #

_BENCHMARK_ID_RE = re.compile(r"BenchmarkTest\d+", re.IGNORECASE)

# scanner tester class  ->  OWASP Benchmark category token(s)
_TESTER_TO_CATEGORY: dict[str, set[str]] = {
    "XSSTester": {"xss"},
    "SQLInjectionTester": {"sqli"},
    "CommandInjectionTester": {"cmdi"},
    "PathTraversalTester": {"pathtraver"},
    "LDAPInjectionTester": {"ldapi"},
    "XPathInjectionTester": {"xpathi"},
    "OpenRedirectTester": {"trustbound"},
    "SSRFTester": {"ssrf"},
}

# tester class  ->  a generic "what confirms this" hint for payload samples
_CONFIRM_HINT: dict[str, str] = {
    "XSSTester": "unique reflected marker rendered unescaped in an executable context",
    "SQLInjectionTester": "database error string, or a repeatable boolean/time oracle differential",
    "CommandInjectionTester": "bounded, payload-correlated response delay above baseline jitter",
    "PathTraversalTester": "contents of a known out-of-webroot file in the response body",
}


def iter_jsonl(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    """Yield decoded objects from every ``*.jsonl`` file under ``paths``."""
    for path in paths:
        if path.is_dir():
            files = sorted(path.glob("**/*.jsonl"))
        else:
            files = [path]
        for fp in files:
            with fp.open("r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError as exc:  # pragma: no cover
                        print(f"warn: {fp}:{lineno}: {exc}", file=sys.stderr)
                        continue
                    if isinstance(row, dict):
                        row.setdefault("_source", str(fp))
                        yield row


def _payload_from_url(url: str, param: str) -> str:
    """Recover the literal injected value from a probe URL's query string."""
    try:
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    except ValueError:
        return ""
    if param and param in qs and qs[param]:
        return qs[param][-1]
    # Fall back to the last query value (single-param benchmark endpoints).
    for values in reversed(list(qs.values())):
        if values:
            return values[-1]
    return unquote(url.rsplit("=", 1)[-1]) if "=" in url else ""


# --------------------------------------------------------------------------- #
# Ground truth
# --------------------------------------------------------------------------- #


@dataclass
class Oracle:
    """Resolves whether a probe hit a genuinely vulnerable sink."""

    benchmark: dict[str, dict[str, Any]] = field(default_factory=dict)
    index: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not self.benchmark and not self.index

    def verdict(self, *, url: str, param: str, vclass: str, tester_id: str) -> bool | None:
        """``True`` = real vuln of this class, ``False`` = not, ``None`` = unknown."""
        m = _BENCHMARK_ID_RE.search(url or "")
        if m and self.benchmark:
            entry = self.benchmark.get(m.group(0).lower())
            if entry is not None:
                cats = _TESTER_TO_CATEGORY.get(tester_id, set())
                same_class = (not cats) or (entry["category"] in cats)
                return bool(entry["real"]) and same_class
        if self.index:
            key = (url, param, (vclass or "").lower())
            if key in self.index:
                return True
            # url-only fallback: a real sink on this endpoint for this class
            for (u, _p, c), _e in self.index.items():
                if u == url and c == (vclass or "").lower():
                    return True
            return False
        return None


def load_oracle(benchmark_csv: Path | None, ground_truth: Path | None) -> Oracle:
    oracle = Oracle()
    if benchmark_csv:
        with benchmark_csv.open("r", encoding="utf-8", newline="") as fh:
            for row in csv.reader(fh):
                if not row or row[0].lstrip().startswith("#"):
                    continue
                name = row[0].strip().lower()
                if not name.startswith("benchmarktest"):
                    continue
                oracle.benchmark[name] = {
                    "category": row[1].strip().lower(),
                    "real": row[2].strip().lower() == "true",
                    "cwe": row[3].strip() if len(row) > 3 else "",
                }
        print(f"oracle: {len(oracle.benchmark)} OWASP Benchmark entries", file=sys.stderr)
    if ground_truth:
        data = json.loads(ground_truth.read_text(encoding="utf-8"))
        entries = data.get("vulnerabilities", data) if isinstance(data, dict) else data
        for entry in entries or []:
            key = (
                entry.get("url", ""),
                entry.get("param", entry.get("parameter", "")),
                (entry.get("type") or entry.get("vuln_class") or "").lower(),
            )
            oracle.index[key] = entry
        print(f"oracle: {len(oracle.index)} ground-truth sinks", file=sys.stderr)
    return oracle


# --------------------------------------------------------------------------- #
# Sample construction
# --------------------------------------------------------------------------- #


@dataclass
class Sample:
    system: str
    user: str
    assistant: str
    meta: dict[str, Any] = field(default_factory=dict)

    def to_chatml(self) -> dict[str, Any]:
        return {
            "messages": [
                {"role": "system", "content": self.system},
                {"role": "user", "content": self.user},
                {"role": "assistant", "content": self.assistant},
            ],
            "meta": self.meta,
        }

    def to_alpaca(self) -> dict[str, Any]:
        return {
            "instruction": self.system,
            "input": self.user,
            "output": self.assistant,
            "meta": self.meta,
        }

    def to_sharegpt(self) -> dict[str, Any]:
        return {
            "conversations": [
                {"from": "system", "value": self.system},
                {"from": "human", "value": self.user},
                {"from": "gpt", "value": self.assistant},
            ],
            "meta": self.meta,
        }


_CONF_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CONFIRMED": 3}


def _is_probe_row(row: dict[str, Any]) -> bool:
    # legacy event-style rows
    if row.get("event") in {"FINDING", "VULN_CANDIDATE", "ANOMALY", "REQUEST", "PROBE"}:
        return True
    # native telemetry rows
    return "decision" in row and "request_index" in row


def _run_baselines(rows: list[dict[str, Any]]) -> dict[tuple[str, str], float]:
    """Per (run_id, tester_id) median probe latency — a cheap benign baseline."""
    buckets: dict[tuple[str, str], list[float]] = defaultdict(list)
    for r in rows:
        try:
            buckets[(r.get("run_id", ""), r.get("tester_id", ""))].append(
                float(r.get("elapsed_time", 0.0) or 0.0)
            )
        except (TypeError, ValueError):
            continue
    out: dict[tuple[str, str], float] = {}
    for key, xs in buckets.items():
        xs.sort()
        out[key] = xs[len(xs) // 2] if xs else 0.0
    return out


def build_triage_samples(
    rows: list[dict[str, Any]], oracle: Oracle, *, weak: bool
) -> Iterator[Sample]:
    system = load_prompt("triage_system")
    baselines = _run_baselines(rows)
    for row in rows:
        if not _is_probe_row(row):
            continue
        decision = bool(row.get("decision"))
        conf_final = row.get("confidence_final")
        # A "candidate" is a probe the scanner flagged (or, in weak mode, any
        # probe that produced a confidence verdict at all).
        is_candidate = decision or (weak and conf_final not in (None, "", "LOW"))
        if not is_candidate:
            continue

        url = row.get("url", "")
        param = row.get("param", row.get("parameter", "")) or ""
        tester_id = row.get("tester_id", "")
        vclass = (row.get("type") or row.get("vuln_class") or "").lower()
        if not vclass:
            cats = _TESTER_TO_CATEGORY.get(tester_id)
            vclass = next(iter(cats)) if cats else "unknown"
        payload = row.get("payload") or _payload_from_url(url, param)

        truth = oracle.verdict(url=url, param=param, vclass=vclass, tester_id=tester_id)
        if truth is None:
            if not weak:
                continue
            # weak label: trust a CONFIRMED verdict, distrust everything softer
            truth = _CONF_RANK.get(str(conf_final).upper(), 0) >= _CONF_RANK["HIGH"]
            label_src = "weak(confidence_final)"
        else:
            label_src = "benchmark" if oracle.benchmark else "ground_truth"

        base = baselines.get((row.get("run_id", ""), tester_id), 0.0)
        elapsed = float(row.get("elapsed_time", 0.0) or 0.0)
        evidence = {
            "scanner_decision": decision,
            "scanner_confidence": conf_final,
            "apriori_confidence": row.get("confidence_apriori"),
            "injection_context": row.get("context"),
            "vector": row.get("vector"),
            "latency_ms": round(elapsed * 1000, 1),
            "run_baseline_latency_ms": round(base * 1000, 1),
            "latency_delta_ms": round((elapsed - base) * 1000, 1),
        }
        verdict = "TRUE_POSITIVE" if truth else "FALSE_POSITIVE"
        user = (
            f"Endpoint: {url}\n"
            f"Parameter: {param}\n"
            f"Suspected class: {vclass}\n"
            f"Payload sent: {payload!r}\n"
            f"Observed evidence: {json.dumps(evidence, ensure_ascii=False)}\n\n"
            "Classify this candidate as TRUE_POSITIVE, FALSE_POSITIVE or UNCERTAIN "
            "and justify from the evidence."
        )
        if truth:
            reasoning = (
                f"The {vclass} sink at this endpoint is confirmed vulnerable and the "
                "probe's context/verdict are consistent with injection rather than "
                "benign reflection or latency noise."
            )
            next_step = "Replay with a differentiating oracle payload to demonstrate impact."
        else:
            reasoning = (
                "No corroborating vulnerable sink for this class at this endpoint. The "
                "signal is consistent with benign reflection, a generic error page, or "
                "normal latency variance around the run baseline."
            )
            next_step = "Suppress the finding and lower this endpoint's priority."
        assistant = json.dumps(
            {
                "verdict": verdict,
                "confidence": 0.9 if label_src != "weak(confidence_final)" else 0.6,
                "reasoning": reasoning,
                "next_step": next_step,
            },
            ensure_ascii=False,
        )
        yield Sample(
            system, user, assistant,
            meta={"url": url, "label": verdict, "label_source": label_src,
                  "tester": tester_id},
        )


def build_payload_samples(
    rows: list[dict[str, Any]], oracle: Oracle, *, weak: bool
) -> Iterator[Sample]:
    system = load_prompt("payload_system")
    # Reconstruct each parameter's probing trajectory.
    traj: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if not _is_probe_row(row):
            continue
        key = (
            row.get("run_id", ""),
            row.get("tester_id", ""),
            row.get("url", "").split("?", 1)[0],
            row.get("param", row.get("parameter", "")) or "",
        )
        traj[key].append(row)

    for (_run, tester_key, base_url, param), seq in traj.items():
        seq.sort(key=lambda r: r.get("request_index", 0) or r.get("ts", 0))
        for prev, nxt in zip(seq, seq[1:]):
            nxt_payload = nxt.get("payload") or _payload_from_url(nxt.get("url", ""), param)
            if not nxt_payload:
                continue
            tester_id = nxt.get("tester_id", "")
            prev_payload = prev.get("payload") or _payload_from_url(prev.get("url", ""), param)
            prev_elapsed = float(prev.get("elapsed_time", 0.0) or 0.0)
            user = (
                f"Target: {base_url}  param={param}\n"
                f"Suspected class: {next(iter(_TESTER_TO_CATEGORY.get(tester_id, {'unknown'})))}\n"
                f"Last payload: {prev_payload!r}\n"
                f"  -> scanner_decision={bool(prev.get('decision'))} "
                f"context={prev.get('context')} "
                f"latency_ms={round(prev_elapsed * 1000, 1)}\n"
                "Propose the single most informative next payload and the signal "
                "that would confirm the vulnerability."
            )
            assistant = json.dumps(
                {
                    "payloads": [
                        {
                            "payload": nxt_payload,
                            "rationale": (
                                f"Escalates probe specificity for the {nxt.get('context')} "
                                "context after the previous vector produced no decisive signal."
                            ),
                            "confirm_signal": _CONFIRM_HINT.get(
                                tester_id, "an unambiguous, payload-correlated response differential"
                            ),
                            "score": {"LOW": 0.4, "MEDIUM": 0.6, "HIGH": 0.8, "CONFIRMED": 0.95}.get(
                                str(nxt.get("confidence_apriori", "")).upper(), 0.5
                            ),
                        }
                    ]
                },
                ensure_ascii=False,
            )
            yield Sample(system, user, assistant, meta={"url": base_url, "param": param})


BUILDERS = {
    "triage": build_triage_samples,
    "payload": build_payload_samples,
}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _to_record(fmt: str):
    return {
        "chatml": lambda s: s.to_chatml(),
        "alpaca": lambda s: s.to_alpaca(),
        "sharegpt": lambda s: s.to_sharegpt(),
    }[fmt]


def write_split(samples: list[Sample], out: Path, fmt: str, split: float, seed: int) -> None:
    rng = random.Random(seed)
    rng.shuffle(samples)
    out.parent.mkdir(parents=True, exist_ok=True)
    to_rec = _to_record(fmt)

    if split >= 1.0:
        pieces = [(out, samples)]
    else:
        cut = int(len(samples) * split)
        pieces = [
            (out.with_name(out.stem + ".train" + out.suffix), samples[:cut]),
            (out.with_name(out.stem + ".val" + out.suffix), samples[cut:]),
        ]

    for path, part in pieces:
        with path.open("w", encoding="utf-8") as fh:
            for s in part:
                fh.write(json.dumps(to_rec(s), ensure_ascii=False) + "\n")
        print(f"wrote {len(part):>6} samples -> {path}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--telemetry", type=Path, action="append", required=True,
                    metavar="PATH", help="JSONL file or directory (repeatable)")
    ap.add_argument("--benchmark-csv", type=Path, default=None,
                    help="OWASP Benchmark expectedresults-*.csv oracle")
    ap.add_argument("--ground-truth", type=Path, default=None,
                    help="JSON list/obj of known vulnerable sinks")
    ap.add_argument("--task", choices=sorted(BUILDERS), default="triage")
    ap.add_argument("--format", choices=["alpaca", "sharegpt", "chatml"], default="alpaca")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--split", type=float, default=1.0,
                    help="train fraction; 1.0 writes a single file")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--limit", type=int, default=0, help="cap sample count (0 = all)")
    ap.add_argument("--weak-labels", action="store_true",
                    help="use the scanner's own decision/confidence as labels "
                         "(implied when no oracle is given)")
    ap.add_argument("--balance", action="store_true",
                    help="downsample the majority class to a 1:1 TP/FP ratio (triage)")
    args = ap.parse_args(argv)

    rows = list(iter_jsonl(args.telemetry))
    print(f"loaded {len(rows)} telemetry rows", file=sys.stderr)
    oracle = load_oracle(args.benchmark_csv, args.ground_truth)
    weak = args.weak_labels or oracle.empty
    if oracle.empty and not args.weak_labels:
        print("no oracle supplied — falling back to weak labels", file=sys.stderr)

    samples = list(BUILDERS[args.task](rows, oracle, weak=weak))

    if args.balance and args.task == "triage":
        rng = random.Random(args.seed)
        by_label: dict[str, list[Sample]] = defaultdict(list)
        for s in samples:
            by_label[s.meta.get("label", "?")].append(s)
        if len(by_label) > 1:
            k = min(len(v) for v in by_label.values())
            samples = [s for v in by_label.values() for s in rng.sample(v, k)]
            print(f"balanced to {k} per class", file=sys.stderr)

    if args.limit:
        samples = samples[: args.limit]
    if not samples:
        print("no samples produced — check telemetry / oracle inputs", file=sys.stderr)
        return 1

    if args.task == "triage":
        n_tp = sum(1 for s in samples if s.meta.get("label") == "TRUE_POSITIVE")
        print(f"{len(samples)} samples (TP={n_tp}, FP={len(samples) - n_tp})", file=sys.stderr)
    else:
        print(f"{len(samples)} samples", file=sys.stderr)
    write_split(samples, args.out, args.format, args.split, args.seed)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
