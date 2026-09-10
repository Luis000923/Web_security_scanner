#!/usr/bin/env python3
"""eval_oracle.py — Phase 4 evaluation oracle for Web_security_scanner.

Cross-references what the scanner reported against a hand-curated ground
truth to produce TP/FP/FN counts and the standard detection metrics
(Precision, Recall, F1, and a trap-restricted FPR). Zero third-party
dependencies — stdlib only — so it runs anywhere the scanner does.

--------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------

    python tools/eval_oracle.py --results RESULTS_FILE --ground-truth GT.json
    python tools/eval_oracle.py --results reports/telemetry/telemetry_...jsonl \\
                                 --ground-truth ground_truth.json
    python tools/eval_oracle.py --results reports/scan_20260906.json \\
                                 --ground-truth ground_truth.json --verbose

Options:
    --results PATH        Scanner output to grade. Either:
                             * the Phase 1 telemetry JSONL (one probe per
                               line; rows with a truthy "decision" count as
                               findings), or
                             * the final JSON report from generate_json_report
                               (its top-level "vulnerabilities" list), or
                             * a bare JSON array of vulnerability dicts
                               ({"type", "url", "parameter"|"param", ...}).
                           Format is auto-detected from content, not the
                           file extension.
    --ground-truth PATH    JSON array of ground-truth records:
                             {"url": ..., "param": ..., "type": ...,
                              "vulnerable": true|false}
                           ``vulnerable: false`` entries are explicit traps —
                           known-safe endpoints the scanner must NOT flag.
    --verbose              Also print every FP/FN tuple (debugging aid).
    --json-out PATH        Additionally write the metrics dict as JSON to
                           PATH (for CI / batch pipelines).

--------------------------------------------------------------------------
MATCHING RULES
--------------------------------------------------------------------------

A "finding" is the tuple (normalized_url, param, canonical_type):

  * normalized_url  — scheme + host (lowercased) + path, query string and
                       fragment stripped, so an injected payload in the query
                       never breaks the match against the original GT URL.
  * canonical_type   — both the scanner's type/tester name and the GT
                       "type" string are folded through the same alias table
                       (see ``canonicalize_type``) so "SQLInjectionTester",
                       "SQL Injection" and "SQLInjection" all collapse to the
                       same bucket. Unrecognized types pass through as a
                       normalized (lowercased, alnum-only) string, so custom
                       GT categories still match as long as both sides spell
                       them the same way once punctuation/case is removed.

  TP: finding is in GT with vulnerable == true.
  FP: finding is NOT in GT, or is in GT with vulnerable == false (a trap).
  FN: a GT record has vulnerable == true and no matching finding was made.

FPR is only meaningful against a *known* population of negatives. This
script exposes exactly that: the explicit traps (``vulnerable: false``)
in the ground truth. ``FPR = (traps incorrectly flagged) / (total traps)``.
FPs against URLs/params/types the ground truth never mentions at all are
still counted in the total FP/Precision, but they fall outside the trap
population and cannot contribute to a rate over an unknown universe —
FPR is reported as N/A when the ground truth defines zero explicit traps.
"""

from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# --------------------------------------------------------------------------
# Type canonicalization
# --------------------------------------------------------------------------
# Ordered most-specific-first so e.g. "NoSQL Injection" is claimed by
# nosql_injection before the plain "sql" alias in sql_injection can match it.
# Each canonical maps to a list of alias tuples; a tuple matches when ALL of
# its substrings are present in the normalized input (AND), and the overall
# rule matches when ANY alias tuple matches (OR). Covers scanner class names
# (e.g. "SQLInjectionTester"), the en/es i18n display strings, and plain
# ground-truth spellings ("SQLInjection", "XSS") alike.
_TYPE_ALIASES: list[tuple[str, list[tuple[str, ...]]]] = [
    ("nosql_injection", [("nosql",)]),
    ("sql_injection", [("sql",)]),
    ("xss", [("xss",), ("crosssite", "script")]),
    ("ssrf", [("ssrf",), ("serverside", "requestforgery")]),
    ("command_injection", [("commandinjection",), ("cmdi",), ("inyeccion", "comando")]),
    ("path_traversal", [("pathtraversal",), ("directorytraversal",),
                         ("traversal", "ruta"), ("lfi",)]),
    ("xxe", [("xxe",), ("xmlexternalentity",), ("entidad", "xml")]),
    ("csrf", [("csrf",), ("crosssite", "requestforgery"), ("falsificacion", "sitios")]),
    ("idor", [("idor",), ("insecuredirectobject",), ("referencia", "directa", "objeto")]),
    ("open_redirect", [("openredirect",), ("redireccion", "abierta")]),
    ("ssti", [("ssti",), ("serverside", "template"), ("inyeccion", "plantilla")]),
    ("crlf", [("crlf",), ("responsesplitting",), ("division", "respuesta")]),
    ("log4shell", [("log4shell",), ("jndi",)]),
    ("ldap_injection", [("ldap",)]),
    ("deserialization", [("deserializ",)]),
    ("missing_header", [("missingheader",), ("missingsecurityheader",),
                         ("cabecera", "faltante"), ("cabecera", "segur")]),
    ("info_disclosure", [("infodisclos",), ("informationdisclos",),
                          ("divulgacion", "informacion")]),
]


def _fold(s: str) -> str:
    """Lowercase, strip accents, keep only [a-z0-9] — an alias-matching key."""
    decomposed = unicodedata.normalize("NFKD", s)
    ascii_only = "".join(c for c in decomposed if not unicodedata.combining(c))
    return "".join(ch for ch in ascii_only.lower() if ch.isalnum())


def canonicalize_type(raw: str | None) -> str:
    """Fold a scanner tester-id / display name / GT "type" onto one bucket.

    Applied identically to both the scanner output and the ground truth, so
    any spelling that reduces to the same alias bucket compares equal — see
    the module docstring's MATCHING RULES section.
    """
    if not raw:
        return ""
    norm = _fold(str(raw))
    for canonical, alias_tuples in _TYPE_ALIASES:
        for substrings in alias_tuples:
            if all(sub in norm for sub in substrings):
                return canonical
    return norm  # unknown type: passthrough, still comparable to itself


def normalize_url(raw_url: str) -> str:
    """scheme://host/path, lowercase scheme+host, no query/fragment/port default."""
    try:
        parts = urlsplit(raw_url)
    except ValueError:
        return raw_url
    scheme = (parts.scheme or "http").lower()
    netloc = (parts.netloc or "").lower()
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return f"{scheme}://{netloc}{path}"


Tuple3 = tuple[str, Any, str]  # (normalized_url, param, canonical_type)


def _finding_key(url: str, param: Any, vuln_type: str) -> Tuple3:
    return (normalize_url(url), param, canonicalize_type(vuln_type))


# --------------------------------------------------------------------------
# Ground truth loading
# --------------------------------------------------------------------------

@dataclass
class GroundTruth:
    positives: set[Tuple3] = field(default_factory=set)
    traps: set[Tuple3] = field(default_factory=set)   # vulnerable: false
    all_keys: dict[Tuple3, bool] = field(default_factory=dict)


def load_ground_truth(path: str | Path) -> GroundTruth:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("--ground-truth must be a JSON array of records")
    gt = GroundTruth()
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict) or "url" not in entry or "type" not in entry:
            raise ValueError(f"ground-truth entry {i} needs at least 'url' and 'type'")
        key = _finding_key(entry["url"], entry.get("param"), entry["type"])
        vulnerable = bool(entry.get("vulnerable", True))
        if key in gt.all_keys and gt.all_keys[key] != vulnerable:
            print(
                f"[WARN] ground-truth entry {i} redefines {key} "
                f"(was vulnerable={gt.all_keys[key]}, now {vulnerable}); last write wins.",
                file=sys.stderr,
            )
        gt.all_keys[key] = vulnerable
        # Keep the two sets mutually exclusive even if an earlier entry
        # redefined this same tuple's vulnerable flag.
        gt.positives.discard(key)
        gt.traps.discard(key)
        (gt.positives if vulnerable else gt.traps).add(key)
    return gt


# --------------------------------------------------------------------------
# Scanner results loading (telemetry JSONL, JSON report, or bare vuln list)
# --------------------------------------------------------------------------

def _iter_jsonl(text: str) -> Iterable[dict]:
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"--results: malformed JSONL at line {lineno}: {exc}") from exc


def load_scanner_findings(path: str | Path) -> set[Tuple3]:
    """Return the deduped set of finding tuples the scanner reported.

    Auto-detects the format from content:
      * a JSON object with a "vulnerabilities" list -> final JSON report
      * a bare JSON array of vulnerability dicts    -> report-style list
      * anything else                                -> telemetry JSONL
        (only rows with a truthy "decision" count as findings)
    """
    text = Path(path).read_text(encoding="utf-8")
    findings: set[Tuple3] = set()

    parsed: Any = None
    whole_json_ok = False
    try:
        parsed = json.loads(text)
        whole_json_ok = True
    except json.JSONDecodeError:
        pass

    if whole_json_ok and isinstance(parsed, dict) and "vulnerabilities" in parsed:
        records: list[dict] = parsed["vulnerabilities"]
        for v in records:
            param = v.get("parameter", v.get("param"))
            findings.add(_finding_key(v.get("url", ""), param, v.get("type", "")))
        return findings

    if whole_json_ok and isinstance(parsed, list):
        for v in parsed:
            if not isinstance(v, dict):
                continue
            if "decision" in v:  # a JSON array of telemetry-shaped rows
                if v.get("decision"):
                    param = v.get("param")
                    findings.add(_finding_key(v.get("url", ""), param,
                                               v.get("tester_id") or v.get("context", "")))
            else:  # bare vulnerability dict
                param = v.get("parameter", v.get("param"))
                findings.add(_finding_key(v.get("url", ""), param, v.get("type", "")))
        return findings

    # Fall back to line-delimited telemetry.
    for row in _iter_jsonl(text):
        if not row.get("decision"):
            continue
        param = row.get("param")
        vuln_type = row.get("tester_id") or row.get("context") or ""
        findings.add(_finding_key(row.get("url", ""), param, vuln_type))
    return findings


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------

@dataclass
class Metrics:
    tp: set[Tuple3]
    fp: set[Tuple3]
    fn: set[Tuple3]
    fp_on_traps: set[Tuple3]
    total_traps: int

    @property
    def precision(self) -> float | None:
        denom = len(self.tp) + len(self.fp)
        return len(self.tp) / denom if denom else None

    @property
    def recall(self) -> float | None:
        denom = len(self.tp) + len(self.fn)
        return len(self.tp) / denom if denom else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if not p or not r or (p + r) == 0:
            return None
        return 2 * (p * r) / (p + r)

    @property
    def fpr(self) -> float | None:
        return len(self.fp_on_traps) / self.total_traps if self.total_traps else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "tp": len(self.tp),
            "fp": len(self.fp),
            "fn": len(self.fn),
            "fp_on_traps": len(self.fp_on_traps),
            "total_traps": self.total_traps,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1,
            "fpr": self.fpr,
        }


def evaluate(findings: set[Tuple3], gt: GroundTruth) -> Metrics:
    tp = findings & gt.positives
    fp = findings - gt.positives
    fn = gt.positives - findings
    fp_on_traps = findings & gt.traps
    return Metrics(tp=tp, fp=fp, fn=fn, fp_on_traps=fp_on_traps, total_traps=len(gt.traps))


# --------------------------------------------------------------------------
# LLM triage-agent audit (--enable-ai-triaging)
# --------------------------------------------------------------------------

def load_ai_triage(path: str | Path) -> dict | None:
    """Return the ``ai_triage`` audit block from a final JSON report, or None.

    Telemetry JSONL and bare vuln lists have no audit trail, so this simply
    returns ``None`` for them (the scan ran without the agent, or the block
    was never emitted).
    """
    try:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(parsed, dict):
        block = parsed.get("ai_triage")
        if isinstance(block, dict) and block.get("enabled"):
            return block
    return None


@dataclass
class AITriageMetrics:
    """How the LLM triage stage changed the raw heuristic verdict set.

    ``fp_suppressed``  — a suppressed candidate that is NOT a ground-truth
                          positive: the agent correctly removed a false
                          positive.
    ``fn_introduced``  — a suppressed candidate that IS a ground-truth
                          positive AND is not otherwise reported: the agent
                          hid a real vulnerability (the cost of the stage).
    """

    triaged: int
    suppressed: set[Tuple3]
    fp_suppressed: set[Tuple3]
    fn_introduced: set[Tuple3]
    backend: str | None = None
    fp_threshold: float | None = None

    @property
    def suppression_precision(self) -> float | None:
        n = len(self.suppressed)
        return len(self.fp_suppressed) / n if n else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "fp_threshold": self.fp_threshold,
            "candidates_triaged": self.triaged,
            "suppressed": len(self.suppressed),
            "fp_suppressed": len(self.fp_suppressed),
            "fn_introduced": len(self.fn_introduced),
            "suppression_precision": self.suppression_precision,
        }


def evaluate_ai_triage(block: dict, reported: set[Tuple3],
                       gt: GroundTruth) -> AITriageMetrics:
    """Grade the agent's suppressions against ground truth.

    ``reported`` is the *final* deduped finding set (post-suppression); a
    suppressed key that another probe re-reported does not count as a lost
    detection.
    """
    decisions = block.get("decisions") or []
    suppressed: set[Tuple3] = set()
    for d in decisions:
        if not d.get("dropped"):
            continue
        suppressed.add(_finding_key(d.get("url", ""),
                                    d.get("parameter") or d.get("param"),
                                    d.get("type", "")))
    fn_introduced = (suppressed & gt.positives) - reported
    fp_suppressed = suppressed - gt.positives
    return AITriageMetrics(
        triaged=int(block.get("total_candidates_triaged", len(decisions))),
        suppressed=suppressed,
        fp_suppressed=fp_suppressed,
        fn_introduced=fn_introduced,
        backend=block.get("backend"),
        fp_threshold=block.get("fp_threshold"),
    )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _fmt(x: float | None) -> str:
    return f"{x:.4f}" if x is not None else "N/A"


def _fmt_key(k: Tuple3) -> str:
    url, param, vtype = k
    return f"url={url} param={param!r} type={vtype}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eval_oracle.py",
        description="Cross-reference scanner output against a ground-truth "
                     "vulnerability list and print detection metrics.",
    )
    parser.add_argument("--results", required=True, metavar="FILE",
                         help="Telemetry JSONL or final JSON report from the scanner.")
    parser.add_argument("--ground-truth", required=True, metavar="FILE.json",
                         help="JSON array of {url, param, type, vulnerable} records.")
    parser.add_argument("--verbose", action="store_true",
                         help="Print every FP/FN tuple, not just the counts.")
    parser.add_argument("--json-out", default=None, metavar="FILE.json",
                         help="Also write the metrics dict as JSON to this path.")
    parser.add_argument("--report", default=None, metavar="FILE.json",
                         help="Final JSON report to read the '--enable-ai-triaging' "
                              "audit trail from (defaults to --results when that is "
                              "itself a JSON report).")
    args = parser.parse_args(argv)

    try:
        gt = load_ground_truth(args.ground_truth)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"[ERROR] --ground-truth: {e}", file=sys.stderr)
        return 2

    try:
        findings = load_scanner_findings(args.results)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"[ERROR] --results: {e}", file=sys.stderr)
        return 2

    metrics = evaluate(findings, gt)

    ai_block = load_ai_triage(args.report or args.results)
    ai_metrics = (evaluate_ai_triage(ai_block, findings, gt)
                  if ai_block is not None else None)

    print("=" * 60)
    print("  eval_oracle.py — Phase 4 evaluation report")
    print("=" * 60)
    print(f"  Scanner findings (deduped):  {len(findings)}")
    print(f"  Ground-truth positives:      {len(gt.positives)}")
    print(f"  Ground-truth explicit traps: {len(gt.traps)}")
    print("-" * 60)
    print(f"  TP  (true positives):        {len(metrics.tp)}")
    print(f"  FP  (false positives):       {len(metrics.fp)}"
          f"   [{len(metrics.fp_on_traps)} on explicit traps]")
    print(f"  FN  (false negatives):       {len(metrics.fn)}")
    print("-" * 60)
    print(f"  Precision:  {_fmt(metrics.precision)}")
    print(f"  Recall:     {_fmt(metrics.recall)}")
    print(f"  F1-score:   {_fmt(metrics.f1)}")
    fpr_note = "" if metrics.total_traps else "  (N/A: no explicit traps in ground truth)"
    print(f"  FPR:        {_fmt(metrics.fpr)}{fpr_note}")
    print("=" * 60)

    if ai_metrics is not None:
        n_sup = len(ai_metrics.suppressed)
        # Recall the heuristic engine alone would have scored (add back the
        # real positives the agent suppressed and no other probe re-found).
        tp_without_ai = metrics.tp | ai_metrics.fn_introduced
        denom = len(gt.positives)
        recall_without_ai = len(tp_without_ai) / denom if denom else None
        print("  LLM triage agent (--enable-ai-triaging)")
        print(f"    backend / fp-threshold:    {ai_metrics.backend} / "
              f"{ai_metrics.fp_threshold}")
        print(f"    candidates triaged:        {ai_metrics.triaged}")
        print(f"    findings suppressed:       {n_sup}")
        print(f"    -> real false positives:   {len(ai_metrics.fp_suppressed)}  "
              f"(suppression precision {_fmt(ai_metrics.suppression_precision)})")
        print(f"    -> false negatives added:  {len(ai_metrics.fn_introduced)}  "
              f"(real vulns the model hid)")
        print(f"    recall  without agent:     {_fmt(recall_without_ai)}")
        print(f"    recall  with agent:        {_fmt(metrics.recall)}")
        print("=" * 60)
        if args.verbose and ai_metrics.fn_introduced:
            print("\n-- False Negatives introduced by the LLM --")
            for k in sorted(ai_metrics.fn_introduced):
                print(f"  {_fmt_key(k)}")

    if args.verbose:
        if metrics.fp:
            print("\n-- False Positives --")
            for k in sorted(metrics.fp):
                marker = " [TRAP]" if k in gt.traps else ""
                print(f"  {_fmt_key(k)}{marker}")
        if metrics.fn:
            print("\n-- False Negatives --")
            for k in sorted(metrics.fn):
                print(f"  {_fmt_key(k)}")

    if args.json_out:
        payload = metrics.as_dict()
        if ai_metrics is not None:
            payload["ai_triage"] = ai_metrics.as_dict()
            tp_without_ai = metrics.tp | ai_metrics.fn_introduced
            payload["ai_triage"]["recall_without_agent"] = (
                len(tp_without_ai) / len(gt.positives) if gt.positives else None
            )
        Path(args.json_out).write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n[*] Metrics written to {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
