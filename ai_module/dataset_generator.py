#!/usr/bin/env python3
"""
dataset_generator.py — Telemetry JSONL  ->  curated LLM fine-tuning dataset.

The async scanner, when run with ``--telemetry-dir PATH``, writes one
newline-delimited JSON row per payload probe (see
``web_security_scanner/core/telemetry_async.py``). Our testbed sweep leaves
those files at ``testbed/results/<run>/telemetry_*.jsonl``. OWASP Benchmark
runs add response bodies / evidence snippets. This script folds the raw probe
rows into supervised samples the QLoRA pipeline consumes:

  * ``triage``   — given a candidate finding + evidence, label it TP / FP.
  * ``payload``  — given an endpoint/param probe history, propose the next payload.

Curation pipeline
-----------------
1. **Ingest + enrich** — decode every ``*.jsonl`` row, join to the ground-truth
   oracle (OWASP Benchmark CSV and/or a ``--ground-truth`` sink list) to label
   TP / FP with surgical precision.
2. **Clean** (``classify_noise`` / ``normalize_body`` / ``dedup``):
     - drop malformed rows, timeouts, transport errors not caused by the
       scanner, and truncated/empty responses;
     - normalise evidence: strip control/binary bytes, collapse whitespace,
       and truncate long bodies to the first ~2 KB *or* the reflection windows
       around the injected payload / canary markers;
     - de-duplicate: identical ``(payload, response, class, verdict)`` samples
       repeated across iterations collapse to one.
3. **Structure** — emit Alpaca / ShareGPT / ChatML, one task per file.
4. **Balance + split** — optional 1:1 (``--balance-ratio``) TP/FP downsampling,
   then a stratified train/val split (``--split 0.9``) so val keeps both
   classes.

Ground truth
------------
  * ``--benchmark-csv testbed/.cache/benchmark/expectedresults-1.2.csv``
    joined by the ``BenchmarkTestNNNNN`` id in the request URL path.
  * ``--ground-truth file.json`` — ``{"vulnerabilities": [{"url","param","type"}]}``
    or a bare list; joined on ``(url, param, vuln_class)``.
With no oracle the script falls back to *weak labels* from the scanner's own
``decision`` / ``confidence_final`` columns (``--weak-labels`` implied).

Output formats
--------------
- ``alpaca``   : ``{"instruction","input","output","meta"}`` per line
- ``sharegpt`` : ``{"conversations": [{"from","value"}, ...], "meta": ...}``
- ``chatml``   : ``{"messages": [{"role","content"}, ...], "meta": ...}``

Usage
-----
    python -m ai_module.dataset_generator \
        --telemetry testbed/results \
        --benchmark-csv testbed/.cache/benchmark/expectedresults-1.2.csv \
        --task triage --format alpaca --balance \
        --out data/triage.jsonl --split 0.9 --report data/triage.clean.json
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
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
# Data cleaning
# --------------------------------------------------------------------------- #

_MAX_BODY_BYTES = 2048
_REFLECT_WINDOW = 240          # chars kept either side of a reflection hit
_MAX_PLAUSIBLE_ELAPSED = 180.0  # s — anything slower is a hung socket, not signal

# Substrings that mark a transport failure the *scanner* caused, not the target.
_NETWORK_ERROR_TOKENS = (
    "timeout", "timed out", "connection reset", "connection refused",
    "connection aborted", "connection closed", "server disconnected",
    "clientconnectorerror", "serverdisconnectederror", "econnreset",
    "cannot connect to host", "name or service not known",
    "temporary failure in name resolution", "ssl", "certificate verify failed",
    "too many redirects", "client error", "event loop is closed",
)

# Keys a body / evidence snippet may arrive under (benchmark & legacy rows).
_BODY_KEYS = (
    "response_body", "response_text", "body", "response", "evidence",
    "evidence_snippet", "match_context", "snippet", "reflection_context",
)

# Canary / marker tokens our testers embed so we can find the reflection window.
_MARKER_RE = re.compile(
    r"(?:wss|zap|scan|inj|xss|sqli|cmd|ptrav|canary|probe|marker)[-_]?[0-9a-fA-F]{4,}"
)


def _f(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _extract_body(row: dict[str, Any]) -> tuple[str, bool]:
    """Return ``(raw_body, truncated_flag)`` — ``("", …)`` when no body is present."""
    truncated = bool(row.get("truncated") or row.get("body_truncated"))
    for key in _BODY_KEYS:
        val = row.get(key)
        if isinstance(val, str) and val:
            return val, truncated
        if isinstance(val, dict):
            inner = val.get("snippet") or val.get("text") or val.get("body")
            if isinstance(inner, str) and inner:
                return inner, truncated
    return "", truncated


def _has_body(row: dict[str, Any]) -> bool:
    return bool(_extract_body(row)[0])


def classify_noise(row: dict[str, Any]) -> str | None:
    """Return a short reason string if the row is unusable for training, else ``None``.

    Native telemetry rows legitimately omit ``status_code`` / body, so we only
    reject on *explicit* failure signals — never on absence.
    """
    if not row.get("url"):
        return "missing_url"

    err = str(
        row.get("error") or row.get("exception") or row.get("err") or ""
    ).lower()
    if err:
        if any(tok in err for tok in _NETWORK_ERROR_TOKENS):
            return "network_error"
        return "request_error"
    if row.get("timed_out") or row.get("timeout_hit") or row.get("is_timeout"):
        return "timeout"

    if "status_code" in row or "status" in row:
        status = row.get("status_code", row.get("status"))
        try:
            code = int(status)
        except (TypeError, ValueError):
            code = -1
        if code == 0:
            return "no_response"
        if code >= 500 and not row.get("decision") and not _has_body(row):
            return "server_error"

    raw, truncated = _extract_body(row)
    if truncated and len(raw.strip()) < 16:
        return "truncated_empty"
    if ("status_code" in row or "status" in row) and not raw and not row.get("decision"):
        # a response we recorded but that carried no usable payload
        if row.get("content_length") == 0 or row.get("empty_response"):
            return "empty_response"

    if _f(row.get("elapsed_time")) > _MAX_PLAUSIBLE_ELAPSED:
        return "implausible_latency"
    return None


def _looks_binary(text: str) -> bool:
    sample = text[:4096]
    if not sample:
        return False
    ok = sum(1 for c in sample if c.isprintable() or c in "\r\n\t ")
    return ok / len(sample) < 0.75


def normalize_body(
    raw: str, payload: str, *, max_bytes: int = _MAX_BODY_BYTES, window: int = _REFLECT_WINDOW
) -> str:
    """Clean and shrink an HTTP body for the model context.

    - drops NULs and control noise, collapses whitespace runs;
    - if the body already fits ``max_bytes``, returns it verbatim (trimmed);
    - otherwise keeps only the windows around each payload / canary-marker
      occurrence, joined by ``---`` and prefixed/suffixed with ``…``.
    """
    text = raw.replace("\x00", "")
    if _looks_binary(text):
        return "<non-text / binary response body omitted>"
    text = re.sub(r"[ \t\f\v]{3,}", "  ", text)
    text = re.sub(r"(?:\r?\n){3,}", "\n\n", text).strip()

    if len(text.encode("utf-8", "ignore")) <= max_bytes:
        return text

    needles: list[str] = []
    if payload and len(payload) >= 3:
        needles.append(payload)
    needles.extend(dict.fromkeys(_MARKER_RE.findall(text)))

    spans: list[tuple[int, int]] = []
    for needle in dict.fromkeys(needles):
        start = text.find(needle)
        while start != -1 and len(spans) < 8:
            spans.append((max(0, start - window), min(len(text), start + len(needle) + window)))
            start = text.find(needle, start + 1)

    if not spans:
        return text[:max_bytes].rstrip() + "\n…[truncated]"

    spans.sort()
    merged = [spans[0]]
    for lo, hi in spans[1:]:
        if lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))

    chunks = [
        ("…" if lo > 0 else "") + text[lo:hi] + ("…" if hi < len(text) else "")
        for lo, hi in merged
    ]
    return "\n---\n".join(chunks)[: max_bytes * 2].rstrip()


def clean_rows(
    rows: list[dict[str, Any]], *, drop_noise: bool = True
) -> tuple[list[dict[str, Any]], Counter[str]]:
    """Filter raw telemetry rows; return ``(kept_rows, reason_counts)``."""
    stats: Counter[str] = Counter()
    kept: list[dict[str, Any]] = []
    for row in rows:
        if not _is_probe_row(row):
            stats["skipped:not_a_probe"] += 1
            continue
        reason = classify_noise(row)
        if reason:
            stats[f"noise:{reason}"] += 1
            if drop_noise:
                continue
        kept.append(row)
    stats["kept"] = len(kept)
    return kept, stats


def dedup(samples: list["Sample"]) -> tuple[list["Sample"], int]:
    """Collapse samples that share a ``meta['_dedup']`` signature (or a rendered
    ``user``+``assistant`` hash when no explicit key was set)."""
    seen: set[str] = set()
    out: list[Sample] = []
    for s in samples:
        key = s.meta.get("_dedup") or hashlib.sha1(
            (s.user + "\x00" + s.assistant).encode("utf-8")
        ).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out, len(samples) - len(out)


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

    def _public_meta(self) -> dict[str, Any]:
        return {k: v for k, v in self.meta.items() if not k.startswith("_")}

    def to_chatml(self) -> dict[str, Any]:
        return {
            "messages": [
                {"role": "system", "content": self.system},
                {"role": "user", "content": self.user},
                {"role": "assistant", "content": self.assistant},
            ],
            "meta": self._public_meta(),
        }

    def to_alpaca(self) -> dict[str, Any]:
        return {
            "instruction": self.system,
            "input": self.user,
            "output": self.assistant,
            "meta": self._public_meta(),
        }

    def to_sharegpt(self) -> dict[str, Any]:
        return {
            "conversations": [
                {"from": "system", "value": self.system},
                {"from": "human", "value": self.user},
                {"from": "gpt", "value": self.assistant},
            ],
            "meta": self._public_meta(),
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


def _reflection_evidence(row: dict[str, Any], payload: str) -> tuple[dict[str, Any], str]:
    """Body-derived evidence for triage, normalised for the model context."""
    raw, truncated = _extract_body(row)
    if not raw:
        return {}, ""
    excerpt = normalize_body(raw, payload)
    reflected = bool(payload) and len(payload) >= 3 and payload in raw
    ev: dict[str, Any] = {
        "response_excerpt": excerpt,
        "payload_reflected_verbatim": reflected,
        "response_truncated": truncated,
    }
    note = ""
    if reflected:
        note = (
            " The injected string appears verbatim in the response body excerpt; "
            "assess whether the surrounding context makes it executable."
        )
    return ev, note


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
        body_ev, body_note = _reflection_evidence(row, payload)
        evidence.update(body_ev)

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
                "benign reflection or latency noise." + body_note
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
        # No explicit _dedup key: dedup() hashes the fully-rendered
        # (user, assistant) pair, so only *byte-identical* samples — same
        # endpoint, payload, evidence and verdict — collapse. Two probes of
        # different BenchmarkTest endpoints that happen to share a payload stay
        # distinct (their URL and latency evidence differ).
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
    traj: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
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
            vclass = next(iter(_TESTER_TO_CATEGORY.get(tester_id, {"unknown"})))
            user = (
                f"Target: {base_url}  param={param}\n"
                f"Suspected class: {vclass}\n"
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
            yield Sample(
                system, user, assistant,
                meta={"url": base_url, "param": param, "label": vclass},
            )


BUILDERS = {
    "triage": build_triage_samples,
    "payload": build_payload_samples,
}


# --------------------------------------------------------------------------- #
# Balancing + split
# --------------------------------------------------------------------------- #


def balance_classes(
    samples: list[Sample], ratio: float, seed: int
) -> tuple[list[Sample], dict[str, int]]:
    """Downsample majority classes so ``len(class) <= ratio * len(smallest)``."""
    rng = random.Random(seed)
    by_label: dict[str, list[Sample]] = defaultdict(list)
    for s in samples:
        by_label[s.meta.get("label", "?")].append(s)
    before = {k: len(v) for k, v in by_label.items()}
    if len(by_label) < 2:
        return samples, before
    smallest = min(len(v) for v in by_label.values())
    cap = max(smallest, int(round(smallest * ratio)))
    out: list[Sample] = []
    for grp in by_label.values():
        out.extend(rng.sample(grp, cap) if len(grp) > cap else grp)
    rng.shuffle(out)
    return out, before


def _to_record(fmt: str):
    return {
        "chatml": lambda s: s.to_chatml(),
        "alpaca": lambda s: s.to_alpaca(),
        "sharegpt": lambda s: s.to_sharegpt(),
    }[fmt]


def _dump(path: Path, part: list[Sample], to_rec) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for s in part:
            fh.write(json.dumps(to_rec(s), ensure_ascii=False) + "\n")
    print(f"wrote {len(part):>6} samples -> {path}")


def write_split(
    samples: list[Sample], out: Path, fmt: str, split: float, seed: int
) -> dict[str, int]:
    """Stratified train/val split (by ``meta['label']``); returns piece sizes."""
    rng = random.Random(seed)
    out.parent.mkdir(parents=True, exist_ok=True)
    to_rec = _to_record(fmt)

    if split >= 1.0:
        rng.shuffle(samples)
        _dump(out, samples, to_rec)
        return {"single": len(samples)}

    buckets: dict[str, list[Sample]] = defaultdict(list)
    for s in samples:
        buckets[s.meta.get("label", "_")].append(s)

    train: list[Sample] = []
    val: list[Sample] = []
    for _, grp in sorted(buckets.items()):
        rng.shuffle(grp)
        cut = round(len(grp) * split)
        train.extend(grp[:cut])
        val.extend(grp[cut:])
    rng.shuffle(train)
    rng.shuffle(val)

    _dump(out.with_name(out.stem + ".train" + out.suffix), train, to_rec)
    _dump(out.with_name(out.stem + ".val" + out.suffix), val, to_rec)
    return {"train": len(train), "val": len(val)}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _run_task(
    task: str,
    rows: list[dict[str, Any]],
    oracle: Oracle,
    args: argparse.Namespace,
    weak: bool,
) -> dict[str, Any]:
    report: dict[str, Any] = {"task": task}
    samples = list(BUILDERS[task](rows, oracle, weak=weak))
    report["samples_built"] = len(samples)

    if not args.no_dedup:
        samples, removed = dedup(samples)
        report["deduped_removed"] = removed
    report["after_dedup"] = len(samples)

    if args.balance and task == "triage":
        samples, before = balance_classes(samples, args.balance_ratio, args.seed)
        report["class_counts_before_balance"] = before
        print(f"[{task}] balanced (ratio {args.balance_ratio}) -> {len(samples)}", file=sys.stderr)
    report["class_counts"] = dict(Counter(s.meta.get("label", "?") for s in samples))

    if args.limit:
        samples = samples[: args.limit]

    if not samples:
        print(f"[{task}] no samples produced", file=sys.stderr)
        report["error"] = "no_samples"
        return report

    out = args.out
    if len(args.task_list) > 1:
        out = out.with_name(out.stem + f".{task}" + out.suffix)
    report["split"] = write_split(samples, out, args.format, args.split, args.seed)
    report["out"] = str(out)
    return report


def main(argv: list[str] | None = None) -> int:
    global _MAX_BODY_BYTES
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--telemetry", type=Path, action="append", required=True,
                    metavar="PATH", help="JSONL file or directory (repeatable)")
    ap.add_argument("--benchmark-csv", type=Path, default=None,
                    help="OWASP Benchmark expectedresults-*.csv oracle")
    ap.add_argument("--ground-truth", type=Path, default=None,
                    help="JSON list/obj of known vulnerable sinks")
    ap.add_argument("--task", choices=[*sorted(BUILDERS), "both"], default="triage")
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
                    help="downsample the majority class toward a 1:1 TP/FP ratio (triage)")
    ap.add_argument("--balance-ratio", type=float, default=1.0,
                    help="max majority:minority ratio kept by --balance (default 1.0)")
    ap.add_argument("--keep-noise", action="store_true",
                    help="keep malformed / timeout / truncated rows instead of dropping them")
    ap.add_argument("--no-dedup", action="store_true",
                    help="do not collapse identical (payload, response, verdict) samples")
    ap.add_argument("--max-body-bytes", type=int, default=_MAX_BODY_BYTES,
                    help="response-body truncation budget for evidence (default 2048)")
    ap.add_argument("--report", type=Path, default=None,
                    help="write a JSON cleaning/curation manifest to this path")
    args = ap.parse_args(argv)

    _MAX_BODY_BYTES = max(256, args.max_body_bytes)

    raw_rows = list(iter_jsonl(args.telemetry))
    print(f"loaded {len(raw_rows)} telemetry rows", file=sys.stderr)

    rows, clean_stats = clean_rows(raw_rows, drop_noise=not args.keep_noise)
    print(f"clean: kept {len(rows)}/{len(raw_rows)} rows "
          f"({dict(clean_stats)})", file=sys.stderr)

    oracle = load_oracle(args.benchmark_csv, args.ground_truth)
    weak = args.weak_labels or oracle.empty
    if oracle.empty and not args.weak_labels:
        print("no oracle supplied — falling back to weak labels", file=sys.stderr)

    args.task_list = ["triage", "payload"] if args.task == "both" else [args.task]

    manifest: dict[str, Any] = {
        "input_rows": len(raw_rows),
        "cleaned_rows": len(rows),
        "clean_stats": dict(clean_stats),
        "oracle": {
            "benchmark_entries": len(oracle.benchmark),
            "ground_truth_sinks": len(oracle.index),
            "weak_labels": weak,
        },
        "params": {
            "format": args.format, "split": args.split, "seed": args.seed,
            "balance": args.balance, "balance_ratio": args.balance_ratio,
            "dedup": not args.no_dedup, "drop_noise": not args.keep_noise,
            "max_body_bytes": _MAX_BODY_BYTES,
        },
        "tasks": [],
    }

    rc = 0
    for task in args.task_list:
        result = _run_task(task, rows, oracle, args, weak)
        manifest["tasks"].append(result)
        if result.get("error"):
            rc = 1
        else:
            cc = result["class_counts"]
            print(f"[{task}] {sum(cc.values())} samples {cc}", file=sys.stderr)

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), "utf-8")
        print(f"manifest -> {args.report}", file=sys.stderr)

    return rc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
