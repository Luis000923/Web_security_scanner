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
     - **anonymise the endpoint** (``sanitize_endpoint`` / ``generic_param``):
       the OWASP Benchmark encodes the vuln class *and* verdict in the URL
       path, so the model input keeps only ``/app/target_endpoint/`` — no
       shortcut from the URL to the label;
     - **filter junk payloads** (``is_junk_payload``): drop structureless blobs
       >120 chars and ultra-short <15-char strings with no injection tokens;
     - de-duplicate on the *observable* key (anonymised prompt + bucketed
       latency): rows the model cannot tell apart collapse to one, so
       millisecond jitter can never leak a near-identical row across the split.
3. **Structure** — emit Alpaca / ShareGPT / ChatML, one task per file. Triage
   ``output`` is built *dynamically* from the evidence (latency delta vs. run
   baseline, verbatim reflection, interpreter errors, a-priori/scanner
   confidence); genuinely non-discriminating probes are labelled ``UNCERTAIN``
   rather than forced onto a binary, and endpoints whose ground truth conflicts
   under an identical evidence profile are reconciled to ``UNCERTAIN``.
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

# NOTE: payload-sample confirm signals are now derived per *payload family*
# (see ``_FAMILY_CONFIRM``), not per tester class.


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
# Anonymisation — keep endpoint identity out of the model's reach
# --------------------------------------------------------------------------- #

_GENERIC_ENDPOINT = "/app/target_endpoint/"
_BENCH_PARAM_RE = re.compile(
    r"^(?:benchmarktest\d+|param\d*|p\d*|q|input|foo|bar|arg\d*)$", re.I
)


def sanitize_endpoint(url: str) -> str:
    """Collapse a probe URL to a class-free placeholder path.

    The OWASP Benchmark encodes the vulnerability *class* and often the verdict
    in the path (``/benchmark/xss-03/BenchmarkTest01234``). Leaving that in the
    model input lets it shortcut the whole triage/synthesis task straight from
    the URL, so we drop scheme, host, query string and every path segment down
    to one opaque endpoint token. The real URL is retained only in private
    (``_``-prefixed) metadata for traceability.
    """
    return _GENERIC_ENDPOINT


def generic_param(param: str) -> str:
    """Replace oracle-correlated parameter names with a neutral token."""
    p = (param or "").strip()
    if not p or _BENCH_PARAM_RE.match(p):
        return "p"
    return p


# --------------------------------------------------------------------------- #
# Payload sanity filtering
# --------------------------------------------------------------------------- #

_INJECTION_MARKERS = (
    "<", ">", "'", '"', ";", "--", "/*", "*/", "${", "{{", "}}", "|", "&&",
    "../", "..\\", "%00", "%2e", "\\x", "`", "$(", "()", "=", "\n", "\r",
    "select", "union", "sleep", "benchmark(", "waitfor", "pg_sleep", "script",
    "alert(", "confirm(", "prompt(", "onerror", "onload", "svg", "img",
    "javascript:", "/etc/", "cmd", "nslookup", "curl ", "http://", "https://",
)


def _has_injection_marker(payload: str) -> bool:
    low = payload.lower()
    return any(m in low for m in _INJECTION_MARKERS)


def is_junk_payload(payload: str) -> bool:
    """True for strings that carry no learnable injection semantics."""
    s = (payload or "").strip()
    if not s:
        return True
    if len(s) < 15 and not _has_injection_marker(s):
        return True
    if len(s) > 120 and not _has_injection_marker(s):
        return True
    if len(s) > 120:
        punct = sum(1 for c in s if not c.isalnum() and not c.isspace())
        if punct / len(s) < 0.05:          # long, near-structureless blob
            return True
    return False


_PAYLOAD_FAMILY_KEYS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sqli-time", ("sleep(", "benchmark(", "waitfor", "pg_sleep", "dbms_lock")),
    ("sqli-error-union", ("union select", "union all select", "extractvalue",
                           "updatexml", "convert(int", "cast(")),
    ("sqli-boolean", (" or 1=1", "' or '", "\" or \"", " and 1=", "'='", "')-- ")),
    ("xss", ("<script", "<svg", "<img", "<iframe", "onerror", "onload",
              "javascript:", "alert(", "confirm(", "prompt(", "<body")),
    ("path-traversal", ("../", "..\\", "/etc/passwd", "%2e%2e", "c:\\", "file://")),
    ("cmd-injection", (";id", "|id", "&&", "`id`", "$(", "nslookup", "curl ",
                        "|nslookup", ";sleep")),
    ("ssrf", ("http://169.254", "http://127.0.0.1", "http://localhost",
               "gopher://", "dict://", "@")),
    ("open-redirect", ("//evil", "https://evil", "\\\\evil", "///")),
)


def payload_family(payload: str, tester_id: str = "") -> str:
    low = (payload or "").lower()
    for name, keys in _PAYLOAD_FAMILY_KEYS:
        if any(k in low for k in keys):
            return name
    cats = _TESTER_TO_CATEGORY.get(tester_id)
    return next(iter(cats)) if cats else "generic"


_FAMILY_CONFIRM: dict[str, str] = {
    "sqli-time": ("a repeatable, payload-correlated delay matching the injected "
                  "sleep interval, with no delay for a 0-second control"),
    "sqli-error-union": ("a database error disclosing schema/version, or extra "
                          "UNION-sourced columns/rows appearing in the response"),
    "sqli-boolean": ("a stable content differential between the true (1=1) and "
                      "false (1=2) variants of the predicate"),
    "xss": ("the unique marker rendered unescaped in an executable HTML/JS "
             "context — the script actually runs in a browser"),
    "path-traversal": ("the verbatim contents of a known out-of-webroot file in "
                        "the response body"),
    "cmd-injection": ("an out-of-band DNS/HTTP callback, or a bounded "
                       "command-correlated response delay"),
    "ssrf": "an out-of-band request from the target to a collaborator host",
    "open-redirect": "a 3xx Location header pointing at the attacker-controlled host",
    "generic": "an unambiguous, payload-correlated response differential",
}

_FAMILY_LEAD: dict[str, str] = {
    "sqli-time": "Switches to a time-based blind oracle",
    "sqli-error-union": "Forces an error-based / UNION disclosure",
    "sqli-boolean": "Tests a boolean predicate differential",
    "xss": "Breaks out of the current markup context",
    "path-traversal": "Walks the path toward an out-of-webroot file",
    "cmd-injection": "Chains an OS command with an out-of-band signal",
    "ssrf": "Points the server-side fetch at an internal address",
    "open-redirect": "Supplies an external absolute URL to the redirect sink",
    "generic": "Escalates probe specificity",
}


def payload_rationale(
    family: str, prev_payload: str, prev_ctx: str, prev_latency_ms: float,
    prev_decision: bool,
) -> str:
    lead = _FAMILY_LEAD.get(family, _FAMILY_LEAD["generic"])
    prior = (
        f"the previous vector {prev_payload!r} "
        f"({prev_ctx or 'unknown'} context, {prev_latency_ms:.1f} ms, "
        f"scanner_decision={prev_decision})"
    )
    return f"{lead} after {prior} produced no decisive signal."


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


_DB_ERROR_RE = re.compile(
    r"(SQL syntax|ORA-\d{5}|SQLSTATE|ODBC|mysql_fetch|pg_query|psql:|"
    r"Unclosed quotation mark|quoted string not properly terminated|"
    r"System\.Data\.|Microsoft OLE DB|java\.sql\.|javax\.servlet|"
    r"org\.hibernate|Warning: |Fatal error|Traceback \(most recent call last\)|"
    r"XPathException|LDAP: error code|supplied argument is not a valid)",
    re.I,
)
_TIME_CONTEXT_HINTS = ("time_based", "time-based", "time_blind", "timeblind", "timing")

_NEXT_PROOF: dict[str, str] = {
    "xss": "Load the reflected marker in a browser context to confirm script execution.",
    "sqli": "Send paired boolean payloads (1=1 vs 1=2) or a bounded time delay to confirm the oracle.",
    "cmdi": "Confirm with a bounded out-of-band DNS/HTTP callback rather than timing alone.",
    "pathtraver": "Fetch a known out-of-webroot file and diff it against a control path.",
    "ssrf": "Point the fetch at a collaborator host and watch for the inbound request.",
}


def _assess_evidence(evidence: dict[str, Any], *, context: str) -> dict[str, Any]:
    """Derive discriminating signals from the raw evidence, dynamically."""
    delta = _f(evidence.get("latency_delta_ms"))
    base = abs(_f(evidence.get("run_baseline_latency_ms")))
    noise = max(40.0, 0.75 * base)
    excerpt = evidence.get("response_excerpt") or ""
    reflected = bool(evidence.get("payload_reflected_verbatim"))
    has_error = bool(excerpt) and bool(_DB_ERROR_RE.search(excerpt))
    ctx = (context or "").lower()
    time_class = "time" in ctx or any(h in ctx for h in _TIME_CONTEXT_HINTS)
    time_hit = time_class and delta >= max(750.0, noise * 5)
    apriori = str(evidence.get("apriori_confidence") or "").upper()

    signals: list[str] = []
    if reflected:
        signals.append("the payload is reflected verbatim in the response body")
    if has_error:
        signals.append("the response leaks an interpreter/database error string")
    if time_hit:
        signals.append(
            f"a payload-correlated delay of ~{delta:.0f} ms far exceeds the "
            f"~{base:.0f} ms run baseline"
        )

    within_noise = abs(delta) <= noise
    if within_noise:
        latency_note = (
            f"the latency delta ({delta:+.1f} ms) sits inside run jitter "
            f"(~±{noise:.0f} ms)"
        )
    else:
        latency_note = (
            f"the latency delta is {delta:+.1f} ms against a ~{base:.0f} ms "
            "baseline, not a repeatable time oracle by itself"
        )

    if delta <= -noise:
        lat_bucket = "faster"
    elif within_noise:
        lat_bucket = "noise"
    elif delta < 750:
        lat_bucket = "slower"
    else:
        lat_bucket = "much_slower"

    return {
        "signals": signals,
        "discriminating": bool(signals),
        "within_noise": within_noise,
        "latency_note": latency_note,
        "lat_bucket": lat_bucket,
        "apriori": apriori,
        "reflected": reflected,
        "has_error": has_error,
        "scanner_conf": str(evidence.get("scanner_confidence") or "").upper(),
        "scanner_decision": bool(evidence.get("scanner_decision")),
        "context": str(evidence.get("injection_context") or ""),
    }


def _compose_reasoning(verdict: str, a: dict[str, Any], vclass: str) -> str:
    sig = a["signals"]
    if verdict == "TRUE_POSITIVE":
        if sig:
            body = "; ".join(sig)
            if len(sig) > 1 or not a["within_noise"]:
                return (
                    f"Evidence supports {vclass} injection: {body}. Separately, "
                    f"{a['latency_note']}, but the reflection/error signal is decisive."
                )
            return f"Evidence supports {vclass} injection: {body}."
        ctx = a["context"] or "the inferred"
        return (
            f"The scanner flagged this probe (a-priori {a['apriori'].lower() or 'unset'}, "
            f"final {a['scanner_conf'].lower() or 'unset'}) and the {ctx} context is "
            f"consistent with {vclass} injection; {a['latency_note']}, so impact still "
            "needs an explicit oracle to demonstrate."
        )
    if verdict == "FALSE_POSITIVE":
        tail = (
            "" if a["apriori"] in {"", "LOW"} else
            f" The a-priori {a['apriori'].lower()} rating is not corroborated by "
            "the response."
        )
        return (
            f"Nothing in the evidence discriminates {vclass} injection from benign "
            f"behaviour: no verbatim reflection, no interpreter errors, and "
            f"{a['latency_note']}.{tail}"
        )
    # UNCERTAIN
    missing = []
    if not a["reflected"]:
        missing.append("the payload is not reflected")
    if not a["has_error"]:
        missing.append("no interpreter error is present")
    return (
        f"The evidence does not settle this {vclass} candidate: {a['latency_note']}"
        + ((", " + ", ".join(missing)) if missing else "")
        + f". A-priori confidence was {a['apriori'].lower() or 'unset'}."
    )


def build_triage_samples(
    rows: list[dict[str, Any]], oracle: Oracle, *, weak: bool
) -> Iterator[Sample]:
    system = load_prompt("triage_system")
    baselines = _run_baselines(rows)
    # Reconcile by *observable* key (the anonymised prompt, latency bucketed):
    # rows whose model-visible evidence is identical must not disagree on the
    # label and must not straddle the train/val split. When distinct real sinks
    # produce byte-identical evidence but conflicting ground truth, the honest
    # label is UNCERTAIN — the evidence genuinely does not discriminate.
    groups: dict[str, dict[str, Any]] = {}
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
        body_ev, _body_note = _reflection_evidence(row, payload)
        evidence.update(body_ev)

        weak_label = label_src.startswith("weak")
        a = _assess_evidence(evidence, context=row.get("context") or "")
        strong_apriori = a["apriori"] in {"HIGH", "CONFIRMED"}
        # "Grey zone": no discriminating body signal, latency inside jitter, and
        # neither the a-priori nor the scanner's final confidence is high. These
        # probes genuinely do not carry enough evidence to force a binary label.
        ambiguous = (
            not a["discriminating"]
            and a["within_noise"]
            and not strong_apriori
            and a["scanner_conf"] not in {"HIGH", "CONFIRMED"}
        )

        strong_final = a["scanner_conf"] in {"HIGH", "CONFIRMED"}
        if weak_label:
            if a["discriminating"] or (strong_apriori and not a["within_noise"]):
                verdict = "TRUE_POSITIVE"
            elif ambiguous:
                verdict = "UNCERTAIN"
            else:
                verdict = "FALSE_POSITIVE"
        elif not truth:
            # Oracle: no vulnerable sink of this class. With no corroborating
            # body signal the benign explanation is the confident call — this is
            # exactly the FALSE_POSITIVE the operator needs suppressed.
            verdict = "FALSE_POSITIVE"
        elif a["discriminating"] or strong_final or strong_apriori:
            verdict = "TRUE_POSITIVE"
        else:
            # Oracle-confirmed sink, but this probe leaned on a mid-confidence
            # heuristic with latency inside jitter and no body — it did not
            # itself demonstrate the bug.
            verdict = "UNCERTAIN"

        endpoint = sanitize_endpoint(url)
        gparam = generic_param(param)
        user = (
            f"Endpoint: {endpoint}\n"
            f"Parameter: {gparam}\n"
            f"Suspected class: {vclass}\n"
            f"Payload sent: {payload!r}\n"
            f"Observed evidence: {json.dumps(evidence, ensure_ascii=False)}\n\n"
            "Classify this candidate as TRUE_POSITIVE, FALSE_POSITIVE or UNCERTAIN "
            "and justify from the evidence."
        )

        # Observable key: everything the model can actually see, latency bucketed.
        obs_key = "|".join(
            [
                "triage", vclass, payload,
                str(a["reflected"]), str(a["has_error"]), a["lat_bucket"],
                str(a["apriori"]), a["scanner_conf"],
                str(evidence.get("injection_context") or ""),
                str(evidence.get("vector") or ""),
            ]
        )
        g = groups.get(obs_key)
        if g is None:
            groups[obs_key] = {
                "user": user, "vclass": vclass, "a": a, "weak": weak_label,
                "verdicts": Counter([verdict]), "testers": {tester_id},
                "urls": {url}, "label_src": label_src,
            }
        else:
            g["verdicts"][verdict] += 1
            g["testers"].add(tester_id)
            g["urls"].add(url)

    for obs_key, g in groups.items():
        a = g["a"]
        vclass = g["vclass"]
        votes = g["verdicts"]
        conflicted = len(votes) > 1
        verdict = "UNCERTAIN" if conflicted else next(iter(votes))

        if conflicted:
            reasoning = (
                f"Ground truth is split across the {len(g['urls'])} sinks that produced "
                f"this exact evidence profile, so the model-visible signals cannot "
                f"discriminate a real {vclass} bug here: {a['latency_note']}, "
                f"{'a reflected payload' if a['reflected'] else 'no verbatim reflection'}, "
                f"{'an interpreter error' if a['has_error'] else 'no interpreter error'}."
            )
        else:
            reasoning = _compose_reasoning(verdict, a, vclass)

        if verdict == "TRUE_POSITIVE":
            confidence = 0.9 if len(a["signals"]) >= 2 else (0.8 if a["signals"] else 0.62)
            next_step = _NEXT_PROOF.get(
                vclass, "Replay with a differentiating oracle payload to demonstrate impact."
            )
        elif verdict == "UNCERTAIN":
            confidence = 0.5
            next_step = (
                "Re-probe with a repeatable oracle (paired true/false or timed "
                "payloads) and capture the response body to separate reflection "
                "from execution."
            )
        else:
            confidence = 0.85 if a["apriori"] in {"", "LOW"} else 0.7
            next_step = "Suppress the finding and lower this endpoint's priority."
        if g["weak"]:
            confidence = round(confidence * 0.8, 2)

        assistant = json.dumps(
            {
                "verdict": verdict,
                "confidence": confidence,
                "reasoning": reasoning,
                "next_step": next_step,
            },
            ensure_ascii=False,
        )
        # Dedup + split key is the observable key alone: identical model inputs
        # can never straddle train/val, and jitter-only repeats collapse.
        yield Sample(
            system, g["user"], assistant,
            meta={"endpoint": _GENERIC_ENDPOINT, "label": verdict,
                  "label_source": g["label_src"], "tester": sorted(g["testers"])[0],
                  "_url": sorted(g["urls"])[0], "conflicted": conflicted,
                  "_dedup": hashlib.sha1(obs_key.encode("utf-8")).hexdigest()},
        )


def build_payload_samples(
    rows: list[dict[str, Any]], oracle: Oracle, *, weak: bool
) -> Iterator[Sample]:
    system = load_prompt("payload_system")
    baselines = _run_baselines(rows)
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
            prev_payload = prev.get("payload") or _payload_from_url(prev.get("url", ""), param)
            if not nxt_payload or not prev_payload:
                continue
            if nxt_payload == prev_payload:
                continue
            if is_junk_payload(nxt_payload) or is_junk_payload(prev_payload):
                continue
            tester_id = nxt.get("tester_id", "")
            prev_elapsed = float(prev.get("elapsed_time", 0.0) or 0.0)
            prev_decision = bool(prev.get("decision"))
            prev_ctx = prev.get("context") or ""
            vclass = next(iter(_TESTER_TO_CATEGORY.get(tester_id, {"unknown"})))
            family = payload_family(nxt_payload, tester_id)
            endpoint = sanitize_endpoint(base_url)
            gparam = generic_param(param)
            prev_lat_ms = round(prev_elapsed * 1000, 1)
            prev_base = baselines.get((prev.get("run_id", ""), tester_id), 0.0) * 1000
            lat_state = "at baseline" if abs(prev_lat_ms - prev_base) <= max(40.0, 0.75 * abs(prev_base)) else "elevated"
            user = (
                f"Target: {endpoint}  param={gparam}\n"
                f"Suspected class: {vclass}\n"
                f"Last payload: {prev_payload!r}\n"
                f"  -> scanner_decision={prev_decision} "
                f"context={prev_ctx or 'unknown'} "
                f"latency={lat_state}\n"
                "Propose the single most informative next payload and the signal "
                "that would confirm the vulnerability."
            )
            assistant = json.dumps(
                {
                    "payloads": [
                        {
                            "payload": nxt_payload,
                            "rationale": payload_rationale(
                                family, prev_payload, prev_ctx,
                                round(prev_elapsed * 1000, 1), prev_decision,
                            ),
                            "confirm_signal": _FAMILY_CONFIRM.get(
                                family, _FAMILY_CONFIRM["generic"]
                            ),
                            "score": {
                                "LOW": 0.4, "MEDIUM": 0.6, "HIGH": 0.8, "CONFIRMED": 0.95
                            }.get(str(nxt.get("confidence_apriori", "")).upper(), 0.5),
                        }
                    ]
                },
                ensure_ascii=False,
            )
            # Dedup + split key is the observable prompt itself: two trajectory
            # steps that present an identical history collapse to one row and
            # can never land on opposite sides of the split.
            key = hashlib.sha1(user.encode("utf-8")).hexdigest()
            yield Sample(
                system, user, assistant,
                meta={"endpoint": endpoint, "param": gparam, "label": vclass,
                      "_url": base_url, "_dedup": key},
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
    total = sum(before.values())
    # Small classes (e.g. UNCERTAIN) shouldn't drive the balancing floor —
    # balance TP vs FP and leave a genuinely rare third class intact.
    major = [c for c in before.values() if c >= 0.05 * total]
    smallest = min(major) if major else min(before.values())
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

    # Disjointness is already guaranteed upstream: samples are de-duplicated on
    # their *observable* key (the anonymised prompt, latency bucketed), so no two
    # rows with model-indistinguishable inputs survive to reach this point. A
    # plain stratified split can therefore not leak a near-duplicate across.
    # Ordering by that key first keeps the split stable across regenerations.
    train: list[Sample] = []
    val: list[Sample] = []
    for _, grp in sorted(buckets.items()):
        grp.sort(key=lambda s: s.meta.get("_dedup", "") or (s.user + s.assistant))
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
