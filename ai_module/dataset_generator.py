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
4. **Synthesise** (``--synthetic-multiplier N`` / ``--enable-synthetic``) —
   the base telemetry has no HTTP bodies, so this crosses each unique real
   probe seed with a catalogue of mocked response bodies (verbatim vs. escaped
   reflection, DBMS syntax errors, WAF blocks, blank pages, out-of-webroot file
   reads, timing oracles) to produce a balanced TP / FP / ``UNCERTAIN`` set
   whose reasoning cites the concrete body evidence. Every synthetic label is
   re-checked against ``_assess_evidence`` before it is emitted.
5. **Balance + split** — optional 1:1 (``--balance-ratio``) TP/FP downsampling,
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
import html
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
from web_security_scanner.core.param_semantics import is_redirect_param

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
            code = -1 if status is None else int(status)
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


def dedup(samples: list[Sample]) -> tuple[list[Sample], int]:
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
    r"unterminated quoted string|syntax error at or near|near \".+\": syntax error|"
    r"SQLException|SQLite|psycopg2|PG::\w+Error|"
    r"System\.Data\.|Microsoft OLE DB|java\.sql\.|javax\.servlet|"
    r"org\.hibernate|Warning: |Fatal error|Traceback \(most recent call last\)|"
    r"XPathException|LDAP: error code|supplied argument is not a valid)",
    re.I,
)
# Contents of a file outside the web root (unix passwd, windows boot.ini, hosts).
_FILE_DISCLOSURE_RE = re.compile(
    r"(root:.*?:0:0:|daemon:x:1:1:|\[boot loader\]|\[fonts\]|"
    r"# Copyright \(c\) \d{4} Microsoft Corp|"
    r"127\.0\.0\.1\s+localhost)",
    re.I | re.S,
)
# Output of an injected shell command (id / uname / ipconfig / dir).
_CMD_OUTPUT_RE = re.compile(
    r"(uid=\d+\([\w-]+\) gid=\d+\([\w-]+\)|"
    r"Linux \S+ \d+\.\d+\.\d+|"
    r"Windows IP Configuration|Volume Serial Number is [0-9A-F-]{9})",
)
_TIME_CONTEXT_HINTS = ("time_based", "time-based", "time_blind", "timeblind", "timing")

_NEXT_PROOF: dict[str, str] = {
    "xss": "Load the reflected marker in a browser context to confirm script execution.",
    "sqli": "Send paired boolean payloads (1=1 vs 1=2) or a bounded time delay to confirm the oracle.",
    "cmdi": "Confirm with a bounded out-of-band DNS/HTTP callback rather than timing alone.",
    "pathtraver": "Fetch a known out-of-webroot file and diff it against a control path.",
    "ssrf": "Point the fetch at a collaborator host and watch for the inbound request.",
}


def _assess_evidence(
    evidence: dict[str, Any], *, context: str, vclass: str = ""
) -> dict[str, Any]:
    """Derive discriminating signals from the raw evidence, dynamically."""
    delta = _f(evidence.get("latency_delta_ms"))
    base = abs(_f(evidence.get("run_baseline_latency_ms")))
    noise = max(40.0, 0.75 * base)
    excerpt = evidence.get("response_excerpt") or ""
    reflected = bool(evidence.get("payload_reflected_verbatim"))
    has_error = bool(excerpt) and bool(_DB_ERROR_RE.search(excerpt))
    has_file = bool(excerpt) and bool(_FILE_DISCLOSURE_RE.search(excerpt))
    has_cmd_output = bool(excerpt) and bool(_CMD_OUTPUT_RE.search(excerpt))
    ctx = (context or "").lower()
    vc = (vclass or "").lower()
    time_class = "time" in ctx or any(h in ctx for h in _TIME_CONTEXT_HINTS)
    time_hit = time_class and delta >= max(750.0, noise * 5)
    apriori = str(evidence.get("apriori_confidence") or "").upper()
    # Verbatim reflection only *proves* something for markup-injection classes;
    # a reflected SQL/OS payload in an HTML body is ordinary templating.
    reflection_is_signal = reflected and (not vc or "xss" in vc or vc == "unknown")

    signals: list[str] = []
    if reflection_is_signal:
        signals.append("the payload is reflected verbatim in the response body")
    if has_error:
        signals.append("the response leaks an interpreter/database error string")
    if has_file:
        signals.append("the response body returns the contents of an out-of-webroot file")
    if has_cmd_output:
        signals.append("the response echoes the output of an injected shell command")
    if time_hit:
        signals.append(
            f"a payload-correlated delay of ~{delta:.0f} ms far exceeds the "
            f"~{base:.0f} ms run baseline"
        )

    within_noise = abs(delta) <= noise
    if time_hit:
        latency_note = (
            f"the response is ~{delta:.0f} ms slower than the ~{base:.0f} ms "
            "baseline, tracking the injected delay"
        )
    elif within_noise:
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
        "has_file": has_file,
        "has_cmd_output": has_cmd_output,
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


def _render_triage_user(
    endpoint: str, gparam: str, vclass: str, payload: str, evidence: dict[str, Any]
) -> str:
    """Format one triage prompt. ``response_excerpt`` is pulled out of the JSON
    blob and shown as its own fenced block so the model reads it as a body."""
    ev_public = {k: v for k, v in evidence.items() if k != "response_excerpt"}
    excerpt = evidence.get("response_excerpt")
    block = (
        f"Endpoint: {endpoint}\n"
        f"Parameter: {gparam}\n"
        f"Suspected class: {vclass}\n"
        f"Payload sent: {payload!r}\n"
        f"Observed evidence: {json.dumps(ev_public, ensure_ascii=False)}\n"
    )
    if excerpt:
        block += f"Response body excerpt:\n---\n{excerpt}\n---\n"
    block += (
        "\nClassify this candidate as TRUE_POSITIVE, FALSE_POSITIVE or UNCERTAIN "
        "and justify from the evidence."
    )
    return block


def _triage_next_step(verdict: str, vclass: str) -> str:
    if verdict == "TRUE_POSITIVE":
        return _NEXT_PROOF.get(
            vclass, "Replay with a differentiating oracle payload to demonstrate impact."
        )
    if verdict == "UNCERTAIN":
        return (
            "Re-probe with a repeatable oracle (paired true/false or timed "
            "payloads) and capture the response body to separate reflection "
            "from execution."
        )
    return "Suppress the finding and lower this endpoint's priority."


# --------------------------------------------------------------------------- #
# Synthetic triage augmentation
# --------------------------------------------------------------------------- #
#
# The OWASP-Benchmark telemetry carries no HTTP bodies, so once the URL shortcut
# is anonymised away only ~26 genuinely-distinct triage instances survive. This
# augmenter takes the *real* probe seeds (class / payload / context / a-priori
# confidence / run baseline latency) and crosses each one with a catalogue of
# realistic mocked response bodies — verbatim vs. escaped reflection, DB syntax
# errors, WAF blocks, blank pages, out-of-webroot file reads, timing oracles —
# to synthesise a balanced TP / FP / UNCERTAIN set whose reasoning cites the
# concrete evidence in the mocked body.

_SHELL_TITLES = ("ACME Search", "Product Catalogue", "Support Portal",
                 "Member Area", "Document Library", "Order Lookup")
_SHELL_FILLERS = (
    "<aside>Popular: Widgets, Gadgets, Sprockets</aside>",
    "<div class='promo'>Free shipping over $50</div>",
    "<section class='recent'>Recently viewed: 3 items</section>",
    "<p class='hint'>Tip: use quotes for an exact match.</p>",
    "",
)


def _shell(inner: str, rng: random.Random) -> str:
    title = rng.choice(_SHELL_TITLES)
    filler = rng.choice(_SHELL_FILLERS)
    return (
        f"<!DOCTYPE html><html><head><title>{title}</title></head><body>"
        f"<header><nav>Home &middot; Account &middot; Help</nav></header>"
        f"<main>{inner}{filler}</main>"
        f"<footer>&copy; {rng.randint(2019, 2026)} ACME Corp</footer></body></html>"
    )
_HTML_CTX_TEMPLATES = {
    "html_text": '<p>Results for <span class="q">{p}</span></p><ul><li>No matches</li></ul>',
    "html_attribute": '<input type="text" name="q" value="{p}" class="search-box">',
    "js_string": '<script>var query = "{p}"; renderResults(query);</script>',
}
_HTML_CTX_LABEL = {
    "html_text": "an HTML text node",
    "html_attribute": "a double-quoted HTML attribute",
    "js_string": "a JavaScript string literal",
}

_SQL_ERROR_TEMPLATES = [
    ("MySQL", "You have an error in your SQL syntax; check the manual that "
              "corresponds to your MySQL server version for the right syntax to "
              "use near '{f}' at line 1"),
    ("PostgreSQL", "ERROR: unterminated quoted string at or near \"'{f}\"\n"
                   "LINE 1: SELECT * FROM items WHERE name = '{f}"),
    ("SQLite", "SQLSTATE[HY000]: General error: 1 near \"{f}\": syntax error"),
    ("MS SQL Server", "System.Data.SqlClient.SqlException: Unclosed quotation "
                      "mark after the character string '{f}'."),
    ("Oracle", "ORA-01756: quoted string not properly terminated"),
]
_GENERIC_5XX_TEMPLATES = [
    "<html><head><title>500 Internal Server Error</title></head><body>"
    "<h1>Internal Server Error</h1><p>The server encountered an internal error "
    "and was unable to complete your request.</p><hr>"
    "<address>Apache/2.4.41 (Ubuntu)</address></body></html>",
    "<html><head><title>Whitelabel Error Page</title></head><body>"
    "<h1>Whitelabel Error Page</h1><p>This application has no explicit mapping "
    "for /error</p><div>There was an unexpected error (type=Internal Server "
    "Error, status=500).</div></body></html>",
    "<h1>Oops! Something went wrong (HTTP 500)</h1>"
    "<p>Our team has been notified. Please try again later.</p>",
]
_WAF_TEMPLATES = [
    ("HTTP 403 / block page", "<html><head><title>403 Forbidden</title></head>"
     "<body><h1>Request blocked</h1><p>The requested URL was rejected. Please "
     "consult with your administrator. Support ID: {sid}</p></body></html>"),
    ("Cloudflare challenge", "<!DOCTYPE html><html><head><title>Attention "
     "Required! | Cloudflare</title></head><body>Sorry, you have been blocked."
     "<br>Cloudflare Ray ID: {sid}</body></html>"),
    ("ModSecurity rule", "ModSecurity: Access denied with code 403 (phase 2). "
     "Matched phrase in ARGS:q [id \"942100\"] [msg \"SQL Injection Attack "
     "Detected via libinjection\"] [severity \"CRITICAL\"]"),
]
_BLANK_TEMPLATES = [
    "<html><head></head><body></body></html>",
    "OK",
    "{\"status\":\"ok\",\"results\":[]}",
]
_PASSWD_BODY = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)
_WIN_INI_BODY = (
    "; for 16-bit app support\n"
    "[fonts]\n"
    "[extensions]\n"
    "[mci extensions]\n"
    "[files]\n"
    "[Mail]\nMAPI=1\n"
)
_HOSTS_BODY = (
    "127.0.0.1\tlocalhost\n"
    "255.255.255.255\tbroadcasthost\n"
    "::1\tlocalhost\n"
    "10.0.0.7\tinternal-db\n"
)
# Out-of-webroot file bodies keyed by the token that proves the disclosure
# (must stay matched by ``_FILE_DISCLOSURE_RE``).
_FILE_DISCLOSURE_BODIES: tuple[tuple[str, str, str], ...] = (
    ("passwd", _PASSWD_BODY, "root:"),
    ("win.ini", _WIN_INI_BODY, "[fonts]"),
    ("hosts", _HOSTS_BODY, "127.0.0.1"),
)
_CMD_OUTPUT_BODY = (
    "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    "Linux web-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
)
# Stdout of an injected OS command (each stays matched by ``_CMD_OUTPUT_RE``).
_CMD_OUTPUT_BODIES: tuple[str, ...] = (
    _CMD_OUTPUT_BODY,
    "uid=0(root) gid=0(root) groups=0(root)\n",
    "uid=1000(app) gid=1000(app) groups=1000(app),27(sudo)\n"
    "Linux app-node-3 6.1.0-18-amd64 #1 SMP x86_64 GNU/Linux\n",
    "Windows IP Configuration\n\n"
    "   Host Name . . . . . . . . . . . . : WEB01\n"
    "   Primary Dns Suffix  . . . . . . . : corp.local\n",
)


def _win(text: str, needle: str, span: int = 70) -> str:
    """Short window of ``text`` around ``needle`` for quoting in reasoning."""
    i = text.find(needle)
    if i == -1:
        return text[:span].strip()
    lo, hi = max(0, i - span // 2), min(len(text), i + len(needle) + span // 2)
    return ("…" if lo else "") + text[lo:hi].strip() + ("…" if hi < len(text) else "")


@dataclass
class _Scenario:
    name: str
    classes: set[str]          # suspected vclass this applies to; {"*"} = any
    verdict: str
    latency: str               # "noise" | "slower" | "much_slower" | "faster"
    # build(payload, ctx, rng) -> (excerpt, reflected_verbatim, reason, ctx_override)
    build: Any
    confidence: float


def _sc_xss_verbatim(payload, ctx, rng):
    ctx = ctx if ctx in _HTML_CTX_TEMPLATES else rng.choice(list(_HTML_CTX_TEMPLATES))
    inner = _HTML_CTX_TEMPLATES[ctx].format(p=payload)
    body = _shell(inner, rng)
    reason = (
        f"The payload is reflected unescaped into {_HTML_CTX_LABEL[ctx]} of the "
        f"response body ({_win(body, payload)!r}); the browser parses the "
        f"injected markup, so this is an exploitable reflected XSS."
    )
    return body, True, reason, ctx


def _sc_xss_escaped(payload, ctx, rng):
    ctx = ctx if ctx in _HTML_CTX_TEMPLATES else rng.choice(list(_HTML_CTX_TEMPLATES))
    esc = html.escape(payload, quote=True)
    inner = _HTML_CTX_TEMPLATES[ctx].format(p=esc)
    body = _shell(inner, rng)
    reason = (
        f"The payload appears in the body but HTML-entity-encoded "
        f"({_win(body, esc[:20])!r}), so it renders as inert text rather than "
        f"markup. Output encoding neutralises the vector — false positive."
    )
    return body, False, reason, ctx


def _sc_xss_stripped(payload, ctx, rng):
    shown = re.sub(r"[<>\"'();]", "", payload)
    inner = _HTML_CTX_TEMPLATES["html_text"].format(p=shown)
    body = _shell(inner, rng)
    reason = (
        f"The response reflects the value with the angle brackets and quotes "
        f"removed ({shown!r}); the sanitiser strips the characters needed to "
        f"break out, but the exact filter and any downstream sink are unknown, "
        f"so execution can be neither confirmed nor ruled out from this evidence."
    )
    return body, False, reason, "html_text"


def _sc_sql_error(payload, ctx, rng):
    dbms, tmpl = rng.choice(_SQL_ERROR_TEMPLATES)
    frag = payload.strip()[:24]
    err = tmpl.format(f=frag)
    body = _shell(f"<pre class=\"error\">{err}</pre>", rng)
    reason = (
        f"The response body contains a verbatim {dbms} error triggered by the "
        f"quote in the payload ({_win(err, frag) or err[:60]!r}) — the input "
        f"reaches the SQL parser unsanitised, confirming injection."
    )
    return body, False, reason, "error_based"


def _sc_sql_time(payload, ctx, rng):
    body = _shell("<p>Your request has been processed.</p>", rng)
    reason = (
        "No error string or reflection, but the request is delayed far beyond "
        "the run baseline in a way that tracks the injected time function; a "
        "repeatable payload-correlated delay is a time-based blind SQLi oracle."
    )
    return body, False, reason, "time_based_blind"


def _sc_sql_generic_500(payload, ctx, rng):
    rid = "".join(rng.choice("0123456789abcdef") for _ in range(12))
    body = rng.choice(_GENERIC_5XX_TEMPLATES) + f"<!-- trace-id: {rid} -->"
    reason = (
        "The body is a generic framework 500 page with no SQL error text, no "
        "reflected payload and latency within noise; a 500 fires for many "
        "malformed inputs and is not by itself evidence of injection."
    )
    return body, False, reason, ctx or "error_based"


def _sc_waf_block(payload, ctx, rng):
    label, tmpl = rng.choice(_WAF_TEMPLATES)
    sid = "".join(rng.choice("0123456789abcdef") for _ in range(16))
    body = tmpl.format(sid=sid)
    reason = (
        f"The response is a WAF/CDN block ({label}); the payload was filtered "
        f"before reaching the application, so there is no application-level "
        f"vulnerability here — only a proxy rule that fired."
    )
    return body, False, reason, ctx or "generic"


def _sc_blank(payload, ctx, rng):
    rid = "".join(rng.choice("0123456789abcdef") for _ in range(12))
    base = rng.choice(_BLANK_TEMPLATES)
    body = base.replace("</body>", f"<!-- {rid} --></body>") if "</body>" in base else base
    reason = (
        "The response is an essentially empty 200 with the payload absent from "
        "the body and latency at baseline — indistinguishable from normal "
        "handling of an unexpected parameter value."
    )
    return body, False, reason, ctx or "generic"


def _path_encoding_note(payload: str) -> str:
    """One clause describing which traversal encoding layer the read honoured."""
    p = payload.lower()
    if "%25" in payload:
        return " The double-URL-encoded separators survived a single decode pass."
    if "%00" in payload or "\x00" in payload or "%2500" in payload:
        return " A trailing NUL byte truncated the appended extension before the open."
    if "..%c0%af" in p or "%c0%ae" in p or "%e0%80%ae" in p:
        return " The overlong-UTF-8 encoded dots were folded back to '..' on decode."
    if "%2e" in p or "%2f" in p or "%5c" in p:
        return " The percent-encoded path separators were decoded before the file open."
    if "....//" in payload or "....\\" in payload:
        return " The doubled 'dot-dot-slash' sequence collapsed past the filter into '../'."
    if payload.startswith("/") or payload.startswith("file:"):
        return " The parameter is treated as an absolute path, skipping the intended base directory."
    return ""


_PASSWD_EXTRA_LINES = (
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n",
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n",
    "sync:x:4:65534:sync:/bin:/bin/sync\n",
    "mysql:x:106:113:MySQL Server,,,:/nonexistent:/bin/false\n",
    "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n",
    "postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n",
)


def _sc_path_file(payload, ctx, rng):
    p = payload.lower()
    if "win.ini" in p or "boot.ini" in p or "windows" in p or "%5cwindows" in p:
        needle, body, mark = "win.ini", _WIN_INI_BODY, "[fonts]"
    elif "hosts" in p:
        needle, body, mark = "hosts", _HOSTS_BODY, "127.0.0.1"
    elif "passwd" in p:
        needle, mark = "passwd", "root:"
        extra = "".join(
            rng.sample(_PASSWD_EXTRA_LINES, rng.randint(0, len(_PASSWD_EXTRA_LINES)))
        )
        body = _PASSWD_BODY + extra
    else:
        needle, body, mark = rng.choice(_FILE_DISCLOSURE_BODIES)
    frame = rng.randint(0, 2)
    if frame == 1:
        body = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n{body}"
    elif frame == 2:
        body = _shell(f"<pre>{body}</pre>", rng)
    reason = (
        f"The response body returns the contents of a system file outside the "
        f"web root ({_win(body, mark) or body[:50]!r}); the traversal sequence "
        f"is honoured by the file read — confirmed path traversal."
        + _path_encoding_note(payload)
    )
    return body, False, reason, "file_read"


def _sc_path_blocked(payload, ctx, rng):
    leaf = re.split(r"[\\/]", payload)[-1][:48] or payload[:48]
    body = _shell(
        f"<h1>File not found</h1><p>The requested document "
        f"<code>{html.escape(leaf)}</code> could not be located. "
        f"Check the name and try again.</p>",
        rng,
    )
    reason = (
        "The application rejects the traversal: the response is a generic "
        "'file not found' page with no out-of-webroot file contents, the path "
        "sequence is not honoured, and latency sits at the run baseline. Nothing "
        "in this evidence discriminates a real path traversal from a mistyped "
        "filename."
    )
    return body, False, reason, "file_read"


def _sc_path_within_root(payload, ctx, rng):
    body = _shell(
        "<h2>Image gallery</h2><ul><li>logo.png</li><li>banner.jpg</li>"
        "<li>icon.svg</li></ul><p>3 files in /assets/img.</p>",
        rng,
    )
    reason = (
        "The traversal sequence is normalised away and the handler returns a "
        "normal in-webroot asset listing: no system-file contents, no error, "
        "latency at baseline. The evidence neither confirms nor rules out a "
        "traversal that would only bite on a different target path."
    )
    return body, False, reason, "file_read"


def _sc_cmd_output(payload, ctx, rng):
    out = rng.choice(_CMD_OUTPUT_BODIES)
    body = _shell(f"<pre>{out}</pre>", rng)
    needle = "uid=" if out.startswith("uid=") else out.split("\n", 1)[0][:18]
    reason = (
        f"The response echoes the output of an injected shell command "
        f"({_win(out, needle)!r}); the parameter is passed to a command "
        f"interpreter — confirmed OS command injection."
    )
    return body, False, reason, "shell"


def _sc_cmd_time(payload, ctx, rng):
    body = _shell("<p>Your request has been queued for processing.</p>", rng)
    reason = (
        "No command output is echoed and nothing is reflected, but the response "
        "is delayed far beyond the run baseline in a way that tracks an injected "
        "`sleep`/`ping -c` delay; a repeatable payload-correlated delay is a "
        "blind OS command-injection oracle."
    )
    return body, False, reason, "time_based_blind"


def _sc_cmd_filtered(payload, ctx, rng):
    stripped = re.sub(r"[;&|`$()<>\n\r]", "", payload).strip() or "query"
    body = _shell(
        f"<p>Looking up '<b>{html.escape(stripped)}</b>'&hellip; 0 records found.</p>",
        rng,
    )
    reason = (
        f"The shell metacharacters are stripped before the value is used — only "
        f"{stripped!r} survives — and the response is an ordinary lookup with no "
        f"command output and baseline latency. The input never reaches a command "
        f"interpreter, so this is not command injection."
    )
    return body, False, reason, "shell"


def _sc_cmd_echoed_arg(payload, ctx, rng):
    inner = f"<p>Report generated for: {payload}</p><p>Status: queued.</p>"
    body = _shell(inner, rng)
    reason = (
        "The value is echoed back into the page as a literal argument, but there "
        "is no command output, no interpreter error and no timing delta. "
        "Reflection of an OS payload in an HTML body is ordinary templating, so "
        "execution can be neither confirmed nor ruled out from this evidence."
    )
    return body, True, reason, "shell"


def _sc_echo_nonexec(payload, ctx, rng):
    inner = f"<title>Search: {payload}</title><p>0 results.</p>"
    body = _shell(inner, rng)
    reason = (
        "The value is echoed back into the page title, but the suspected class "
        "is not XSS — reflection here is ordinary templating. There is no "
        "SQL/interpreter error and no timing signal, so the hypothesis is "
        "unsupported yet not disproven."
    )
    return body, True, reason, "html_text"


def _sc_boolean_weak(payload, ctx, rng):
    n = rng.randint(1180, 1240)
    body = _shell(f"<p>Showing {n} of many products.</p>", rng)
    reason = (
        "The true/false payloads produce only a small content-length delta that "
        "is within the range of caching and rotating content; without a stable, "
        "repeated differential this boolean probe is inconclusive."
    )
    return body, False, reason, "boolean_blind"


_SCENARIOS: list[_Scenario] = [
    _Scenario("xss_verbatim_reflection", {"xss"}, "TRUE_POSITIVE", "noise", _sc_xss_verbatim, 0.9),
    _Scenario("sql_error_disclosure", {"sqli"}, "TRUE_POSITIVE", "noise", _sc_sql_error, 0.93),
    _Scenario("sql_time_oracle", {"sqli"}, "TRUE_POSITIVE", "much_slower", _sc_sql_time, 0.85),
    _Scenario("path_traversal_file_read", {"pathtraver"}, "TRUE_POSITIVE", "noise", _sc_path_file, 0.93),
    _Scenario("cmd_injection_output", {"cmdi"}, "TRUE_POSITIVE", "noise", _sc_cmd_output, 0.93),
    _Scenario("cmd_injection_time_oracle", {"cmdi"}, "TRUE_POSITIVE", "much_slower", _sc_cmd_time, 0.8),
    _Scenario("xss_output_encoded", {"xss"}, "FALSE_POSITIVE", "noise", _sc_xss_escaped, 0.9),
    _Scenario("generic_500_page", {"sqli", "cmdi", "pathtraver", "unknown"}, "FALSE_POSITIVE", "noise", _sc_sql_generic_500, 0.8),
    _Scenario("path_traversal_blocked", {"pathtraver"}, "FALSE_POSITIVE", "noise", _sc_path_blocked, 0.9),
    _Scenario("cmd_injection_filtered", {"cmdi"}, "FALSE_POSITIVE", "noise", _sc_cmd_filtered, 0.88),
    _Scenario("waf_block_page", {"*"}, "FALSE_POSITIVE", "noise", _sc_waf_block, 0.9),
    _Scenario("blank_response", {"*"}, "FALSE_POSITIVE", "noise", _sc_blank, 0.82),
    _Scenario("xss_partial_filter", {"xss"}, "UNCERTAIN", "noise", _sc_xss_stripped, 0.5),
    _Scenario("path_traversal_within_root", {"pathtraver"}, "UNCERTAIN", "noise", _sc_path_within_root, 0.5),
    _Scenario("cmd_injection_echoed_arg", {"cmdi"}, "UNCERTAIN", "noise", _sc_cmd_echoed_arg, 0.5),
    _Scenario("reflection_irrelevant_to_class", {"sqli", "cmdi", "ldapi", "xpathi"}, "UNCERTAIN", "noise", _sc_echo_nonexec, 0.5),
    _Scenario("weak_boolean_differential", {"sqli"}, "UNCERTAIN", "noise", _sc_boolean_weak, 0.5),
]
_SCENARIOS_BY_VERDICT: dict[str, list[_Scenario]] = defaultdict(list)
for _sc in _SCENARIOS:
    _SCENARIOS_BY_VERDICT[_sc.verdict].append(_sc)

_VERDICTS = ("TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN")


def _scenario_applies(sc: _Scenario, vclass: str) -> bool:
    return "*" in sc.classes or vclass in sc.classes


def _synth_latency(bucket: str, base_ms: float, rng: random.Random) -> float:
    noise = max(40.0, 0.75 * abs(base_ms))
    if bucket == "noise":
        return round(rng.uniform(-0.55 * noise, 0.55 * noise), 1)
    if bucket == "slower":
        return round(rng.uniform(noise * 1.4, 690.0), 1)
    if bucket == "much_slower":
        return round(rng.uniform(3500.0, 9000.0), 1)
    if bucket == "faster":
        return round(-rng.uniform(noise * 1.3, noise * 3.0), 1)
    return 0.0


# --------------------------------------------------------------------------- #
# Standalone (telemetry-independent) probe seeds
# --------------------------------------------------------------------------- #
#
# The base telemetry sweep only exercised the SQLi and XSS testers, so classes
# such as Path Traversal and OS Command Injection produced *zero* real probe
# seeds and their synthetic scenarios never fired. These hardcoded seeds give
# the augmenter a robust base of realistic GET-parameter payloads (relative and
# absolute traversal, several URL-encoding layers, NUL-byte truncation; shell
# metacharacter / newline / backtick / subshell command injection) so those
# classes get balanced TP / FP / UNCERTAIN coverage even when the telemetry has
# no trace of the corresponding tester.

_STANDALONE_SEED_SPECS: dict[str, dict[str, Any]] = {
    "pathtraver": {
        "tester_id": "PathTraversalTester",
        "context": "file_read",
        "payloads": [
            "../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "../../../../etc/passwd%00.png",
            "/etc/passwd",
            "file:///etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
            "../../../../etc/hosts",
        ],
    },
    "cmdi": {
        "tester_id": "CommandInjectionTester",
        "context": "shell",
        "payloads": [
            "; id",
            "| id",
            "| uname -a",
            "`id`",
            "$(id)",
            "& whoami",
            "&& cat /etc/passwd",
            "%0aid",
            "%0a/usr/bin/id",
            "; sleep 5",
            "| ping -c 5 127.0.0.1",
            "| nslookup wsscanary.example.com",
        ],
    },
}


def _standalone_triage_seeds(
    classes: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Hardcoded probe seeds in the same shape as :func:`_triage_seeds` output.

    ``classes`` filters which vuln classes to emit; ``None`` emits all of them.
    """
    want = set(classes) if classes is not None else set(_STANDALONE_SEED_SPECS)
    seeds: list[dict[str, Any]] = []
    for vclass, spec in _STANDALONE_SEED_SPECS.items():
        if vclass not in want:
            continue
        for i, payload in enumerate(spec["payloads"]):
            seeds.append(
                {
                    "vclass": vclass,
                    "payload": payload,
                    "context": spec["context"],
                    "vector": "getparam",
                    "apriori": "MEDIUM",
                    "scanner_conf": "HIGH" if i % 2 == 0 else "MEDIUM",
                    "base_latency_ms": 16.0 + (i % 5) * 3.0,
                    "tester_id": spec["tester_id"],
                    "standalone_seed": True,
                }
            )
    return seeds


def _merge_standalone_seeds(
    seeds: list[dict[str, Any]], *, force_all: bool = False
) -> list[dict[str, Any]]:
    """Append hardcoded seeds for any standalone class not already represented
    (or, with ``force_all``, for every standalone class), de-duplicating on the
    ``(vclass, payload, context)`` key the rest of the pipeline joins on."""
    covered = {s["vclass"] for s in seeds}
    wanted = (
        list(_STANDALONE_SEED_SPECS)
        if force_all
        else [c for c in _STANDALONE_SEED_SPECS if c not in covered]
    )
    if not wanted:
        return seeds
    have = {(s["vclass"], s["payload"], s.get("context") or "") for s in seeds}
    merged = list(seeds)
    for s in _standalone_triage_seeds(wanted):
        if (s["vclass"], s["payload"], s["context"]) not in have:
            merged.append(s)
    return merged


def _triage_seeds(
    rows: list[dict[str, Any]], oracle: Oracle, *, weak: bool
) -> list[dict[str, Any]]:
    """Unique (class, payload, context) probe seeds for synthetic augmentation."""
    baselines = _run_baselines(rows)
    seen: set[tuple[str, str, str]] = set()
    seeds: list[dict[str, Any]] = []
    for row in rows:
        if not _is_probe_row(row):
            continue
        decision = bool(row.get("decision"))
        conf_final = row.get("confidence_final")
        if not (decision or (weak and conf_final not in (None, "", "LOW"))):
            continue
        tester_id = row.get("tester_id", "")
        vclass = (row.get("type") or row.get("vuln_class") or "").lower()
        if not vclass:
            cats = _TESTER_TO_CATEGORY.get(tester_id)
            vclass = next(iter(cats)) if cats else "unknown"
        url = row.get("url", "")
        param = row.get("param", row.get("parameter", "")) or ""
        payload = row.get("payload") or _payload_from_url(url, param)
        if not payload or is_junk_payload(payload):
            continue
        ctx = row.get("context") or ""
        key = (vclass, payload, ctx)
        if key in seen:
            continue
        seen.add(key)
        seeds.append({
            "vclass": vclass,
            "payload": payload,
            "context": ctx,
            "vector": row.get("vector") or "getparam",
            "apriori": str(row.get("confidence_apriori") or "MEDIUM").upper(),
            "scanner_conf": str(conf_final or "MEDIUM").upper(),
            "base_latency_ms": round(
                baselines.get((row.get("run_id", ""), tester_id), 0.02) * 1000, 1
            ) or 20.0,
            "tester_id": tester_id,
        })
    return seeds


def synthesize_triage_samples(
    seeds: list[dict[str, Any]], *, multiplier: int, seed: int
) -> Iterator[Sample]:
    """Yield ``~len(seeds) * multiplier`` body-enriched triage samples with a
    balanced TP / FP / UNCERTAIN split. Deterministic for a given ``seed``."""
    if not seeds or multiplier <= 0:
        return
    system = load_prompt("triage_system")
    rng = random.Random(seed ^ 0x5717)
    target = len(seeds) * multiplier
    produced: Counter[str] = Counter()
    emitted: set[str] = set()

    attempts = 0
    while sum(produced.values()) < target and attempts < target * 40:
        attempts += 1
        # Drive toward balance: fill the currently-thinnest verdict.
        verdict = min(_VERDICTS, key=lambda v: (produced[v], _VERDICTS.index(v)))
        sc = rng.choice(_SCENARIOS_BY_VERDICT[verdict])
        candidates = [s for s in seeds if _scenario_applies(sc, s["vclass"])]
        if not candidates:
            continue
        sd = rng.choice(candidates)
        vclass = sd["vclass"]
        payload = sd["payload"]

        excerpt, reflected, reason, ctx_override = sc.build(
            payload, sd["context"], rng
        )
        excerpt = normalize_body(excerpt, payload, max_bytes=_MAX_BODY_BYTES)
        injection_context = ctx_override or sd["context"] or "generic"
        base_ms = float(sd["base_latency_ms"])
        delta_ms = _synth_latency(sc.latency, base_ms, rng)
        evidence: dict[str, Any] = {
            "scanner_decision": True,
            "scanner_confidence": sd["scanner_conf"],
            "apriori_confidence": sd["apriori"],
            "injection_context": injection_context,
            "vector": sd["vector"],
            "latency_ms": round(base_ms + delta_ms, 1),
            "run_baseline_latency_ms": round(base_ms, 1),
            "latency_delta_ms": round(delta_ms, 1),
            "response_excerpt": excerpt,
            "payload_reflected_verbatim": reflected,
            "response_truncated": False,
        }

        a = _assess_evidence(evidence, context=injection_context, vclass=vclass)
        # Guard: never emit a sample whose intended label contradicts what the
        # shared assessor would read out of the evidence we just built.
        if sc.verdict == "TRUE_POSITIVE" and not a["discriminating"]:
            continue
        if sc.verdict == "FALSE_POSITIVE" and a["discriminating"]:
            continue
        if sc.verdict == "UNCERTAIN" and (a["discriminating"] or not a["within_noise"]):
            continue

        # Reasoning = scenario-specific body citation + the shared latency read.
        reasoning = reason
        if sc.latency in {"slower", "much_slower", "faster"} or not a["signals"]:
            reasoning = f"{reason} Latency-wise, {a['latency_note']}."
        assistant = json.dumps(
            {
                "verdict": sc.verdict,
                "confidence": sc.confidence,
                "reasoning": reasoning,
                "next_step": _triage_next_step(sc.verdict, vclass),
            },
            ensure_ascii=False,
        )
        user = _render_triage_user(_GENERIC_ENDPOINT, "p", vclass, payload, evidence)

        obs_key = "|".join([
            "triage-synth", vclass, payload, sc.name, str(reflected),
            str(a["has_error"] or a["has_file"] or a["has_cmd_output"]),
            a["lat_bucket"], sd["apriori"], sd["scanner_conf"], injection_context,
            hashlib.sha1(excerpt.encode("utf-8")).hexdigest()[:10],
        ])
        key = hashlib.sha1(obs_key.encode("utf-8")).hexdigest()
        if key in emitted:
            continue
        emitted.add(key)
        produced[sc.verdict] += 1
        yield Sample(
            system, user, assistant,
            meta={
                "label": sc.verdict, "label_source": "synthetic", "synthetic": True,
                "scenario": sc.name, "suspected_class": vclass,
                "tester": sd["tester_id"], "_dedup": key, "_evidence": evidence,
            },
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
        # Make the parameter's *role* an explicit, learnable feature. The name
        # itself is anonymised away (``generic_param``), so without this the
        # model could never tell a redirect destination from an identifier —
        # and redirect destinations are where the scanner's differential oracle
        # produces most of its false positives.
        redirect_param = is_redirect_param(param)
        if redirect_param:
            evidence["parameter_role"] = "redirect/flow-control destination (URL or path)"

        weak_label = label_src.startswith("weak")
        a = _assess_evidence(evidence, context=row.get("context") or "", vclass=vclass)
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
            if a["discriminating"]:
                verdict = "TRUE_POSITIVE"
            elif redirect_param:
                # A flow-control parameter carries a URL the application
                # validates before redirecting. Any divergence that is not a
                # body/timing signal is explained by that validation, so a weak
                # label must never promote it to TRUE_POSITIVE.
                verdict = "FALSE_POSITIVE"
            elif strong_apriori and not a["within_noise"]:
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
        user = _render_triage_user(endpoint, gparam, vclass, payload, evidence)

        # Observable key: everything the model can actually see, latency bucketed.
        obs_key = "|".join(
            [
                "triage", vclass, payload,
                str(a["reflected"]), str(a["has_error"]), a["lat_bucket"],
                str(a["apriori"]), a["scanner_conf"],
                str(evidence.get("injection_context") or ""),
                str(evidence.get("vector") or ""),
                str(evidence.get("parameter_role") or ""),
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

    for (_run, _tester_key, base_url, param), seq in traj.items():
        seq.sort(key=lambda r: r.get("request_index", 0) or r.get("ts", 0))
        for prev, nxt in zip(seq, seq[1:], strict=False):  # pairwise: seq[1:] is 1 shorter
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
            dedup_key = hashlib.sha1(user.encode("utf-8")).hexdigest()
            yield Sample(
                system, user, assistant,
                meta={"endpoint": endpoint, "param": gparam, "label": vclass,
                      "_url": base_url, "_dedup": dedup_key},
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

    mult = getattr(args, "synthetic_multiplier", 0)
    if task == "triage" and mult > 0:
        seeds = _triage_seeds(rows, oracle, weak=weak)
        telemetry_seed_classes = dict(Counter(s["vclass"] for s in seeds))
        if not getattr(args, "no_standalone_seeds", False):
            seeds = _merge_standalone_seeds(
                seeds, force_all=getattr(args, "standalone_all_seeds", False)
            )
        synth = list(synthesize_triage_samples(seeds, multiplier=mult, seed=args.seed))
        report["synthetic"] = {
            "seeds": len(seeds),
            "telemetry_seed_classes": telemetry_seed_classes,
            "seed_classes": dict(Counter(s["vclass"] for s in seeds)),
            "standalone_seeds": sum(1 for s in seeds if s.get("standalone_seed")),
            "multiplier": mult,
            "built": len(synth),
            "class_counts": dict(Counter(s.meta.get("label", "?") for s in synth)),
            "suspected_class_counts": dict(
                Counter(s.meta.get("suspected_class", "?") for s in synth)
            ),
            "scenario_counts": dict(Counter(s.meta.get("scenario", "?") for s in synth)),
        }
        samples.extend(synth)
        report["samples_with_synthetic"] = len(samples)
        print(f"[{task}] +{len(synth)} synthetic (from {len(seeds)} seeds)", file=sys.stderr)

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
    ap.add_argument("--synthetic-multiplier", type=int, default=0, metavar="N",
                    help="augment triage with ~N body-enriched synthetic samples "
                         "per unique real probe seed (mocked HTTP bodies: verbatim/"
                         "escaped reflection, SQL errors, WAF blocks, file reads, "
                         "timing oracles). Balanced across TP/FP/UNCERTAIN. 0 = off")
    ap.add_argument("--enable-synthetic", action="store_true",
                    help="shortcut for --synthetic-multiplier 20 when no explicit "
                         "multiplier is given")
    ap.add_argument("--no-standalone-seeds", action="store_true",
                    help="do not inject the hardcoded Path-Traversal / Command-"
                         "Injection probe seeds for classes missing from the "
                         "telemetry (synthetic augmentation only)")
    ap.add_argument("--standalone-all-seeds", action="store_true",
                    help="inject the hardcoded standalone seeds for every "
                         "supported class even when the telemetry already covers it")
    args = ap.parse_args(argv)
    if args.enable_synthetic and args.synthetic_multiplier == 0:
        args.synthetic_multiplier = 20

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
            "synthetic_multiplier": args.synthetic_multiplier,
            "standalone_seeds": not args.no_standalone_seeds,
            "standalone_all_seeds": args.standalone_all_seeds,
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
