"""Ground-truth loaders for benchmark evaluation.

Two formats, both normalised to :class:`~.ieee_metrics.GroundTruth`:

* :func:`load_owasp_benchmark` -- the OWASP Benchmark project (v1.2+), from its
  ``expectedresults.csv``. The scanner matches on a URL+parameter key, but the
  benchmark's own schema is per-test-case, so this loader reconciles the two.

* :func:`load_json_ground_truth` -- a plain JSON table. **This is the extension
  point**: any target the researcher can label can be scored with the same
  pipeline, without touching this module. A synthetic app, an internal staging
  box, a WAF-protected clone, or a defect-injected service all evaluate through
  this path.

Why URL reconciliation matters here
-----------------------------------
The benchmark states ground truth per *test case* (``BenchmarkTest00042``), not
per (url, parameter). A finding, meanwhile, carries the concrete URL that was
probed -- with host, scheme and the mutated query string. Matching them directly
fails, and failing silently would turn every true positive into a false negative.

This loader therefore stores each instance under **every** key the scanner might
plausibly report for it (case id in path, canonical path+query, and with the
host prefix when a base URL is supplied), and :func:`candidate_keys` in
``ieee_metrics`` lets the caller generate the matching candidates. Duplicates
collapse because the buckets are keyed, not accumulated.
"""

from __future__ import annotations

import csv
import json
import re
import urllib.parse
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from .ieee_metrics import Finding, GroundTruth

# Re-exported so callers holding only a ground-truth loader have the vocabulary
# too: deciding which classes a table can be scored on is the same question as
# loading the table.
from .vuln_classes import canonical_class

__all__ = [
    "load_owasp_benchmark",
    "load_json_ground_truth",
    "load_findings_from_report",
    "benchmark_key_resolver",
    "exact_key_resolver",
    "json_key_resolver",
    "canonical_path",
    "candidate_keys",
    "canonical_class",
]

# OWASP Benchmark expectedresults.csv column names across versions. v1.2 names
# the id column "# test name"; earlier drafts used "# onemore line" / "name" /
# "id". All are accepted so the loader does not refuse a table the project
# itself still ships.
_COL_TEST_ID = (
    "# test name", "test name", "# onemore line", "test_case", "test case",
    "name", "id",
)
_COL_VULN = (
    "real vulnerability", "real_vulnerability", "vulnerable", "is_vulnerable",
)
#: The benchmark states, per test case, *which* vulnerability class the case is
#: about. It is the only thing that separates a correct detection from a correct
#: detection of the wrong thing, so it is loaded as a class label rather than
#: discarded as metadata. Absent from v1.0, present from v1.1 onwards.
_COL_CATEGORY = ("category", "vulnerability category", "vuln_category")

#: Per-entry keys that may carry the expected vulnerability class in a JSON
#: ground-truth table, most authoritative first. ``expected_class`` is the name
#: to use in a hand-written table, because ``type`` is also the field a
#: *finding* carries and the two mean opposite things to a reader. ``type`` and
#: ``category`` are consulted afterwards so tables derived from the benchmark's
#: per-case exports, and tables whose ``category`` is already a class name, are
#: scored without being rewritten.
_CLASS_KEYS = ("expected_class", "expected_type", "class", "type", "category")

_CASE_ID_RE = re.compile(r"BenchmarkTest\d+", re.IGNORECASE)
_TRUE_TOKENS = {"true", "y", "yes", "1", "vulnerable"}
_FALSE_TOKENS = {"false", "n", "no", "0", "safe"}

#: ``ProbeStatus`` values that mean "the scan could not measure this point".
#: Mirrors :class:`web_security_scanner.core.hybrid_score.ProbeStatus`; kept as
#: plain strings so report ingestion does not have to import the decision engine.
_UNTESTED_STATUSES = frozenset({
    "blocked_untested", "soft404_untested", "probe_aborted",
})


def _truthy(value: str) -> bool | None:
    """Parse a benchmark truth column. None when unrecognised."""
    token = (value or "").strip().lower()
    if token in _TRUE_TOKENS:
        return True
    if token in _FALSE_TOKENS:
        return False
    return None


def _find_column(fieldnames: Sequence[str], candidates: Iterable[str]) -> str | None:
    lowered = {(name or "").strip().lower(): name for name in fieldnames}
    for candidate in candidates:
        if candidate in lowered:
            return lowered[candidate]
    return None


def canonical_path(url: str, *, base_url: str = "") -> str:
    """Reduce a URL to ``/path?query`` with query params sorted.

    Sorting makes the key independent of the order the scanner happened to build
    the query in, and dropping scheme/host lets the same key match regardless of
    whether the run used ``127.0.0.1:8443`` or a compose service name.
    """
    if base_url:
        base_path = urllib.parse.urlparse(base_url).path.rstrip("/")
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        if base_path and not path.startswith(base_path):
            path = f"{base_path}{path}" if path != "/" else base_path
    else:
        path = urllib.parse.urlparse(url).path or "/"

    query = urllib.parse.urlparse(url).query
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    canonical_query = urllib.parse.urlencode(sorted(pairs))
    return f"{path}?{canonical_query}" if canonical_query else path


def candidate_keys(url: str, parameter: str = "", *, base_url: str = "") -> list[tuple[str, str]]:
    """Every key a finding for ``(url, parameter)`` might be labelled under.

    The scanner can report a URL with the injected value baked in, the bare
    endpoint, or the benchmark case id. All of those have to resolve to the same
    ground-truth instance or the true positive is lost.

    The candidate list is ordered most-specific-first and stays as short as
    possible: every entry added is one more way a genuine finding can be
    mis-scored, so the set is deliberately limited to the case-id reduction that
    the benchmark format actually needs, plus a parameter-free variant for
    reporters that name the parameter in the path.
    """
    keys: list[tuple[str, str]] = []

    def _add(u: str, p: str) -> None:
        entry = (u, p)
        if entry not in keys:
            keys.append(entry)

    canonical = canonical_path(url, base_url=base_url)
    _add(canonical, parameter)

    # The scanner reports the URL with the *injected value* in the query string
    # (`?id=1%20OR%201=1`), while a ground-truth table labels the instance by its
    # bare endpoint (`/search`, parameter `id`). Matching on the full canonical
    # form therefore never hits, and every genuine detection is scored as
    # "outside the ground truth" -- precision 0.0 on a run that found real
    # vulnerabilities. The query-stripped path is the variant that reconciles the
    # two encodings.
    #
    # Safe here because the two are reconciled on ``(path, parameter)``: a
    # benchmark test case and a JSON table row both name the parameter, so two
    # different instances sharing a path but differing only in a benign query
    # value stay distinct through the parameter.
    _add(canonical.split("?", 1)[0], parameter)

    match = _CASE_ID_RE.search(url)
    if match:
        _add(f"/{match.group(0)}", parameter)

    if parameter:
        # Some reporters put the parameter in the path (`/x/id/42`).
        _add(canonical_path(url, base_url=base_url).rstrip("/"), "")

    return keys


def benchmark_key_resolver(base_url: str = ""):
    """Build the :data:`~.ieee_metrics.KeyResolver` for benchmark-style truth.

    Needed because the two sides encode an instance differently: the ground
    truth is keyed ``/BenchmarkTest00042`` with an empty parameter, while a
    finding carries the concrete URL that was probed
    (``/benchmark/BenchmarkTest00042?foo=1&bar=2``).

    Without this the reconciliation silently produces recall 0.0 on a run that
    actually detected real vulnerabilities -- the failure mode is invisible
    because the run still completes and still prints numbers.
    """
    def _resolve(finding: Finding) -> list[tuple[str, str]]:
        return candidate_keys(finding.url, finding.parameter, base_url=base_url)

    return _resolve


def exact_key_resolver():
    """The identity resolver, for ground truth already keyed like the findings."""
    def _resolve(finding: Finding) -> list[tuple[str, str]]:
        return [finding.key]

    return _resolve


def json_key_resolver(base_url: str = ""):
    """Key resolver for a table loaded by :func:`load_json_ground_truth`.

    Not the identity, despite that table being authored by hand. The two sides
    still encode an instance differently, in the one way that matters for every
    target: the ground truth names the endpoint (``/search``, parameter ``q``)
    while the scanner reports the endpoint with the injected value baked into the
    query (``/search?q=1%20OR%201=1``, parameter ``q``).

    With the identity resolver those keys never intersect, so every genuine
    detection is booked as "outside the ground truth" and the run reports
    precision 0.0 having actually found real vulnerabilities. The reconciliation
    is on ``(path, parameter)``, which is why the query string is dropped: it
    holds the attacker's payload, not part of the instance's identity.
    """
    def _resolve(finding: Finding) -> list[tuple[str, str]]:
        return candidate_keys(finding.url, finding.parameter, base_url=base_url)

    return _resolve


# ---- OWASP Benchmark -------------------------------------------------------


def load_owasp_benchmark(
    expectedresults_csv: str | Path,
    *,
    base_url: str = "",
    name: str = "OWASP Benchmark",
) -> tuple[GroundTruth, dict[str, str]]:
    """Load OWASP Benchmark ground truth from ``expectedresults.csv``.

    The CSV marks each test case vulnerable or safe but does not state which
    query parameter carries the vulnerability. That is deliberate in the
    benchmark (the parameter is inside the servlet). For matching purposes the
    parameter is stored as ``""``, so a finding matches on the canonical path
    alone -- including the benign query parameters that make each test case
    unique. This is the most permissive matching the format allows; if a test
    case has several parameters and the scanner reports one of them, that is
    still credited.

    The ``category`` column (``sqli``, ``xss``, ``pathtraver``, ``ldapi``, ...)
    is loaded into :attr:`~.ieee_metrics.GroundTruth.expected_class` so class
    agreement can be scored. Without it, an LDAP-filter finding on a
    path-traversal endpoint is indistinguishable from a correct detection, and
    the recall figure reads 0.94 for a scanner that names the wrong
    vulnerability 21 % of the time it hits.

    Returns ``(ground_truth, case_index)`` where ``case_index`` maps the test
    case id to its canonical path, so a caller can audit which case produced
    which finding.
    """
    path = Path(expectedresults_csv)
    if not path.exists():
        raise FileNotFoundError(f"expected results CSV not found: {path}")

    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ValueError(f"{path} has no header row")

        id_col = _find_column(reader.fieldnames, _COL_TEST_ID)
        vuln_col = _find_column(reader.fieldnames, _COL_VULN)
        if id_col is None or vuln_col is None:
            raise ValueError(
                f"{path}: could not locate the test-case / vulnerability columns. "
                f"Header was {reader.fieldnames!r}. Expected one of "
                f"{_COL_TEST_ID} and one of {_COL_VULN}."
            )
        cat_col = _find_column(reader.fieldnames, _COL_CATEGORY)

        instances: list[tuple[tuple[str, str], bool, str]] = []
        expected_class: dict[tuple[str, str], str] = {}
        case_index: dict[str, str] = {}
        seen: set[tuple[str, str]] = set()
        skipped = 0

        for row in reader:
            case_id = (row.get(id_col) or "").strip()
            vulnerable = _truthy(row.get(vuln_col) or "")
            if not case_id or vulnerable is None:
                skipped += 1
                continue

            canonical = f"/{case_id}"
            case_index[case_id] = canonical
            key = (canonical, "")
            if key in seen:
                continue
            seen.add(key)
            # Read the class from the real column only. The per-category label
            # has a "vulnerable"/"safe" fallback below, and feeding *that* into
            # expected_class would hand the class-agreement metric a class
            # nobody can resolve -- or worse, one that resolves by accident.
            raw_category = (row.get(cat_col) or "").strip() if cat_col else ""
            category = raw_category or ("vulnerable" if vulnerable else "safe")
            instances.append((key, vulnerable, category))
            # Only *vulnerable* instances get a class label: a safe case has no
            # class to expect, and labelling it would put a benign point into
            # the class-agreement population where it can only ever be a miss.
            if vulnerable and raw_category:
                expected_class[key] = raw_category

    if not instances:
        raise ValueError(
            f"{path}: parsed 0 usable instances (skipped {skipped} row(s)). "
            "Check the truth-column values."
        )

    gt = GroundTruth(
        instances=tuple(instances),
        name=name,
        expected_class=expected_class,
    )
    case_index["_base_url"] = base_url
    return gt, case_index


# ---- generic JSON ----------------------------------------------------------

def load_json_ground_truth(
    path: str | Path,
    *,
    name: str | None = None,
) -> GroundTruth:
    """Load a JSON ground-truth table -- the extension point for any target.

    Expected shape::

        {
          "name": "my-staging-app",
          "instances": [
            {"url": "/search?q=1", "parameter": "q", "vulnerable": true,
             "category": "sqli", "expected_class": "sqli"},
            {"url": "/about",     "parameter": "",    "vulnerable": false}
          ]
        }

    A bare list of the same objects is also accepted. ``vulnerable`` accepts the
    usual boolean and string spellings. This is the path that lets the same
    pipeline score a synthetic or defect-injected target that is not OWASP
    Benchmark -- see ``scripts/evaluate.py --ground-truth my-target.json``.

    ``expected_class`` is optional and enables the class-agreement rates. When
    it is absent, the loader falls back to ``class`` / ``type`` / ``category``
    -- but only when the value names a class the shared vocabulary recognises.
    The per-category table is often written as ``{"category": "sqli"}`` anyway,
    so reading the class from it costs nothing. A ``category`` of ``safe`` /
    ``vulnerable`` / any free-form slice name therefore yields no class label,
    and the class-agreement rates come back ``None`` instead of a flattering
    ``1.0``.

    ``type`` is accepted for tables derived from the benchmark's per-case
    exports (``"type": "SQLInjection"``); prefer ``expected_class`` in anything
    hand-written, because ``type`` is also the field a *finding* carries and
    the two mean opposite things in a reader's head.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))

    if isinstance(raw, list):
        entries: list[dict[str, Any]] = raw
        gt_name = name or Path(path).stem
    elif isinstance(raw, dict):
        entries = raw.get("instances") or []
        gt_name = name or raw.get("name") or Path(path).stem
    else:
        raise ValueError(f"{path}: expected a list or an object, got {type(raw).__name__}")

    instances: list[tuple[tuple[str, str], bool, str]] = []
    expected_class: dict[tuple[str, str], str] = {}
    seen: set[tuple[str, str]] = set()

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: instance {i} is {type(entry).__name__}, expected object")

        url = str(entry.get("url") or "").strip()
        if not url:
            raise ValueError(f"{path}: instance {i} has no 'url'")

        parameter = str(entry.get("parameter") or entry.get("param") or "")
        vulnerable = _truthy(str(entry.get("vulnerable", "")))
        if vulnerable is None:
            raise ValueError(
                f"{path}: instance {i} has unrecognised 'vulnerable' value "
                f"{entry.get('vulnerable')!r}; use true/false, y/n, or 1/0."
            )

        category = str(entry.get("category") or "").strip()
        # A benign instance has no class to expect; labelling it would put a
        # point into the class-agreement population that can only ever miss.
        label = _expected_class(entry) if vulnerable else ""
        if not category:
            # No explicit category: fall back to the class label, canonicalised
            # so the per-category table groups by vulnerability instead of
            # collapsing every instance into "vulnerable" -- a breakdown that
            # says only "vulnerable vs safe" is the same information the
            # confusion matrix already carries.
            category = (canonical_class(label) or label) if label else (
                "vulnerable" if vulnerable else "safe"
            )
        key = (canonical_path(url), parameter)
        if key in seen:
            continue
        seen.add(key)
        instances.append((key, vulnerable, category))
        if label:
            expected_class[key] = label

    if not instances:
        raise ValueError(f"{path}: parsed 0 instances")

    return GroundTruth(
        instances=tuple(instances),
        name=gt_name,
        expected_class=expected_class,
    )


def _expected_class(entry: dict[str, Any]) -> str:
    """The vulnerability class a ground-truth instance expects, if it states one.

    Returns ``""`` when the entry offers nothing the shared vocabulary can
    resolve. Unresolvable is deliberately not an error: a class label is
    optional metadata, and a table that omits it must still score on detection
    alone. The distinction surfaces later, as ``None`` class-agreement rates
    instead of numbers nobody can interpret.
    """
    for field in _CLASS_KEYS:
        value = str(entry.get(field) or "").strip()
        if not value:
            continue
        if canonical_class(value) is not None:
            return value
    return ""


# ---- findings --------------------------------------------------------------

def load_findings_from_report(
    report: dict[str, Any],
    *,
    base_url: str = "",
) -> tuple[list[Finding], list[str]]:
    """Extract findings from a scan's enriched JSON report.

    Returns ``(findings, warnings)``. Warnings record any finding whose URL
    could not be interpreted -- dropped silently, they would deflate recall with
    no trace in the output.
    """
    warnings: list[str] = []
    findings: list[Finding] = []

    raw = report.get("vulnerabilities")
    if raw is None:
        raw = report.get("findings") or []
        if not raw:
            warnings.append(
                "report contains no 'vulnerabilities' key; parsed 0 findings"
            )

    for i, vuln in enumerate(raw):
        url = str(vuln.get("url") or "").strip()
        if not url:
            warnings.append(f"finding {i}: no 'url' field, skipped")
            continue

        parameter = str(
            vuln.get("parameter") or vuln.get("param") or vuln.get("param_name") or ""
        )
        # A record the scan emitted to say "this point could not be measured"
        # rather than a vulnerability claim. Ingested so the metrics can hold it
        # out of tp/fp/fn instead of reading the silence as a miss.
        status = str(vuln.get("probe_status") or "").strip().lower()
        untested = status in _UNTESTED_STATUSES

        findings.append(Finding(
            url=url,
            parameter=parameter,
            vulnerability_type=(status if untested
                                else str(vuln.get("type") or vuln.get("name") or "unknown")),
            severity=str(vuln.get("severity") or "unknown"),
            confidence=str(vuln.get("confidence") or ""),
            untested=untested,
        ))

    if base_url:
        # Keys must be normalised the same way the ground truth was.
        findings = [
            Finding(
                url=canonical_path(f.url, base_url=base_url),
                parameter=f.parameter,
                vulnerability_type=f.vulnerability_type,
                severity=f.severity,
                confidence=f.confidence,
                untested=f.untested,
            )
            for f in findings
        ]

    return findings, warnings
