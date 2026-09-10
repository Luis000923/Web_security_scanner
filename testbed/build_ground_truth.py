#!/usr/bin/env python3
"""build_ground_truth.py — Ground-truth generator for the DAST testbed.

Produces the ``ground_truth.json`` file consumed by ``tools/eval_oracle.py``
(Phase 4 evaluation oracle). Zero third-party dependencies — stdlib only.

--------------------------------------------------------------------------
WHAT IT DOES
--------------------------------------------------------------------------

OWASP Benchmark ships two authoritative artefacts that, joined on the
test-case name, give us everything the oracle needs:

  * ``expectedresults-1.2.csv``      (repo root)
        # test name, category, real vulnerability, cwe
        BenchmarkTest00008,sqli,true,89
        BenchmarkTest00009,hash,false,328

  * ``data/benchmark-crawler-http.xml``
        <benchmarkTest URL="https://localhost:8443/benchmark/sqli-00/BenchmarkTest00008"
                       tcName="BenchmarkTest00008" tcType="SERVLET">
            <getparam name="BenchmarkTest00008" value="..." />
        </benchmarkTest>

    The single child element names the injection vector
    (``getparam`` / ``formparam`` / ``cookie`` / ``header``) and the
    parameter name.

We join them on ``tcName`` and emit one oracle record per test case:

    {"url": "...", "param": "...", "type": "SQLInjection", "vulnerable": true,
     "vector": "getparam", "cwe": 89, "tc": "BenchmarkTest00008"}

``vector``, ``cwe`` and ``tc`` are ignored by the oracle (it only keys on
url + param + canonical type) but kept for slicing the results later.

--------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------

    # Download both artefacts straight from GitHub and write the default file:
    python testbed/build_ground_truth.py --download

    # Use a local BenchmarkJava checkout instead:
    python testbed/build_ground_truth.py --benchmark-repo ~/src/BenchmarkJava

    # Point the URLs at the docker-compose testbed and keep only the
    # vectors our scanner actually fuzzes (query + body):
    python testbed/build_ground_truth.py --download \\
        --base-url https://127.0.0.1:8443 --vectors getparam,formparam

Options:
    --benchmark-repo DIR   Local BenchmarkJava checkout. The CSV is read from
                           <DIR>/expectedresults-1.2.csv and the XML from
                           <DIR>/data/benchmark-crawler-http.xml.
    --download             Fetch both artefacts from the OWASP-Benchmark repo
                           (master) into a local cache dir (--cache-dir).
    --cache-dir DIR        Where --download stores its files.
                           Default: testbed/.cache/benchmark
    --expectedresults PATH / --crawler-xml PATH
                           Explicit overrides for either input file.
    --base-url URL         Replace scheme://host on every test URL (path kept).
                           Default: keep the XML's https://localhost:8443 .
                           Use https://127.0.0.1:8443 to match docker-compose.
    --categories LIST      Comma list of Benchmark categories to include.
                           Default: sqli,cmdi,xss,pathtraver,ldapi
    --vectors LIST         Comma list of vectors to include.
                           Choices: getparam,formparam,cookie,header
                           Default: getparam,formparam
    --no-traps             Drop the ``vulnerable: false`` records (kept by
                           default — they are the oracle's FPR denominator).
    --out PATH             Output file. Default: testbed/ground_truth.json
    --preview N            Also print the first N records to stdout.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

_RAW_BASE = "https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/master"
_CSV_REMOTE = f"{_RAW_BASE}/expectedresults-1.2.csv"
_XML_REMOTE = f"{_RAW_BASE}/data/benchmark-crawler-http.xml"

# Benchmark category slug -> the ``type`` string we hand the oracle. These
# spellings all fold onto the oracle's canonical buckets via canonicalize_type
# (see tools/eval_oracle.py::_TYPE_ALIASES), so they compare equal to whatever
# the scanner emits for the same class of finding.
_CATEGORY_TO_TYPE: dict[str, str] = {
    "sqli": "SQLInjection",
    "cmdi": "CommandInjection",
    "xss": "XSS",
    "pathtraver": "PathTraversal",
    "ldapi": "LDAPInjection",
    "xpathi": "XPathInjection",
    # Non-web-injectable Benchmark categories (crypto, hash, weakrand,
    # trustbound, securecookie) are intentionally absent: a black-box DAST
    # cannot observe them, so scoring against them would only depress recall
    # with cases outside the tool's design scope. Add them to --categories
    # explicitly if you want them in the file anyway.
}

_DEFAULT_CATEGORIES = ["sqli", "cmdi", "xss", "pathtraver", "ldapi"]
_DEFAULT_VECTORS = ["getparam", "formparam"]
_VALID_VECTORS = {"getparam", "formparam", "cookie", "header"}


# --------------------------------------------------------------------------
# Inputs
# --------------------------------------------------------------------------

def _fetch(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] downloading {url}\n      -> {dest}", file=sys.stderr)
    req = urllib.request.Request(url, headers={"User-Agent": "build_ground_truth/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (trusted host)
        dest.write_bytes(resp.read())
    return dest


def resolve_inputs(args: argparse.Namespace) -> tuple[Path, Path]:
    """Return (expectedresults_csv, crawler_xml) as local paths."""
    csv_path: Path | None = Path(args.expectedresults) if args.expectedresults else None
    xml_path: Path | None = Path(args.crawler_xml) if args.crawler_xml else None

    if args.benchmark_repo:
        repo = Path(args.benchmark_repo).expanduser()
        csv_path = csv_path or repo / "expectedresults-1.2.csv"
        xml_path = xml_path or repo / "data" / "benchmark-crawler-http.xml"

    if args.download:
        cache = Path(args.cache_dir)
        if csv_path is None or not csv_path.exists():
            csv_path = _fetch(_CSV_REMOTE, cache / "expectedresults-1.2.csv")
        if xml_path is None or not xml_path.exists():
            xml_path = _fetch(_XML_REMOTE, cache / "benchmark-crawler-http.xml")

    if not csv_path or not xml_path:
        sys.exit("[ERROR] need --download, --benchmark-repo, or both explicit "
                 "--expectedresults / --crawler-xml paths.")
    for p in (csv_path, xml_path):
        if not p.exists():
            sys.exit(f"[ERROR] input not found: {p} (try --download)")
    return csv_path, xml_path


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def parse_expectedresults(path: Path) -> dict[str, tuple[str, bool, int]]:
    """tcName -> (category, is_real_vulnerability, cwe)."""
    out: dict[str, tuple[str, bool, int]] = {}
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.reader(fh):
            if not row or row[0].lstrip().startswith("#") or len(row) < 3:
                continue
            name = row[0].strip()
            category = row[1].strip()
            vulnerable = row[2].strip().lower() == "true"
            try:
                cwe = int(row[3]) if len(row) > 3 and row[3].strip() else 0
            except ValueError:
                cwe = 0
            out[name] = (category, vulnerable, cwe)
    return out


def parse_crawler_xml(path: Path) -> dict[str, tuple[str, str, str]]:
    """tcName -> (url, vector, param_name).

    The vector is the tag of a child element (getparam / formparam / cookie /
    header). A test case may carry several children: real decoy parameters
    (e.g. empty ``username`` / ``password``) alongside the tainted one. By
    OWASP Benchmark convention the injectable parameter is the one whose name
    equals the test-case name (``BenchmarkTestNNNNN``); we prefer that child
    and fall back to the first vector child otherwise.
    """
    out: dict[str, tuple[str, str, str]] = {}
    root = ET.parse(path).getroot()
    for tc in root.findall("benchmarkTest"):
        name = tc.get("tcName") or ""
        url = tc.get("URL") or ""
        if not name or not url:
            continue
        vector_children = [
            (child.tag.split("}")[-1], child.get("name") or "")
            for child in tc
            if child.tag.split("}")[-1] in _VALID_VECTORS
        ]
        chosen = next((vc for vc in vector_children if vc[1] == name),
                      vector_children[0] if vector_children else ("", ""))
        out[name] = (url, chosen[0], chosen[1])
    return out


def rehost(url: str, base_url: str | None) -> str:
    if not base_url:
        return url
    base = urlsplit(base_url)
    path = urlsplit(url).path
    return f"{base.scheme}://{base.netloc}{path}"


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------

def build_records(
    expected: dict[str, tuple[str, bool, int]],
    crawler: dict[str, tuple[str, str, str]],
    *,
    categories: set[str],
    vectors: set[str],
    base_url: str | None,
    keep_traps: bool,
) -> tuple[list[dict], dict[str, int]]:
    records: list[dict] = []
    stats = {"total": 0, "no_crawl_entry": 0, "cat_filtered": 0,
             "vector_filtered": 0, "trap_dropped": 0, "positives": 0, "traps": 0}

    for name, (category, vulnerable, cwe) in sorted(expected.items()):
        stats["total"] += 1
        if category not in categories:
            stats["cat_filtered"] += 1
            continue
        if name not in crawler:
            stats["no_crawl_entry"] += 1
            continue
        url, vector, param = crawler[name]
        if vector not in vectors:
            stats["vector_filtered"] += 1
            continue
        if not vulnerable and not keep_traps:
            stats["trap_dropped"] += 1
            continue

        vuln_type = _CATEGORY_TO_TYPE.get(category, category)
        records.append({
            "url": rehost(url, base_url),
            "param": param or None,
            "type": vuln_type,
            "vulnerable": vulnerable,
            "vector": vector,
            "cwe": cwe,
            "tc": name,
        })
        stats["positives" if vulnerable else "traps"] += 1

    return records, stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="build_ground_truth.py",
                                 description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benchmark-repo", default=None)
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--cache-dir", default="testbed/.cache/benchmark")
    ap.add_argument("--expectedresults", default=None)
    ap.add_argument("--crawler-xml", default=None)
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--categories", default=",".join(_DEFAULT_CATEGORIES))
    ap.add_argument("--vectors", default=",".join(_DEFAULT_VECTORS))
    ap.add_argument("--no-traps", dest="keep_traps", action="store_false")
    ap.add_argument("--out", default="testbed/ground_truth.json")
    ap.add_argument("--emit-targets", default=None, metavar="PATH",
                    help="Also write a scanner --target-list file: an array of "
                         "{url, param, method:'GET'} for every in-scope endpoint "
                         "(positives AND traps), deduped.")
    ap.add_argument("--preview", type=int, default=2, metavar="N")
    args = ap.parse_args(argv)

    categories = {c.strip() for c in args.categories.split(",") if c.strip()}
    vectors = {v.strip() for v in args.vectors.split(",") if v.strip()}
    bad = vectors - _VALID_VECTORS
    if bad:
        sys.exit(f"[ERROR] unknown --vectors: {sorted(bad)}; valid: {sorted(_VALID_VECTORS)}")

    csv_path, xml_path = resolve_inputs(args)
    expected = parse_expectedresults(csv_path)
    crawler = parse_crawler_xml(xml_path)
    if not expected:
        sys.exit(f"[ERROR] no rows parsed from {csv_path}")
    if not crawler:
        sys.exit(f"[ERROR] no <benchmarkTest> entries parsed from {xml_path}")

    records, stats = build_records(
        expected, crawler,
        categories=categories, vectors=vectors,
        base_url=args.base_url, keep_traps=args.keep_traps,
    )
    if not records:
        sys.exit("[ERROR] 0 records after filtering — check --categories / --vectors")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")

    print("=" * 62, file=sys.stderr)
    print(f"  expectedresults rows : {stats['total']}", file=sys.stderr)
    print(f"  category-filtered    : {stats['cat_filtered']}", file=sys.stderr)
    print(f"  no crawler entry     : {stats['no_crawl_entry']}", file=sys.stderr)
    print(f"  vector-filtered      : {stats['vector_filtered']}", file=sys.stderr)
    print(f"  traps dropped        : {stats['trap_dropped']}", file=sys.stderr)
    print("-" * 62, file=sys.stderr)
    print(f"  records written      : {len(records)}  "
          f"({stats['positives']} positive / {stats['traps']} traps)", file=sys.stderr)
    print(f"  -> {out_path}", file=sys.stderr)
    print("=" * 62, file=sys.stderr)

    if args.emit_targets:
        seen: set[tuple[str, str | None]] = set()
        targets: list[dict] = []
        for r in records:
            key = (r["url"], r["param"])
            if key in seen:
                continue
            seen.add(key)
            targets.append({"url": r["url"], "param": r["param"], "method": "GET"})
        tp = Path(args.emit_targets)
        tp.parent.mkdir(parents=True, exist_ok=True)
        tp.write_text(json.dumps(targets, indent=2) + "\n", encoding="utf-8")
        print(f"  target-list written  : {len(targets)}  -> {tp}", file=sys.stderr)

    if args.preview > 0:
        print(json.dumps(records[:args.preview], indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
