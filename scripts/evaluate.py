#!/usr/bin/env python
"""Benchmark evaluation driver: run the scanner, score it, export IEEE tables.

Four modes, so the pipeline is testable at every stage and the same code path
serves an IEEE experiment and a quick regression check.

``live``
    Scan a running target and score it against a ground-truth table.
    Requires the target to be up and the labels to exist.

``--from-report``
    Score a JSON report the scanner already produced. No target needed, no
    network. This is the reproducibility path: keep the report, re-derive the
    metrics later without re-running the scan.

``--synthetic``
    Skip the scanner entirely and score a **canned finding list** against a
    ground-truth table. Runs in milliseconds with no network and no target --
    this is how the metric arithmetic gets regression-tested, and how a new
    ground-truth table can be validated before spending an hour on a scan.

``--template-ground-truth``
    Print a starter JSON ground-truth file and exit. Any target can be scored
    with this tool, not only OWASP Benchmark: label the instances you can
    reach, run ``--synthetic`` to sanity-check the table, then run ``live``.

Examples::

    # OWASP Benchmark, scoring a report you already have
    python scripts/evaluate.py --from-report reports/scan.enriched.json \\
        --benchmark-csv testbed/expectedresults.csv --out results/

    # Any other target: write your own labels, then scan and score
    python scripts/evaluate.py --template-ground-truth -o my-target.json
    python scripts/evaluate.py http://127.0.0.1:9001 --ground-truth my-target.json

    # Validate the metric arithmetic with no target at all
    python scripts/evaluate.py --synthetic --ground-truth my-target.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Allow running as `python scripts/evaluate.py` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web_security_scanner.core.benchmark_ground_truth import (  # noqa: E402
    benchmark_key_resolver,
    json_key_resolver,
    load_findings_from_report,
    load_json_ground_truth,
    load_owasp_benchmark,
)
from web_security_scanner.core.ieee_metrics import (  # noqa: E402
    GroundTruth,
    compute_metrics,
    render_console_summary,
    write_results,
)

_GT_TEMPLATE = {
    "name": "replace-me",
    "_comment": [
        "Ground truth for ANY target. One object per instance you can label.",
        "'vulnerable' accepts true/false, y/n, 1/0.",
        "'url' may be a path (/x?q=1) or absolute; host and query order are",
        "normalised away. 'category' is free-form and drives the per-category",
        "table. Instances the scanner never reports become TN (if benign) or",
        "FN (if vulnerable), so label the negatives too -- without them the",
        "specificity and FPR figures are undefined.",
    ],
    "instances": [
        {"url": "/example/search?q=1", "parameter": "q", "vulnerable": True,
         "category": "sqli"},
        {"url": "/example/about", "parameter": "", "vulnerable": False,
         "category": "info"},
    ],
}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="Target URL to scan (live mode).")
    p.add_argument("--ground-truth", type=Path,
                   help="JSON ground-truth table (any target).")
    p.add_argument("--benchmark-csv", type=Path,
                   help="OWASP Benchmark expectedresults.csv.")
    p.add_argument("--from-report", type=Path,
                   help="Score an existing scan report instead of scanning.")
    p.add_argument("--synthetic", action="store_true",
                   help="Score a canned finding list; no scanner, no network.")
    p.add_argument("--template-ground-truth", action="store_true",
                   help="Write a starter ground-truth JSON and exit.")
    p.add_argument("-o", "--out", type=Path, default=Path("results"),
                   help="Output directory (default: results/).")
    p.add_argument("--basename", default="results",
                   help="Output filename stem (default: results).")

    # Scan controls, passed through to WebSecurityScanner.
    p.add_argument("--profile", default="intense",
                   choices=["quick", "balanced", "intense", "mapping"],
                   help="Scan profile (default: intense, the coverage profile).")
    p.add_argument("--max-payloads", type=int, default=None,
                   help="Payload cap per tester; the recall-per-request knob.")
    p.add_argument("--threads", type=int, default=None)
    p.add_argument("--timeout", type=int, default=None)
    p.add_argument("--global-seed", type=int, default=None,
                   help="Seed for reproducibility. Use it on every run that "
                        "goes into the paper.")
    p.add_argument("--no-map", action="store_true",
                   help="Skip site mapping (faster, narrower).")
    p.add_argument("--target-list", type=Path,
                   help="JSON array of {url, param, method} to probe. Pass this "
                        "when the labelled instances are not reachable by "
                        "crawling from the target URL: OWASP Benchmark's test "
                        "cases are unlinked, so --no-map against the site root "
                        "probes nothing and the run reports recall 0.0 over the "
                        "full ground truth.")
    p.add_argument("--enable-waf-evasion", action="store_true",
                   help="Enable adaptive WAF-evasion retries (Track A arm).")
    p.add_argument("--no-verify-ssl", action="store_true",
                   help="Accept a self-signed certificate. OWASP Benchmark serves "
                        "HTTPS with one; without this flag every request degrades "
                        "to status_code=0, the scan reports nothing, and the run "
                        "still prints a well-formed precision/recall table -- a "
                        "silent all-zero measurement rather than an error.")
    p.add_argument("--allow-private-redirects", action="store_true",
                   help="Permit redirects to private/loopback addresses. Required "
                        "for a self-hosted lab target that redirects back to "
                        "itself (OWASP Benchmark does), because the SSRF guard "
                        "refuses those by default. Only for authorized internal "
                        "targets.")
    return p.parse_args(argv)


# ---- modes -----------------------------------------------------------------


def _load_ground_truth(args: argparse.Namespace):
    """Return ``(ground_truth, key_resolver)``.

    The resolver differs per source because the key encodings differ: the
    benchmark is keyed by test-case id while findings carry concrete probed
    URLs, whereas a JSON table authored for this tool is already keyed the way
    findings are. Getting this wrong does not crash -- it silently reports
    recall 0.0 on a run that found real vulnerabilities.
    """
    if args.benchmark_csv:
        gt, _index = load_owasp_benchmark(args.benchmark_csv)
        return gt, benchmark_key_resolver()
    if args.ground_truth:
        return load_json_ground_truth(args.ground_truth), json_key_resolver()
    raise SystemExit(
        "error: no ground truth. Pass --benchmark-csv (OWASP Benchmark) or\n"
        "       --ground-truth FILE (any target). Use --template-ground-truth\n"
        "       to generate a starter file."
    )


def _synthetic_findings(gt: GroundTruth) -> list:
    """A canned finding list derived from the ground truth itself.

    Reports roughly 70 % of the vulnerable instances plus one spurious finding
    on a benign one, so the arithmetic can be exercised end to end without a
    target. Deliberately includes an unlabelled finding to keep the
    FP-outside-ground-truth path covered.
    """
    from web_security_scanner.core.ieee_metrics import Finding

    vulnerable = [key for key, flag, _ in gt.instances if flag]
    benign = [key for key, flag, _ in gt.instances if not flag]

    findings = [Finding(url=u, parameter=p, vulnerability_type="synthetic")
                for u, p in vulnerable[: max(1, len(vulnerable) * 7 // 10)]]
    if benign:
        findings.append(Finding(url=benign[0][0], parameter=benign[0][1],
                                vulnerability_type="synthetic-false-positive"))
    findings.append(Finding(url="/not/covered/by/ground-truth", parameter="zz",
                            vulnerability_type="synthetic-outside"))
    return findings


async def _run_scan(args: argparse.Namespace) -> dict:
    """Invoke the scanner in-process and return its results dict."""
    from web_security_scanner.cli import _build_config
    from web_security_scanner.web_security_scanner_async import WebSecurityScanner

    argv = [args.target, "--profile", args.profile]
    if args.max_payloads is not None:
        argv += ["--max-payloads", str(args.max_payloads)]
    if args.threads is not None:
        argv += ["--threads", str(args.threads)]
    if args.timeout is not None:
        argv += ["--timeout", str(args.timeout)]
    if args.global_seed is not None:
        argv += ["--global-seed", str(args.global_seed)]
    if args.no_map:
        argv += ["--no-map"]
    if args.target_list:
        argv += ["--target-list", str(args.target_list)]
    if args.enable_waf_evasion:
        argv += ["--enable-waf-evasion"]
    if args.no_verify_ssl:
        argv += ["--no-verify-ssl"]
    if args.allow_private_redirects:
        argv += ["--allow-private-redirects"]
    # Reports are written separately by this script.
    argv += ["--no-output-pdf", "--no-output-json"]

    parser = _build_parser_for(argv)
    parsed = parser.parse_args(argv)
    config = _build_config(parsed)

    # A --target-list has to reach the scanner through the same argument the CLI
    # uses. run_scan() defaults it to None, which silently keeps Phase 1 recon and
    # makes the run probe only the seed URL: the scan still reports, still scores,
    # and simply misses every labelled instance.
    target_list = None
    if args.target_list:
        from web_security_scanner.cli import _load_target_list

        try:
            target_list = _load_target_list(str(args.target_list))
        except (OSError, ValueError) as exc:
            raise SystemExit(f"error: --target-list: {exc}") from exc

    scanner = WebSecurityScanner(config)
    await scanner.initialize()
    return await scanner.run_scan(
        args.target,
        profile=parsed.profile,
        generate_map=parsed.generate_map,
        target_list=target_list,
    )


def _build_parser_for(argv: list[str]):
    from web_security_scanner.cli import _build_parser
    parser = _build_parser()
    parser.parse_args(["scan", *argv])  # validate early
    return _ScanArgvAdapter(parser)


class _ScanArgvAdapter:
    """Turn ``parser.parse_args([...])`` into a scan-subcommand parse."""

    def __init__(self, parser) -> None:
        self._parser = parser

    def parse_args(self, argv: list[str]):
        return self._parser.parse_args(["scan", *argv])


def _load_report(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.template_ground_truth:
        args.out.mkdir(parents=True, exist_ok=True)
        path = args.out / "ground_truth.template.json"
        path.write_text(json.dumps(_GT_TEMPLATE, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
        print(f"wrote starter ground truth: {path}")
        print("edit 'instances', then run:  evaluate.py --synthetic "
              "--ground-truth " + str(path))
        return 0

    gt, resolve_key = _load_ground_truth(args)

    if args.synthetic:
        findings = _synthetic_findings(gt)
        warnings: list[str] = []
        print(f"[synthetic] scored {len(findings)} canned finding(s) -- "
              "no scanner, no network.", file=sys.stderr)
    elif args.from_report:
        report = _load_report(args.from_report)
        findings, warnings = load_findings_from_report(report)
        print(f"[report] {args.from_report}: {len(findings)} finding(s)", file=sys.stderr)
    elif args.target:
        results = asyncio.run(_run_scan(args))
        from web_security_scanner.report_engine import build_enriched_report
        report = build_enriched_report(results)
        findings, warnings = load_findings_from_report(report)
        # Persist the enriched report so a later --from-report run can
        # reproduce this scoring without re-scanning.
        args.out.mkdir(parents=True, exist_ok=True)
        report_path = args.out / f"{args.basename}.report.json"
        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8",
        )
        print(f"[live] report saved: {report_path}", file=sys.stderr)
    else:
        raise SystemExit(
            "error: no mode selected. Use --from-report, --synthetic, or pass a "
            "target URL. See --help."
        )

    for warning in warnings:
        print(f"[warn] {warning}", file=sys.stderr)

    result = compute_metrics(findings, gt, key_resolver=resolve_key)
    paths = write_results(result, args.out, basename=args.basename)

    print()
    print(render_console_summary(result))
    print(f" results.json  -> {paths['json']}")
    print(f" metrics.md    -> {paths['markdown']}")
    print(f" metrics.tex   -> {paths['latex']}")
    if warnings:
        print(f" {len(warnings)} warning(s) during finding ingestion -- see stderr.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
