"""
Command-line interface for the Web Security Scanner.

Single entrypoint replacing the old GUI/launcher. Usage:

    webscanner scan <url> [options]
"""

import argparse
import asyncio
import json
import logging
import random
import sys
from pathlib import Path

from colorama import Fore, Style
from colorama import init as colorama_init

from .banner import print_banner
from .events.event_emitter import ScanEventType
from .reports import generate_reports_async
from .utils.i18n import i18n
from .utils.validation import InvalidTargetError, validate_target_url
from .web_security_scanner_async import WebSecurityScanner

PROFILES = ["quick", "balanced", "intense", "mapping"]
LANGUAGES_FILE = Path(__file__).parent / "languages.yaml"

SEVERITY_COLOR = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.CYAN,
    "info": Fore.WHITE,
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webscanner",
        description="Async web security scanner (authorized testing only).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a target URL for vulnerabilities.")
    scan.add_argument("url", help="Target URL (include http:// or https://).")
    scan.add_argument("-p", "--profile", choices=PROFILES, default="balanced",
                      help="Scan profile (default: balanced).")
    scan.add_argument("--threads", type=int, default=None,
                      help="Max concurrent requests (overrides profile).")
    scan.add_argument("--timeout", type=int, default=None,
                      help="Per-request timeout in seconds.")
    scan.add_argument("--rate-limit", type=float, default=0.0,
                      help="Minimum seconds between requests (0 = no limit).")
    scan.add_argument("--payload-delay", type=float, default=0.0,
                      help="Delay between payloads per tester, in seconds.")
    scan.add_argument("--max-payloads", type=int, default=50,
                      help="Max payloads per parameter (default: 50).")
    scan.add_argument("--waf-bypass-transforms", default="",
                      help="Comma-separated payload transforms applied to every vector "
                           "for WAF evasion (e.g. 'random_case,url_encode').")
    scan.add_argument("--max-duration", type=float, default=None,
                      help="Global cap on total tester time, in seconds.")
    scan.add_argument("--allow-destructive", action="store_true",
                      help="Allow payloads that may modify/destroy target state.")
    scan.add_argument("--no-verify-ssl", dest="verify_ssl", action="store_false",
                      help="Disable TLS certificate verification.")
    scan.add_argument("--allow-private-redirects", action="store_true",
                      help="Allow following redirects to private/loopback IPs "
                           "(SSRF guard is ON by default; only for authorized "
                           "internal targets).")
    scan.add_argument("--no-map", dest="generate_map", action="store_false",
                      help="Skip website crawling/mapping.")
    scan.add_argument("--max-depth", type=int, default=3,
                      help="Max crawl depth for the site mapper (default: 3).")
    scan.add_argument("--max-urls", type=int, default=1000,
                      help="Hard cap on URLs the crawler will visit (default: 1000).")
    # --- Phase 1 recon (route-mapper integration) ---
    scan.add_argument("--sitemap", dest="sitemap", action="store_true",
                      help="Seed the crawl frontier from /sitemap.xml.")
    scan.add_argument("--jitter", type=float, default=0.0,
                      help="Random +/- seconds added to the inter-request delay "
                           "to blur the traffic pattern (default: 0).")
    scan.add_argument("--parse-js", dest="parse_js", action="store_true", default=True,
                      help="Mine endpoints from .js bundles (default: on).")
    scan.add_argument("--no-parse-js", dest="parse_js", action="store_false",
                      help="Disable JavaScript endpoint mining.")
    # --- Phase 4: headless-browser recon (SPA + DOM-XSS) ---
    scan.add_argument("--browser", dest="use_browser", action="store_true",
                      help="Run a headless-browser recon pass (Playwright): execute "
                           "client JS, intercept XHR/fetch for SPA endpoints, and "
                           "trace DOM-XSS source->sink flows. No-op if Playwright "
                           "is not installed.")
    scan.add_argument("--browser-nav-timeout", type=float, default=15.0,
                      help="Per-page navigation timeout for --browser (seconds).")
    scan.add_argument("--browser-max-pages", type=int, default=6,
                      help="Max page navigations for the --browser recon pass.")
    scan.add_argument("--proxy", default=None,
                      help="Route all traffic through a proxy "
                           "(http://host:port or socks5://host:port).")
    scan.add_argument("--ua-file", default=None,
                      help="File with one User-Agent per line; rotated per request.")
    scan.add_argument("-o", "--output", default="reports",
                      help="Output directory for reports (default: reports).")
    scan.add_argument("-f", "--format", default="json,html",
                      help="Report formats, comma-separated: json,html (default: both).")
    scan.add_argument("--lang", choices=["en", "es"], default="en",
                      help="Output language (default: en).")
    scan.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")

    # --- Phase 2: experiment control / ablation toggles ---
    exp = scan.add_argument_group(
        "experiment controls",
        "Feature flags for empirical evaluation / ablation studies.",
    )
    exp.add_argument("--telemetry-dir", default=None, metavar="PATH",
                     help="Enable per-probe telemetry and write the JSONL run log "
                          "into this directory.")
    exp.add_argument("--no-interleave", dest="interleave", action="store_false",
                     help="Ablation: skip _interleave_by_context() in the payload "
                          "pipeline (payloads stay in corpus order per context).")
    exp.add_argument("--no-priority", dest="priority", action="store_false",
                     help="Ablation: skip _prioritize() (no confidence/severity sort).")
    exp.add_argument("--payload-order", choices=["natural", "random", "freq"],
                     default="natural",
                     help="Payload injection order strategy (default: natural / "
                          "corpus order). 'random' shuffles via the stdlib RNG; "
                          "'freq' leads with the most populous context groups.")
    exp.add_argument("--no-runtime-confirm", dest="runtime_confirm",
                     action="store_false",
                     help="Ablation: disable two-stage validation. Testers report "
                          "with the a-priori payload confidence and skip second-"
                          "opinion checks like confirm_time_based().")
    exp.add_argument("--no-adaptive-sorting", dest="adaptive_sorting",
                     action="store_false",
                     help="Ablation: disable Phase 3 live heuristic ordering. "
                          "Payload order stays fixed to the a-priori pipeline "
                          "instead of being re-sorted per injection point as "
                          "anomaly signals accumulate.")
    exp.add_argument("--target-list", default=None, metavar="FILE.json",
                     help="JSON file with an array of {url, param, method} objects. "
                          "Populates the Phase 2 target queue directly and skips "
                          "the crawler/recon phase entirely.")
    exp.add_argument("--global-seed", type=int, default=None, metavar="INT",
                     help="Seed random.seed() at startup for full reproducibility "
                          "of random payload order, User-Agent rotation and "
                          "payload mutations.")

    ai = scan.add_argument_group(
        "AI agent (ai_module)",
        "Optional LLM-assisted triage and payload synthesis. Degrades "
        "gracefully: if ai_module isn't installed or the inference server is "
        "down, the scan continues on its traditional heuristics.")
    ai.add_argument("--ai-verify", action="store_true",
                    help="Send each heuristic finding to AgentClient.triage_finding() "
                         "with the HTTP request/response context. Findings the agent "
                         "confidently rates a false positive are dropped; the rest are "
                         "annotated with the agent's verdict (ai_verified/ai_confidence).")
    ai.add_argument("--ai-synthesize", action="store_true",
                    help="When a parameter's static payload list is exhausted without "
                         "a hit, ask AgentClient.synthesize_payloads() for adapted "
                         "vectors (WAF/framework-aware) and replay the cheap checks.")
    ai.add_argument("--ai-backend", default=None,
                    choices=["openai", "transformers", "echo"],
                    help="AgentClient backend (default: env AI_AGENT_BACKEND or 'openai').")
    ai.add_argument("--ai-base-url", default=None, metavar="URL",
                    help="OpenAI-compatible endpoint for the 'openai' backend "
                         "(default: http://127.0.0.1:8000/v1).")
    ai.add_argument("--ai-model", default=None, metavar="NAME",
                    help="Model / adapter name passed to the backend.")
    ai.add_argument("--ai-fp-threshold", type=float, default=0.75, metavar="0-1",
                    help="Minimum agent confidence required to discard a finding as "
                         "a false positive (default: 0.75).")
    return parser


class ProgressReporter:
    """Minimalist single-line CLI progress indicator.

    Rewrites the current terminal line with ``\\r`` as URLs are scanned, so the
    user gets live feedback during long crawls without flooding the scrollback.
    Any other output (vulns, errors) calls :meth:`clear` first so the transient
    progress line never gets interleaved into permanent log lines.
    """

    def __init__(self, enabled: bool = True):
        # Only animate on a real TTY; piped/redirected output stays clean.
        self.enabled = enabled and sys.stdout.isatty()
        self._active = False
        self._width = 0

    def update(self, current: int, total: int):
        if not self.enabled:
            return
        line = f"{Fore.GREEN}[+] Escaneando: {current}/{total} URLs completadas...{Style.RESET_ALL}"
        self._width = max(self._width, len(line))
        sys.stdout.write("\r" + line)
        sys.stdout.flush()
        self._active = True

    def clear(self):
        """Wipe the progress line so the next print starts clean."""
        if self.enabled and self._active:
            sys.stdout.write("\r" + " " * self._width + "\r")
            sys.stdout.flush()
            self._active = False


def _register_listeners(scanner: WebSecurityScanner, verbose: bool,
                        progress: "ProgressReporter"):
    """Wire scan events to terminal output (replaces the old GUI callbacks)."""

    def on_vuln(**kw):
        progress.clear()
        v = kw.get("vulnerability", {})
        sev = str(v.get("severity", "info")).lower()
        color = SEVERITY_COLOR.get(sev, Fore.WHITE)
        print(f"{color}[VULN] {v.get('severity','?').upper():<8}{Style.RESET_ALL} "
              f"{v.get('type','?')} @ {v.get('url','?')} "
              f"(param={v.get('parameter','-')}, payload={str(v.get('payload',''))[:60]})")

    def on_error(**kw):
        progress.clear()
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {kw.get('error','')}", file=sys.stderr)

    def on_progress(**kw):
        if verbose:
            progress.clear()
            print(f"{Fore.BLUE}[..]{Style.RESET_ALL} {kw.get('message','')}")

    def on_log(**kw):
        if verbose:
            progress.clear()
            print(f"{Fore.WHITE}{Style.DIM}    {kw.get('message','')}{Style.RESET_ALL}")

    def on_url_scanned(**kw):
        progress.update(int(kw.get("current", 0)), int(kw.get("total", 0)))

    scanner.event_emitter.on(ScanEventType.VULNERABILITY_FOUND, on_vuln)
    scanner.event_emitter.on(ScanEventType.ERROR, on_error)
    scanner.event_emitter.on(ScanEventType.PROGRESS_UPDATE, on_progress)
    scanner.event_emitter.on(ScanEventType.LOG_MESSAGE, on_log)
    scanner.event_emitter.on(ScanEventType.URL_SCANNED, on_url_scanned)


def _load_ua_file(path: str) -> list[str]:
    """Read a User-Agent list file (one per line, '#' comments ignored)."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [s.strip() for s in lines if s.strip() and not s.lstrip().startswith("#")]


def _build_config(args) -> dict:
    core = {
        "rate_limit": args.rate_limit,
        "verify_ssl": args.verify_ssl,
        "allow_private_redirects": args.allow_private_redirects,
    }
    if args.threads is not None:
        core["max_concurrency"] = args.threads
    if args.timeout is not None:
        core["timeout"] = args.timeout
    if getattr(args, "proxy", None):
        core["proxy"] = args.proxy
    if getattr(args, "ua_file", None):
        uas = _load_ua_file(args.ua_file)
        if uas:
            core["extra_user_agents"] = uas
    testers = {
        "payload_delay": args.payload_delay,
        "max_payloads": args.max_payloads,
        "allow_destructive": args.allow_destructive,
        "waf_bypass_transforms": [
            t.strip() for t in getattr(args, "waf_bypass_transforms", "").split(",") if t.strip()
        ],
        # Phase 2 ablation toggles (consumed by VulnerabilityTester).
        "interleave": getattr(args, "interleave", True),
        "priority": getattr(args, "priority", True),
        "payload_order": getattr(args, "payload_order", "natural"),
        "runtime_confirm": getattr(args, "runtime_confirm", True),
        # Phase 3 live heuristic ordering (adaptive feedback loop).
        "adaptive_sorting": getattr(args, "adaptive_sorting", True),
        # ai-agent: optional LLM triage / payload synthesis.
        "ai_verify": getattr(args, "ai_verify", False),
        "ai_synthesize": getattr(args, "ai_synthesize", False),
        "ai_backend": getattr(args, "ai_backend", None),
        "ai_base_url": getattr(args, "ai_base_url", None),
        "ai_model": getattr(args, "ai_model", None),
        "ai_fp_threshold": getattr(args, "ai_fp_threshold", 0.75),
    }
    recon = {
        "max_urls": args.max_urls,
        "max_depth": args.max_depth,
        "jitter": args.jitter,
        "parse_js": args.parse_js,
        "use_sitemap": args.sitemap,
        "use_browser": getattr(args, "use_browser", False),
        "browser_nav_timeout": getattr(args, "browser_nav_timeout", 15.0),
        "browser_max_pages": getattr(args, "browser_max_pages", 6),
    }
    config: dict = {"core": core, "testers": testers, "recon": recon}
    # Phase 3: carried through so the scanner can stamp the reproducibility
    # manifest with the exact seed this run was launched with (or None).
    config["global_seed"] = getattr(args, "global_seed", None)
    if getattr(args, "telemetry_dir", None):
        telemetry = {"enabled": True, "dir": args.telemetry_dir}
        if getattr(args, "global_seed", None) is not None:
            # Pin the run id so a seeded run is trivially re-identifiable.
            telemetry["run_id"] = f"seed{args.global_seed}"
        config["telemetry"] = telemetry
    return config


def _load_target_list(path: str) -> list[dict]:
    """Parse a --target-list JSON file into a list of target dicts.

    Expected shape: a JSON array of objects, each with at least ``url`` and
    optionally ``param`` and ``method`` (``method`` defaults to GET; the testers
    are GET-oriented today so it is advisory). Raises ``ValueError`` on a
    malformed file so the CLI can report and exit cleanly.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("target-list must be a JSON array of objects")
    out: list[dict] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict) or not entry.get("url"):
            raise ValueError(f"target-list entry {i} is missing a 'url' field")
        out.append({
            "url": str(entry["url"]),
            "param": entry.get("param"),
            "method": str(entry.get("method", "GET")).upper(),
        })
    return out


async def _run_scan(args) -> int:
    try:
        args.url = validate_target_url(args.url)
    except InvalidTargetError as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {e}", file=sys.stderr)
        return 2

    target_list = None
    if getattr(args, "target_list", None):
        try:
            target_list = _load_target_list(args.target_list)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} --target-list: {e}", file=sys.stderr)
            return 2
        print(f"{Fore.GREEN}[*] Loaded {len(target_list)} static target(s); "
              f"recon phase will be skipped.{Style.RESET_ALL}")

    scanner = WebSecurityScanner(_build_config(args))
    progress = ProgressReporter(enabled=not args.verbose)
    _register_listeners(scanner, args.verbose, progress)

    if args.allow_destructive:
        print(f"{Fore.RED}{Style.BRIGHT}[!] Destructive payloads ENABLED — "
              f"only run against systems you are authorized to test.{Style.RESET_ALL}")

    print(f"{Fore.GREEN}[*] Scanning {args.url} (profile: {args.profile}){Style.RESET_ALL}\n")

    results = await scanner.run_scan(
        args.url,
        profile=args.profile,
        generate_map=args.generate_map,
        max_duration=args.max_duration,
        max_depth=args.max_depth,
        max_urls=args.max_urls,
        target_list=target_list,
    )

    progress.clear()

    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    paths = await generate_reports_async(results, formats, output_dir=args.output)

    count = results["statistics"]["total_vulnerabilities"]
    tech_count = results["statistics"].get("total_technologies", 0)
    print(f"\n{Fore.GREEN}[*] Scan complete: {count} vulnerability(ies) found, "
          f"{tech_count} technology(ies) detected.{Style.RESET_ALL}")
    for fmt, path in paths.items():
        print(f"    {fmt.upper()} report: {path}")
    if results.get("map_report"):
        print(f"    MAP  report: {results['map_report']}")

    # Non-zero exit if any vulnerabilities found (useful for CI).
    return 1 if count > 0 else 0


def main() -> int:
    colorama_init(autoreset=False)
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    i18n.load_languages(str(LANGUAGES_FILE))
    i18n.set_language(getattr(args, "lang", "en"))

    # Phase 2: pin every RNG stream (payload order, UA rotation, mutations)
    # before any scanner object is built so a run is bit-for-bit reproducible.
    seed = getattr(args, "global_seed", None)
    if seed is not None:
        random.seed(seed)
        logging.getLogger("web_security_scanner").info("Global RNG seed = %d", seed)

    if args.command == "scan":
        print_banner()
        try:
            return asyncio.run(_run_scan(args))
        except KeyboardInterrupt:
            # Graceful, quiet exit: the scanner already cancelled + awaited its
            # in-flight tasks and closed the aiohttp session. Emit a single
            # info line — no Python/asyncio stack traces — and exit 130.
            msg = i18n.get("scanner.scan_cancelled")
            logging.getLogger("web_security_scanner").info(msg)
            print(f"\n{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")
            return 130
        finally:
            # Never leave the terminal stuck in a colorama color or on a
            # half-written progress line.
            sys.stdout.write(Style.RESET_ALL)
            sys.stdout.flush()

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
