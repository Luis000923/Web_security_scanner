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

    # --- Injection surface beyond GET query parameters ---
    surf = scan.add_argument_group(
        "injection surface",
        "Enable injection testing in HTTP request headers and session cookies. "
        "POST body / JSON injection points are supplied per-target through "
        "--target-list entries ({vector, method, body, json, headers, cookies}).",
    )
    surf.add_argument("--inject-headers", nargs="?", const="__default__",
                      default=None, metavar="H1,H2,...",
                      help="Fuzz injectable request headers. Bare flag uses the "
                           "default set (User-Agent, Referer, X-Forwarded-For, "
                           "X-Forwarded-Host, X-Real-IP); pass a comma list to "
                           "override.")
    surf.add_argument("--inject-cookies", default=None, metavar="c1,c2 | c=val,...",
                      help="Fuzz the named session cookies (comma list). "
                           "'name=value' pairs seed a benign baseline value.")

    # --- Authentication / session (scan protected zones) ---
    au = scan.add_argument_group(
        "authentication / session",
        "Scan behind a login. Form-based login performs a POST up front and "
        "reuses the resulting session cookie (JSESSIONID / sessionid / ...) or a "
        "JWT on every subsequent request, recon crawl and payload probe. Static "
        "cookies / a bearer token can be injected without any login. All of "
        "this can also be supplied via --session-config (JSON or YAML); CLI "
        "flags override the file. Credentials are never written to reports or "
        "the reproducibility manifest.",
    )
    au.add_argument("--auth-url", default=None, metavar="URL",
                    help="Login form action URL (POST target).")
    au.add_argument("--auth-username", default=None)
    au.add_argument("--auth-password", default=None,
                    help="Login password. INSECURE on shared hosts (shell "
                         "history / ps); prefer --auth-password-env or "
                         "--session-config.")
    au.add_argument("--auth-password-env", default=None, metavar="VAR",
                    help="Read the login password from this environment variable.")
    au.add_argument("--auth-username-field", default="username", metavar="NAME")
    au.add_argument("--auth-password-field", default="password", metavar="NAME")
    au.add_argument("--auth-field", action="append", default=None, metavar="k=v",
                    help="Extra login form field (repeatable), e.g. "
                         "--auth-field csrf_token=... --auth-field Login=Login.")
    au.add_argument("--auth-type", choices=["form", "json"], default="form",
                    help="Login body encoding (default: form / urlencoded).")
    au.add_argument("--auth-token-path", default=None, metavar="DOTTED",
                    help="Extract a token from the login JSON response at this "
                         "dotted path (e.g. data.access_token) and send it as a "
                         "header on every request.")
    au.add_argument("--auth-token-header", default="Authorization", metavar="NAME")
    au.add_argument("--auth-token-prefix", default="Bearer ", metavar="STR")
    au.add_argument("--session-cookie", action="append", default=None,
                    metavar="NAME=VALUE",
                    help="Inject a static session cookie (repeatable).")
    au.add_argument("--cookie-jar", default=None, metavar="FILE",
                    help="Load cookies from a Netscape/Mozilla cookies.txt or a "
                         "JSON file.")
    au.add_argument("--session-config", default=None, metavar="FILE",
                    help="JSON/YAML file with the full session configuration.")
    au.add_argument("--auth-required", action="store_true",
                    help="Abort the scan if authentication fails (default: warn "
                         "and continue unauthenticated).")
    au.add_argument("--no-reauth", dest="reauth", action="store_false",
                    help="Disable transparent re-login when the session expires "
                         "mid-scan.")

    # --- Phase 2: experiment control / ablation toggles ---
    exp = scan.add_argument_group(
        "experiment controls",
        "Feature flags for empirical evaluation / ablation studies.",
    )
    exp.add_argument("--telemetry-dir", default=None, metavar="PATH",
                     help="Enable per-probe telemetry and write the JSONL run log "
                          "into this directory.")
    exp.add_argument("--warmup", type=int, default=0, metavar="N",
                     help="JVM-latency-bias mitigation: fire N discard requests "
                          "per endpoint before any baseline / telemetry capture "
                          "(default 0 = off). See testbed/THREATS_TO_VALIDITY.md.")
    exp.add_argument("--baseline-samples", type=int, default=3, metavar="N",
                     help="Benign latency samples collected per injection point "
                          "for the time-based threshold (default 3).")
    exp.add_argument("--latency-window", type=int, default=12, metavar="N",
                     help="Rolling-window size for the robust (median+MAD) "
                          "benign-latency variance estimate (default 12).")
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
        "LLM triage agent (ai_module)",
        "OFF by default. --enable-ai-triaging routes every heuristic candidate "
        "through the fine-tuned triage model before the finding is emitted; a "
        "confident false-positive verdict suppresses it. Transparent "
        "degradation: if ai_module isn't installed or the inference backend is "
        "unreachable the scan silently continues on the deterministic engine. "
        "Use it to A/B the detection metrics with and without the agent.")
    ai.add_argument("--enable-ai-triaging", dest="enable_ai_triaging",
                    action="store_true",
                    help="Enable the LLM false-positive triage stage.")
    ai.add_argument("--ai-synthesize", dest="ai_synthesize", action="store_true",
                    help="Also let the agent propose adapted payloads when a "
                         "parameter's static list is exhausted with no hit "
                         "(implies --enable-ai-triaging).")
    ai.add_argument("--ai-no-verify", dest="ai_no_verify", action="store_true",
                    help="With --ai-synthesize: keep payload synthesis but skip "
                         "the false-positive triage stage.")
    ai.add_argument("--ai-backend", default=None,
                    choices=["openai", "transformers", "echo"],
                    help="AgentClient backend (default: env AI_AGENT_BACKEND or 'openai').")
    ai.add_argument("--ai-base-url", default=None, metavar="URL",
                    help="OpenAI-compatible endpoint for the 'openai' backend "
                         "(default: http://127.0.0.1:8000/v1).")
    ai.add_argument("--ai-model", default=None, metavar="NAME",
                    help="Model / adapter name passed to the backend.")
    ai.add_argument("--ai-fp-threshold", type=float, default=0.75, metavar="0-1",
                    help="Minimum agent confidence required to discard a finding "
                         "as a false positive (default: 0.75).")
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


def _parse_cookie_spec(raw: str | None) -> dict[str, str] | None:
    """``"sid,csrf"`` or ``"sid=abc,role=user"`` -> ``{name: value}``.

    Bare names get a benign baseline value so the injection point still has a
    template to mutate one field of.
    """
    if not raw:
        return None
    out: dict[str, str] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        name, _, value = part.partition("=")
        out[name.strip()] = value.strip() if _ else "benign_baseline_123"
    return out or None


def _parse_kv_list(items: list[str] | None) -> dict[str, str]:
    """``["a=1", "b=2"]`` -> ``{"a": "1", "b": "2"}`` (first ``=`` splits)."""
    out: dict[str, str] = {}
    for raw in items or []:
        name, sep, value = str(raw).partition("=")
        if sep:
            out[name.strip()] = value.strip()
    return out


def _load_session_config(path: str) -> dict:
    """Parse a --session-config file (JSON or YAML) into a plain dict."""
    from web_security_scanner.core.session_async import _parse_structured

    data = _parse_structured(Path(path).read_text(encoding="utf-8"), path)
    if not isinstance(data, dict):
        raise ValueError("session config must be a JSON/YAML object")
    return data


def _build_session_config(args) -> dict | None:
    """Merge --session-config file (base) with CLI flags (override) into the
    ``config['session']`` dict, or ``None`` when no auth/session option was set.
    """
    import os

    base: dict = {}
    if getattr(args, "session_config", None):
        base = _load_session_config(args.session_config)

    password = getattr(args, "auth_password", None)
    if password is None and getattr(args, "auth_password_env", None):
        password = os.environ.get(args.auth_password_env)

    overrides = {
        "login_url": getattr(args, "auth_url", None),
        "username": getattr(args, "auth_username", None),
        "password": password,
        "username_field": getattr(args, "auth_username_field", None),
        "password_field": getattr(args, "auth_password_field", None),
        "submit_type": getattr(args, "auth_type", None),
        "token_json_path": getattr(args, "auth_token_path", None),
        "token_header": getattr(args, "auth_token_header", None),
        "token_prefix": getattr(args, "auth_token_prefix", None),
        "cookie_jar_file": getattr(args, "cookie_jar", None),
    }
    for key, value in overrides.items():
        if value is not None:
            base[key] = value

    extra = _parse_kv_list(getattr(args, "auth_field", None))
    if extra:
        base["extra_fields"] = {**base.get("extra_fields", {}), **extra}

    static = _parse_kv_list(getattr(args, "session_cookie", None))
    if static:
        base["static_cookies"] = {**base.get("static_cookies", {}), **static}

    if getattr(args, "auth_required", False):
        base["required"] = True
    if getattr(args, "reauth", True) is False:
        base["reauth"] = False

    # Only return a config when it actually carries auth/session material.
    has_material = any(base.get(k) for k in (
        "login_url", "token", "static_cookies", "cookie_jar_file"))
    return base if has_material else None


def _parse_header_spec(raw: str | None):
    """``None`` -> off; ``"__default__"`` -> default set sentinel; list -> names."""
    if raw is None:
        return None
    if raw == "__default__":
        return "__default__"
    names = [h.strip() for h in raw.split(",") if h.strip()]
    return names or "__default__"


def _build_config(args) -> dict:
    inject_headers = _parse_header_spec(getattr(args, "inject_headers", None))
    inject_cookies = _parse_cookie_spec(getattr(args, "inject_cookies", None))
    has_advanced_vectors = bool(
        inject_headers or inject_cookies or getattr(args, "target_list", None)
    )
    core = {
        "rate_limit": args.rate_limit,
        "verify_ssl": args.verify_ssl,
        "allow_private_redirects": args.allow_private_redirects,
        # Body/header/cookie probes get the same SSRF pre-flight the redirect
        # chain already enforces, so a mutated request can't be aimed inward.
        "assert_public_target": has_advanced_vectors,
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
        # Injection surface beyond the query string (Phase: multi-vector DAST).
        "inject_headers": inject_headers,
        "inject_cookies": inject_cookies,
        # JVM latency-bias mitigation (OWASP Benchmark testbed).
        "warmup_requests": getattr(args, "warmup", 0),
        "baseline_latency_samples": getattr(args, "baseline_samples", 3),
        "latency_window": getattr(args, "latency_window", 12),
        # Phase 2 ablation toggles (consumed by VulnerabilityTester).
        "interleave": getattr(args, "interleave", True),
        "priority": getattr(args, "priority", True),
        "payload_order": getattr(args, "payload_order", "natural"),
        "runtime_confirm": getattr(args, "runtime_confirm", True),
        # Phase 3 live heuristic ordering (adaptive feedback loop).
        "adaptive_sorting": getattr(args, "adaptive_sorting", True),
        # LLM triage agent (opt-in via --enable-ai-triaging / --ai-synthesize).
        "ai_enabled": (getattr(args, "enable_ai_triaging", False)
                       or getattr(args, "ai_synthesize", False)),
        "ai_verify": not getattr(args, "ai_no_verify", False),
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
    session_config = _build_session_config(args)
    if session_config is not None:
        config["session"] = session_config
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
    valid_vectors = {"getparam", "formparam", "jsonparam", "header", "cookie"}
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("target-list must be a JSON array of objects")
    out: list[dict] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict) or not entry.get("url"):
            raise ValueError(f"target-list entry {i} is missing a 'url' field")
        vector = str(entry.get("vector", "") or "").lower()
        if vector and vector not in valid_vectors:
            raise ValueError(
                f"target-list entry {i}: unknown vector {vector!r}; "
                f"expected one of {sorted(valid_vectors)}"
            )
        item = {
            "url": str(entry["url"]),
            "param": entry.get("param"),
            "method": str(entry.get("method", "GET")).upper(),
        }
        # Optional advanced-vector descriptors — carried through verbatim to
        # WebSecurityScanner._targets_from_list.
        for key in ("vector", "body", "json", "headers", "cookies"):
            if entry.get(key) is not None:
                item[key] = entry[key]
        out.append(item)
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

    if results.get("aborted") == "authentication":
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Authentication was required "
              f"(--auth-required) but failed; scan aborted.", file=sys.stderr)
        return 2

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
