"""Interactive console TUI: dependency check -> profile -> target -> scan.

An Airgeddon-style menu layer over two otherwise-separate systems this
package ships: the external-tool adapters in
:mod:`web_security_scanner.core.external_tools` (nmap/ffuf/nuclei/sqlmap/...,
see :data:`~.external_tools.ADAPTER_REGISTRY`) and the scanner's own async
engine (25 vulnerability testers, crawler, optional AI triage / exploit
engine) that :mod:`web_security_scanner.cli` drives from the command line.
This module's job is menu navigation, dependency bootstrapping, target
sanitization, profile composition, and rendering a live dashboard while
adapters run concurrently -- then, for URL targets, handing the same choices
to :mod:`web_security_scanner.cli`'s own parser (see
:meth:`TUI.configure_core_engine` / :meth:`TUI.run_core_engine`) so the core
engine runs too, without the operator ever typing a ``webscanner scan``
command by hand.

Security posture (same as the adapter layer it drives)
--------------------------------------------------------
* No ``shell=True`` anywhere, including the package-manager install flow:
  installing missing binaries runs ``asyncio.create_subprocess_exec`` with
  an explicit argv (``["sudo", "apt-get", "install", "-y", *pkgs]``), so a
  package name can never smuggle a shell command even though this module
  itself decides that argv, not the user.
* The single piece of user-controlled data that reaches any subprocess argv
  is the scan target, and it goes through :func:`sanitize_target`, which
  delegates to :func:`~.external_tools.sanitize_url` /
  :func:`~.external_tools.sanitize_host` -- the exact same validators the
  adapters use internally, so a target this module accepts is a target
  every adapter also accepts.
* Ctrl+C during a scan cancels the running asyncio tasks; each adapter's
  own ``run()`` kills its child process on cancellation (see
  ``base.py``'s ``except asyncio.CancelledError`` handler) rather than
  leaving an orphaned subprocess behind.

This module does not run automatically and nothing else in the codebase
imports it yet -- it is an opt-in entrypoint. Wire it up with:

    python -m web_security_scanner.core.tui
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
import shutil
import signal
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from .external_tools import (
    ADAPTER_REGISTRY,
    AsyncToolAdapter,
    ToolResult,
    sanitize_host,
    sanitize_url,
)

__all__ = [
    "TargetKind",
    "SanitizedTarget",
    "TargetValidationError",
    "sanitize_target",
    "PackageManager",
    "detect_package_manager",
    "check_missing_tools",
    "install_missing_tools",
    "ScanProfile",
    "PROFILES",
    "CATEGORIES",
    "run_category",
    "TUI",
    "run_tui",
]


# --------------------------------------------------------------------------
# Target capture and sanitization
# --------------------------------------------------------------------------

TargetKind = str  # "url" | "host"


class TargetValidationError(ValueError):
    """Raised when the operator-supplied target is neither a valid URL nor host."""


@dataclass(frozen=True, slots=True)
class SanitizedTarget:
    """A target that has passed the same validators the adapters enforce internally."""

    raw: str
    kind: TargetKind
    value: str


#: No scheme at all -- not even a foreign one (``ftp://``, ``ssh://``) that
#: this module should refuse rather than silently reinterpret. Only the
#: *absence* of a scheme triggers auto-prefixing; a target that already names
#: one it doesn't support still fails with its own error instead of being
#: rewritten into something the operator didn't type.
_HAS_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def sanitize_target(raw: str) -> SanitizedTarget:
    """Validate operator input as either an ``http(s)://`` URL or a bare host/CIDR.

    Tries URL validation first (the common case -- most categories here are
    HTTP-facing), then falls back to host validation for the recon category
    (nmap/naabu/masscan take a bare address, not a URL). Both paths reuse
    :mod:`core.external_tools`'s own sanitizers, so nothing is duplicated
    and nothing can accept here what an adapter would reject downstream.

    A target with no scheme that also fails host/CIDR validation -- the
    common case is a bare ``host/path`` (``example.com/admin``), which the
    host validator reads as a CIDR suffix and rejects -- is retried with
    ``https://`` prepended, then ``http://``. A bare host with *no* path
    (``example.com``) is left as ``kind="host"``: recon tools need exactly
    that form, and this module has no way to know the operator meant it for
    the web-facing categories instead, so it does not guess there.
    """
    candidate = raw.strip()
    if not candidate:
        raise TargetValidationError("Target must not be empty.")
    try:
        return SanitizedTarget(raw=raw, kind="url", value=sanitize_url(candidate))
    except ValueError:
        pass
    try:
        return SanitizedTarget(raw=raw, kind="host", value=sanitize_host(candidate))
    except ValueError as exc:
        # Auto-prefixing must never be the thing that launders a rejected
        # input into an accepted one: "--data-binary=@/etc/passwd" prepended
        # with "https://" no longer starts with "-" and would sail past
        # sanitize_arg's flag-injection guard even though the operator typed
        # exactly what that guard exists to catch. Refuse to retry anything
        # that already failed *because* of that guard.
        if not candidate.startswith("-") and not _HAS_SCHEME_RE.match(candidate):
            for scheme in ("https://", "http://"):
                try:
                    return SanitizedTarget(
                        raw=raw, kind="url", value=sanitize_url(scheme + candidate)
                    )
                except ValueError:
                    continue
        raise TargetValidationError(
            f"{candidate!r} is neither a valid http(s):// URL nor a valid "
            f"hostname/IPv4[/CIDR]: {exc}"
        ) from None


# --------------------------------------------------------------------------
# Dependency detection and installation
# --------------------------------------------------------------------------

#: Adapter registry key -> the package name it ships under on each manager.
#: A tool absent from a manager's mapping (e.g. ysoserial, kiterunner,
#: joern -- not packaged by mainstream distro repos) is left out of that
#: manager's install list; check_missing_tools() still reports it as
#: missing, install_missing_tools() just can't offer to install it and
#: says so.
_PACKAGE_NAMES: dict[str, dict[str, str]] = {
    "apt-get": {
        "nmap": "nmap",
        "masscan": "masscan",
        "ffuf": "ffuf",
        "sqlmap": "sqlmap",
        "nuclei": "nuclei",
    },
    "pacman": {
        "nmap": "nmap",
        "masscan": "masscan",
        "sqlmap": "sqlmap",
        "z3": "z3",
    },
    "dnf": {
        "nmap": "nmap",
        "masscan": "masscan",
        "sqlmap": "sqlmap",
    },
    "brew": {
        "nmap": "nmap",
        "masscan": "masscan",
        "ffuf": "ffuf",
        "sqlmap": "sqlmap",
        "nuclei": "nuclei",
    },
}

#: Managers probed in preference order; the first one found on PATH wins.
_MANAGER_INSTALL_ARGS: dict[str, list[str]] = {
    "apt-get": ["install", "-y"],
    "pacman": ["-S", "--noconfirm"],
    "dnf": ["install", "-y"],
    "brew": ["install"],
}


@dataclass(frozen=True, slots=True)
class PackageManager:
    name: str
    path: str
    needs_sudo: bool


def detect_package_manager() -> PackageManager | None:
    """Return the first available system package manager, or None."""
    for name in ("apt-get", "pacman", "dnf", "brew"):
        path = shutil.which(name)
        if path:
            return PackageManager(name=name, path=path, needs_sudo=name != "brew")
    return None


def check_missing_tools() -> dict[str, bool]:
    """Return ``{tool_name: is_available}`` for every adapter in the registry."""
    return {
        tool_name: shutil.which(adapter_cls.binary) is not None
        for tool_name, adapter_cls in sorted(ADAPTER_REGISTRY.items())
    }


async def install_missing_tools(
    manager: PackageManager, tool_names: list[str]
) -> ToolResult:
    """Install ``tool_names`` via ``manager`` with one controlled subprocess call.

    Builds an explicit argv (``sudo`` prefix only when the manager needs
    elevation) and never touches a shell -- package names are looked up from
    the static :data:`_PACKAGE_NAMES` table, never taken as raw user input,
    so there is no injection surface here even without an extra sanitize
    step; the table lookup itself is the allowlist.
    """
    catalog = _PACKAGE_NAMES.get(manager.name, {})
    packages = [catalog[name] for name in tool_names if name in catalog]
    if not packages:
        # Most of this registry's tools are Go/Java/Python projects with no
        # mainstream distro package at all (AUR-only, or built from source) --
        # naming them here is the difference between "nothing happened" and
        # "here is exactly why, go install these yourself".
        unresolved = ", ".join(tool_names)
        return ToolResult(
            tool=manager.name,
            command=(),
            returncode=None,
            stdout="",
            stderr=(
                f"none of the requested tools have a {manager.name} package: "
                f"{unresolved}. These are typically AUR-only, `go install`able, "
                "or built from source -- see each tool's own docs."
            ),
            duration_s=0.0,
            tool_missing=True,
        )

    argv = [manager.path, *_MANAGER_INSTALL_ARGS[manager.name], *packages]
    if manager.needs_sudo:
        sudo_path = shutil.which("sudo")
        if sudo_path:
            argv = [sudo_path, *argv]

    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await proc.communicate()
    duration = time.monotonic() - start
    return ToolResult(
        tool=manager.name,
        command=tuple(argv),
        returncode=proc.returncode,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
        duration_s=duration,
    )


# --------------------------------------------------------------------------
# Scan profiles and categories
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScanProfile:
    """A named bundle of concurrency/depth/intensity defaults.

    ``categories`` names the ordered set of category keys (see
    :data:`CATEGORIES`) the profile runs; ``full_hybrid`` runs all seven so
    it exercises every adapter category in one pass.
    """

    key: str
    label: str
    description: str
    concurrency: int
    crawl_depth: int
    intensity: str  # "low" | "medium" | "high"
    evasion_level: int  # 0 = none .. 2 = aggressive
    categories: tuple[str, ...]


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        key="quick",
        label="Quick Recon",
        description="Fast port sweep + template scan. Minimal footprint.",
        concurrency=10,
        crawl_depth=1,
        intensity="low",
        evasion_level=0,
        categories=("recon", "templates"),
    ),
    "deep": ScanProfile(
        key="deep",
        label="Deep Audit",
        description="Full crawl, parameter discovery, and confirmed injection.",
        concurrency=25,
        crawl_depth=4,
        intensity="high",
        evasion_level=1,
        categories=("crawling", "fuzzing", "injection"),
    ),
    "full_hybrid": ScanProfile(
        key="full_hybrid",
        label="Full Hybrid Scan",
        description="Every category, every adapter. Slowest, most thorough.",
        concurrency=15,
        crawl_depth=3,
        intensity="high",
        evasion_level=2,
        categories=(
            "recon",
            "crawling",
            "fuzzing",
            "injection",
            "oob",
            "templates",
            "symbolic",
        ),
    ),
}

#: category key -> (label, adapter registry keys in that category)
CATEGORIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "recon": ("Reconnaissance", ("nmap", "naabu", "masscan")),
    "crawling": ("Crawling / DOM extraction", ("katana", "gospider", "kiterunner")),
    "fuzzing": ("Parameter fuzzing", ("ffuf", "arjun")),
    "injection": ("Confirmed injection / exploitation", ("sqlmap", "tplmap", "ysoserial")),
    "oob": ("Out-of-band confirmation", ("interactsh",)),
    "templates": ("Template-based scanning", ("nuclei",)),
    "symbolic": ("Symbolic analysis / instrumentation", ("z3", "frida", "joern")),
}


#: Materialized ffuf wordlist path, built once per process and reused; ``""``
#: is the cached "materialization already failed" sentinel so a target that
#: can't build it doesn't retry the disk I/O on every category run.
_ffuf_wordlist_cache: str | None = None


def _ffuf_wordlist_path() -> str | None:
    """Return a plain-text, one-entry-per-line wordlist for ffuf's ``-w``.

    ffuf reads a flat text file; the bundled wordlist ships as the JSON array
    in ``wordlists/directories.json`` (see ``wordlists/README.md``), so it is
    materialized to a temp file the first time this runs. Returns ``None``
    when the bundled wordlist can't be loaded, which the caller must read as
    "skip ffuf" -- there is no other default to fall back to here, and
    guessing a system wordlist path (``/usr/share/wordlists/...``) would
    silently vary this module's behaviour by distro.
    """
    global _ffuf_wordlist_cache
    if _ffuf_wordlist_cache:
        return _ffuf_wordlist_cache
    if _ffuf_wordlist_cache == "":
        return None
    try:
        from ..wordlists import load_wordlist
        labels = load_wordlist("directories")
    except Exception:
        labels = []
    if not labels:
        _ffuf_wordlist_cache = ""
        return None
    fd, path = tempfile.mkstemp(prefix="wss_ffuf_wordlist_", suffix=".txt")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(labels))
    _ffuf_wordlist_cache = path
    return path


def _adapter_kwargs(target: SanitizedTarget, tool_name: str, profile: ScanProfile) -> dict[str, Any]:
    """Map a profile's abstract knobs onto one adapter's concrete build_command kwargs.

    Kept centralized and defensive: an adapter this doesn't have a case for
    still runs with just the target, since every ``build_command`` accepts
    the target positionally and everything else is keyword-optional.

    Raises :class:`TargetValidationError` for a tool this profile/target
    combination cannot run at all (currently: ffuf with no wordlist
    available) -- the caller already has a skip path for that exception from
    the target-kind checks, so a missing *argument* reuses it rather than
    needing a second one.
    """
    if tool_name in ("katana", "gospider"):
        return {"depth": profile.crawl_depth}
    if tool_name == "ffuf":
        wordlist = _ffuf_wordlist_path()
        if wordlist is None:
            raise TargetValidationError(
                "ffuf requires a wordlist and the bundled one could not be "
                "loaded; skipping (pass one via a future --ffuf-wordlist flag)"
            )
        return {"wordlist": wordlist}
    if tool_name == "nuclei":
        severity = {"low": "info,low", "medium": "medium,high", "high": "high,critical"}[
            profile.intensity
        ]
        return {"severity": severity}
    if tool_name == "sqlmap":
        risk = min(3, 1 + profile.evasion_level)
        level = min(5, 1 + profile.crawl_depth)
        return {"risk": risk, "level": level}
    return {}


async def run_category(
    category_key: str,
    target: SanitizedTarget,
    profile: ScanProfile,
    *,
    on_result: Any = None,
) -> dict[str, ToolResult]:
    """Run every adapter in one category concurrently, bounded by ``profile.concurrency``.

    Returns ``{tool_name: ToolResult}``. Tools whose target kind doesn't
    match (e.g. a bare-host target handed to a URL-only crawler) are skipped
    with a synthetic ``tool_missing`` result rather than raising, so one
    mismatched category never aborts the whole run.
    """
    _, tool_names = CATEGORIES[category_key]
    semaphore = asyncio.Semaphore(max(1, profile.concurrency))

    async def _run_one(tool_name: str) -> tuple[str, ToolResult]:
        adapter_cls = ADAPTER_REGISTRY[tool_name]
        adapter: AsyncToolAdapter = adapter_cls()
        async with semaphore:
            try:
                kwargs = _adapter_kwargs(target, tool_name, profile)
                if category_key == "recon":
                    if target.kind != "host":
                        raise TargetValidationError("recon adapters require a bare host, not a URL")
                    result = await adapter.run(target.value, **kwargs)
                else:
                    if target.kind != "url":
                        raise TargetValidationError(
                            f"{tool_name} requires an http(s):// URL target"
                        )
                    url = target.value
                    if tool_name == "ffuf" and "FUZZ" not in url:
                        # ffuf fuzzes literal text, not a named parameter -- it
                        # needs the placeholder spelled out in the URL. Content
                        # discovery on a target with no placeholder of its own
                        # means "probe paths under this one", so append it.
                        url = url.rstrip("/") + "/FUZZ"
                    result = await adapter.run(url, **kwargs)
            except TargetValidationError as exc:
                result = ToolResult(
                    tool=tool_name,
                    command=(),
                    returncode=None,
                    stdout="",
                    stderr=str(exc),
                    duration_s=0.0,
                    tool_missing=True,
                )
            if on_result is not None:
                on_result(tool_name, result)
            return tool_name, result

    pairs = await asyncio.gather(*(_run_one(name) for name in tool_names))
    return dict(pairs)


# --------------------------------------------------------------------------
# The interactive shell
# --------------------------------------------------------------------------


class TUI:
    """Menu-driven console shell. Every screen is one method so tests can
    exercise them individually without driving the full interactive loop."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._cancelled = False

    # -- dependency screen --------------------------------------------------

    def show_dependency_summary(self, status: dict[str, bool]) -> list[str]:
        table = Table(title="External tool availability")
        table.add_column("Tool")
        table.add_column("Status")
        missing = []
        for tool_name, available in status.items():
            table.add_row(tool_name, "[green]found[/]" if available else "[red]missing[/]")
            if not available:
                missing.append(tool_name)
        self.console.print(table)
        return missing

    async def offer_install(self, missing: list[str]) -> None:
        if not missing:
            return
        manager = detect_package_manager()
        if manager is None:
            self.console.print(
                "[yellow]No supported package manager (apt-get/pacman/dnf/brew) "
                "found on PATH; install the missing tools manually.[/]"
            )
            return
        self.console.print(
            f"Missing: {', '.join(missing)}. Package manager detected: {manager.name}."
        )
        if not Confirm.ask(f"Install available packages via {manager.name}?", default=False):
            return
        result = await install_missing_tools(manager, missing)
        if result.tool_missing:
            self.console.print(f"[yellow]{rich_escape(result.stderr)}[/]")
        elif result.returncode == 0:
            self.console.print("[green]Install completed.[/]")
        else:
            self.console.print(f"[red]Install failed (exit {result.returncode}).[/]")

    # -- profile / target screens -------------------------------------------

    def select_profile(self) -> ScanProfile:
        table = Table(title="Scan profiles")
        table.add_column("#")
        table.add_column("Name")
        table.add_column("Description")
        keys = list(PROFILES)
        for i, key in enumerate(keys, start=1):
            profile = PROFILES[key]
            table.add_row(str(i), profile.label, profile.description)
        self.console.print(table)
        choice = IntPrompt.ask("Select a profile", choices=[str(i) for i in range(1, len(keys) + 1)])
        return PROFILES[keys[choice - 1]]

    def capture_target(self) -> SanitizedTarget:
        while True:
            raw = Prompt.ask("Target (URL or host/IP)")
            try:
                return sanitize_target(raw)
            except TargetValidationError as exc:
                self.console.print(f"[red]{rich_escape(str(exc))}[/]")

    def select_categories(self, profile: ScanProfile) -> list[str]:
        """Category selection defaults to the profile's own set; operator may narrow it."""
        table = Table(title=f"Categories for {profile.label}")
        table.add_column("#")
        table.add_column("Category")
        table.add_column("Tools")
        for i, key in enumerate(profile.categories, start=1):
            label, tools = CATEGORIES[key]
            table.add_row(str(i), label, ", ".join(tools))
        self.console.print(table)
        if not Confirm.ask("Run all listed categories?", default=True):
            raw = Prompt.ask(
                "Comma-separated category numbers to run", default="1"
            )
            try:
                indices = [int(x.strip()) for x in raw.split(",") if x.strip()]
                return [profile.categories[i - 1] for i in indices if 1 <= i <= len(profile.categories)]
            except (ValueError, IndexError):
                self.console.print("[yellow]Could not parse selection; running all categories.[/]")
        return list(profile.categories)

    # -- core engine (25 testers / AI triage / exploit engine) ---------------

    def configure_core_engine(self) -> list[str] | None:
        """Menu-driven equivalent of every ``webscanner scan`` flag this TUI
        offers a knob for. Returns the argv this session should hand to
        :func:`web_security_scanner.cli._build_parser` (everything after the
        target URL), or ``None`` if the operator declines the core engine
        entirely.

        Deliberately not every one of the CLI's ~90 flags gets a menu entry --
        auth/session, proxy, UA rotation and the fine payload-scheduling knobs
        keep their CLI defaults here. What *is* exposed is exactly the surface
        this module's own docstring and the earlier conversation about "the
        most powerful command" walked through by hand: profile, AI triage,
        the exploit engine and its containment gate, and destructive payloads.
        Building an argv and handing it to the real parser (rather than
        hand-assembling an ``argparse.Namespace``) means every default this
        menu *doesn't* ask about still comes from the one place that owns
        them, and stays correct as the CLI grows new flags.
        """
        if not Confirm.ask(
            "Also run the core scanning engine (25 vulnerability testers, "
            "crawler, optional AI triage / exploit engine)?", default=True,
        ):
            return None

        from .. import cli as core_cli

        argv: list[str] = []
        profile = Prompt.ask(
            "Core engine profile", choices=core_cli.PROFILES, default="balanced"
        )
        argv += ["--profile", profile]

        if Confirm.ask(
            "[red]Allow destructive payloads[/] (only for systems you own/are "
            "explicitly authorized to test)?", default=False,
        ):
            argv.append("--allow-destructive")

        if Confirm.ask("Run headless-browser recon (SPA/DOM-XSS)?", default=True):
            argv.append("--browser")
        if Confirm.ask("Probe for exposed sensitive files (.env, .git/HEAD, ...)?",
                       default=True):
            argv.append("--detect-sensitive-files")
        if Confirm.ask("Fingerprint server/framework versions?", default=True):
            argv.append("--fingerprint-server")

        if Confirm.ask("Enable the LLM triage agent (ai_module)?", default=False):
            argv.append("--enable-ai-triaging")
            if Confirm.ask("  Also let it synthesize new payloads?", default=False):
                argv.append("--ai-synthesize")
            if Confirm.ask("  Also run post-scan AI-guided re-discovery?",
                           default=False):
                argv.append("--enable-ai-discovery")
            backend = Prompt.ask(
                "  AI backend", choices=["openai", "transformers", "echo"],
                default="openai",
            )
            argv += ["--ai-backend", backend]
            if backend == "transformers":
                model = Prompt.ask(
                    "  Local model path (merged checkpoint directory)",
                    default="runs/triage-qlora/merged",
                )
                argv += ["--ai-model", model, "--ai-load-in-4bit"]
            elif backend == "openai":
                base_url = Prompt.ask(
                    "  OpenAI-compatible endpoint",
                    default="http://127.0.0.1:8000/v1",
                )
                argv += ["--ai-base-url", base_url]

        if Confirm.ask(
            "Enable the adaptive exploit engine (Proof-of-Impact)?", default=False,
        ):
            argv.append("--enable-exploit-engine")
            if Confirm.ask("  Also enable adaptive WAF-evasion retries?",
                           default=False):
                argv.append("--enable-waf-evasion")
            gate = Prompt.ask(
                "  Containment: 'lab' (RFC1918/loopback/localhost only), a "
                "domain you're authorized to test, or 'ack' (take "
                "responsibility, forces simulation profile)",
                default="lab",
            )
            if gate not in ("lab", ""):
                if gate == "ack":
                    argv.append("--acknowledge-offensive-payloads")
                else:
                    argv += ["--containment-allowed-domain", gate]

        if Confirm.ask("Pin a reproducibility seed (--global-seed)?", default=True):
            seed = IntPrompt.ask("  Seed", default=42)
            argv += ["--global-seed", str(seed)]

        argv += ["-o", Prompt.ask("Report output directory", default="reports")]
        return argv

    async def run_core_engine(self, target: SanitizedTarget, argv: list[str]) -> int:
        """Run ``webscanner scan`` in-process against ``argv`` (built by
        :meth:`configure_core_engine`), reusing :mod:`web_security_scanner.cli`
        verbatim -- same parser, same validation, same
        :func:`~web_security_scanner.cli._run_scan` the real CLI runs, so this
        can never drift from what typing the command by hand would do.

        Returns the same exit code ``webscanner scan`` would (0 = clean,
        1 = findings, 2 = invalid args/auth failure); this method never raises
        for an operator-facing reason -- an invalid flag combination prints
        the parser's own error and returns 2 instead of tearing down the TUI.
        """
        from .. import cli as core_cli

        parser = core_cli._build_parser()
        try:
            args = parser.parse_args(["scan", target.value, *argv])
            core_cli._validate_args(args, parser)
        except SystemExit as exc:
            self.console.print(f"[red]Core engine argument error (exit {exc.code}).[/]")
            return int(exc.code or 2)

        core_cli.i18n.load_languages(str(core_cli.LANGUAGES_FILE))
        core_cli.i18n.set_language(getattr(args, "lang", "en"))
        seed = getattr(args, "global_seed", None)
        if seed is not None:
            random.seed(seed)

        try:
            return await core_cli._run_scan(args)
        except asyncio.CancelledError:
            self.console.print("[yellow]Core engine scan cancelled.[/]")
            raise

    # -- execution dashboard --------------------------------------------------

    async def run_scan(
        self, target: SanitizedTarget, profile: ScanProfile, categories: list[str]
    ) -> dict[str, dict[str, ToolResult]]:
        results: dict[str, dict[str, ToolResult]] = {}
        alerts = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:
            overall = progress.add_task("Overall", total=len(categories))
            try:
                for category_key in categories:
                    label, tool_names = CATEGORIES[category_key]
                    cat_task = progress.add_task(label, total=len(tool_names))

                    def _on_result(
                        tool_name: str, result: ToolResult, _task: Any = cat_task
                    ) -> None:
                        progress.advance(_task)

                    results[category_key] = await run_category(
                        category_key, target, profile, on_result=_on_result
                    )
                    for result in results[category_key].values():
                        if result.findings:
                            alerts += len(result.findings)
                    progress.advance(overall)
            except asyncio.CancelledError:
                self._cancelled = True
                self.console.print("[yellow]Scan cancelled by operator.[/]")
                raise

        self.console.print(
            Panel(f"{alerts} finding(s) across {len(categories)} categor(y/ies).", title="Summary")
        )
        return results

    # -- report ---------------------------------------------------------------

    @staticmethod
    def _default_report_path() -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"webscanner_tui_report_{stamp}.json"

    def save_report(
        self,
        target: SanitizedTarget,
        profile: ScanProfile,
        categories: list[str],
        results: dict[str, dict[str, ToolResult]],
        path: str,
    ) -> Path:
        """Serialize the run to ``path`` as JSON; return the resolved path.

        Every :class:`ToolResult` this session produced (recon hits, crawl
        output, findings) would otherwise exist only in the terminal's
        scrollback once the process exits -- this is the one artifact that
        survives it. Plain ``dataclasses.asdict`` is enough: ``ToolResult``
        holds only JSON-safe fields already (str/int/float/bool/list/dict).
        """
        report = {
            "target": {"raw": target.raw, "kind": target.kind, "value": target.value},
            "profile": profile.key,
            "categories": categories,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "results": {
                category_key: {
                    tool_name: asdict(result) for tool_name, result in tools.items()
                }
                for category_key, tools in results.items()
            },
        }
        resolved = Path(path).expanduser()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return resolved

    def prompt_report_path(self) -> str | None:
        """Ask where to save the JSON report; empty input skips saving.

        A default filename is offered rather than forced -- an operator who
        wants to discard a throwaway run (or pipe results elsewhere already)
        should not be required to name a file for output they don't want.
        """
        raw = Prompt.ask(
            "Save JSON report to (empty to skip)",
            default=self._default_report_path(),
        )
        return raw.strip() or None

    # -- main loop --------------------------------------------------------

    async def main_loop(self) -> None:
        self.console.print(Panel("Web Security Scanner -- Interactive Console", style="bold cyan"))

        status = check_missing_tools()
        missing = self.show_dependency_summary(status)
        await self.offer_install(missing)

        profile = self.select_profile()
        target = self.capture_target()
        categories = self.select_categories(profile)

        task = asyncio.ensure_future(self.run_scan(target, profile, categories))
        loop = asyncio.get_running_loop()

        def _handle_sigint() -> None:
            if not task.done():
                task.cancel()

        try:
            loop.add_signal_handler(signal.SIGINT, _handle_sigint)
        except (NotImplementedError, RuntimeError):
            # Platforms without add_signal_handler support (e.g. some
            # Windows event loops) fall back to default KeyboardInterrupt
            # propagation; the scan simply won't cancel as gracefully there.
            pass

        try:
            results = await task
        except asyncio.CancelledError:
            return

        path = self.prompt_report_path()
        if path is not None:
            resolved = self.save_report(target, profile, categories, results, path)
            self.console.print(f"[green]Report saved to {resolved}[/]")

        if target.kind != "url":
            self.console.print(
                "[yellow]Core engine skipped: it scans http(s):// URLs only, "
                f"and this target ({target.value!r}) validated as a bare "
                "host/CIDR for the recon-only adapters above.[/]"
            )
            return

        core_argv = self.configure_core_engine()
        if core_argv is None:
            return

        core_task = asyncio.ensure_future(self.run_core_engine(target, core_argv))

        def _handle_sigint_core() -> None:
            if not core_task.done():
                core_task.cancel()

        try:
            loop.add_signal_handler(signal.SIGINT, _handle_sigint_core)
        except (NotImplementedError, RuntimeError):
            pass

        try:
            await core_task
        except asyncio.CancelledError:
            self.console.print("[yellow]Core engine scan cancelled by operator.[/]")


def run_tui() -> None:
    """Synchronous entrypoint: ``python -m web_security_scanner.core.tui``."""
    tui = TUI()
    try:
        asyncio.run(tui.main_loop())
    except KeyboardInterrupt:
        tui.console.print("[yellow]Interrupted.[/]")


if __name__ == "__main__":
    run_tui()
