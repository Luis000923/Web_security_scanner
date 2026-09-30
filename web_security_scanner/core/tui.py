"""Interactive console TUI: dependency check -> profile -> target -> scan.

An Airgeddon-style menu layer over :mod:`web_security_scanner.core.external_tools`.
It is deliberately a thin orchestrator: every actual scan action is one
``AsyncToolAdapter.run()`` call from that package (see
:data:`web_security_scanner.core.external_tools.ADAPTER_REGISTRY`); this
module's job is menu navigation, dependency bootstrapping, target
sanitization, profile composition, and rendering a live dashboard while
adapters run concurrently.

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
import re
import shutil
import signal
import time
from dataclasses import dataclass
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


def sanitize_target(raw: str) -> SanitizedTarget:
    """Validate operator input as either an ``http(s)://`` URL or a bare host/CIDR.

    Tries URL validation first (the common case -- most categories here are
    HTTP-facing), then falls back to host validation for the recon category
    (nmap/naabu/masscan take a bare address, not a URL). Both paths reuse
    :mod:`core.external_tools`'s own sanitizers, so nothing is duplicated
    and nothing can accept here what an adapter would reject downstream.
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
        # The common way to land here: a bare "host/path" with no scheme.
        # sanitize_host then reads the first "/" as a CIDR separator and
        # reports "invalid CIDR suffix" against the URL path -- true, but not
        # what the operator needs to hear. Flag the likely cause explicitly
        # rather than let a correct-but-opaque low-level error stand alone.
        hint = ""
        if "/" in candidate and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
            hint = (
                " -- looks like a URL missing its scheme; scanning always needs "
                f"one explicitly (try 'https://{candidate}' or 'http://{candidate}')."
            )
        raise TargetValidationError(
            f"{candidate!r} is neither a valid http(s):// URL nor a valid "
            f"hostname/IPv4[/CIDR]: {exc}{hint}"
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
        return ToolResult(
            tool=manager.name,
            command=(),
            returncode=None,
            stdout="",
            stderr="no requested tool has a known package for this manager",
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


def _adapter_kwargs(target: SanitizedTarget, tool_name: str, profile: ScanProfile) -> dict[str, Any]:
    """Map a profile's abstract knobs onto one adapter's concrete build_command kwargs.

    Kept centralized and defensive: an adapter this doesn't have a case for
    still runs with just the target, since every ``build_command`` accepts
    the target positionally and everything else is keyword-optional.
    """
    if tool_name in ("katana", "gospider"):
        return {"depth": profile.crawl_depth}
    if tool_name == "ffuf":
        return {}  # requires a wordlist path the operator must supply separately
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
        kwargs = _adapter_kwargs(target, tool_name, profile)
        async with semaphore:
            try:
                if category_key == "recon":
                    if target.kind != "host":
                        raise TargetValidationError("recon adapters require a bare host, not a URL")
                    result = await adapter.run(target.value, **kwargs)
                else:
                    if target.kind != "url":
                        raise TargetValidationError(
                            f"{tool_name} requires an http(s):// URL target"
                        )
                    result = await adapter.run(target.value, **kwargs)
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
            await task
        except asyncio.CancelledError:
            pass


def run_tui() -> None:
    """Synchronous entrypoint: ``python -m web_security_scanner.core.tui``."""
    tui = TUI()
    try:
        asyncio.run(tui.main_loop())
    except KeyboardInterrupt:
        tui.console.print("[yellow]Interrupted.[/]")


if __name__ == "__main__":
    run_tui()
