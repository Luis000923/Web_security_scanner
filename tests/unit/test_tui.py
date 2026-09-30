"""Tests for core/tui.py: target sanitization, dependency detection/install,
profile selection, and menu/dashboard flow. All subprocess and console I/O
mocked -- no real binaries, no real terminal interaction."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from rich.console import Console

from web_security_scanner.core.external_tools import ToolResult
from web_security_scanner.core.tui import (
    CATEGORIES,
    PROFILES,
    TUI,
    PackageManager,
    SanitizedTarget,
    ScanProfile,
    TargetValidationError,
    check_missing_tools,
    detect_package_manager,
    install_missing_tools,
    run_category,
    sanitize_target,
)

# --------------------------------------------------------------------------
# Target sanitization
# --------------------------------------------------------------------------


class TestSanitizeTarget:
    def test_accepts_https_url(self) -> None:
        target = sanitize_target("https://example.com/path")
        assert target.kind == "url"
        assert target.value == "https://example.com/path"

    def test_accepts_bare_host(self) -> None:
        target = sanitize_target("10.0.0.1")
        assert target.kind == "host"
        assert target.value == "10.0.0.1"

    def test_accepts_hostname(self) -> None:
        target = sanitize_target("scanme.example.com")
        assert target.kind == "host"

    def test_rejects_empty(self) -> None:
        with pytest.raises(TargetValidationError):
            sanitize_target("   ")

    def test_rejects_flag_injection_as_url(self) -> None:
        with pytest.raises(TargetValidationError):
            sanitize_target("--data-binary=@/etc/passwd")

    def test_rejects_flag_injection_as_host(self) -> None:
        with pytest.raises(TargetValidationError):
            sanitize_target("--script=evil")

    def test_rejects_control_characters(self) -> None:
        with pytest.raises(TargetValidationError):
            sanitize_target("example.com\x01evil")

    def test_rejects_shell_metacharacter_payload(self) -> None:
        # Not a shell-injection concern (no shell is ever invoked downstream)
        # but it is neither a valid URL nor a valid host, so it must still
        # be rejected as an unusable target.
        with pytest.raises(TargetValidationError):
            sanitize_target("host; rm -rf /")

    def test_frozen_dataclass_is_immutable(self) -> None:
        target = sanitize_target("https://example.com")
        with pytest.raises(AttributeError):
            target.value = "https://other.com"  # type: ignore[misc]


# --------------------------------------------------------------------------
# Dependency detection
# --------------------------------------------------------------------------


class TestCheckMissingTools:
    def test_reports_all_registry_tools(self) -> None:
        with patch("shutil.which", return_value=None):
            status = check_missing_tools()
        assert set(status) == {
            "nmap", "naabu", "masscan", "katana", "gospider", "kiterunner",
            "ffuf", "arjun", "sqlmap", "tplmap", "ysoserial", "interactsh",
            "nuclei", "z3", "frida", "joern",
        }
        assert all(available is False for available in status.values())

    def test_reports_available_when_found(self) -> None:
        with patch("shutil.which", return_value="/usr/bin/tool"):
            status = check_missing_tools()
        assert all(status.values())


class TestDetectPackageManager:
    def test_returns_first_found_manager(self) -> None:
        def _which(name: str) -> str | None:
            return "/usr/bin/pacman" if name == "pacman" else None

        with patch("shutil.which", side_effect=_which):
            manager = detect_package_manager()
        assert manager is not None
        assert manager.name == "pacman"
        assert manager.needs_sudo is True

    def test_brew_does_not_need_sudo(self) -> None:
        def _which(name: str) -> str | None:
            return "/usr/local/bin/brew" if name == "brew" else None

        with patch("shutil.which", side_effect=_which):
            manager = detect_package_manager()
        assert manager is not None
        assert manager.needs_sudo is False

    def test_returns_none_when_no_manager_found(self) -> None:
        with patch("shutil.which", return_value=None):
            assert detect_package_manager() is None


class TestInstallMissingTools:
    @pytest.mark.asyncio
    async def test_builds_argv_never_shell(self) -> None:
        manager = PackageManager(name="apt-get", path="/usr/bin/apt-get", needs_sudo=True)
        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"done", b""))
        with patch("shutil.which", return_value="/usr/bin/sudo"):
            with patch(
                "asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)
            ) as mock_exec:
                result = await install_missing_tools(manager, ["nmap"])
        assert result.returncode == 0
        args, kwargs = mock_exec.call_args
        assert args[0] == "/usr/bin/sudo"
        assert "/usr/bin/apt-get" in args
        assert "install" in args
        assert "-y" in args
        assert "nmap" in args
        assert "shell" not in kwargs

    @pytest.mark.asyncio
    async def test_skips_sudo_when_absent(self) -> None:
        manager = PackageManager(name="apt-get", path="/usr/bin/apt-get", needs_sudo=True)
        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"", b""))
        with patch("shutil.which", return_value=None):
            with patch(
                "asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)
            ) as mock_exec:
                await install_missing_tools(manager, ["nmap"])
        args, _ = mock_exec.call_args
        assert args[0] == "/usr/bin/apt-get"

    @pytest.mark.asyncio
    async def test_no_known_package_reports_tool_missing_without_subprocess(self) -> None:
        manager = PackageManager(name="apt-get", path="/usr/bin/apt-get", needs_sudo=True)
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            result = await install_missing_tools(manager, ["ysoserial"])
        assert result.tool_missing is True
        mock_exec.assert_not_called()

    @pytest.mark.asyncio
    async def test_only_catalog_packages_reach_argv_unknown_tools_dropped(self) -> None:
        manager = PackageManager(name="apt-get", path="/usr/bin/apt-get", needs_sudo=True)
        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"", b""))
        with patch("shutil.which", return_value=None):
            with patch(
                "asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)
            ) as mock_exec:
                await install_missing_tools(manager, ["nmap", "ysoserial"])
        args, _ = mock_exec.call_args
        assert "nmap" in args
        assert "ysoserial" not in args


# --------------------------------------------------------------------------
# Profiles and categories
# --------------------------------------------------------------------------


class TestProfilesAndCategories:
    def test_all_profiles_reference_known_categories(self) -> None:
        for profile in PROFILES.values():
            for category_key in profile.categories:
                assert category_key in CATEGORIES

    def test_full_hybrid_covers_every_category(self) -> None:
        assert set(PROFILES["full_hybrid"].categories) == set(CATEGORIES)

    def test_all_category_tools_are_registered_adapters(self) -> None:
        from web_security_scanner.core.external_tools import ADAPTER_REGISTRY

        for _label, tools in CATEGORIES.values():
            for tool_name in tools:
                assert tool_name in ADAPTER_REGISTRY

    def test_quick_profile_is_low_intensity_no_evasion(self) -> None:
        assert PROFILES["quick"].evasion_level == 0
        assert PROFILES["quick"].intensity == "low"


# --------------------------------------------------------------------------
# run_category
# --------------------------------------------------------------------------


class TestRunCategory:
    @pytest.mark.asyncio
    async def test_recon_with_url_target_reports_mismatch_not_crash(self) -> None:
        target = SanitizedTarget(raw="https://example.com", kind="url", value="https://example.com")
        profile = PROFILES["quick"]
        results = await run_category("recon", target, profile)
        assert set(results) == {"nmap", "naabu", "masscan"}
        assert all(r.tool_missing for r in results.values())

    @pytest.mark.asyncio
    async def test_templates_with_host_target_reports_mismatch_not_crash(self) -> None:
        target = SanitizedTarget(raw="10.0.0.1", kind="host", value="10.0.0.1")
        profile = PROFILES["quick"]
        results = await run_category("templates", target, profile)
        assert results["nuclei"].tool_missing is True

    @pytest.mark.asyncio
    async def test_recon_with_host_target_invokes_adapters(self) -> None:
        target = SanitizedTarget(raw="10.0.0.1", kind="host", value="10.0.0.1")
        profile = PROFILES["quick"]

        async def _fake_run(self: Any, *args: Any, **kwargs: Any) -> ToolResult:  # type: ignore[no-untyped-def]
            return ToolResult(
                tool=self.name, command=(), returncode=0, stdout="", stderr="",
                duration_s=0.01, findings=[],
            )

        from web_security_scanner.core.external_tools import AsyncToolAdapter

        with patch.object(AsyncToolAdapter, "run", new=_fake_run):
            results = await run_category("recon", target, profile)
        assert set(results) == {"nmap", "naabu", "masscan"}
        assert all(r.ok for r in results.values())

    @pytest.mark.asyncio
    async def test_on_result_callback_invoked_per_tool(self) -> None:
        target = SanitizedTarget(raw="10.0.0.1", kind="host", value="10.0.0.1")
        profile = PROFILES["quick"]
        seen: list[str] = []

        async def _fake_run(self: Any, *args: Any, **kwargs: Any) -> ToolResult:  # type: ignore[no-untyped-def]
            return ToolResult(
                tool=self.name, command=(), returncode=0, stdout="", stderr="", duration_s=0.0,
            )

        from web_security_scanner.core.external_tools import AsyncToolAdapter

        with patch.object(AsyncToolAdapter, "run", new=_fake_run):
            await run_category(
                "recon", target, profile, on_result=lambda name, _r: seen.append(name)
            )
        assert set(seen) == {"nmap", "naabu", "masscan"}


# --------------------------------------------------------------------------
# TUI menu/dashboard flow
# --------------------------------------------------------------------------


def _tui() -> TUI:
    return TUI(console=Console(file=MagicMock(), force_terminal=False))


class TestTUIDependencyScreen:
    def test_show_dependency_summary_returns_missing_list(self) -> None:
        tui = _tui()
        missing = tui.show_dependency_summary({"nmap": True, "sqlmap": False, "ffuf": False})
        assert set(missing) == {"sqlmap", "ffuf"}

    @pytest.mark.asyncio
    async def test_offer_install_noop_when_nothing_missing(self) -> None:
        tui = _tui()
        with patch("web_security_scanner.core.tui.detect_package_manager") as mock_detect:
            await tui.offer_install([])
        mock_detect.assert_not_called()

    @pytest.mark.asyncio
    async def test_offer_install_skips_when_no_manager_found(self) -> None:
        tui = _tui()
        with patch("web_security_scanner.core.tui.detect_package_manager", return_value=None):
            await tui.offer_install(["nmap"])  # must not raise

    @pytest.mark.asyncio
    async def test_offer_install_respects_declined_confirmation(self) -> None:
        tui = _tui()
        manager = PackageManager(name="apt-get", path="/usr/bin/apt-get", needs_sudo=True)
        with patch("web_security_scanner.core.tui.detect_package_manager", return_value=manager):
            with patch("web_security_scanner.core.tui.Confirm.ask", return_value=False):
                with patch("web_security_scanner.core.tui.install_missing_tools") as mock_install:
                    await tui.offer_install(["nmap"])
        mock_install.assert_not_called()

    @pytest.mark.asyncio
    async def test_offer_install_runs_when_confirmed(self) -> None:
        tui = _tui()
        manager = PackageManager(name="apt-get", path="/usr/bin/apt-get", needs_sudo=True)
        fake_result = ToolResult(
            tool="apt-get", command=(), returncode=0, stdout="", stderr="", duration_s=0.1,
        )
        with patch("web_security_scanner.core.tui.detect_package_manager", return_value=manager):
            with patch("web_security_scanner.core.tui.Confirm.ask", return_value=True):
                with patch(
                    "web_security_scanner.core.tui.install_missing_tools",
                    new=AsyncMock(return_value=fake_result),
                ) as mock_install:
                    await tui.offer_install(["nmap"])
        mock_install.assert_awaited_once()


class TestTUIProfileAndTarget:
    def test_select_profile_returns_chosen_profile(self) -> None:
        tui = _tui()
        with patch("web_security_scanner.core.tui.IntPrompt.ask", return_value=1):
            profile = tui.select_profile()
        assert isinstance(profile, ScanProfile)
        assert profile.key == list(PROFILES)[0]

    def test_capture_target_reprompts_on_invalid_input(self) -> None:
        tui = _tui()
        with patch(
            "web_security_scanner.core.tui.Prompt.ask",
            side_effect=["--evil", "https://example.com"],
        ):
            target = tui.capture_target()
        assert target.value == "https://example.com"

    def test_select_categories_defaults_to_all_when_confirmed(self) -> None:
        tui = _tui()
        profile = PROFILES["quick"]
        with patch("web_security_scanner.core.tui.Confirm.ask", return_value=True):
            categories = tui.select_categories(profile)
        assert categories == list(profile.categories)

    def test_select_categories_narrows_on_explicit_selection(self) -> None:
        tui = _tui()
        profile = PROFILES["quick"]
        with patch("web_security_scanner.core.tui.Confirm.ask", return_value=False):
            with patch("web_security_scanner.core.tui.Prompt.ask", return_value="1"):
                categories = tui.select_categories(profile)
        assert categories == [profile.categories[0]]

    def test_select_categories_falls_back_to_all_on_unparseable_input(self) -> None:
        tui = _tui()
        profile = PROFILES["quick"]
        with patch("web_security_scanner.core.tui.Confirm.ask", return_value=False):
            with patch("web_security_scanner.core.tui.Prompt.ask", return_value="not-a-number"):
                categories = tui.select_categories(profile)
        assert categories == list(profile.categories)


class TestTUIRunScan:
    @pytest.mark.asyncio
    async def test_run_scan_aggregates_results_across_categories(self) -> None:
        tui = _tui()
        target = SanitizedTarget(raw="10.0.0.1", kind="host", value="10.0.0.1")
        profile = PROFILES["quick"]

        async def _fake_run_category(
            category_key: str, _target: Any, _profile: Any, on_result: Any = None
        ) -> dict[str, ToolResult]:
            _, tools = CATEGORIES[category_key]
            out = {}
            for name in tools:
                result = ToolResult(
                    tool=name, command=(), returncode=0, stdout="", stderr="", duration_s=0.0,
                    findings=[{"x": 1}] if name == "nmap" else [],
                )
                if on_result:
                    on_result(name, result)
                out[name] = result
            return out

        with patch("web_security_scanner.core.tui.run_category", new=_fake_run_category):
            results = await tui.run_scan(target, profile, list(profile.categories))
        assert set(results) == set(profile.categories)

    @pytest.mark.asyncio
    async def test_run_scan_propagates_cancellation_and_sets_flag(self) -> None:
        tui = _tui()
        target = SanitizedTarget(raw="10.0.0.1", kind="host", value="10.0.0.1")
        profile = PROFILES["quick"]

        async def _cancel(*_a: Any, **_k: Any) -> dict[str, ToolResult]:
            raise asyncio.CancelledError()

        with patch("web_security_scanner.core.tui.run_category", new=_cancel):
            with pytest.raises(asyncio.CancelledError):
                await tui.run_scan(target, profile, list(profile.categories))
        assert tui._cancelled is True


class TestRunTuiEntrypoint:
    def test_run_tui_handles_keyboard_interrupt_cleanly(self) -> None:
        from web_security_scanner.core import tui as tui_module

        with patch.object(
            tui_module.TUI, "main_loop", new=AsyncMock(side_effect=KeyboardInterrupt)
        ):
            tui_module.run_tui()  # must not raise: KeyboardInterrupt is caught internally
