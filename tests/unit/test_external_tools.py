"""Tests for core/external_tools/: framework behavior + one parse-path test
per adapter, all mocked. No real binaries are required or invoked."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from web_security_scanner.core.external_tools import (
    ADAPTER_REGISTRY,
    ArjunAdapter,
    FfufAdapter,
    FridaAdapter,
    GospiderAdapter,
    InteractshAdapter,
    JoernAdapter,
    KatanaAdapter,
    KiterunnerAdapter,
    MasscanAdapter,
    NaabuAdapter,
    NmapAdapter,
    NucleiAdapter,
    SqlmapAdapter,
    ToolNotFoundError,
    ToolTimeoutError,
    TplmapAdapter,
    YsoserialAdapter,
    Z3Adapter,
    sanitize_arg,
    sanitize_host,
    sanitize_url,
)

# --------------------------------------------------------------------------
# sanitize_* helpers
# --------------------------------------------------------------------------


class TestSanitizeArg:
    def test_rejects_empty(self) -> None:
        with pytest.raises(ValueError):
            sanitize_arg("")

    def test_rejects_nul_byte(self) -> None:
        with pytest.raises(ValueError):
            sanitize_arg("foo\x00bar")

    def test_rejects_control_chars(self) -> None:
        with pytest.raises(ValueError):
            sanitize_arg("foo\x01bar")

    def test_rejects_leading_dash_flag_injection(self) -> None:
        with pytest.raises(ValueError):
            sanitize_arg("--evil-flag")

    def test_accepts_normal_value(self) -> None:
        assert sanitize_arg("example.com") == "example.com"

    def test_shell_metacharacters_pass_through_unescaped(self) -> None:
        # No shell is ever invoked (create_subprocess_exec), so metacharacters
        # in an argv element are inert -- they are not shell syntax, just
        # literal bytes of one argument. sanitize_arg does not need to (and
        # does not) reject them.
        assert sanitize_arg("foo;rm -rf /;bar") == "foo;rm -rf /;bar"


class TestSanitizeHost:
    def test_accepts_hostname(self) -> None:
        assert sanitize_host("scanme.example.com") == "scanme.example.com"

    def test_accepts_ipv4(self) -> None:
        assert sanitize_host("192.168.1.1") == "192.168.1.1"

    def test_accepts_cidr(self) -> None:
        assert sanitize_host("10.0.0.0/24") == "10.0.0.0/24"

    def test_rejects_invalid_cidr_suffix(self) -> None:
        with pytest.raises(ValueError):
            sanitize_host("10.0.0.0/99")

    def test_rejects_garbage(self) -> None:
        with pytest.raises(ValueError):
            sanitize_host("not a host!!")

    def test_rejects_flag_injection(self) -> None:
        with pytest.raises(ValueError):
            sanitize_host("--script=evil")


class TestSanitizeUrl:
    def test_accepts_http(self) -> None:
        assert sanitize_url("http://example.com/path") == "http://example.com/path"

    def test_accepts_https(self) -> None:
        assert sanitize_url("https://example.com") == "https://example.com"

    def test_rejects_non_http_scheme(self) -> None:
        with pytest.raises(ValueError):
            sanitize_url("file:///etc/passwd")

    def test_rejects_flag_injection(self) -> None:
        with pytest.raises(ValueError):
            sanitize_url("--data-binary=@/etc/passwd")


# --------------------------------------------------------------------------
# Framework behavior: graceful fallback, timeout, argv-only exec
# --------------------------------------------------------------------------


class _StubAdapter(NmapAdapter):
    """Reuses NmapAdapter's build_command/parse but lets us force the binary lookup."""


def _mock_proc(stdout: bytes, stderr: bytes = b"", returncode: int = 0) -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode

    async def _read_stdout(_n: int = -1) -> bytes:
        nonlocal stdout
        chunk, stdout = stdout, b""
        return chunk

    async def _read_stderr(_n: int = -1) -> bytes:
        nonlocal stderr
        chunk, stderr = stderr, b""
        return chunk

    proc.stdout = MagicMock()
    proc.stdout.read = AsyncMock(side_effect=_read_stdout)
    proc.stderr = MagicMock()
    proc.stderr.read = AsyncMock(side_effect=_read_stderr)
    proc.wait = AsyncMock(return_value=returncode)
    proc.kill = MagicMock()
    return proc


class TestFrameworkGracefulFallback:
    @pytest.mark.asyncio
    async def test_missing_binary_returns_tool_missing_without_raising(self) -> None:
        adapter = NmapAdapter(binary_path=None)
        with patch("shutil.which", return_value=None):
            result = await adapter.run("192.168.1.1")
        assert result.tool_missing is True
        assert result.ok is False
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_missing_binary_strict_mode_raises(self) -> None:
        adapter = NmapAdapter(binary_path=None)
        with patch("shutil.which", return_value=None):
            with pytest.raises(ToolNotFoundError):
                await adapter.run("192.168.1.1", strict=True)

    @pytest.mark.asyncio
    async def test_successful_run_never_uses_a_shell(self) -> None:
        adapter = NmapAdapter(binary_path="/usr/bin/nmap")
        empty_xml = b"<nmaprun></nmaprun>"
        proc = _mock_proc(empty_xml)
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)
        ) as mock_exec:
            result = await adapter.run("192.168.1.1")
        assert result.ok is True
        # create_subprocess_exec, never create_subprocess_shell / shell=True.
        args, kwargs = mock_exec.call_args
        assert args[0] == "/usr/bin/nmap"
        assert "shell" not in kwargs

    @pytest.mark.asyncio
    async def test_timeout_kills_process_and_reports_timed_out(self) -> None:
        adapter = NmapAdapter(binary_path="/usr/bin/nmap")

        async def _hang(*_: Any) -> bytes:
            await asyncio.sleep(10)
            return b""

        proc = MagicMock()
        proc.returncode = None
        proc.stdout = MagicMock()
        proc.stdout.read = AsyncMock(side_effect=_hang)
        proc.stderr = MagicMock()
        proc.stderr.read = AsyncMock(side_effect=_hang)
        proc.wait = AsyncMock(return_value=None)
        proc.kill = MagicMock()

        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)):
            result = await adapter.run("192.168.1.1", timeout=0.01)

        assert result.timed_out is True
        assert result.ok is False
        proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_timeout_strict_mode_raises(self) -> None:
        adapter = NmapAdapter(binary_path="/usr/bin/nmap")

        async def _hang(*_: Any) -> bytes:
            await asyncio.sleep(10)
            return b""

        proc = MagicMock()
        proc.returncode = None
        proc.stdout = MagicMock()
        proc.stdout.read = AsyncMock(side_effect=_hang)
        proc.stderr = MagicMock()
        proc.stderr.read = AsyncMock(side_effect=_hang)
        proc.wait = AsyncMock(return_value=None)
        proc.kill = MagicMock()

        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)):
            with pytest.raises(ToolTimeoutError):
                await adapter.run("192.168.1.1", timeout=0.01, strict=True)

    @pytest.mark.asyncio
    async def test_malformed_output_does_not_crash_run(self) -> None:
        adapter = NmapAdapter(binary_path="/usr/bin/nmap")
        proc = _mock_proc(b"not valid xml <<<")
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)):
            result = await adapter.run("192.168.1.1")
        assert result.findings == []
        # returncode 0 but unparsable body: run() must not raise.
        assert result.returncode == 0

    def test_available_true_when_binary_present(self) -> None:
        adapter = NmapAdapter(binary_path="/usr/bin/nmap")
        assert asyncio.run(adapter.available()) is True

    def test_available_false_when_binary_absent(self) -> None:
        adapter = NmapAdapter()
        with patch("shutil.which", return_value=None):
            assert asyncio.run(adapter.available()) is False


# --------------------------------------------------------------------------
# build_command: argument validation per adapter
# --------------------------------------------------------------------------


class TestBuildCommandValidation:
    def test_nmap_rejects_invalid_host(self) -> None:
        with pytest.raises(ValueError):
            NmapAdapter().build_command("--script=evil")

    def test_nmap_rejects_invalid_ports(self) -> None:
        with pytest.raises(ValueError):
            NmapAdapter().build_command("10.0.0.1", ports="80;whoami")

    def test_naabu_builds_expected_argv(self) -> None:
        cmd = NaabuAdapter().build_command("10.0.0.1", ports="80,443")
        assert cmd == ["naabu", "-host", "10.0.0.1", "-json", "-silent", "-p", "80,443"]

    def test_masscan_rejects_bad_rate(self) -> None:
        with pytest.raises(ValueError):
            MasscanAdapter().build_command("10.0.0.1", rate=0)

    def test_katana_requires_valid_url(self) -> None:
        with pytest.raises(ValueError):
            KatanaAdapter().build_command("not-a-url")

    def test_gospider_rejects_zero_threads(self) -> None:
        with pytest.raises(ValueError):
            GospiderAdapter().build_command("http://example.com", threads=0)

    def test_kiterunner_rejects_flag_as_wordlist(self) -> None:
        with pytest.raises(ValueError):
            KiterunnerAdapter().build_command("http://example.com", wordlist="--evil")

    def test_ffuf_requires_fuzz_placeholder(self) -> None:
        with pytest.raises(ValueError):
            FfufAdapter().build_command("http://example.com/", wordlist="/tmp/wl.txt")

    def test_ffuf_builds_expected_argv(self) -> None:
        cmd = FfufAdapter().build_command(
            "http://example.com/FUZZ", wordlist="/tmp/wl.txt"
        )
        assert "-u" in cmd and "http://example.com/FUZZ" in cmd

    def test_arjun_rejects_bad_url(self) -> None:
        with pytest.raises(ValueError):
            ArjunAdapter().build_command("ftp://example.com")

    def test_sqlmap_rejects_bad_level(self) -> None:
        with pytest.raises(ValueError):
            SqlmapAdapter().build_command("http://example.com", level=9)

    def test_sqlmap_rejects_bad_technique(self) -> None:
        with pytest.raises(ValueError):
            SqlmapAdapter().build_command("http://example.com", technique="X")

    def test_tplmap_builds_expected_argv(self) -> None:
        cmd = TplmapAdapter().build_command("http://example.com")
        assert cmd == ["tplmap", "-u", "http://example.com"]

    def test_ysoserial_rejects_bad_gadget_name(self) -> None:
        with pytest.raises(ValueError):
            YsoserialAdapter().build_command("Commons;Collections", "id")

    def test_ysoserial_builds_expected_argv(self) -> None:
        cmd = YsoserialAdapter().build_command("CommonsCollections6", "id")
        assert cmd == ["ysoserial", "CommonsCollections6", "id"]

    def test_interactsh_default_argv(self) -> None:
        cmd = InteractshAdapter().build_command()
        assert cmd == ["interactsh-client", "-json", "-no-color"]

    def test_nuclei_rejects_bad_severity(self) -> None:
        with pytest.raises(ValueError):
            NucleiAdapter().build_command("http://example.com", severity="apocalyptic")

    def test_nuclei_rejects_bad_tags(self) -> None:
        with pytest.raises(ValueError):
            NucleiAdapter().build_command("http://example.com", tags="cve; rm -rf")

    def test_z3_rejects_flag_as_path(self) -> None:
        with pytest.raises(ValueError):
            Z3Adapter().build_command("--evil")

    def test_frida_spawn_mode_argv(self) -> None:
        cmd = FridaAdapter().build_command("com.example.app", "/tmp/hook.js")
        assert cmd == ["frida", "-U", "-f", "com.example.app", "--no-pause", "-l", "/tmp/hook.js"]

    def test_joern_rejects_flag_as_path(self) -> None:
        with pytest.raises(ValueError):
            JoernAdapter().build_command("--evil")


# --------------------------------------------------------------------------
# parse(): one representative fixture per adapter
# --------------------------------------------------------------------------


class TestParsers:
    def test_nmap_parses_open_port(self) -> None:
        xml = """<nmaprun>
          <host><address addr="10.0.0.1"/>
            <ports><port protocol="tcp" portid="22">
              <state state="open"/>
              <service name="ssh" product="OpenSSH" version="8.9"/>
            </port></ports>
          </host>
        </nmaprun>"""
        findings = NmapAdapter().parse(xml)
        assert findings == [
            {
                "host": "10.0.0.1",
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "8.9",
            }
        ]

    def test_naabu_parses_jsonl(self) -> None:
        stdout = '{"host": "10.0.0.1", "port": 443}\n{"host": "10.0.0.1", "port": 80}\n'
        findings = NaabuAdapter().parse(stdout)
        assert len(findings) == 2
        assert findings[0]["port"] == 443

    def test_naabu_skips_malformed_lines(self) -> None:
        assert NaabuAdapter().parse("not json\n{bad\n") == []

    def test_masscan_parses_json_array(self) -> None:
        stdout = '[{"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]}]'
        findings = MasscanAdapter().parse(stdout)
        assert findings == [{"host": "10.0.0.1", "port": 80, "protocol": "tcp", "state": "open"}]

    def test_katana_parses_jsonl(self) -> None:
        stdout = '{"request": {"endpoint": "http://x/a", "method": "GET"}, "response": {"status_code": 200}}\n'
        findings = KatanaAdapter().parse(stdout)
        assert findings[0]["url"] == "http://x/a"

    def test_gospider_parses_jsonl(self) -> None:
        stdout = '{"output": "http://x/b", "type": "url", "status": 200, "input": "http://x"}\n'
        findings = GospiderAdapter().parse(stdout)
        assert findings[0]["url"] == "http://x/b"

    def test_kiterunner_parses_jsonl(self) -> None:
        stdout = '{"url": "http://x/api/v1", "method": "GET", "status_code": 200, "content_length": 10}\n'
        findings = KiterunnerAdapter().parse(stdout)
        assert findings[0]["method"] == "GET"

    def test_ffuf_parses_report(self) -> None:
        stdout = '{"results": [{"url": "http://x/admin", "input": {"FUZZ": "admin"}, "status": 200, "length": 10, "words": 2}]}'
        findings = FfufAdapter().parse(stdout)
        assert findings[0]["status_code"] == 200

    def test_ffuf_handles_empty_output(self) -> None:
        assert FfufAdapter().parse("") == []

    def test_arjun_parses_report(self) -> None:
        stdout = '{"http://x/": ["id", "next"]}'
        findings = ArjunAdapter().parse(stdout)
        assert {"url": "http://x/", "parameter": "id"} in findings
        assert {"url": "http://x/", "parameter": "next"} in findings

    def test_sqlmap_parses_parameter_block(self) -> None:
        stdout = (
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
            "    Payload: id=1 AND 1=1\n"
        )
        findings = SqlmapAdapter().parse(stdout)
        assert findings[0]["parameter"] == "id"
        assert findings[0]["place"] == "GET"

    def test_tplmap_parses_confirmation(self) -> None:
        stdout = "engine Jinja2 plugin is confirmed! injection point: name"
        findings = TplmapAdapter().parse(stdout)
        assert findings[0]["engine"] == "Jinja2"

    def test_ysoserial_reports_generated_bytes(self) -> None:
        findings = YsoserialAdapter().parse("\x00\x01payloadbytes")
        assert findings[0]["generated_bytes"] > 0

    def test_ysoserial_empty_output_no_findings(self) -> None:
        assert YsoserialAdapter().parse("") == []

    def test_interactsh_parses_interaction_line(self) -> None:
        stdout = '{"protocol": "dns", "remote-address": "1.2.3.4", "full-id": "abc123"}\n'
        findings = InteractshAdapter().parse(stdout)
        assert findings[0]["protocol"] == "dns"

    def test_nuclei_parses_jsonl(self) -> None:
        stdout = '{"template-id": "cve-2021-1234", "info": {"name": "X", "severity": "high", "tags": ["cve"]}, "matched-at": "http://x/"}\n'
        findings = NucleiAdapter().parse(stdout)
        assert findings[0]["template_id"] == "cve-2021-1234"
        assert findings[0]["severity"] == "high"

    def test_z3_parses_sat_model(self) -> None:
        stdout = "sat\n(model\n  (define-fun x () Int 5)\n)"
        findings = Z3Adapter().parse(stdout)
        assert findings[0]["status"] == "sat"
        assert "define-fun" in findings[0]["model"]

    def test_frida_parses_console_lines(self) -> None:
        stdout = "[*] Attaching...\nleaked secret: abc123\n"
        findings = FridaAdapter().parse(stdout)
        assert findings == [{"message": "leaked secret: abc123"}]

    def test_joern_parses_trailing_json_array(self) -> None:
        stdout = 'Compiling CPG...\n[{"name": "sql-injection", "file": "app.py", "lineNumber": 10, "code": "cursor.execute(q)"}]'
        findings = JoernAdapter().parse(stdout)
        assert findings[0]["query"] == "sql-injection"
        assert findings[0]["line"] == 10

    def test_joern_handles_no_json(self) -> None:
        assert JoernAdapter().parse("no results found") == []


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


class TestAdapterRegistry:
    def test_registry_has_sixteen_adapters(self) -> None:
        assert len(ADAPTER_REGISTRY) == 16

    @pytest.mark.parametrize(
        "name",
        [
            "nmap",
            "naabu",
            "masscan",
            "katana",
            "gospider",
            "kiterunner",
            "ffuf",
            "arjun",
            "sqlmap",
            "tplmap",
            "ysoserial",
            "interactsh",
            "nuclei",
            "z3",
            "frida",
            "joern",
        ],
    )
    def test_registry_contains_expected_tool(self, name: str) -> None:
        assert name in ADAPTER_REGISTRY

    def test_registry_values_are_adapter_subclasses(self) -> None:
        from web_security_scanner.core.external_tools import AsyncToolAdapter

        for cls in ADAPTER_REGISTRY.values():
            assert issubclass(cls, AsyncToolAdapter)
