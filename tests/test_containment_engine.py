"""Unit tests for Phase 3 exploit-engine containment.

Covers: the Safety Gate's scope decisions (RFC 1918/loopback/localhost,
explicit allowed domains, the ``--acknowledge-offensive-payloads`` exemption,
and the raising ``enforce()`` boundary used by the CLI), the Payload
Sandbox's command-to-echo rewriting, the exploit engine's end-to-end
containment wiring (sandboxed vs. real probes, in-run scope-deviation
skipping), the new telemetry counters, and the CLI's containment argument
validation family.
"""

import argparse

import pytest
from conftest import MockScanner

from web_security_scanner.core.telemetry_engine import TelemetryEngine
from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.containment_core import (
    ContainmentProfile,
    ContainmentVector,
    PayloadSandbox,
    SafetyGate,
    ScopeDeviationError,
)
from web_security_scanner.modules.exploit_engine import ExploitEngine
from web_security_scanner.modules.recon.surface_correlator import PrioritizedTarget

# ---------------------------------------------------------------------------
# SafetyGate: scope decisions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/app",
    "http://localhost/app",
    "http://sub.localhost/app",
    "http://10.0.0.5/app",
    "http://172.16.4.9/app",
    "http://192.168.1.1/app",
    "http://169.254.1.1/app",  # link-local
])
def test_safety_gate_allows_lab_ranges(url):
    gate = SafetyGate()
    decision = gate.evaluate(url)
    assert decision.allowed is True
    assert decision.in_lab_scope is True


def test_safety_gate_refuses_public_target_without_exemption():
    gate = SafetyGate()
    decision = gate.evaluate("http://example.com/app")
    assert decision.allowed is False
    assert decision.in_lab_scope is False
    assert "outside" in decision.reason.lower()


def test_safety_gate_enforce_raises_on_out_of_scope_target():
    gate = SafetyGate()
    with pytest.raises(ScopeDeviationError, match="Safety Gate refused"):
        gate.enforce("http://public-target.example.com/")


def test_safety_gate_enforce_passes_for_lab_target():
    gate = SafetyGate()
    gate.enforce("http://127.0.0.1:8080/app")  # must not raise


def test_safety_gate_allows_public_target_with_explicit_exemption():
    gate = SafetyGate(acknowledge_offensive_payloads=True)
    decision = gate.evaluate("http://example.com/app")
    assert decision.allowed is True
    assert decision.in_lab_scope is False


def test_safety_gate_allows_explicit_allowed_domain_and_subdomains():
    gate = SafetyGate(allowed_domains=("corp-lab.internal",))
    assert gate.evaluate("http://corp-lab.internal/").allowed is True
    assert gate.evaluate("http://app.corp-lab.internal/").allowed is True
    assert gate.evaluate("http://other.example.com/").allowed is False


def test_safety_gate_rejects_url_with_no_host():
    gate = SafetyGate()
    decision = gate.evaluate("not-a-url")
    assert decision.allowed is False


# ---------------------------------------------------------------------------
# PayloadSandbox
# ---------------------------------------------------------------------------


def test_sandbox_rewrites_known_command_token_to_echo():
    sandbox = PayloadSandbox()
    vector, token = sandbox.sandbox_command("; id")
    assert "id" not in vector.replace(token, "")  # the original command is gone
    assert f"echo {token}" in vector
    assert vector.startswith("; ")


def test_sandbox_rewrites_path_traversal_style_command():
    sandbox = PayloadSandbox()
    vector, token = sandbox.sandbox_command("; cat /etc/passwd")
    assert "/etc/passwd" not in vector
    assert token in vector


def test_sandbox_tokens_are_unique_per_call():
    sandbox = PayloadSandbox()
    _, token1 = sandbox.sandbox_command("; id")
    _, token2 = sandbox.sandbox_command("; id")
    assert token1 != token2


def test_sandbox_falls_back_for_unrecognised_command_shape():
    sandbox = PayloadSandbox()
    vector, token = sandbox.sandbox_command("; some_unknown_binary --flag")
    assert "some_unknown_binary" in vector  # original left untouched
    assert f"echo {token}" in vector        # echo appended, never destructive


# ---------------------------------------------------------------------------
# TelemetryEngine: containment counters
# ---------------------------------------------------------------------------


def test_telemetry_records_containment_attempts():
    telemetry = TelemetryEngine()
    telemetry.record_containment_attempt(elapsed=0.1, contained=True)
    telemetry.record_containment_attempt(elapsed=0.2, contained=False)
    snap = telemetry.snapshot()["containment"]
    assert snap["payload_execution_attempts"] == 2
    assert snap["contained_simulation_attempts"] == 1
    assert snap["controlled_execution_attempts"] == 1
    assert snap["attack_vector_latency_mean_s"] == pytest.approx(0.15)


def test_telemetry_records_safety_gate_interception():
    telemetry = TelemetryEngine()
    telemetry.record_safety_gate_interception()
    telemetry.record_safety_gate_interception()
    assert telemetry.snapshot()["containment"]["safety_gate_interceptions"] == 2


def test_telemetry_records_scope_deviation_with_host_dedup():
    telemetry = TelemetryEngine()
    telemetry.record_scope_deviation("evil.example.com")
    telemetry.record_scope_deviation("evil.example.com")
    telemetry.record_scope_deviation("other.example.com")
    snap = telemetry.snapshot()["containment"]
    assert snap["scope_deviation_alerts"] == 3
    assert snap["scope_deviation_hosts"] == ["evil.example.com", "other.example.com"]


def test_telemetry_reset_clears_containment_metrics():
    telemetry = TelemetryEngine()
    telemetry.record_containment_attempt(elapsed=1.0, contained=True)
    telemetry.reset()
    assert telemetry.snapshot()["containment"]["payload_execution_attempts"] == 0


# ---------------------------------------------------------------------------
# ExploitEngine integration
# ---------------------------------------------------------------------------


class _TelemetryScanner(MockScanner):
    """MockScanner with a live TelemetryEngine, like AsyncScannerCore."""

    def __init__(self, responder):
        super().__init__(responder)
        self.telemetry_engine = TelemetryEngine()


def command_injection_responder(method, url, kwargs):
    return {"text": "<html>no evidence here</html>", "status_code": 200}


def make_rce_target(url="http://127.0.0.1/upload?file=1"):
    return PrioritizedTarget(url=url, categories=("file_upload",), score=90.0, priority="CRITICAL")


@pytest.mark.asyncio
async def test_exploit_engine_sandboxes_command_injection_in_simulation_profile():
    em = ScanEventEmitter()
    attempts = []
    em.on(ScanEventType.EXPLOIT_ATTEMPT, lambda **k: attempts.append(k.get("attempt")))
    scanner = _TelemetryScanner(command_injection_responder)
    engine = ExploitEngine(
        scanner, em, {}, technologies={"languages": ["PHP"]},
        safety_gate=SafetyGate(),  # 127.0.0.1 is in lab scope
        containment_profile="simulation",
    )
    results = await engine.run([make_rce_target()])
    rce_attempts = [a for a in results if a.vulnerability_class == "rce"
                    and a.payload_category == "command_injection"]
    assert rce_attempts, "expected at least one command_injection PoC attempt"
    attempt = rce_attempts[0]
    assert attempt.containment_vector == ContainmentVector.CONTAINED_SIMULATION.value
    assert attempt.containment_profile == ContainmentProfile.SIMULATION.value
    # The real command tokens (id / uid=) must never appear in the vector sent.
    assert "id" not in attempt.adaptive_payload.replace("echo", "").split()
    snap = scanner.telemetry_engine.snapshot()["containment"]
    # file_upload also probes path_traversal, which is never sandboxed -- only
    # assert the command_injection-specific containment signal here.
    assert snap["contained_simulation_attempts"] >= 1


@pytest.mark.asyncio
async def test_exploit_engine_strict_profile_sends_real_probe():
    em = ScanEventEmitter()
    scanner = _TelemetryScanner(command_injection_responder)
    engine = ExploitEngine(
        scanner, em, {}, technologies={"languages": ["PHP"]},
        safety_gate=SafetyGate(),
        containment_profile="strict",
    )
    results = await engine.run([make_rce_target()])
    rce_attempts = [a for a in results if a.payload_category == "command_injection"]
    assert rce_attempts
    assert rce_attempts[0].containment_vector == ContainmentVector.CONTROLLED_EXECUTION.value
    snap = scanner.telemetry_engine.snapshot()["containment"]
    assert snap["controlled_execution_attempts"] >= 1
    assert snap["contained_simulation_attempts"] == 0


@pytest.mark.asyncio
async def test_exploit_engine_confirms_sandboxed_token_when_echoed_back():
    em = ScanEventEmitter()

    def echoing_responder(method, url, kwargs):
        # Simulate a genuinely vulnerable endpoint that executes the injected
        # command: the sandboxed vector's "echo <token>" comes back verbatim.
        return {"text": f"<html>{url}</html>", "status_code": 200}

    scanner = _TelemetryScanner(echoing_responder)
    engine = ExploitEngine(
        scanner, em, {}, technologies={"languages": ["PHP"]},
        safety_gate=SafetyGate(),
        containment_profile="simulation",
    )
    results = await engine.run([make_rce_target()])
    rce_attempts = [a for a in results if a.payload_category == "command_injection"]
    assert rce_attempts
    assert rce_attempts[0].classification == "CONFIRMED_EXPLOITABLE"
    assert rce_attempts[0].containment_vector == ContainmentVector.CONTAINED_SIMULATION.value


@pytest.mark.asyncio
async def test_exploit_engine_forces_simulation_for_acknowledged_out_of_scope_target():
    """--containment-profile strict must never reach a target that was only
    admitted via --acknowledge-offensive-payloads (i.e. not an actual lab) --
    the exemption covers authorization, not the target being safe to run a
    real command against."""
    em = ScanEventEmitter()
    scanner = _TelemetryScanner(command_injection_responder)
    engine = ExploitEngine(
        scanner, em, {}, technologies={"languages": ["PHP"]},
        safety_gate=SafetyGate(acknowledge_offensive_payloads=True),
        containment_profile="strict",
    )
    results = await engine.run(
        [make_rce_target(url="http://public.example.com/upload?file=1")]
    )
    rce_attempts = [a for a in results if a.payload_category == "command_injection"]
    assert rce_attempts
    assert rce_attempts[0].containment_vector == ContainmentVector.CONTAINED_SIMULATION.value
    assert rce_attempts[0].containment_profile == ContainmentProfile.SIMULATION.value


@pytest.mark.asyncio
async def test_exploit_engine_skips_out_of_scope_target_without_raising():
    em = ScanEventEmitter()
    deviations = []
    em.on(ScanEventType.SCOPE_DEVIATION, lambda **k: deviations.append(k))
    scanner = _TelemetryScanner(command_injection_responder)
    engine = ExploitEngine(
        scanner, em, {}, technologies={"languages": ["PHP"]},
        safety_gate=SafetyGate(acknowledge_offensive_payloads=False),
    )
    results = await engine.run([make_rce_target(url="http://public.example.com/upload?file=1")])
    assert results == []
    assert len(deviations) == 1
    assert deviations[0]["host"] == "public.example.com"
    snap = scanner.telemetry_engine.snapshot()["containment"]
    assert snap["scope_deviation_alerts"] == 1
    assert snap["scope_deviation_hosts"] == ["public.example.com"]


@pytest.mark.asyncio
async def test_exploit_engine_default_safety_gate_is_permissive_for_library_use():
    """An engine built without an explicit safety_gate (direct/library use,
    e.g. a unit test exercising payload selection in isolation) behaves as it
    did before Phase 3 -- unrestricted. Real enforcement lives at the CLI
    boundary and in the orchestrator, both of which always pass an explicit
    gate built from the run's actual containment flags (see
    web_security_scanner_async._run_exploit_engine)."""
    em = ScanEventEmitter()
    scanner = _TelemetryScanner(command_injection_responder)
    engine = ExploitEngine(scanner, em, {}, technologies={"languages": ["PHP"]})
    results = await engine.run([make_rce_target(url="http://public.example.com/upload?file=1")])
    assert results != []


@pytest.mark.asyncio
async def test_exploit_engine_post_exploitation_chain_bounded_by_depth():
    em = ScanEventEmitter()

    def echoing_responder(method, url, kwargs):
        return {"text": f"<html>{url}</html>", "status_code": 200}

    scanner = _TelemetryScanner(echoing_responder)
    engine = ExploitEngine(
        scanner, em, {}, technologies={"languages": ["PHP"]},
        safety_gate=SafetyGate(),
        containment_profile="simulation",
        max_exploit_depth=3,
    )
    results = await engine.run([make_rce_target()])
    rce_attempts = [a for a in results if a.payload_category == "command_injection"]
    assert rce_attempts
    assert "Post-exploitation chain" in rce_attempts[0].confirmation_evidence
    assert "max_exploit_depth=3" in rce_attempts[0].confirmation_evidence
    # base probe + 2 chained echoes = 3 sandboxed containment attempts total.
    snap = scanner.telemetry_engine.snapshot()["containment"]
    assert snap["contained_simulation_attempts"] == 3


# ---------------------------------------------------------------------------
# CLI containment argument validation
# ---------------------------------------------------------------------------


def _base_cli_args(**overrides):
    from web_security_scanner.cli import DEFAULT_CONTAINMENT_PROFILE, DEFAULT_MAX_EXPLOIT_DEPTH
    from web_security_scanner.modules.exploit_engine import DEFAULT_MAX_TARGETS

    ns = argparse.Namespace(
        url="http://127.0.0.1/app",
        generate_map=True, target_list=None,
        max_depth=3, max_urls=1000, sitemap=False, jitter=0.0, parse_js=True,
        use_browser=False, browser_nav_timeout=15.0, browser_max_pages=None,
        browser_max_concurrent_pages=3, detect_sensitive_files=False,
        sensitive_files_max_base_paths=6, sensitive_files_max_concurrent=8,
        fingerprint_server=False, fingerprint_active_probes=True,
        enable_ai_triaging=False, ai_synthesize=False, ai_no_verify=False,
        ai_backend=None, ai_base_url=None, ai_model=None, ai_fp_threshold=0.75,
        ai_max_retries=None, ai_concurrency=None, ai_batch_size=None, ai_batch_linger=None,
        ai_temperature=None, ai_payload_temperature=None, ai_max_tokens=None,
        ai_repetition_penalty=None, ai_load_in_4bit=False, ai_load_in_8bit=False,
        enable_exploit_engine=False, exploit_max_targets=DEFAULT_MAX_TARGETS,
        enable_waf_evasion=False, waf_evasion_max_retries=4,
        lab_mode=False, acknowledge_offensive_payloads=False,
        containment_allowed_domains=[], containment_profile=DEFAULT_CONTAINMENT_PROFILE,
        max_exploit_depth=DEFAULT_MAX_EXPLOIT_DEPTH,
        auth_password=None, auth_password_env=None, auth_url=None, session_config=None,
        auth_username=None, auth_username_field="username", auth_password_field="password",
        auth_field=[], auth_type="form", auth_token_path=None,
        auth_token_header="Authorization", auth_token_prefix="Bearer ",
        auth_required=False, reauth=True,
        output_file=None, output_format=None,
        adaptive_concurrency=False, adaptive_concurrency_min=2,
    )
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


def _parser():
    from web_security_scanner.cli import _build_parser
    return _build_parser()


def test_cli_containment_flags_rejected_without_exploit_engine():
    from web_security_scanner.cli import _validate_args

    args = _base_cli_args(lab_mode=True)
    with pytest.raises(SystemExit):
        _validate_args(args, _parser())


def test_cli_strict_profile_requires_lab_mode():
    from web_security_scanner.cli import _validate_args

    args = _base_cli_args(enable_exploit_engine=True, containment_profile="strict",
                          lab_mode=False)
    with pytest.raises(SystemExit):
        _validate_args(args, _parser())


def test_cli_strict_profile_with_lab_mode_passes():
    from web_security_scanner.cli import _validate_args

    args = _base_cli_args(enable_exploit_engine=True, containment_profile="strict",
                          lab_mode=True)
    _validate_args(args, _parser())  # must not raise


def test_cli_safety_gate_aborts_for_public_target():
    from web_security_scanner.cli import _validate_args

    args = _base_cli_args(enable_exploit_engine=True, url="http://public-target.example.com/")
    with pytest.raises(SystemExit):
        _validate_args(args, _parser())


def test_cli_safety_gate_allows_public_target_with_acknowledgement():
    from web_security_scanner.cli import _validate_args

    args = _base_cli_args(
        enable_exploit_engine=True, url="http://public-target.example.com/",
        acknowledge_offensive_payloads=True,
    )
    _validate_args(args, _parser())  # must not raise


def test_cli_max_exploit_depth_must_be_positive():
    from web_security_scanner.cli import _validate_args

    args = _base_cli_args(enable_exploit_engine=True, max_exploit_depth=0)
    with pytest.raises(SystemExit):
        _validate_args(args, _parser())
