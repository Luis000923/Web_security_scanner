"""AI-agent robustness + cross-validation (Phase 2, Point 3).

Covers:
* The formalized two-stage pipeline: stage 1 (``--enable-ai-triaging``)
  heuristic-anomaly verification, stage 2 (``--ai-synthesize``)
  cross-validation via synthesized PoC replay, gating a finding's
  ``CONFIRMED`` upgrade -- and stage 2's "never suppress" guarantee: a
  synthesis/replay failure or an inconclusive replay always leaves the
  finding exactly as stage 1 left it.
* False-positive threshold robustness: boundary behavior at
  ``--ai-fp-threshold`` and CLI-level range/gating validation.
* Backend/model configuration wiring (``--ai-backend`` / ``--ai-model`` /
  ``--ai-base-url`` / ``--ai-max-retries``) and graceful retry/backoff +
  exception handling in ``AgentClient``'s 'openai' backend.
* Telemetry integration: every stage's calls (success, failure, drop,
  confirm) are recorded into ``core.telemetry_engine.TelemetryEngine``.
* Report reflection: the enriched JSON and SARIF reports carry the stage-1
  and stage-2 verdicts faithfully.
"""

import asyncio

import pytest
from conftest import MockScanner, param_value

from ai_module.agent_inference import AgentClient, PayloadSuggestion, TriageResult
from web_security_scanner.core.telemetry_engine import TelemetryEngine
from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.base_tester_async import (
    VulnerabilityTester,
)
from web_security_scanner.report_engine import build_enriched_report, build_sarif_report
from web_security_scanner.report_generator import build_structured_report

# --------------------------------------------------------------------------- #
# Fixtures / fakes
# --------------------------------------------------------------------------- #


class _Dummy(VulnerabilityTester):
    """Minimal concrete VulnerabilityTester so report_vulnerability / the
    private AI-pipeline hooks can be exercised directly, without needing a
    full SQLI/XSS tester's payload sweep."""

    name = "dummy"
    description = "dummy"

    async def run_test(self, target_url, **kwargs):  # pragma: no cover - unused here
        return None


class _ScannerWithTelemetry:
    """A MockScanner-equivalent that also carries a real TelemetryEngine, so
    the AI-pipeline <-> telemetry wiring can be asserted on directly."""

    def __init__(self, responder):
        self.responder = responder
        self.telemetry_engine = TelemetryEngine()

    async def request(self, method, url, **kwargs):
        resp = self.responder(method, url, kwargs)
        resp.setdefault("status_code", 200)
        resp.setdefault("text", "")
        resp.setdefault("headers", {})
        resp.setdefault("elapsed", 0.0)
        resp.setdefault("url", url)
        return resp


class FakeAgent:
    """Records every call; verdict/payloads/failures configurable per test."""

    backend = "fake"

    def __init__(self, *, triage=None, payloads=None, triage_boom=None, synth_boom=None):
        self._triage = triage
        self._payloads = payloads or []
        self._triage_boom = triage_boom
        self._synth_boom = synth_boom
        self.triage_calls: list = []
        self.synth_calls: list = []

    async def triage_finding(self, finding):
        self.triage_calls.append(finding)
        if self._triage_boom:
            raise self._triage_boom
        return self._triage

    async def synthesize_payloads(self, context, n=5):
        self.synth_calls.append((context, n))
        if self._synth_boom:
            raise self._synth_boom
        return self._payloads[:n]

    async def healthcheck(self):
        return True


def _tester(scanner, config):
    return _Dummy(scanner, ScanEventEmitter(), config)


def _vuln(**overrides):
    base = {
        "type": "SQL Injection",
        "severity": "high",
        "confidence": "MEDIUM",
        "url": "http://t/p?id=1",
        "parameter": "id",
        "vector": "getparam",
        "payload": "' OR '1'='1",
        "evidence": "db error",
    }
    base.update(overrides)
    return base


def _reflecting_responder(magic: str, benign_body="<div>filtered</div>"):
    """A baseline-vs-payload responder: only ``magic`` reflected in the body
    produces a response that differs significantly from the benign baseline
    (see VulnerabilityTester.response_differs_significantly)."""

    def responder(method, url, kwargs):
        val = param_value(url, "id")
        if val == magic:
            return {"text": f"<div>{magic}{'X' * 200}</div>"}
        return {"text": benign_body}

    return responder


# --------------------------------------------------------------------------- #
# 1. Two-stage pipeline: stage 1 (triage) -> stage 2 (cross-validation)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_stage2_upgrades_confidence_when_replay_reproduces_signal():
    magic = "XV-CONFIRM-9f3c"
    agent = FakeAgent(payloads=[PayloadSuggestion(payload=magic)])
    scanner = _ScannerWithTelemetry(_reflecting_responder(magic))
    tester = _tester(scanner, {"ai_synthesize": True})
    tester.ai_client = agent

    found = await tester.report_vulnerability(_vuln(confidence="MEDIUM"))

    assert found is not None
    assert found["confidence"] == "CONFIRMED"
    assert found["ai_cross_validated"] is True
    assert found["ai_cross_validation_confirmed"] is True
    assert found["ai_cross_validation_payloads_tried"] == [magic]


@pytest.mark.asyncio
async def test_stage2_leaves_confidence_unchanged_when_replay_inconclusive():
    agent = FakeAgent(payloads=[PayloadSuggestion(payload="no-signal")])
    # Every response is identical -> never "differs significantly".
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "<div>same</div>"})
    tester = _tester(scanner, {"ai_synthesize": True})
    tester.ai_client = agent

    found = await tester.report_vulnerability(_vuln(confidence="MEDIUM"))

    assert found is not None
    assert found["confidence"] == "MEDIUM"  # not upgraded
    assert found["ai_cross_validated"] is True
    assert found["ai_cross_validation_confirmed"] is False


@pytest.mark.asyncio
async def test_stage2_is_noop_without_ai_synthesize():
    agent = FakeAgent(payloads=[PayloadSuggestion(payload="x")])
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "ok"})
    tester = _tester(scanner, {"ai_synthesize": False})
    tester.ai_client = agent

    found = await tester.report_vulnerability(_vuln())

    assert found is not None
    assert "ai_cross_validated" not in found
    assert agent.synth_calls == []


@pytest.mark.asyncio
async def test_stage2_is_noop_without_agent_attached():
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "ok"})
    tester = _tester(scanner, {"ai_synthesize": True})
    assert tester.ai_client is None

    found = await tester.report_vulnerability(_vuln())

    assert found is not None
    assert "ai_cross_validated" not in found


@pytest.mark.asyncio
async def test_stage2_never_drops_finding_on_synthesis_failure():
    agent = FakeAgent(synth_boom=TimeoutError("backend down"))
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "ok"})
    tester = _tester(scanner, {"ai_synthesize": True})
    tester.ai_client = agent

    found = await tester.report_vulnerability(_vuln(confidence="MEDIUM"))

    assert found is not None                 # kept, never suppressed
    assert found["confidence"] == "MEDIUM"    # not upgraded either
    assert "ai_cross_validated" not in found  # stage 2 had no opinion


@pytest.mark.asyncio
async def test_stage2_skips_destructive_candidates_without_allow_destructive():
    agent = FakeAgent(payloads=[PayloadSuggestion(payload="'; DROP TABLE users--")])
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "ok"})
    tester = _tester(scanner, {"ai_synthesize": True, "allow_destructive": False})
    tester.ai_client = agent

    found = await tester.report_vulnerability(_vuln(confidence="MEDIUM"))

    assert found is not None
    assert found["ai_cross_validation_payloads_tried"] == []  # filtered out
    assert found["ai_cross_validation_confirmed"] is False


@pytest.mark.asyncio
async def test_stage2_requires_addressable_url_and_parameter():
    agent = FakeAgent(payloads=[PayloadSuggestion(payload="x")])
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "ok"})
    tester = _tester(scanner, {"ai_synthesize": True})
    tester.ai_client = agent

    found = await tester.report_vulnerability(_vuln(parameter=None))

    assert found is not None
    assert "ai_cross_validated" not in found
    assert agent.synth_calls == []


@pytest.mark.asyncio
async def test_stage2_emits_ai_cross_validation_event():
    magic = "EVT-MAGIC"
    agent = FakeAgent(payloads=[PayloadSuggestion(payload=magic)])
    scanner = _ScannerWithTelemetry(_reflecting_responder(magic))
    em = ScanEventEmitter()
    events: list = []
    em.on(ScanEventType.AI_CROSS_VALIDATION, lambda **k: events.append(k["decision"]))
    tester = _Dummy(scanner, em, {"ai_synthesize": True})
    tester.ai_client = agent

    await tester.report_vulnerability(_vuln())

    assert len(events) == 1
    assert events[0]["confirmed"] is True
    assert events[0]["payloads_tried"] == [magic]


@pytest.mark.asyncio
async def test_stage1_drop_prevents_stage2_from_ever_running():
    """A confident false-positive verdict at stage 1 must short-circuit
    report_vulnerability entirely -- stage 2 (a separate, costlier live
    replay) must never fire for a finding that was already discarded."""
    agent = FakeAgent(
        triage=TriageResult("FALSE_POSITIVE", 0.95, "generic error page"),
        payloads=[PayloadSuggestion(payload="x")],
    )
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "ok"})
    tester = _tester(scanner, {"ai_synthesize": True, "ai_fp_threshold": 0.75})
    tester.ai_client = agent

    found = await tester.report_vulnerability(_vuln())

    assert found is None
    assert agent.synth_calls == []


# --------------------------------------------------------------------------- #
# 2. False-positive threshold robustness
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_threshold_boundary_equal_confidence_drops():
    agent = FakeAgent(triage=TriageResult("FALSE_POSITIVE", 0.75, "boundary"))
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "ok"})
    tester = _tester(scanner, {"ai_fp_threshold": 0.75})
    tester.ai_client = agent

    found = await tester.report_vulnerability(_vuln())
    assert found is None  # ">=" comparator: exact equality still drops


@pytest.mark.asyncio
async def test_threshold_boundary_just_below_keeps():
    agent = FakeAgent(triage=TriageResult("FALSE_POSITIVE", 0.7499, "boundary"))
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "ok"})
    tester = _tester(scanner, {"ai_fp_threshold": 0.75})
    tester.ai_client = agent

    found = await tester.report_vulnerability(_vuln())
    assert found is not None
    assert found["ai_is_vulnerable"] is False  # annotated, but not confident enough to drop


def test_cli_ai_fp_threshold_out_of_range_rejected():
    from web_security_scanner.cli import _build_parser, _validate_args

    parser = _build_parser()
    for bad in ("-0.1", "1.5"):
        args = parser.parse_args(
            ["scan", "http://t", "--enable-ai-triaging", "--ai-fp-threshold", bad]
        )
        with pytest.raises(SystemExit):
            _validate_args(args, parser)


def test_cli_ai_fp_threshold_valid_range_accepted():
    from web_security_scanner.cli import _build_parser, _validate_args

    parser = _build_parser()
    for ok in ("0.0", "1.0", "0.5"):
        args = parser.parse_args(
            ["scan", "http://t", "--enable-ai-triaging", "--ai-fp-threshold", ok]
        )
        _validate_args(args, parser)  # must not raise


def test_cli_ai_max_retries_requires_ai_enabled():
    from web_security_scanner.cli import _build_parser, _validate_args

    parser = _build_parser()
    args = parser.parse_args(["scan", "http://t", "--ai-max-retries", "3"])
    with pytest.raises(SystemExit):
        _validate_args(args, parser)


def test_cli_ai_max_retries_negative_rejected():
    from web_security_scanner.cli import _build_parser, _validate_args

    parser = _build_parser()
    args = parser.parse_args(
        ["scan", "http://t", "--enable-ai-triaging", "--ai-max-retries", "-1"]
    )
    with pytest.raises(SystemExit):
        _validate_args(args, parser)


def test_cli_ai_backend_model_and_retries_wired_into_config():
    from web_security_scanner.cli import _build_config, _build_parser

    args = _build_parser().parse_args([
        "scan", "http://t", "--enable-ai-triaging",
        "--ai-backend", "openai", "--ai-model", "my-model",
        "--ai-base-url", "http://127.0.0.1:9000/v1", "--ai-max-retries", "5",
    ])
    testers_cfg = _build_config(args)["testers"]
    assert testers_cfg["ai_backend"] == "openai"
    assert testers_cfg["ai_model"] == "my-model"
    assert testers_cfg["ai_base_url"] == "http://127.0.0.1:9000/v1"
    assert testers_cfg["ai_max_retries"] == 5


def test_cli_ai_max_retries_defaults_to_none():
    from web_security_scanner.cli import _build_config, _build_parser

    args = _build_parser().parse_args(["scan", "http://t", "--enable-ai-triaging"])
    assert _build_config(args)["testers"]["ai_max_retries"] is None


# --------------------------------------------------------------------------- #
# 3. AgentClient retry/backoff + exception handling ('openai' backend)
# --------------------------------------------------------------------------- #


class _FlakyResp:
    def __init__(self, status=200, content="", raise_status_error=False):
        self.status = status
        self._content = content
        self._raise = raise_status_error

    def raise_for_status(self):
        if self._raise:
            import aiohttp
            raise aiohttp.ClientResponseError(
                request_info=None, history=(), status=self.status
            )

    async def json(self):
        return {"choices": [{"message": {"content": self._content}}]}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FlakySession:
    """Simulates a backend that fails N times (connection error or a chosen
    HTTP status) before succeeding, or fails forever."""

    def __init__(self, *, fail_times=0, fail_status=None, success_content="{}"):
        self.fail_times = fail_times
        self.fail_status = fail_status
        self.success_content = success_content
        self.calls = 0

    def post(self, url, json, headers):
        self.calls += 1
        if self.calls <= self.fail_times:
            if self.fail_status is not None:
                return _FlakyResp(status=self.fail_status, raise_status_error=True)
            import aiohttp
            raise aiohttp.ClientConnectorError(connection_key=None, os_error=OSError("boom"))
        return _FlakyResp(status=200, content=self.success_content)


def _reply(verdict="TRUE_POSITIVE", confidence=0.9):
    import json as _json
    return _json.dumps({
        "verdict": verdict, "confidence": confidence,
        "reasoning": "ok", "next_step": "",
    })


def test_agent_retries_transient_connection_error_then_succeeds(monkeypatch):
    import aiohttp

    sess = _FlakySession(fail_times=2, success_content=_reply())
    monkeypatch.setattr(aiohttp, "ClientSession", lambda **kw: sess)
    client = AgentClient(backend="openai", max_retries=2, retry_backoff_base=0.001,
                         retry_backoff_max=0.002)

    res = asyncio.run(client.triage_finding({"url": "http://t"}))

    assert sess.calls == 3  # 2 failures + 1 success
    assert res.verdict == "TRUE_POSITIVE"


def test_agent_exhausts_retries_on_persistent_5xx_and_degrades(monkeypatch):
    import aiohttp

    sess = _FlakySession(fail_times=999, fail_status=503)
    monkeypatch.setattr(aiohttp, "ClientSession", lambda **kw: sess)
    client = AgentClient(backend="openai", max_retries=2, retry_backoff_base=0.001,
                         retry_backoff_max=0.002)

    res = asyncio.run(client.triage_finding({"url": "http://t"}))

    assert sess.calls == 3  # 1 initial + 2 retries, all exhausted
    assert res.verdict == "UNCERTAIN"  # safe contingency verdict, never raises


def test_agent_does_not_retry_4xx_client_error(monkeypatch):
    import aiohttp

    sess = _FlakySession(fail_times=999, fail_status=400)
    monkeypatch.setattr(aiohttp, "ClientSession", lambda **kw: sess)
    client = AgentClient(backend="openai", max_retries=3, retry_backoff_base=0.001,
                         retry_backoff_max=0.002)

    res = asyncio.run(client.triage_finding({"url": "http://t"}))

    assert sess.calls == 1  # fails fast, no retry burned on a client error
    assert res.verdict == "UNCERTAIN"


def test_agent_synthesize_payloads_also_benefits_from_retry(monkeypatch):
    import json as _json

    import aiohttp

    payloads_reply = _json.dumps({
        "payloads": [{"payload": "p1", "rationale": "r", "confirm_signal": "c", "score": 0.5}]
    })
    sess = _FlakySession(fail_times=1, success_content=payloads_reply)
    monkeypatch.setattr(aiohttp, "ClientSession", lambda **kw: sess)
    client = AgentClient(backend="openai", max_retries=2, retry_backoff_base=0.001,
                         retry_backoff_max=0.002)

    suggestions = asyncio.run(client.synthesize_payloads({"url": "http://t"}, n=3))

    assert sess.calls == 2
    assert len(suggestions) == 1
    assert suggestions[0].payload == "p1"


def test_agent_cancelled_error_propagates_without_retry(monkeypatch):
    import aiohttp

    class _CancellingSession:
        def __init__(self):
            self.calls = 0

        def post(self, url, json, headers):
            self.calls += 1
            raise asyncio.CancelledError()

    sess = _CancellingSession()
    monkeypatch.setattr(aiohttp, "ClientSession", lambda **kw: sess)
    client = AgentClient(backend="openai", max_retries=3)

    async def _run():
        with pytest.raises(asyncio.CancelledError):
            await client._chat_openai("system", "user")

    asyncio.run(_run())
    assert sess.calls == 1  # never retried


def test_agent_client_max_retries_zero_means_single_attempt(monkeypatch):
    import aiohttp

    sess = _FlakySession(fail_times=999, fail_status=503)
    monkeypatch.setattr(aiohttp, "ClientSession", lambda **kw: sess)
    client = AgentClient(backend="openai", max_retries=0)

    res = asyncio.run(client.triage_finding({"url": "http://t"}))

    assert sess.calls == 1
    assert res.verdict == "UNCERTAIN"


# --------------------------------------------------------------------------- #
# 4. Telemetry integration (core.telemetry_engine <-> AI pipeline)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_telemetry_records_successful_triage_call():
    agent = FakeAgent(triage=TriageResult("TRUE_POSITIVE", 0.9, "ok"))
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "ok"})
    tester = _tester(scanner, {})
    tester.ai_client = agent

    await tester.report_vulnerability(_vuln())

    snap = scanner.telemetry_engine.snapshot()["ai_triage"]
    assert snap["triage"]["calls"] == 1
    assert snap["triage"]["failures"] == 0


@pytest.mark.asyncio
async def test_telemetry_records_failed_triage_call():
    agent = FakeAgent(triage_boom=TimeoutError("down"))
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "ok"})
    tester = _tester(scanner, {})
    tester.ai_client = agent

    await tester.report_vulnerability(_vuln())

    snap = scanner.telemetry_engine.snapshot()["ai_triage"]
    assert snap["triage"]["calls"] == 1
    assert snap["triage"]["failures"] == 1


@pytest.mark.asyncio
async def test_telemetry_records_dropped_finding():
    agent = FakeAgent(triage=TriageResult("FALSE_POSITIVE", 0.95, "boilerplate"))
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "ok"})
    tester = _tester(scanner, {"ai_fp_threshold": 0.75})
    tester.ai_client = agent

    await tester.report_vulnerability(_vuln())

    snap = scanner.telemetry_engine.snapshot()["ai_triage"]
    assert snap["triage"]["dropped_as_false_positive"] == 1


@pytest.mark.asyncio
async def test_telemetry_records_confirmed_cross_validation():
    magic = "TELEMETRY-MAGIC"
    agent = FakeAgent(payloads=[PayloadSuggestion(payload=magic)])
    scanner = _ScannerWithTelemetry(_reflecting_responder(magic))
    tester = _tester(scanner, {"ai_synthesize": True})
    tester.ai_client = agent

    await tester.report_vulnerability(_vuln())

    snap = scanner.telemetry_engine.snapshot()["ai_triage"]
    assert snap["cross_validation"]["calls"] == 1
    assert snap["cross_validation"]["confirmed"] == 1


@pytest.mark.asyncio
async def test_telemetry_records_payload_synthesis_stage():
    agent = FakeAgent(payloads=[PayloadSuggestion(payload="p")])
    scanner = _ScannerWithTelemetry(lambda m, u, k: {"text": "ok"})
    tester = _tester(scanner, {"ai_synthesize": True})
    tester.ai_client = agent

    await tester.ai_supplemental_payloads("SQL Injection", "id",
                                          hints={}, limit=3)

    snap = scanner.telemetry_engine.snapshot()["ai_triage"]
    assert snap["payload_synthesis"]["calls"] == 1


@pytest.mark.asyncio
async def test_telemetry_hook_is_a_noop_without_engine_attached():
    """A scanner without a telemetry_engine attribute (e.g. the plain
    MockScanner most other tests use) must never raise."""
    agent = FakeAgent(triage=TriageResult("TRUE_POSITIVE", 0.9, "ok"))
    tester = _tester(MockScanner(lambda m, u, k: {"text": "ok"}), {})
    tester.ai_client = agent

    found = await tester.report_vulnerability(_vuln())
    assert found is not None  # no AttributeError


# --------------------------------------------------------------------------- #
# 5. Report reflection (enriched JSON + SARIF)
# --------------------------------------------------------------------------- #


def _scan_data_with(vuln):
    return {
        "target": "http://t/",
        "profile": "balanced",
        "statistics": {"total_vulnerabilities": 1},
        "technologies": {},
        "vulnerabilities": [vuln],
        "ai_triage": {
            "enabled": True,
            "active": True,
            "backend": "openai",
            "fp_threshold": 0.75,
            "total_candidates_triaged": 1,
            "suppressed": 0,
            "kept": 1,
            "decisions": [],
            "cross_validation": {
                "enabled": True,
                "total_candidates": 1,
                "confirmed": 1,
                "inconclusive": 0,
                "decisions": [],
            },
        },
    }


def test_enriched_report_execution_trace_includes_both_ai_stages():
    vuln = _vuln(
        confidence="CONFIRMED",
        ai_verified=True, ai_verdict="TRUE_POSITIVE", ai_confidence=0.9,
        ai_cross_validated=True, ai_cross_validation_confirmed=True,
        ai_cross_validation_payloads_tried=["p1"],
    )
    report = build_enriched_report(_scan_data_with(vuln))
    steps = {s["step"] for s in report["vulnerabilities"][0]["execution_trace"]}
    assert "ai_triage" in steps
    assert "ai_cross_validation" in steps


def test_enriched_report_surfaces_cross_validation_summary_top_level():
    vuln = _vuln(confidence="CONFIRMED")
    report = build_enriched_report(_scan_data_with(vuln))
    assert report["ai_triage"]["cross_validation"]["confirmed"] == 1


def test_sarif_result_carries_ai_verification_and_cross_validation_properties():
    vuln = _vuln(
        confidence="CONFIRMED",
        ai_verified=True, ai_verdict="TRUE_POSITIVE",
        ai_cross_validated=True, ai_cross_validation_confirmed=True,
    )
    sarif = build_sarif_report(_scan_data_with(vuln))
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["ai_verified"] is True
    assert props["ai_verdict"] == "TRUE_POSITIVE"
    assert props["ai_cross_validated"] is True
    assert props["ai_cross_validation_confirmed"] is True


def test_sarif_result_ai_properties_are_null_without_ai_pipeline():
    vuln = _vuln()  # no AI annotations at all
    sarif = build_sarif_report(_scan_data_with(vuln))
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["ai_verified"] is None
    assert props["ai_cross_validated"] is None


def test_structured_report_keeps_cross_validation_backward_compatible():
    """A scan_data without 'ai_triage' at all (AI pipeline never used) must
    not surface the key -- matches build_structured_report's existing
    contract (see report_generator.py)."""
    scan_data = _scan_data_with(_vuln())
    del scan_data["ai_triage"]
    report = build_structured_report(scan_data)
    assert "ai_triage" not in report
