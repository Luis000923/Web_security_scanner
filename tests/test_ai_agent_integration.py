"""LLM triage agent integration (opt-in: ``--enable-ai-triaging``).

Covers the three guarantees of the design:

* the agent sits *before* the finding is emitted and can suppress a
  confident false positive (§II-D / §IV);
* **transparent degradation** — a missing ``ai_module``, an unreachable
  backend or a mid-scan inference error always falls back to the
  deterministic heuristics without raising;
* **structured decoding** — the OpenAI-compatible request carries the exact
  ``TriageOut`` / ``PayloadOut`` json_schema and malformed output folds to the
  safe ``UNCERTAIN`` contingency verdict.
"""
import asyncio

from conftest import MockScanner

from ai_module.agent_inference import AgentClient, TriageResult
from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.sql_injection_async import (
    SQLInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.xss_tester_async import XSSTester

SQLI_ERROR = "You have an error in your SQL syntax; check the manual"


class FakeAgent:
    """Records calls; verdict / payloads configurable per test."""

    backend = "fake"

    def __init__(self, *, triage=None, payloads=None, boom=None):
        self._triage = triage
        self._payloads = payloads or []
        self._boom = boom
        self.triage_calls = []
        self.synth_calls = []

    async def triage_finding(self, finding):
        self.triage_calls.append(finding)
        if self._boom:
            raise self._boom
        return self._triage

    async def synthesize_payloads(self, context, n=5):
        self.synth_calls.append((context, n))
        if self._boom:
            raise self._boom
        return self._payloads[:n]

    async def healthcheck(self):
        return True


async def _run(tester_cls, responder, config, agent, target="http://t/p?id=1"):
    em = ScanEventEmitter()
    found, logs, decisions = [], [], []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k["vulnerability"]))
    em.on(ScanEventType.LOG_MESSAGE, lambda **k: logs.append(k.get("message", "")))
    em.on(ScanEventType.AI_TRIAGE_DECISION, lambda **k: decisions.append(k["decision"]))
    cfg = {"payload_delay": 0, "max_payloads": 6}
    cfg.update(config)
    tester = tester_cls(MockScanner(responder), em, cfg)
    tester.ai_client = agent
    await tester.run_test(target)
    return found, logs, decisions


# --------------------------------------------------------------------------- #
# TriageResult contract
# --------------------------------------------------------------------------- #

def test_triageresult_is_vulnerable_bool():
    assert TriageResult("TRUE_POSITIVE", 0.9, "").is_vulnerable is True
    assert TriageResult("UNCERTAIN", 0.4, "").is_vulnerable is True  # never hide
    assert TriageResult("FALSE_POSITIVE", 0.95, "").is_vulnerable is False


# --------------------------------------------------------------------------- #
# 1. AI triage in the detection flow
# --------------------------------------------------------------------------- #

def test_ai_verify_discards_false_positive():
    agent = FakeAgent(triage=TriageResult("FALSE_POSITIVE", 0.92,
                                          "generic error page, not injection"))
    found, logs, decisions = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_verify": True}, agent))
    assert found == []                                   # suppressed
    assert agent.triage_calls                            # agent was consulted
    assert any("AI triage discarded" in m for m in logs)
    assert decisions and decisions[0]["dropped"] is True
    assert agent.triage_calls[0]["response"]["status_code"] == 200


def test_ai_verify_keeps_true_positive_and_annotates():
    agent = FakeAgent(triage=TriageResult("TRUE_POSITIVE", 0.88, "sqlstate leak"))
    found, _, decisions = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_verify": True}, agent))
    assert len(found) == 1
    v = found[0]
    assert v["ai_verified"] is True
    assert v["ai_verdict"] == "TRUE_POSITIVE"
    assert v["ai_confidence"] == 0.88
    assert decisions[0]["dropped"] is False


def test_ai_verify_uncertain_does_not_discard():
    agent = FakeAgent(triage=TriageResult("UNCERTAIN", 0.99, "cannot tell"))
    found, _, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_verify": True}, agent))
    assert len(found) == 1
    assert found[0]["ai_is_vulnerable"] is True


def test_low_confidence_fp_is_not_discarded():
    agent = FakeAgent(triage=TriageResult("FALSE_POSITIVE", 0.40, "maybe"))
    found, _, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_verify": True, "ai_fp_threshold": 0.75}, agent))
    assert len(found) == 1                     # below threshold -> keep finding
    assert found[0]["ai_verdict"] == "FALSE_POSITIVE"


def test_no_agent_attached_is_a_noop():
    found, _, decisions = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR}, {}, None))
    assert len(found) == 1
    assert "ai_verified" not in found[0]
    assert decisions == []


# --------------------------------------------------------------------------- #
# 2. transparent degradation
# --------------------------------------------------------------------------- #

def test_triage_backend_down_falls_back_to_heuristics():
    agent = FakeAgent(boom=ConnectionRefusedError("localhost:8000 refused"))
    found, _, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_verify": True}, agent))
    assert len(found) == 1                     # heuristic finding survives
    assert "ai_verified" not in found[0]


def test_synthesis_backend_down_does_not_break_scan():
    agent = FakeAgent(boom=TimeoutError("inference timeout"))
    found, _, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": "hello world"},
             {"ai_verify": True, "ai_synthesize": True}, agent))
    assert found == []
    assert agent.synth_calls                    # synthesis was attempted


# --------------------------------------------------------------------------- #
# 3. dynamic payload synthesis feeds the tester
# --------------------------------------------------------------------------- #

def test_synthesized_payload_finds_xss_after_static_exhaustion():
    magic = "<xss-ai-9f3c>"

    def responder(method, url, kwargs):
        from conftest import param_value
        val = param_value(url, "id")
        body = f"<div>{val}</div>" if val == magic else "<div>filtered</div>"
        return {"text": body, "headers": {"Content-Type": "text/html"}}

    agent = FakeAgent(payloads=[
        {"payload": magic, "rationale": "attr break", "confirm_signal": "reflected",
         "score": 0.7},
    ])
    found, _, _ = asyncio.run(
        _run(XSSTester, responder, {"ai_synthesize": True}, agent,
             target="http://t/p?id=1"))
    assert len(found) == 1
    assert found[0]["payload"] == magic
    assert "AI-synthesised" in found[0]["evidence"]


def test_synthesis_skipped_when_static_list_hits():
    agent = FakeAgent(payloads=[{"payload": "x"}])
    found, _, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_synthesize": True}, agent))
    assert len(found) == 1
    assert agent.synth_calls == []             # never needed


def test_destructive_synth_payload_filtered_without_flag():
    agent = FakeAgent(payloads=[{"payload": "'; DROP TABLE users--"}])
    found, _, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": "ok"},
             {"ai_synthesize": True}, agent))
    assert found == []
    assert agent.synth_calls


# --------------------------------------------------------------------------- #
# 4. echo backend + structured decoding
# --------------------------------------------------------------------------- #

def test_echo_backend_roundtrip():
    client = AgentClient(backend="echo")
    res = asyncio.run(client.triage_finding({"url": "http://t", "param": "q"}))
    assert res.verdict == "UNCERTAIN" and res.is_vulnerable is True


class _FakeAiohttpResp:
    def __init__(self, content):
        self._content = content

    def raise_for_status(self):
        pass

    async def json(self):
        return {"choices": [{"message": {"content": self._content}}]}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeAiohttpSession:
    def __init__(self, content, captured):
        self._content = content
        self._captured = captured

    def post(self, url, json, headers):
        self._captured["payload"] = json
        return _FakeAiohttpResp(self._content)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def test_chat_openai_injects_triage_json_schema(monkeypatch):
    import aiohttp

    captured: dict = {}
    reply = ('{"verdict": "TRUE_POSITIVE", "confidence": 0.9, '
             '"reasoning": "sqlstate leak", "next_step": "confirm"}')
    monkeypatch.setattr(aiohttp, "ClientSession",
                        lambda **kw: _FakeAiohttpSession(reply, captured))
    client = AgentClient(backend="openai")
    res = asyncio.run(client.triage_finding({"url": "http://t", "param": "id"}))
    fmt = captured["payload"]["response_format"]
    assert fmt["type"] == "json_schema"
    assert fmt["json_schema"]["name"] == "TriageOut"
    assert res.verdict == "TRUE_POSITIVE" and res.confidence == 0.9


def test_triage_falls_back_to_uncertain_on_garbage_response(monkeypatch):
    async def _fake_chat(self, system, user, *, response_format=None):
        return "the server hiccuped and sent back plain prose, not JSON"

    monkeypatch.setattr(AgentClient, "_chat", _fake_chat)
    res = asyncio.run(AgentClient(backend="openai").triage_finding({"url": "http://t"}))
    assert res.verdict == "UNCERTAIN"


# --------------------------------------------------------------------------- #
# 5. CLI: opt-in wiring
# --------------------------------------------------------------------------- #

from web_security_scanner.cli import _build_config, _build_parser  # noqa: E402


def _cfg(*argv):
    args = _build_parser().parse_args(["scan", "http://t", *argv])
    return _build_config(args)["testers"]


def test_cli_ai_off_by_default():
    t = _cfg()
    assert t["ai_enabled"] is False


def test_cli_enable_ai_triaging():
    t = _cfg("--enable-ai-triaging")
    assert t["ai_enabled"] is True
    assert t["ai_verify"] is True
    assert t["ai_synthesize"] is False


def test_cli_ai_synthesize_implies_enabled():
    t = _cfg("--ai-synthesize")
    assert t["ai_enabled"] is True
    assert t["ai_synthesize"] is True


def test_cli_ai_no_verify_disables_triage_half():
    t = _cfg("--ai-synthesize", "--ai-no-verify")
    assert t["ai_enabled"] is True
    assert t["ai_verify"] is False
    assert t["ai_synthesize"] is True


def test_cli_ai_backend_options_forwarded():
    t = _cfg("--enable-ai-triaging", "--ai-backend", "echo",
             "--ai-fp-threshold", "0.9")
    assert t["ai_backend"] == "echo"
    assert t["ai_fp_threshold"] == 0.9


# --------------------------------------------------------------------------- #
# 6. orchestrator graceful fallback
# --------------------------------------------------------------------------- #

def _mk_scanner(testers_cfg):
    from web_security_scanner.web_security_scanner_async import WebSecurityScanner

    scanner = WebSecurityScanner.__new__(WebSecurityScanner)
    scanner.config = {"testers": testers_cfg}
    scanner._logger = __import__("logging").getLogger("test")
    scanner.event_emitter = ScanEventEmitter()
    scanner.ai_client = None

    class _T:
        ai_client = None

    scanner.testers = [_T()]
    return scanner


def test_orchestrator_noop_without_flag():
    scanner = _mk_scanner({})
    asyncio.run(scanner._start_ai_agent())
    assert scanner.testers[0].ai_client is None


def test_orchestrator_attaches_when_enabled(monkeypatch):
    scanner = _mk_scanner({"ai_enabled": True, "ai_backend": "echo"})
    asyncio.run(scanner._start_ai_agent())
    assert scanner.testers[0].ai_client is not None


def test_orchestrator_falls_back_when_backend_down(monkeypatch):
    scanner = _mk_scanner({"ai_enabled": True})
    import ai_module.agent_inference as inf

    async def _dead(self):
        return False

    monkeypatch.setattr(inf.AgentClient, "healthcheck", _dead)
    asyncio.run(scanner._start_ai_agent())
    assert scanner.testers[0].ai_client is None
