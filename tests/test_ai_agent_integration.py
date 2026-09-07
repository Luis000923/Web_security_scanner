"""AI-agent integration: triage-based noise reduction + dynamic payload synthesis.

Every test here also asserts *graceful degradation* — if the agent is missing
or its backend is unreachable, the scanner must keep working on its
traditional heuristics without raising.
"""
import asyncio

from conftest import MockScanner

from ai_module.agent_inference import AgentClient, TriageResult
from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.sql_injection_async import (
    SQLInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.xss_tester_async import XSSTester

# --------------------------------------------------------------------------- #
# test doubles
# --------------------------------------------------------------------------- #

SQLI_ERROR = "You have an error in your SQL syntax; check the manual"


class FakeAgent:
    """Records calls; verdict/payloads are configurable per test."""

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


async def _run(tester_cls, responder, config, agent, target="http://t/p?id=1"):
    em = ScanEventEmitter()
    found, logs = [], []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k["vulnerability"]))
    em.on(ScanEventType.LOG_MESSAGE, lambda **k: logs.append(k.get("message", "")))
    cfg = {"payload_delay": 0, "max_payloads": 6}
    cfg.update(config)
    tester = tester_cls(MockScanner(responder), em, cfg)
    tester.ai_client = agent
    await tester.run_test(target)
    return found, logs


# --------------------------------------------------------------------------- #
# TriageResult contract
# --------------------------------------------------------------------------- #

def test_triageresult_is_vulnerable_bool():
    assert TriageResult("TRUE_POSITIVE", 0.9, "").is_vulnerable is True
    assert TriageResult("UNCERTAIN", 0.4, "").is_vulnerable is True  # never hide
    assert TriageResult("FALSE_POSITIVE", 0.95, "").is_vulnerable is False
    d = TriageResult("FALSE_POSITIVE", 0.95, "why", "next").as_dict()
    assert d == {"is_vulnerable": False, "verdict": "FALSE_POSITIVE",
                 "confidence": 0.95, "reasoning": "why", "next_step": "next"}


# --------------------------------------------------------------------------- #
# 1. AI triage in the detection flow
# --------------------------------------------------------------------------- #

def test_ai_verify_discards_false_positive():
    agent = FakeAgent(triage=TriageResult("FALSE_POSITIVE", 0.92,
                                          "generic error page, not injection"))
    found, logs = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_verify": True}, agent))
    assert found == []                                   # suppressed
    assert agent.triage_calls                            # agent was consulted
    assert any("AI triage discarded" in m for m in logs)
    # the raw HTTP response was handed to the agent
    assert agent.triage_calls[0]["response"]["status_code"] == 200


def test_ai_verify_keeps_true_positive_and_annotates():
    agent = FakeAgent(triage=TriageResult("TRUE_POSITIVE", 0.88, "sqlstate leak"))
    found, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_verify": True}, agent))
    assert len(found) == 1
    v = found[0]
    assert v["ai_verified"] is True
    assert v["ai_verdict"] == "TRUE_POSITIVE"
    assert v["ai_confidence"] == 0.88


def test_ai_verify_uncertain_does_not_discard():
    agent = FakeAgent(triage=TriageResult("UNCERTAIN", 0.99, "cannot tell"))
    found, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_verify": True}, agent))
    assert len(found) == 1
    assert found[0]["ai_is_vulnerable"] is True


def test_low_confidence_fp_is_not_discarded():
    agent = FakeAgent(triage=TriageResult("FALSE_POSITIVE", 0.40, "maybe"))
    found, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_verify": True, "ai_fp_threshold": 0.75}, agent))
    assert len(found) == 1                     # below threshold -> keep finding
    assert found[0]["ai_verdict"] == "FALSE_POSITIVE"


def test_ai_verify_off_never_calls_agent():
    agent = FakeAgent(triage=TriageResult("FALSE_POSITIVE", 0.99, "x"))
    found, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR}, {}, agent))
    assert len(found) == 1
    assert agent.triage_calls == []


# --------------------------------------------------------------------------- #
# 2. graceful degradation
# --------------------------------------------------------------------------- #

def test_triage_backend_down_falls_back_to_heuristics():
    agent = FakeAgent(boom=ConnectionRefusedError("localhost:8000 refused"))
    found, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_verify": True}, agent))
    assert len(found) == 1                     # heuristic finding survives
    assert "ai_verified" not in found[0]


def test_no_agent_attached_is_a_noop():
    found, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_verify": True, "ai_synthesize": True}, None))
    assert len(found) == 1


def test_synthesis_backend_down_does_not_break_scan():
    agent = FakeAgent(boom=TimeoutError("inference timeout"))
    # benign responder -> static list is exhausted, synthesis is attempted
    found, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": "hello world"},
             {"ai_verify": True, "ai_synthesize": True}, agent))
    assert found == []                          # nothing found, nothing raised
    assert agent.synth_calls                    # synthesis was attempted


# --------------------------------------------------------------------------- #
# 3. dynamic payload synthesis actually feeds the tester
# --------------------------------------------------------------------------- #

def test_synthesized_payload_finds_xss_after_static_exhaustion():
    magic = "<xss-ai-9f3c>"

    def responder(method, url, kwargs):
        # reflect ONLY the AI-synthesised marker, never the static payloads
        from conftest import param_value
        val = param_value(url, "id")
        body = f"<div>{val}</div>" if val == magic else "<div>filtered</div>"
        return {"text": body, "headers": {"Content-Type": "text/html"}}

    agent = FakeAgent(payloads=[
        {"payload": magic, "rationale": "attr break", "confirm_signal": "reflected",
         "score": 0.7},
    ])
    found, _ = asyncio.run(
        _run(XSSTester, responder, {"ai_synthesize": True}, agent,
             target="http://t/p?id=1"))
    assert len(found) == 1
    assert found[0]["payload"] == magic
    assert "AI-synthesised" in found[0]["evidence"]
    assert agent.synth_calls[0][0]["vuln_class"] == "xss"


def test_synthesis_skipped_when_static_list_hits():
    agent = FakeAgent(payloads=[{"payload": "x"}])
    found, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": SQLI_ERROR},
             {"ai_synthesize": True}, agent))
    assert len(found) == 1
    assert agent.synth_calls == []             # never needed


def test_destructive_synth_payload_filtered_without_flag():
    agent = FakeAgent(payloads=[{"payload": "'; DROP TABLE users--"}])
    found, _ = asyncio.run(
        _run(SQLInjectionTester, lambda m, u, k: {"text": "ok"},
             {"ai_synthesize": True}, agent))
    assert found == []
    # tester requested payloads but the destructive one was dropped pre-probe
    assert agent.synth_calls


# --------------------------------------------------------------------------- #
# 4. echo backend end-to-end (no network)
# --------------------------------------------------------------------------- #

def test_echo_backend_roundtrip():
    client = AgentClient(backend="echo")
    res = asyncio.run(
        client.triage_finding({"url": "http://t", "param": "q"}))
    assert res.verdict == "UNCERTAIN" and res.is_vulnerable is True
    sugg = asyncio.run(
        client.synthesize_payloads({"url": "http://t", "param": "q"}, n=3))
    assert sugg and sugg[0].payload
