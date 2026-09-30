"""Phase 3 (PLAN_DESARROLLO.md): proactive re-prioritization discovery loop.

Deliberately narrower than the plan's original free-text "propose novel
vuln classes" design: the model stays confined to the existing
``sqli``/``xss``/``pathtraver``/``cmdi`` taxonomy via structured decoding,
consistent with ``structured_inference.py`` / ``prompt_guard.py``'s existing
hardening. Covers:

* ``parse_discovery`` — refusal sentinel / malformed / partially-malformed /
  well-formed JSON all fold to a safe ``DiscoveryOut`` (never raises).
* ``AgentClient.discover_attack_surface`` — untrusted app-context wrapping,
  schema-constrained request, backend-failure degradation to ``[]``.
* ``iterative_discovery_loop`` — stops early on empty hypotheses / no new
  findings; feeds accumulated findings into later rounds.
* ``web_security_scanner.modules.ai_discovery`` adapter — taxonomy-to-tester
  mapping and hypothesis-to-URL translation.
"""
from ai_module.agent_inference import AgentClient, AttackHypothesis
from ai_module.structured_inference import (
    REFUSAL_SENTINEL,
    DiscoveryOut,
    parse_discovery,
)
from ai_module.vuln_discovery import iterative_discovery_loop
from web_security_scanner.modules.ai_discovery import (
    VULN_CLASS_TO_TESTER,
    build_app_context,
    hypothesis_target_url,
)
from web_security_scanner.modules.vulnerability_testers.command_injection_async import (
    CommandInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.path_traversal_async import (
    PathTraversalTester,
)
from web_security_scanner.modules.vulnerability_testers.sql_injection_async import (
    SQLInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.xss_tester_async import XSSTester

# ---- parse_discovery ---------------------------------------------------------

def test_parse_discovery_refusal_sentinel_yields_empty():
    out = parse_discovery(REFUSAL_SENTINEL)
    assert out.hypotheses == []


def test_parse_discovery_garbage_yields_empty():
    out = parse_discovery("total nonsense, not even json")
    assert out.hypotheses == []


def test_parse_discovery_well_formed():
    text = (
        '{"hypotheses": [{"vuln_class": "sqli", "endpoint": "/search", '
        '"parameter": "q", "attack_vector": "boolean-blind", '
        '"rationale": "never tested", "priority": 0.9}]}'
    )
    out = parse_discovery(text)
    assert len(out.hypotheses) == 1
    assert out.hypotheses[0].vuln_class.value == "sqli"
    assert out.hypotheses[0].priority == 0.9


def test_parse_discovery_off_taxonomy_class_dropped():
    """A class outside sqli/xss/pathtraver/cmdi must never survive parsing --
    this is the enforcement point for staying inside the fixed taxonomy."""
    text = (
        '{"hypotheses": ['
        '{"vuln_class": "prototype_pollution", "endpoint": "/x"}, '
        '{"vuln_class": "xss", "endpoint": "/ok", "priority": 0.4}'
        ']}'
    )
    out = parse_discovery(text)
    assert len(out.hypotheses) == 1
    assert out.hypotheses[0].vuln_class.value == "xss"


def test_parse_discovery_fenced_json_salvaged():
    text = 'noise before {"hypotheses": []} noise after'
    out = parse_discovery(text)
    assert isinstance(out, DiscoveryOut)
    assert out.hypotheses == []


# ---- AgentClient.discover_attack_surface -------------------------------------

class _FakeChatClient(AgentClient):
    """Overrides ``_chat`` to avoid any real network/model call."""

    def __init__(self, response_text: str, **kw):
        super().__init__(backend="echo", **kw)
        self._response_text = response_text
        self.chat_calls: list[tuple[str, str]] = []

    async def _chat(self, system, user, *, response_format=None, temperature=None):
        self.chat_calls.append((system, user))
        return self._response_text


async def test_discover_attack_surface_returns_sorted_by_priority():
    text = (
        '{"hypotheses": ['
        '{"vuln_class": "xss", "endpoint": "/a", "priority": 0.3}, '
        '{"vuln_class": "sqli", "endpoint": "/b", "priority": 0.9}'
        ']}'
    )
    client = _FakeChatClient(text)
    result = await client.discover_attack_surface({"endpoints": ["/a", "/b"]}, [])
    assert [h.priority for h in result] == [0.9, 0.3]
    assert all(isinstance(h, AttackHypothesis) for h in result)


async def test_discover_attack_surface_wraps_context_as_untrusted():
    client = _FakeChatClient('{"hypotheses": []}')
    await client.discover_attack_surface(
        {"technologies": {"server": ["nginx"]}}, [{"type": "xss"}])
    assert client.chat_calls
    _, user_msg = client.chat_calls[0]
    assert "UNTRUSTED_WEB_CONTENT" in user_msg


async def test_discover_attack_surface_backend_failure_degrades_to_empty():
    class _BoomClient(AgentClient):
        async def _chat(self, *a, **kw):
            raise RuntimeError("backend down")

    client = _BoomClient(backend="echo")
    result = await client.discover_attack_surface({}, [])
    assert result == []


async def test_discover_attack_surface_respects_max_hypotheses():
    text = '{"hypotheses": [' + ", ".join(
        f'{{"vuln_class": "xss", "endpoint": "/{i}", "priority": {i / 10}}}'
        for i in range(10)
    ) + ']}'
    client = _FakeChatClient(text)
    result = await client.discover_attack_surface({}, [], max_hypotheses=3)
    assert len(result) == 3


# ---- iterative_discovery_loop -------------------------------------------------

class _StubDiscoveryClient:
    """Yields a scripted sequence of hypothesis batches, one per round."""

    def __init__(self, rounds: list[list[AttackHypothesis]]):
        self._rounds = list(rounds)
        self.call_count = 0

    async def discover_attack_surface(self, app_context, findings_so_far, max_hypotheses=10):
        idx = self.call_count
        self.call_count += 1
        if idx >= len(self._rounds):
            return []
        return self._rounds[idx]


async def test_loop_stops_when_no_hypotheses():
    client = _StubDiscoveryClient([])

    async def build_context(findings):
        return {}

    async def run_hypothesis(h):
        raise AssertionError("must not be called with zero hypotheses")

    result = await iterative_discovery_loop(
        client, build_context=build_context, run_hypothesis=run_hypothesis)
    assert result == []
    assert client.call_count == 1


async def test_loop_stops_when_no_new_findings():
    hyp = AttackHypothesis(vuln_class="xss", endpoint="/a")
    client = _StubDiscoveryClient([[hyp], [hyp]])  # round 2 would run if not stopped

    async def build_context(findings):
        return {}

    async def run_hypothesis(h):
        return []  # no new findings -> loop must stop after round 1

    result = await iterative_discovery_loop(
        client, build_context=build_context, run_hypothesis=run_hypothesis, max_rounds=5)
    assert result == []
    assert client.call_count == 1  # round 2 never requested


async def test_loop_feeds_accumulated_findings_into_later_rounds():
    hyp = AttackHypothesis(vuln_class="sqli", endpoint="/a")
    client = _StubDiscoveryClient([[hyp], [hyp], []])
    seen_findings_counts = []

    async def build_context(findings):
        seen_findings_counts.append(len(findings))
        return {}

    call_n = {"n": 0}
    async def run_hypothesis(h):
        call_n["n"] += 1
        return [{"type": "sqli", "url": h.endpoint, "round": call_n["n"]}]

    result = await iterative_discovery_loop(
        client, build_context=build_context, run_hypothesis=run_hypothesis, max_rounds=5)
    assert len(result) == 2
    # Round 2 sees round 1's finding; round 3 (empty hypotheses) still builds
    # context before stopping, seeing both rounds' findings.
    assert seen_findings_counts == [0, 1, 2]


async def test_loop_respects_max_rounds():
    hyp = AttackHypothesis(vuln_class="cmdi", endpoint="/a")
    client = _StubDiscoveryClient([[hyp]] * 10)  # would run forever if unbounded

    async def build_context(findings):
        return {}

    async def run_hypothesis(h):
        return [{"type": "cmdi"}]

    result = await iterative_discovery_loop(
        client, build_context=build_context, run_hypothesis=run_hypothesis, max_rounds=2)
    assert client.call_count == 2
    assert len(result) == 2


# ---- web_security_scanner.modules.ai_discovery adapter -----------------------

def test_vuln_class_to_tester_covers_fixed_taxonomy():
    assert VULN_CLASS_TO_TESTER == {
        "sqli": SQLInjectionTester,
        "xss": XSSTester,
        "pathtraver": PathTraversalTester,
        "cmdi": CommandInjectionTester,
    }


def test_build_app_context_shape():
    class _FakeMapper:
        visited_urls = {"http://t/a", "http://t/b", "http://t/c"}

    ctx = build_app_context(
        _FakeMapper(), {"server": ["nginx"]},
        [{"url": "http://t/a"}, {"url": "http://t/b"}])
    assert ctx["technologies"] == {"server": ["nginx"]}
    assert ctx["endpoints"] == ["http://t/a", "http://t/b"]
    assert ctx["visited_url_count"] == 3


def test_hypothesis_target_url_injects_param_when_missing():
    hyp = AttackHypothesis(vuln_class="sqli", endpoint="http://t/search", parameter="q")
    url = hypothesis_target_url(hyp)
    assert url == "http://t/search?q=1"


def test_hypothesis_target_url_leaves_existing_query_untouched():
    hyp = AttackHypothesis(vuln_class="xss", endpoint="http://t/search?q=1", parameter="q")
    url = hypothesis_target_url(hyp)
    assert url == "http://t/search?q=1"


def test_hypothesis_target_url_no_parameter_returns_endpoint_as_is():
    hyp = AttackHypothesis(vuln_class="pathtraver", endpoint="http://t/file")
    assert hypothesis_target_url(hyp) == "http://t/file"
