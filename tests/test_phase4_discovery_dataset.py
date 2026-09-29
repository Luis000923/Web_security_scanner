"""Phase 4 (PLAN_DESARROLLO.md §4): dataset expansion + evaluation metrics
for the discovery-mode agent, both confined to the fixed sqli/xss/pathtraver/
cmdi taxonomy (see Phase 3's design note for why)."""
from ai_module.agent_inference import AgentClient, AttackHypothesis
from ai_module.dataset_generator import BUILDERS, build_discovery_samples
from ai_module.evaluate_golden import (
    DISCOVERY_GOLDEN_SET,
    evaluate_discovery_golden,
    score_discovery,
)
from ai_module.structured_inference import DiscoveryOut


# ---- build_discovery_samples -------------------------------------------------

def test_discovery_registered_in_builders():
    assert BUILDERS["discovery"] is build_discovery_samples


def test_build_discovery_samples_nonempty_and_schema_valid():
    samples = list(build_discovery_samples([], None, weak=True))
    assert len(samples) >= 4
    for s in samples:
        import json
        obj = json.loads(s.assistant)
        DiscoveryOut.model_validate(obj)  # raises on schema drift
        assert s.system  # non-empty prompt
        assert "Attack surface" in s.user


def test_build_discovery_samples_only_fixed_taxonomy_classes():
    import json
    allowed = {"sqli", "xss", "pathtraver", "cmdi"}
    samples = list(build_discovery_samples([], None, weak=True))
    for s in samples:
        obj = json.loads(s.assistant)
        for h in obj["hypotheses"]:
            assert h["vuln_class"] in allowed


def test_build_discovery_samples_includes_empty_hypotheses_case():
    """At least one scenario must teach the model that an exhausted surface
    is a valid empty-list answer, not just always emitting something."""
    import json
    samples = list(build_discovery_samples([], None, weak=True))
    assert any(json.loads(s.assistant)["hypotheses"] == [] for s in samples)


def test_build_discovery_samples_dedup_keys_unique():
    samples = list(build_discovery_samples([], None, weak=True))
    keys = [s.meta["_dedup"] for s in samples]
    assert len(keys) == len(set(keys))


# ---- score_discovery ----------------------------------------------------------

def test_score_discovery_full_overlap():
    hyps = [AttackHypothesis(vuln_class="xss", endpoint="/a"),
            AttackHypothesis(vuln_class="sqli", endpoint="/b")]
    assert score_discovery(hyps, ["xss", "sqli"]) == 1.0


def test_score_discovery_partial_overlap():
    hyps = [AttackHypothesis(vuln_class="xss", endpoint="/a")]
    assert score_discovery(hyps, ["xss", "sqli"]) == 0.5


def test_score_discovery_accepts_plain_dicts():
    hyps = [{"vuln_class": "cmdi", "endpoint": "/a"}]
    assert score_discovery(hyps, ["cmdi"]) == 1.0


def test_score_discovery_empty_expected_and_empty_predicted_scores_one():
    assert score_discovery([], []) == 1.0


def test_score_discovery_empty_expected_but_predicted_noise_scores_zero():
    hyps = [AttackHypothesis(vuln_class="xss", endpoint="/a")]
    assert score_discovery(hyps, []) == 0.0


def test_score_discovery_no_overlap():
    hyps = [AttackHypothesis(vuln_class="pathtraver", endpoint="/a")]
    assert score_discovery(hyps, ["xss"]) == 0.0


# ---- evaluate_discovery_golden -------------------------------------------------

class _ScriptedClient(AgentClient):
    """Returns a canned hypothesis list matching each golden case's expected
    class, to exercise the harness end-to-end without a live backend."""

    def __init__(self):
        super().__init__(backend="echo")

    async def discover_attack_surface(self, app_context, findings_so_far, max_hypotheses=10):
        # Perfect-recall stub: emit exactly what disc-001..003 expect, and
        # nothing for disc-004's already-exhausted surface (2 prior findings).
        if len(findings_so_far) >= 2:
            return []
        if "/upload2" in app_context.get("endpoints", []):
            return [AttackHypothesis(vuln_class="pathtraver", endpoint="/upload2")]
        if any(f.get("vuln_class") == "sqli" for f in findings_so_far):
            return [AttackHypothesis(vuln_class="cmdi", endpoint="/report.php")]
        return [AttackHypothesis(vuln_class="xss", endpoint="/feed.gtl")]


async def test_evaluate_discovery_golden_perfect_client_scores_one():
    client = _ScriptedClient()
    result = await evaluate_discovery_golden(client)
    assert result["mean_score"] == 1.0
    assert len(result["rows"]) == len(DISCOVERY_GOLDEN_SET)


async def test_evaluate_discovery_golden_empty_client_partial_score():
    class _EmptyClient(AgentClient):
        async def discover_attack_surface(self, app_context, findings_so_far, max_hypotheses=10):
            return []

    client = _EmptyClient(backend="echo")
    result = await evaluate_discovery_golden(client)
    # disc-004 expects empty -> scores 1.0; the other three expect a
    # non-empty class and get nothing -> score 0.0 each.
    assert result["mean_score"] == 0.25
