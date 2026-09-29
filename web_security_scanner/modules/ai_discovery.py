"""Adapter wiring ``ai_module.vuln_discovery``'s constrained hypothesis loop
to this scanner's own tester classes and crawl state.

Kept as a thin translation layer specifically so ``ai_module`` stays fully
decoupled from ``web_security_scanner`` (no import in that direction) --
see ``ai_module/vuln_discovery.py`` for why the loop itself takes generic
callbacks instead of scanner types.
"""
from __future__ import annotations

from typing import Any

from .vulnerability_testers.command_injection_async import CommandInjectionTester
from .vulnerability_testers.path_traversal_async import PathTraversalTester
from .vulnerability_testers.sql_injection_async import SQLInjectionTester
from .vulnerability_testers.xss_tester_async import XSSTester

# Maps the fixed ai_module taxonomy (VulnClass: sqli/xss/pathtraver/cmdi) onto
# this scanner's own tester classes -- the two must never diverge (see
# ai_module/structured_inference.py's VulnClass docstring and
# ai_module/prompts/discovery_system.md, which hard-codes this same list).
VULN_CLASS_TO_TESTER: dict[str, type] = {
    "sqli": SQLInjectionTester,
    "xss": XSSTester,
    "pathtraver": PathTraversalTester,
    "cmdi": CommandInjectionTester,
}

MAX_ENDPOINTS_IN_CONTEXT = 60


def build_app_context(
    mapper: Any,
    technologies: dict[str, list[str]],
    scan_targets: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarize crawl state into the JSON context the discovery prompt sees.

    Every value here either originates from the scanned (adversarial) target
    (technologies, endpoint paths) or is this scan's own accumulated state
    (visited-URL count) -- ``AgentClient.discover_attack_surface`` wraps the
    whole blob as untrusted before it reaches the model, exactly like an HTTP
    response body reaching ``_ai_triage``.
    """
    endpoints = [str(t.get("url")) for t in scan_targets if t.get("url")]
    return {
        "technologies": {k: list(v) for k, v in (technologies or {}).items()},
        "endpoints": endpoints[:MAX_ENDPOINTS_IN_CONTEXT],
        "visited_url_count": len(getattr(mapper, "visited_urls", None) or []),
    }


def hypothesis_target_url(hypothesis: Any) -> str:
    """Build the concrete URL to re-test for one hypothesis.

    When the hypothesis names a parameter and the endpoint has no query
    string of its own, a benign placeholder value is injected so the
    tester's own ``get_query_params``/``iter_injection_points`` discovery
    has something to mutate -- mirroring how ``--target-list`` entries seed
    a parameter for a URL that doesn't already carry one.
    """
    from .vulnerability_testers.base_tester_async import VulnerabilityTester

    endpoint = str(getattr(hypothesis, "endpoint", "") or "")
    parameter = str(getattr(hypothesis, "parameter", "") or "")
    if parameter and "?" not in endpoint:
        return VulnerabilityTester.inject_param(endpoint, parameter, "1")
    return endpoint
