"""vuln_discovery.py — proactive re-prioritization loop for the DAST scanner.

**Deliberately narrower than a general "propose novel vulnerabilities"
agent.** The rest of ``ai_module`` (``structured_inference.py``,
``prompt_guard.py``) invests heavily in constraining the fine-tuned model to
a fixed, code-reviewable taxonomy (``VulnClass``: ``sqli``/``xss``/
``pathtraver``/``cmdi``) and in isolating any target-controlled text from
being interpreted as instructions -- specifically so the agent can never be
steered into emitting free-text guidance (a new "vulnerability class", an
attack technique, arbitrary prose) that a downstream consumer might act on
unreviewed. This module keeps that same constraint for discovery: the model
does not invent vulnerability classes, it only re-prioritizes *where* to
re-apply the four classes the scanner already knows how to confirm, using
its own accumulated findings and crawl state as context.

Concretely: the model returns :class:`~ai_module.agent_inference.
AttackHypothesis` objects (a fixed schema, enforced by structured decoding
exactly like ``TriageOut``/``PayloadOut``), and this loop's caller supplies
two callbacks so ``ai_module`` never needs to import the scanner package:

- ``build_context(findings_so_far) -> dict``: summarize crawl state
  (technologies, endpoints, ...) for the next round's prompt.
- ``run_hypothesis(hypothesis) -> list[dict]``: translate one hypothesis into
  an actual re-test against the scanner's own tester for that
  ``vuln_class``, and return whatever new findings it produced.

The loop stops as soon as a round produces no new hypotheses or no new
findings, so an unproductive model never spins the scanner indefinitely.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol


class _DiscoveryClient(Protocol):
    async def discover_attack_surface(
        self, app_context: dict[str, Any], findings_so_far: list[dict[str, Any]],
        max_hypotheses: int = 10,
    ) -> list[Any]: ...


async def discover_attack_surface(
    client: _DiscoveryClient,
    app_context: dict[str, Any],
    findings_so_far: list[dict[str, Any]],
    max_hypotheses: int = 10,
) -> list[Any]:
    """Thin functional-style wrapper over ``client.discover_attack_surface``.

    Kept as a module-level function (matching ``analyze_js_for_dom_xss``-style
    call sites elsewhere in this codebase) so callers/tests can patch a single
    entry point without reaching into ``AgentClient`` internals.
    """
    return await client.discover_attack_surface(app_context, findings_so_far, max_hypotheses)


async def iterative_discovery_loop(
    client: _DiscoveryClient,
    *,
    build_context: Callable[[list[dict[str, Any]]], Awaitable[dict[str, Any]]],
    run_hypothesis: Callable[[Any], Awaitable[list[dict[str, Any]]]],
    max_rounds: int = 3,
    max_hypotheses_per_round: int = 10,
) -> list[dict[str, Any]]:
    """Round-trip discovery: context -> hypotheses -> re-test -> feed back.

    Round 1 sees only the findings the caller already had (typically the
    scanner's normal heuristic pass); each later round's ``build_context``
    and ``discover_attack_surface`` call see everything confirmed so far,
    including this loop's own prior rounds. Stops early (before
    ``max_rounds``) as soon as a round proposes nothing or confirms nothing
    new, so a model that has run out of useful ideas doesn't waste further
    scan time.
    """
    all_findings: list[dict[str, Any]] = []

    for _round_num in range(1, max_rounds + 1):
        app_context = await build_context(all_findings)
        hypotheses = await discover_attack_surface(
            client, app_context, all_findings, max_hypotheses_per_round)
        if not hypotheses:
            break

        round_findings: list[dict[str, Any]] = []
        for hypothesis in hypotheses:
            round_findings.extend(await run_hypothesis(hypothesis))
        if not round_findings:
            break
        all_findings.extend(round_findings)

    return all_findings
