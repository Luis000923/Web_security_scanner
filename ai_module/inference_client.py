#!/usr/bin/env python3
"""
inference_client.py — hybrid local / web inference client with resilient
fallback, for the model this ai_module fine-tunes.

Three concerns this module adds on top of :class:`ai_module.agent_inference.
AgentClient` (which already owns the raw backend calls, per-backend retry/
backoff and circuit breaker — see its docstring):

1. **Two named deployment modes.** :meth:`InferenceClient.local` wraps a
   quantized (bitsandbytes int8/4-bit) in-process ``transformers`` model —
   the 6 GB-VRAM-laptop path. :meth:`InferenceClient.web` wraps a remote
   OpenAI-compatible endpoint (vLLM / llama.cpp / any hosted domain) over the
   same async ``aiohttp`` session :class:`AgentClient` already manages.
   :meth:`InferenceClient.hybrid` configures both, with one declared primary.

2. **Defense-in-depth payload sanitisation.** ``AgentClient.triage_finding``
   does *not* itself sanitise ``finding`` before embedding it in the prompt —
   today that only happens because every in-repo caller
   (``base_tester_async._ai_triage``) remembers to wrap untrusted response
   text first (see ``ai_module/prompt_guard.py``). A client library must not
   depend on every future caller remembering that: :meth:`triage_with_fallback`
   sanitises the known untrusted fields itself before the call ever reaches
   the network, so a caller — this module's own :mod:`evaluate_model`, a
   future integration, anything — gets the same indirect-prompt-injection
   defense for free.

3. **Resilient hybrid fallback, three tiers deep.** ``web -> local ->
   deterministic heuristic``, never raising. A tier is skipped when it was
   not configured, or when its own :meth:`AgentClient.healthcheck` fails
   (cached for ``healthcheck_ttl`` seconds so a scan of many findings does
   not re-probe the backend on every single one). The final tier is the
   caller's own deterministic callable — e.g. the scanner's existing
   heuristic engine — so a finding is *never* left unclassified merely
   because both inference tiers are down. This is the same "transparent
   degradation" contract :class:`AgentClient` already documents; this module
   just extends it across two inference tiers instead of one.

Latency budget
--------------
``latency_budget_s`` (default 0.05s / 50ms) is recorded against and
*annotated* on every call, never enforced as a hard cutoff: a real LLM
generation call — local or remote — routinely takes 100s of milliseconds to
low seconds depending on token count and hardware, so a literal 50ms budget
is not achievable for full triage generation on any backend this module
targets. What *is* meaningful at that budget is the client-side overhead
around the call (sanitisation, tier selection, health-check cache lookup) and
a served, low-token, batched endpoint's *network* round-trip — so the budget
is reported as a separate ``overhead_s`` measurement alongside the real
``latency_s``, rather than silently redefining "latency" to make the number
look achievable.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from ai_module.agent_inference import AgentClient, TriageResult

Tier = Literal["web", "local", "heuristic"]

# The exact prefix AgentClient.triage_finding() uses for its internal
# "the backend call itself failed" contingency reasoning (see its docstring /
# source). Used only as a *secondary*, best-effort signal alongside the
# authoritative one (a failed healthcheck) -- see module docstring point 3.
_BACKEND_FAILURE_MARKER = "Structured triage unavailable"


@dataclass
class HybridTriageResult:
    """The outcome of :meth:`InferenceClient.triage_with_fallback`.

    ``tier`` records which of ``web`` / ``local`` / ``heuristic`` actually
    produced ``verdict`` — the whole point of the hybrid client is that a
    caller (or ``evaluate_model.py``'s report) can see *which* tier answered,
    not just that *something* did.
    """

    verdict: TriageResult
    tier: Tier
    latency_s: float
    overhead_s: float
    tiers_tried: list[Tier] = field(default_factory=list)
    degraded: bool = False


def _sanitize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Wrap the known untrusted text fields of ``finding`` before it is ever
    serialised into a prompt, regardless of whether the caller already did.

    ``sanitize_untrusted`` wraps in idempotent, self-escaping delimiters (see
    ``prompt_guard.py``), so re-wrapping an already-wrapped value is safe: it
    nests one more quarantine layer rather than corrupting or double-escaping
    the content. Only the fields realistically populated straight from a
    scanned target's response are touched; structural fields (endpoint,
    parameter name, the tool's own decision) are not attacker-controlled text
    and are left as-is.
    """
    from ai_module.prompt_guard import sanitize_untrusted

    untrusted_keys = ("response_excerpt", "response", "body", "text", "raw_response")
    out = dict(finding)
    for key in untrusted_keys:
        value = out.get(key)
        if isinstance(value, str) and value:
            out[key] = sanitize_untrusted(value).wrapped
    return out


@dataclass
class InferenceClient:
    """Hybrid local/web inference over the fine-tuned triage model.

    Construct via :meth:`local`, :meth:`web` or :meth:`hybrid` rather than
    the bare constructor — they fill in the backend/quantisation knobs each
    mode actually needs so a caller only names the model and, for ``web``,
    the endpoint.
    """

    web_client: AgentClient | None = None
    local_client: AgentClient | None = None
    primary: Tier = "web"
    healthcheck_ttl: float = 30.0
    latency_budget_s: float = 0.05
    _health_cache: dict[str, tuple[bool, float]] = field(
        default_factory=dict, repr=False, init=False
    )

    # ------------------------------------------------------------------ #
    # constructors
    # ------------------------------------------------------------------ #

    @classmethod
    def local(
        cls, model: str, *, load_in_4bit: bool = True, load_in_8bit: bool = False,
        healthcheck_ttl: float = 30.0, latency_budget_s: float = 0.05,
        **agent_kwargs: Any,
    ) -> InferenceClient:
        """In-process ``transformers`` backend, quantized by default.

        ``load_in_4bit=True`` is the default because this mode exists for
        the small-VRAM case (a 6 GB RTX 4050 running the 1.5B fine-tune);
        pass ``load_in_4bit=False, load_in_8bit=False`` for a full-precision
        local load on a bigger card. ``**agent_kwargs`` forwards to the
        underlying :class:`AgentClient` (e.g. ``max_tokens``, ``timeout``) --
        :class:`InferenceClient`'s own knobs (``healthcheck_ttl``,
        ``latency_budget_s``) are named explicitly so they are never confused
        for one of those.
        """
        client = AgentClient(
            backend="transformers", model=model,
            load_in_4bit=load_in_4bit, load_in_8bit=load_in_8bit,
            **agent_kwargs,
        )
        return cls(local_client=client, primary="local",
                   healthcheck_ttl=healthcheck_ttl, latency_budget_s=latency_budget_s)

    @classmethod
    def web(
        cls, base_url: str, model: str, *, api_key: str = "not-needed",
        healthcheck_ttl: float = 30.0, latency_budget_s: float = 0.05,
        **agent_kwargs: Any,
    ) -> InferenceClient:
        """Remote OpenAI-compatible endpoint (vLLM / llama.cpp / a hosted domain)."""
        client = AgentClient(
            backend="openai", base_url=base_url, model=model, api_key=api_key,
            **agent_kwargs,
        )
        return cls(web_client=client, primary="web",
                   healthcheck_ttl=healthcheck_ttl, latency_budget_s=latency_budget_s)

    @classmethod
    def hybrid(
        cls, *, web_base_url: str, web_model: str, local_model: str,
        primary: Tier = "web", web_api_key: str = "not-needed",
        local_load_in_4bit: bool = True, web_kwargs: dict[str, Any] | None = None,
        local_kwargs: dict[str, Any] | None = None,
        healthcheck_ttl: float = 30.0, latency_budget_s: float = 0.05,
    ) -> InferenceClient:
        """Both tiers configured: try ``primary`` first, the other on failure."""
        web_client = AgentClient(
            backend="openai", base_url=web_base_url, model=web_model,
            api_key=web_api_key, **(web_kwargs or {}),
        )
        local_client = AgentClient(
            backend="transformers", model=local_model,
            load_in_4bit=local_load_in_4bit, **(local_kwargs or {}),
        )
        return cls(web_client=web_client, local_client=local_client, primary=primary,
                   healthcheck_ttl=healthcheck_ttl, latency_budget_s=latency_budget_s)

    # ------------------------------------------------------------------ #
    # health
    # ------------------------------------------------------------------ #

    def _client_for(self, tier: Tier) -> AgentClient | None:
        if tier == "web":
            return self.web_client
        if tier == "local":
            return self.local_client
        return None

    async def _is_healthy(self, tier: Tier) -> bool:
        """Cached readiness probe for one tier.

        A fresh probe per finding would mean every single triage call in a
        long scan pays an extra round-trip (or, for ``transformers``, would
        be a no-op after the first call anyway since
        :meth:`AgentClient.healthcheck` is idempotent there) -- the TTL cache
        makes that cost amortised instead of per-call.
        """
        client = self._client_for(tier)
        if client is None:
            return False
        cached = self._health_cache.get(tier)
        now = time.monotonic()
        if cached is not None and (now - cached[1]) < self.healthcheck_ttl:
            return cached[0]
        healthy = await client.healthcheck()
        self._health_cache[tier] = (healthy, now)
        return healthy

    async def healthcheck_all(self) -> dict[Tier, bool]:
        """Probe every configured tier now (bypassing the cache) and return
        its readiness. Useful at scan/eval startup to report which tiers are
        actually live before committing to them (mirrors the orchestrator's
        own startup healthcheck for a single :class:`AgentClient`)."""
        out: dict[Tier, bool] = {}
        for tier in ("web", "local"):
            client = self._client_for(tier)  # type: ignore[arg-type]
            if client is None:
                continue
            healthy = await client.healthcheck()
            self._health_cache[tier] = (healthy, time.monotonic())
            out[tier] = healthy  # type: ignore[index]
        return out

    # ------------------------------------------------------------------ #
    # triage with fallback
    # ------------------------------------------------------------------ #

    def _tier_order(self) -> list[Tier]:
        tiers: list[Tier] = ["web", "local"] if self.primary == "web" else ["local", "web"]
        return [t for t in tiers if self._client_for(t) is not None]

    async def triage_with_fallback(
        self, finding: dict[str, Any], *,
        deterministic_fallback: Callable[[dict[str, Any]], Any] | None = None,
    ) -> HybridTriageResult:
        """Classify ``finding``, degrading web -> local -> heuristic.

        Never raises: a tier that is unhealthy, unconfigured, or whose call
        itself fails is skipped in favour of the next one; if every
        configured inference tier is unavailable, ``deterministic_fallback``
        (when given) is called and its return value wrapped in a
        ``TriageResult`` with ``verdict="UNCERTAIN"`` unless the callable
        itself sets a concrete verdict via a ``{"verdict": ..., "reasoning":
        ...}`` mapping return; a plain truthy/falsy return is read as
        vulnerable/not. With no fallback callable and no healthy tier, returns
        the same safe ``UNCERTAIN`` contingency :class:`AgentClient` itself
        uses.
        """
        overhead_start = time.monotonic()
        sanitized = _sanitize_finding(finding)
        overhead_s = time.monotonic() - overhead_start

        tried: list[Tier] = []
        for tier in self._tier_order():
            tried.append(tier)
            if not await self._is_healthy(tier):
                continue
            client = self._client_for(tier)
            assert client is not None  # narrowed by _is_healthy
            start = time.monotonic()
            verdict = await client.triage_finding(sanitized)
            latency_s = time.monotonic() - start
            # A healthy tier can still hand back the internal failure
            # contingency for a transient, per-call reason (see
            # _BACKEND_FAILURE_MARKER) -- treat that the same as an unhealthy
            # tier and fall through, rather than trusting a contingency
            # UNCERTAIN as if it were the model's own verdict.
            if _BACKEND_FAILURE_MARKER in verdict.reasoning:
                continue
            return HybridTriageResult(
                verdict=verdict, tier=tier, latency_s=latency_s,
                overhead_s=overhead_s, tiers_tried=tried, degraded=False,
            )

        tried.append("heuristic")
        start = time.monotonic()
        verdict = _run_deterministic_fallback(deterministic_fallback, sanitized)
        latency_s = time.monotonic() - start
        return HybridTriageResult(
            verdict=verdict, tier="heuristic", latency_s=latency_s,
            overhead_s=overhead_s, tiers_tried=tried, degraded=True,
        )


def _run_deterministic_fallback(
    fallback: Callable[[dict[str, Any]], Any] | None, finding: dict[str, Any],
) -> TriageResult:
    """Normalise whatever ``fallback`` returns into a :class:`TriageResult`.

    Isolated as its own function (rather than inlined) so a fallback that
    raises degrades to the same safe ``UNCERTAIN`` contingency
    :class:`AgentClient` uses on a backend failure — this tier must not be
    the one place the "never raise" contract breaks.
    """
    if fallback is None:
        return TriageResult(
            verdict="UNCERTAIN", confidence=0.0,
            reasoning="No inference tier was available and no deterministic "
                      "fallback was configured; held to the safe contingency verdict.",
        )
    try:
        result = fallback(finding)
    except Exception as exc:  # noqa: BLE001 - the fallback itself must never abort the caller
        return TriageResult(
            verdict="UNCERTAIN", confidence=0.0,
            reasoning=f"Deterministic fallback raised ({type(exc).__name__}: {exc}); "
                      "held to the safe contingency verdict.",
        )
    if isinstance(result, TriageResult):
        return result
    if isinstance(result, dict):
        verdict = str(result.get("verdict", "UNCERTAIN")).upper()
        if verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"):
            verdict = "UNCERTAIN"
        return TriageResult(
            verdict=verdict,  # type: ignore[arg-type]
            confidence=float(result.get("confidence", 0.5)),
            reasoning=str(result.get("reasoning", "deterministic heuristic fallback")),
        )
    # Plain truthy/falsy return from a bare heuristic predicate.
    return TriageResult(
        verdict="TRUE_POSITIVE" if result else "FALSE_POSITIVE",
        confidence=0.5, reasoning="deterministic heuristic fallback",
    )
