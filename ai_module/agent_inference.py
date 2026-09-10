#!/usr/bin/env python3
"""
agent_inference.py — async local inference bridge for the DAST scanner.

Two jobs, one client:

  1. ``triage_finding()``  — decide TRUE_POSITIVE / FALSE_POSITIVE for a
     candidate finding, with reasoning and a suggested next step.
  2. ``synthesize_payloads()`` — given endpoint/param context and probe
     history, return a ranked list of dynamic payloads to try next.

Backends (selected by ``AI_AGENT_BACKEND`` or ``AgentClient(backend=...)``):

  * ``openai``  — any OpenAI-compatible HTTP server (vLLM, TGI, llama.cpp
    ``--api``, Ollama ``/v1``, LM Studio). Default base URL
    ``http://127.0.0.1:8000/v1``. Uses aiohttp, no SDK dependency.
  * ``transformers`` — in-process HF pipeline with the QLoRA adapter merged
    or loaded on top of the 4-bit base (runs on the local RTX 5090).
  * ``echo`` — deterministic stub for tests / offline CI.

The scanner should call this behind its existing worker-pool backpressure and
treat every result as advisory (confidence-scored), never authoritative.

Structured decoding
--------------------
Both ``triage_finding()`` and ``synthesize_payloads()`` decode through
``ai_module.structured_inference``: the OpenAI-compatible request carries a
``json_schema`` ``response_format`` built from the shared pydantic taxonomy
(``TriageOut`` / ``PayloadOut``), enforced server-side (vLLM ``guided_json`` /
recent TGI); the response text is then validated with ``parse_triage`` /
``parse_payloads`` rather than hand-rolled regex/JSON-object scraping. Parsing
never raises — malformed or refused output folds to the safe ``UNCERTAIN``
contingency verdict (triage) or an empty suggestion list (payloads), so a
server that ignores the schema hint degrades gracefully instead of crashing
the scan.
"""
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any, Literal

from ai_module.prompts import load_prompt
from ai_module.structured_inference import (
    PayloadOut,
    TriageOut,
    openai_response_format,
    parse_payloads,
    parse_triage,
)

Verdict = Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"]

DEFAULT_BASE_URL = os.environ.get("AI_AGENT_BASE_URL", "http://127.0.0.1:8000/v1")
DEFAULT_MODEL = os.environ.get("AI_AGENT_MODEL", "local-security-agent")


@dataclass
class TriageResult:
    verdict: Verdict
    confidence: float
    reasoning: str
    next_step: str = ""
    raw: str = ""

    @property
    def is_vulnerable(self) -> bool:
        """Conservative bool view: only an explicit FALSE_POSITIVE is ``False``.

        UNCERTAIN stays ``True`` so a hesitant model never silently hides a
        real finding — the scanner keeps the heuristic verdict in that case.
        """
        return self.verdict != "FALSE_POSITIVE"

    def as_dict(self) -> dict[str, Any]:
        return {
            "is_vulnerable": self.is_vulnerable,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "next_step": self.next_step,
        }


@dataclass
class PayloadSuggestion:
    payload: str
    rationale: str = ""
    confirm_signal: str = ""
    score: float = 0.0


@dataclass
class AgentClient:
    backend: str = field(default_factory=lambda: os.environ.get("AI_AGENT_BACKEND", "openai"))
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    api_key: str = field(default_factory=lambda: os.environ.get("AI_AGENT_API_KEY", "not-needed"))
    timeout: float = 60.0
    max_tokens: int = 768
    temperature: float = 0.2
    _hf: Any = field(default=None, repr=False, init=False)

    # ------------------------------------------------------------------ #
    # public API
    # ------------------------------------------------------------------ #

    async def healthcheck(self) -> bool:
        """Cheap readiness probe used by the orchestrator before it commits the
        agent as the scan's engine.

        ``echo`` is always ready; ``transformers`` loads lazily in-process so we
        assume it is intended; ``openai`` pings the server's ``/models`` route
        with a short timeout. Any failure returns ``False`` and the caller falls
        back to the deterministic heuristics.
        """
        if self.backend in ("echo", "transformers"):
            return True
        try:
            import aiohttp

            timeout = aiohttp.ClientTimeout(total=min(self.timeout, 5.0))
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                ) as resp:
                    return resp.status < 500
        except Exception:  # noqa: BLE001 - unreachable / DNS / TLS / timeout
            return False

    async def triage_finding(self, finding: dict[str, Any]) -> TriageResult:
        user = (
            "Classify the following DAST candidate.\n\n"
            f"{json.dumps(finding, ensure_ascii=False, indent=2)}\n\n"
            "Return the verdict as the required structured JSON object."
        )
        text = await self._chat(
            load_prompt("triage_system"), user,
            response_format=openai_response_format(TriageOut),
        )
        try:
            parsed = parse_triage(text)
        except Exception:  # pragma: no cover - parse_triage never raises today;
            # this is defense in depth so a future bug there can never crash a scan.
            return TriageResult(
                verdict="UNCERTAIN", confidence=0.0,
                reasoning="Structured triage parse failed catastrophically; "
                          "held to the safe contingency verdict.",
                next_step="Investigate the backend's response format.", raw=text,
            )
        verdict = parsed.verdict.value
        if verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"):
            # Covers RESTRICTED (the lobotomy's refusal sentinel) and any future
            # taxonomy addition: TriageResult's contract is exactly these three
            # values, and a hedge is always safer than fabricating a verdict.
            verdict = "UNCERTAIN"
        return TriageResult(
            verdict=verdict,  # type: ignore[arg-type]
            confidence=parsed.confidence,
            reasoning=parsed.reasoning,
            next_step=parsed.next_step,
            raw=text,
        )

    async def synthesize_payloads(
        self, context: dict[str, Any], n: int = 5
    ) -> list[PayloadSuggestion]:
        user = (
            f"Target context:\n{json.dumps(context, ensure_ascii=False, indent=2)}\n\n"
            f"Propose the {n} most informative next payloads, best first. "
            "Return them as the required structured JSON object."
        )
        text = await self._chat(
            load_prompt("payload_system"), user,
            response_format=openai_response_format(PayloadOut),
        )
        try:
            parsed = parse_payloads(text)
        except Exception:  # pragma: no cover - defense in depth, see triage_finding
            return []
        out: list[PayloadSuggestion] = []
        for item in parsed.payloads[:n]:
            # parse_payloads() falls back to a "<none>" placeholder on
            # unparseable output; that sentinel must never be forwarded as a
            # real payload to fire at a target.
            if item.payload == "<none>" and item.rationale == "parse failure":
                continue
            out.append(
                PayloadSuggestion(
                    payload=item.payload,
                    rationale=item.rationale,
                    confirm_signal=item.confirm_signal,
                    score=item.score,
                )
            )
        return out

    async def batch_triage(
        self, findings: list[dict[str, Any]], concurrency: int = 4
    ) -> list[TriageResult]:
        sem = asyncio.Semaphore(concurrency)

        async def _one(f: dict[str, Any]) -> TriageResult:
            async with sem:
                return await self.triage_finding(f)

        return await asyncio.gather(*(_one(f) for f in findings))

    # ------------------------------------------------------------------ #
    # backends
    # ------------------------------------------------------------------ #

    async def _chat(
        self, system: str, user: str, *, response_format: dict[str, Any] | None = None,
    ) -> str:
        if self.backend == "echo":
            return self._echo(system, user)
        if self.backend == "transformers":
            # In-process transformers generation has no server to hand a
            # response_format to; structured enforcement there is
            # StructuredLocalAgent's job (ai_module/structured_inference.py),
            # a separate opt-in path. Free text still lands in parse_triage /
            # parse_payloads at the call site, which is schema-tolerant.
            return await asyncio.to_thread(self._chat_hf, system, user)
        return await self._chat_openai(system, user, response_format=response_format)

    async def _chat_openai(
        self, system: str, user: str, *, response_format: dict[str, Any] | None = None,
    ) -> str:
        import aiohttp

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            # Caller-supplied json_schema (see openai_response_format) enforces
            # our exact taxonomy server-side; fall back to the older open-ended
            # json_object mode if a call site doesn't provide one.
            "response_format": response_format or {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            async with sess.post(
                f"{self.base_url}/chat/completions", json=payload, headers=headers
            ) as resp:
                resp.raise_for_status()
                body = await resp.json()
        return body["choices"][0]["message"]["content"]

    def _chat_hf(self, system: str, user: str) -> str:
        if self._hf is None:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline

            model_id = os.environ.get("AI_AGENT_HF_MODEL", self.model)
            tok = AutoTokenizer.from_pretrained(model_id)
            model = AutoModelForCausalLM.from_pretrained(
                model_id, torch_dtype=torch.bfloat16, device_map="auto"
            )
            self._hf = pipeline("text-generation", model=model, tokenizer=tok)
        prompt = self._hf.tokenizer.apply_chat_template(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            tokenize=False,
            add_generation_prompt=True,
        )
        out = self._hf(
            prompt,
            max_new_tokens=self.max_tokens,
            do_sample=self.temperature > 0,
            temperature=max(self.temperature, 1e-3),
            return_full_text=False,
        )
        return out[0]["generated_text"]

    @staticmethod
    def _echo(system: str, user: str) -> str:
        if "next payloads" in user:
            return json.dumps(
                {"payloads": [{"payload": "'\"><svg/onload=confirm(1)>",
                               "rationale": "stub", "confirm_signal": "reflected marker",
                               "score": 0.5}]}
            )
        return json.dumps(
            {"verdict": "UNCERTAIN", "confidence": 0.0,
             "reasoning": "echo backend", "next_step": "use a real backend"}
        )


# --------------------------------------------------------------------------- #
# manual smoke test:  python -m ai_module.agent_inference
# --------------------------------------------------------------------------- #

async def _demo() -> None:
    client = AgentClient(backend="echo")
    print(await client.triage_finding({"url": "http://t/a", "param": "q", "payload": "<x>"}))
    print(await client.synthesize_payloads({"url": "http://t/a", "param": "q"}, n=2))


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_demo())
