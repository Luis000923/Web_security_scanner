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
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from ai_module.prompts import load_prompt

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

    async def triage_finding(self, finding: dict[str, Any]) -> TriageResult:
        user = (
            "Classify the following DAST candidate.\n\n"
            f"{json.dumps(finding, ensure_ascii=False, indent=2)}\n\n"
            'Respond as JSON: {"verdict": "...", "confidence": 0-1, '
            '"reasoning": "...", "next_step": "..."}'
        )
        text = await self._chat(load_prompt("triage_system"), user)
        data = _extract_json(text)
        verdict = str(data.get("verdict", "UNCERTAIN")).upper()
        if verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"):
            verdict = "UNCERTAIN"
        return TriageResult(
            verdict=verdict,  # type: ignore[arg-type]
            confidence=_clamp01(data.get("confidence", 0.0)),
            reasoning=str(data.get("reasoning", "")).strip(),
            next_step=str(data.get("next_step", "")).strip(),
            raw=text,
        )

    async def synthesize_payloads(
        self, context: dict[str, Any], n: int = 5
    ) -> list[PayloadSuggestion]:
        user = (
            f"Target context:\n{json.dumps(context, ensure_ascii=False, indent=2)}\n\n"
            f"Propose the {n} most informative next payloads, best first. "
            'Respond as JSON: {"payloads": [{"payload": "...", "rationale": "...", '
            '"confirm_signal": "...", "score": 0-1}]}'
        )
        text = await self._chat(load_prompt("payload_system"), user)
        data = _extract_json(text)
        out: list[PayloadSuggestion] = []
        for item in data.get("payloads", [])[:n]:
            if not isinstance(item, dict) or not item.get("payload"):
                continue
            out.append(
                PayloadSuggestion(
                    payload=str(item["payload"]),
                    rationale=str(item.get("rationale", "")),
                    confirm_signal=str(item.get("confirm_signal", "")),
                    score=_clamp01(item.get("score", 0.0)),
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

    async def _chat(self, system: str, user: str) -> str:
        if self.backend == "echo":
            return self._echo(system, user)
        if self.backend == "transformers":
            return await asyncio.to_thread(self._chat_hf, system, user)
        return await self._chat_openai(system, user)

    async def _chat_openai(self, system: str, user: str) -> str:
        import aiohttp

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"},
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
# helpers
# --------------------------------------------------------------------------- #

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = _JSON_RE.search(text or "")
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return {}


def _clamp01(v: Any) -> float:
    try:
        return max(0.0, min(1.0, float(v)))
    except (TypeError, ValueError):
        return 0.0


# --------------------------------------------------------------------------- #
# manual smoke test:  python -m ai_module.agent_inference
# --------------------------------------------------------------------------- #

async def _demo() -> None:
    client = AgentClient(backend="echo")
    print(await client.triage_finding({"url": "http://t/a", "param": "q", "payload": "<x>"}))
    print(await client.synthesize_payloads({"url": "http://t/a", "param": "q"}, n=2))


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_demo())
