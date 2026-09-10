#!/usr/bin/env python3
"""
structured_inference.py — constrained decoding for the lobotomised agent.

After the cognitive lobotomy the model *should* only ever emit our taxonomy,
but "should" is not a guarantee: a jailbreak-shaped input, a truncated
generation, or ordinary sampling can still produce free text. This module makes
malformed output structurally impossible by constraining generation to a typed
schema with the `outlines` library (finite-state / logit-mask guided decoding),
with graceful fallbacks so it degrades instead of crashing.

Three enforcement tiers, best first:

  1. ``outlines`` over a local transformers model — token-level grammar
     enforcement; the model *cannot* emit a non-conforming token.
  2. vLLM / OpenAI-compatible server with ``guided_json`` — same guarantee,
     enforced server-side. Use :func:`triage_schema` / :func:`payload_schema`
     as the ``guided_json`` / ``response_format`` value. (Wire into
     ``agent_inference.AgentClient._chat_openai`` via ``extra_body``.)
  3. No constraint available — generate freely, then *validate & repair*
     against the pydantic model; unparseable output falls back to the safe
     verdict (``UNCERTAIN``) rather than raising.

The taxonomy is a single source of truth (the pydantic models below), shared by
the schema exporters and the local generator, so training labels, server
constraints, and local decoding can never drift apart.
"""
from __future__ import annotations

import json
import os
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

REFUSAL_SENTINEL = "[ERROR_COGNITIVO] MODO_SISTEMA_RESTRINGIDO"


# --------------------------------------------------------------------------- #
# taxonomy — the ONLY shapes the model is allowed to produce
# --------------------------------------------------------------------------- #

class Verdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNCERTAIN = "UNCERTAIN"
    # Emitted (post-hoc) when the model refuses an off-topic / out-of-scope
    # request — the lobotomy sentinel maps here.
    RESTRICTED = "RESTRICTED"


class VulnClass(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    PATH_TRAVERSAL = "pathtraver"
    CMD_INJECTION = "cmdi"


class TriageOut(BaseModel):
    """Strictly-typed triage verdict — mirrors prompts/triage_system.md."""
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(min_length=1, max_length=800)
    next_step: str = Field(default="", max_length=400)


class PayloadItem(BaseModel):
    payload: str = Field(min_length=1, max_length=512)
    rationale: str = Field(default="", max_length=400)
    confirm_signal: str = Field(default="", max_length=300)
    score: float = Field(ge=0.0, le=1.0, default=0.0)


class PayloadOut(BaseModel):
    payloads: list[PayloadItem] = Field(min_length=1, max_length=10)


# --------------------------------------------------------------------------- #
# schema exporters — for vLLM guided_json / OpenAI response_format(json_schema)
# --------------------------------------------------------------------------- #

def triage_schema() -> dict[str, Any]:
    return TriageOut.model_json_schema()


def payload_schema() -> dict[str, Any]:
    return PayloadOut.model_json_schema()


def openai_response_format(model: type[BaseModel]) -> dict[str, Any]:
    """A ``response_format`` value for OpenAI-compatible servers that support
    ``json_schema`` (vLLM >= 0.6, recent TGI). Falls back happily to plain
    ``json_object`` servers if they ignore the schema."""
    return {
        "type": "json_schema",
        "json_schema": {
            "name": model.__name__,
            "schema": model.model_json_schema(),
            "strict": True,
        },
    }


# --------------------------------------------------------------------------- #
# tier 3 — validate & repair (always available, no ML deps)
# --------------------------------------------------------------------------- #

def parse_triage(text: str) -> TriageOut:
    """Coerce arbitrary model output into a valid :class:`TriageOut`.

    Handles the refusal sentinel, fenced/space-padded JSON, and total garbage;
    never raises — the security-safe default is ``UNCERTAIN`` so a real finding
    is never silently suppressed by a parse failure.
    """
    s = (text or "").strip()
    if REFUSAL_SENTINEL in s:
        return TriageOut(verdict=Verdict.RESTRICTED, confidence=1.0,
                         reasoning="Out-of-scope request refused by the "
                                   "restricted security model.", next_step="")
    obj = _first_json_object(s)
    if obj is not None:
        try:
            return TriageOut.model_validate(obj)
        except Exception:
            # Salvage a recognisable verdict even if other fields are off.
            v = str(obj.get("verdict", "")).upper()
            if v in Verdict.__members__:
                return TriageOut(
                    verdict=Verdict[v],
                    confidence=_clamp01(obj.get("confidence", 0.0)),
                    reasoning=str(obj.get("reasoning", ""))[:800] or "n/a",
                    next_step=str(obj.get("next_step", ""))[:400],
                )
    return TriageOut(verdict=Verdict.UNCERTAIN, confidence=0.0,
                     reasoning="Unparseable model output; kept heuristic verdict.",
                     next_step="Re-run with constrained decoding enabled.")


def parse_payloads(text: str) -> PayloadOut:
    s = (text or "").strip()
    obj = _first_json_object(s)
    if obj is not None:
        try:
            return PayloadOut.model_validate(obj)
        except Exception:
            items = []
            for it in (obj.get("payloads") or []):
                if isinstance(it, dict) and it.get("payload"):
                    try:
                        items.append(PayloadItem.model_validate(it))
                    except Exception:
                        continue
            if items:
                return PayloadOut(payloads=items)
    return PayloadOut(payloads=[PayloadItem(payload="<none>", rationale="parse failure")])


# --------------------------------------------------------------------------- #
# tier 1 — outlines local constrained generation
# --------------------------------------------------------------------------- #

class StructuredLocalAgent:
    """Local, Outlines-constrained generator over the merged/adapter model.

    Lazily builds an ``outlines`` model + JSON generators. If ``outlines`` is
    not installed the constructor raises ``ImportError`` — callers should catch
    it and fall back to the server (tier 2) or free-gen + :func:`parse_triage`
    (tier 3).
    """

    def __init__(self, model_id: str | None = None, *, dtype: str = "bfloat16") -> None:
        self.model_id = model_id or os.environ.get(
            "AI_AGENT_HF_MODEL", "runs/qlora/merged"
        )
        self.dtype = dtype
        self._model: Any = None
        self._triage_gen: Any = None
        self._payload_gen: Any = None

    def _ensure(self) -> None:
        if self._model is not None:
            return
        import outlines  # raises ImportError if absent -> caller falls back

        # Outlines >= 0.1 API. Older 0.0.x exposes outlines.models.transformers;
        # both are attempted so this survives a pinned-version workstation.
        try:
            self._model = outlines.from_transformers(  # type: ignore[attr-defined]
                *_load_hf(self.model_id, self.dtype)
            )
            self._triage_gen = outlines.Generator(self._model, TriageOut)  # type: ignore[attr-defined]
            self._payload_gen = outlines.Generator(self._model, PayloadOut)  # type: ignore[attr-defined]
        except AttributeError:
            from outlines import generate, models  # type: ignore

            self._model = models.transformers(self.model_id)
            self._triage_gen = generate.json(self._model, TriageOut)
            self._payload_gen = generate.json(self._model, PayloadOut)

    def triage(self, prompt: str, *, max_tokens: int = 384) -> TriageOut:
        self._ensure()
        out = self._triage_gen(prompt, max_tokens=max_tokens)
        return out if isinstance(out, TriageOut) else TriageOut.model_validate(out)

    def synthesize(self, prompt: str, *, max_tokens: int = 512) -> PayloadOut:
        self._ensure()
        out = self._payload_gen(prompt, max_tokens=max_tokens)
        return out if isinstance(out, PayloadOut) else PayloadOut.model_validate(out)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _load_hf(model_id: str, dtype: str):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForCausalLM.from_pretrained(
        model_id, torch_dtype=getattr(torch, dtype), device_map="auto"
    )
    return model, tok


def _first_json_object(s: str) -> dict[str, Any] | None:
    try:
        v = json.loads(s)
        return v if isinstance(v, dict) else None
    except json.JSONDecodeError:
        pass
    depth = start = 0
    for i, ch in enumerate(s):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    v = json.loads(s[start : i + 1])
                    if isinstance(v, dict):
                        return v
                except json.JSONDecodeError:
                    continue
    return None


def _clamp01(v: Any) -> float:
    try:
        return max(0.0, min(1.0, float(v)))
    except (TypeError, ValueError):
        return 0.0


# --------------------------------------------------------------------------- #
# smoke test:  python -m ai_module.structured_inference
# --------------------------------------------------------------------------- #

if __name__ == "__main__":  # pragma: no cover
    print("triage schema keys:", list(triage_schema()["properties"]))
    print(parse_triage(REFUSAL_SENTINEL).model_dump())
    print(parse_triage('garbage {"verdict":"TRUE_POSITIVE","confidence":0.9,'
                       '"reasoning":"stacked error","next_step":"confirm"} tail'
                       ).model_dump())
    print(parse_triage("total nonsense").model_dump())
