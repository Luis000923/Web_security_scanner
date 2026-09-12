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
import random
import time
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
    # >1.0 discourages repeating tokens already generated -- useful against a
    # compact model's tendency to loop on a single evasion technique when
    # sampled at the higher temperature payload synthesis wants. 1.0 = off.
    # Sent as top-level 'repetition_penalty' (vLLM's OpenAI-compatible server
    # and llama.cpp --api both accept it; a strict OpenAI server ignores an
    # unknown field rather than rejecting the request) and, for the
    # 'transformers' backend, passed straight to `generate()`.
    repetition_penalty: float = 1.1
    # Payload synthesis wants more creative/varied sampling than triage (a
    # verification task where a hedged, low-temperature verdict is safer);
    # None falls back to `temperature` so setting only `temperature` keeps
    # today's single-knob behaviour unchanged.
    payload_temperature: float | None = None
    # Max sockets the shared session keeps open to the inference server.
    pool_limit: int = 8
    # 'transformers' backend only: load the base model quantized via
    # bitsandbytes instead of full bf16, trading a little quality for a
    # much smaller footprint (matches the QLoRA training precision, see
    # AUDIT.md 1.7 -- train/serve quantization skew). Mutually exclusive;
    # 4-bit wins if both are set. No effect on the 'openai' backend, where
    # quantization is the serving stack's concern (vLLM/llama.cpp flags).
    load_in_4bit: bool = False
    load_in_8bit: bool = False
    # Bounded retry/backoff for the 'openai' backend's HTTP call (Phase 2,
    # Point 3 -- "manejo elegante de reintentos... en caso de fallos del LLM
    # o API externa"). Only a transient failure is retried (connection
    # error, timeout, or a 5xx from the inference server); a 4xx (bad
    # request, auth) fails fast since retrying it changes nothing. Exhausting
    # every attempt still raises -- callers (``triage_finding`` /
    # ``synthesize_payloads``) already catch that and degrade to their safe
    # contingency value, so a struggling backend never aborts a scan, it just
    # gets a bounded number of extra chances first.
    max_retries: int = 2
    retry_backoff_base: float = 0.5
    retry_backoff_max: float = 4.0
    # Circuit breaker for the 'openai' backend (AUDIT.md 1.2/B2): once
    # ``circuit_fail_threshold`` consecutive requests exhaust their retries,
    # the breaker opens and every call fails fast (no network attempt, no
    # 60s timeout) for ``circuit_reset_after`` seconds -- callers
    # (``triage_finding`` / ``synthesize_payloads``) already degrade that
    # failure to the safe heuristic/local contingency, so opening the
    # breaker just makes a dead server cheap to sit behind instead of
    # stalling every finding for a full timeout.
    circuit_fail_threshold: int = 5
    circuit_reset_after: float = 30.0
    _hf: Any = field(default=None, repr=False, init=False)
    _session: Any = field(default=None, repr=False, init=False)
    _hf_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False, init=False)
    _circuit_fail_count: int = field(default=0, repr=False, init=False)
    _circuit_opened_at: float | None = field(default=None, repr=False, init=False)

    # ------------------------------------------------------------------ #
    # circuit breaker (openai backend)
    # ------------------------------------------------------------------ #

    def _circuit_is_open(self) -> bool:
        """``True`` while the breaker is tripped and calls should fail fast.

        Half-open on timeout: once ``circuit_reset_after`` has elapsed since
        the breaker opened, it resets itself and lets the next call through
        as a trial -- a fresh failure re-opens it (via ``_circuit_record_failure``),
        a success closes it for good (via ``_circuit_record_success``).
        """
        if self._circuit_opened_at is None:
            return False
        if time.monotonic() - self._circuit_opened_at >= self.circuit_reset_after:
            self._circuit_opened_at = None
            self._circuit_fail_count = 0
            return False
        return True

    def _circuit_record_success(self) -> None:
        self._circuit_fail_count = 0
        self._circuit_opened_at = None

    def _circuit_record_failure(self) -> None:
        self._circuit_fail_count += 1
        if self._circuit_fail_count >= self.circuit_fail_threshold:
            self._circuit_opened_at = time.monotonic()

    # ------------------------------------------------------------------ #
    # HTTP session (shared)
    # ------------------------------------------------------------------ #

    async def _get_session(self) -> Any:
        """Lazily create — and then reuse — one ``aiohttp.ClientSession``.

        A session per call meant a fresh TCP (and, off localhost, TLS) handshake
        for every single finding triaged. Holding one keyed-alive pool across
        the scan removes that per-call setup cost and lets
        :meth:`batch_triage` actually overlap requests on live connections.
        """
        import aiohttp

        sess = self._session
        if sess is None or getattr(sess, "closed", False):
            sess = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(limit=max(1, self.pool_limit)),
            )
            self._session = sess
        return sess

    async def aclose(self) -> None:
        """Close the shared session. Idempotent; safe if none was ever built."""
        sess, self._session = self._session, None
        if sess is not None and not getattr(sess, "closed", False):
            close = getattr(sess, "close", None)
            if close is not None:
                await close()

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

            sess = await self._get_session()
            async with sess.get(
                f"{self.base_url}/models",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=aiohttp.ClientTimeout(total=min(self.timeout, 5.0)),
            ) as resp:
                return bool(resp.status < 500)
        except Exception:  # noqa: BLE001 - unreachable / DNS / TLS / timeout
            return False

    async def triage_finding(self, finding: dict[str, Any]) -> TriageResult:
        user = (
            "Classify the following DAST candidate.\n\n"
            f"{json.dumps(finding, ensure_ascii=False, indent=2)}\n\n"
            "Return the verdict as the required structured JSON object."
        )
        try:
            text = await self._chat(
                load_prompt("triage_system"), user,
                response_format=openai_response_format(TriageOut),
            )
            parsed = parse_triage(text)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # The backend call (network / TLS / timeout) or a future parse bug:
            # this method's contract is that it never raises into a scan, so
            # fall back to the safe contingency verdict.
            return TriageResult(
                verdict="UNCERTAIN", confidence=0.0,
                reasoning=f"Structured triage unavailable ({type(exc).__name__}); "
                          "held to the safe contingency verdict.",
                next_step="Investigate the backend's response format.", raw="",
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
        try:
            text = await self._chat(
                load_prompt("payload_system"), user,
                response_format=openai_response_format(PayloadOut),
                temperature=self.payload_temperature,
            )
            parsed = parse_payloads(text)
        except asyncio.CancelledError:
            raise
        except Exception:  # backend failure or a future parse bug -> static corpus
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
        temperature: float | None = None,
    ) -> str:
        if self.backend == "echo":
            return self._echo(system, user)
        if self.backend == "transformers":
            # In-process transformers generation has no server to hand a
            # response_format to; structured enforcement there is
            # StructuredLocalAgent's job (ai_module/structured_inference.py),
            # a separate opt-in path. Free text still lands in parse_triage /
            # parse_payloads at the call site, which is schema-tolerant.
            await self._ensure_hf_loaded()
            return await asyncio.to_thread(self._generate_hf, system, user, temperature)
        return await self._chat_openai(system, user, response_format=response_format,
                                       temperature=temperature)

    async def _chat_openai(
        self, system: str, user: str, *, response_format: dict[str, Any] | None = None,
        temperature: float | None = None,
    ) -> str:
        import aiohttp

        if self._circuit_is_open():
            raise RuntimeError(
                f"AI backend circuit breaker open (>= {self.circuit_fail_threshold} "
                f"consecutive failures); skipping the network call for "
                f"{self.circuit_reset_after}s to avoid paying a full timeout "
                f"per finding while the server is down."
            )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": self.max_tokens,
            # Top-level, non-standard OpenAI field: vLLM's OpenAI-compatible
            # server and llama.cpp --api both read it; a strict OpenAI-spec
            # server just ignores an extra field rather than erroring.
            "repetition_penalty": self.repetition_penalty,
            # Caller-supplied json_schema (see openai_response_format) enforces
            # our exact taxonomy server-side; fall back to the older open-ended
            # json_object mode if a call site doesn't provide one.
            "response_format": response_format or {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        attempts = max(1, self.max_retries + 1)
        last_exc: BaseException | None = None
        for attempt in range(attempts):
            try:
                sess = await self._get_session()
                async with sess.post(
                    f"{self.base_url}/chat/completions", json=payload, headers=headers
                ) as resp:
                    resp.raise_for_status()
                    body = await resp.json()
                content = str(body["choices"][0]["message"]["content"])
                self._circuit_record_success()
                return content
            except asyncio.CancelledError:
                raise
            except aiohttp.ClientResponseError as exc:
                # A 4xx (bad request, auth, unknown model) will not fix
                # itself on retry -- fail fast instead of burning the
                # latency budget three times over.
                if exc.status < 500 or attempt == attempts - 1:
                    self._circuit_record_failure()
                    raise
                last_exc = exc
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                # Connection reset/refused, DNS failure, read timeout: the
                # classic transient failures an overloaded/restarting local
                # inference server produces.
                if attempt == attempts - 1:
                    self._circuit_record_failure()
                    raise
                last_exc = exc
            delay = min(self.retry_backoff_max, self.retry_backoff_base * (2 ** attempt))
            await asyncio.sleep(random.uniform(0.0, delay))
        # Unreachable (the loop above always returns or raises on its last
        # attempt), but keeps type-checkers happy about the return path.
        assert last_exc is not None
        raise last_exc

    async def _ensure_hf_loaded(self) -> None:
        """Idempotent lazy-load of the transformers pipeline under a lock.

        Two concurrent findings both hitting the cold path used to each
        build the model (double VRAM allocation / race, AUDIT.md 1.6/B5).
        Double-checked locking: the cheap check outside the lock skips the
        `await` entirely once warm; the check repeated inside the lock
        stops a second caller that was already waiting from rebuilding it.
        """
        if self._hf is not None:
            return
        async with self._hf_lock:
            if self._hf is not None:
                return
            self._hf = await asyncio.to_thread(self._build_hf_pipeline)

    def _build_hf_pipeline(self) -> Any:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline

        model_id = os.environ.get("AI_AGENT_HF_MODEL", self.model)
        tok = AutoTokenizer.from_pretrained(model_id)
        model_kwargs: dict[str, Any] = {"torch_dtype": torch.bfloat16, "device_map": "auto"}
        quant_config = self._build_quantization_config()
        if quant_config is not None:
            # bitsandbytes handles its own dtype internally; passing both a
            # 4/8-bit config and a plain torch_dtype is what the base model's
            # weights get compute-cast to (NF4 storage, bf16 compute) -- same
            # split train_qlora.py uses (AUDIT.md 1.7 -- train/serve skew).
            model_kwargs["quantization_config"] = quant_config
        model = AutoModelForCausalLM.from_pretrained(model_id, **model_kwargs)
        return pipeline("text-generation", model=model, tokenizer=tok)

    def _build_quantization_config(self) -> Any:
        """A ``BitsAndBytesConfig`` for the 'transformers' backend, or ``None``.

        Best-effort: bitsandbytes is an optional, GPU-only dependency (the
        ``ai-local`` extra doesn't require it) -- a missing install degrades
        to the plain bf16 load instead of crashing the agent.
        """
        if not (self.load_in_4bit or self.load_in_8bit):
            return None
        try:
            import torch
            from transformers import BitsAndBytesConfig
        except ImportError:
            return None
        if self.load_in_4bit:
            return BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.bfloat16,
                bnb_4bit_use_double_quant=True,
            )
        return BitsAndBytesConfig(load_in_8bit=True)

    def _generate_hf(self, system: str, user: str, temperature: float | None = None) -> str:
        temp = temperature if temperature is not None else self.temperature
        prompt = self._hf.tokenizer.apply_chat_template(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            tokenize=False,
            add_generation_prompt=True,
        )
        out = self._hf(
            prompt,
            max_new_tokens=self.max_tokens,
            do_sample=temp > 0,
            temperature=max(temp, 1e-3),
            repetition_penalty=self.repetition_penalty,
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


class BatchingTriageClient:
    """Coalesces concurrent per-finding triage calls into batched requests.

    ``VulnerabilityTester.report_vulnerability`` consults the agent inline, once
    per candidate, from whichever tester found it. Left alone that turns the
    scan's tail into one full inference round trip per finding, serialised —
    with several testers running concurrently, the backend sits idle between
    them.

    This wrapper keeps exactly the ``triage_finding(finding) -> TriageResult``
    contract the testers duck-type against, but parks each caller on a future,
    gathers everything that arrives within ``linger`` seconds (or ``max_batch``
    findings, whichever lands first) and settles them all from a single
    :meth:`AgentClient.batch_triage` — which fans out over the client's one
    reusable HTTP session instead of a connection per finding.

    Failure semantics are unchanged: a backend error propagates to every caller
    in the batch, and ``_ai_triage`` catches it and keeps the heuristic verdict.
    """

    def __init__(self, agent: Any, *, max_batch: int = 8, linger: float = 0.05,
                 concurrency: int = 4) -> None:
        self._agent = agent
        self._max_batch = max(1, int(max_batch))
        self._linger = max(0.0, float(linger))
        self._concurrency = max(1, int(concurrency))
        self._pending: list[tuple[dict[str, Any], asyncio.Future[TriageResult]]] = []
        self._flush_task: asyncio.Task[None] | None = None
        self.batches = 0          # observability: batched calls actually issued
        self.findings = 0         # findings routed through this wrapper

    @property
    def backend(self) -> Any:
        return getattr(self._agent, "backend", None)

    @property
    def base_url(self) -> Any:
        return getattr(self._agent, "base_url", None)

    async def synthesize_payloads(self, context: dict[str, Any],
                                  n: int = 5) -> list[PayloadSuggestion]:
        """Pass-through: synthesis is already off the per-finding hot path."""
        result = await self._agent.synthesize_payloads(context, n=n)
        return list(result)

    async def triage_finding(self, finding: dict[str, Any]) -> TriageResult:
        fut: asyncio.Future[TriageResult] = asyncio.get_running_loop().create_future()
        self._pending.append((finding, fut))
        self.findings += 1
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._run_flush())
        return await fut

    async def aclose(self) -> None:
        """Settle anything still queued, then close the wrapped agent."""
        task = self._flush_task
        if task is not None and not task.done():
            try:
                await task
            except Exception:  # noqa: BLE001 - already delivered to the callers
                pass
        self._fail_pending(RuntimeError("triage client closed"))
        close = getattr(self._agent, "aclose", None)
        if close is not None:
            await close()

    # ---- internals ---------------------------------------------------

    async def _run_flush(self) -> None:
        try:
            # Give concurrent callers a beat to join this batch — unless enough
            # have already arrived to fill it.
            if self._linger and len(self._pending) < self._max_batch:
                await asyncio.sleep(self._linger)
            while self._pending:
                batch = self._pending[: self._max_batch]
                del self._pending[: self._max_batch]
                await self._settle(batch)
        except BaseException as exc:  # cancellation included
            self._fail_pending(exc)
            raise

    async def _settle(
        self, batch: list[tuple[dict[str, Any], asyncio.Future[TriageResult]]]
    ) -> None:
        self.batches += 1
        try:
            results = await self._agent.batch_triage(
                [f for f, _ in batch], concurrency=self._concurrency
            )
        except Exception as exc:  # noqa: BLE001 - each caller degrades on its own
            self._settle_error(batch, exc)
            return
        for i, (_, fut) in enumerate(batch):
            if fut.done():
                continue
            if i < len(results):
                fut.set_result(results[i])
            else:
                fut.set_exception(RuntimeError(
                    "triage backend returned fewer results than findings"
                ))

    @staticmethod
    def _settle_error(
        batch: list[tuple[dict[str, Any], asyncio.Future[TriageResult]]],
        exc: BaseException,
    ) -> None:
        for _, fut in batch:
            if not fut.done():
                fut.set_exception(exc)

    def _fail_pending(self, exc: BaseException) -> None:
        pending, self._pending = self._pending, []
        self._settle_error(pending, exc)


# --------------------------------------------------------------------------- #
# manual smoke test:  python -m ai_module.agent_inference
# --------------------------------------------------------------------------- #

async def _demo() -> None:
    client = AgentClient(backend="echo")
    print(await client.triage_finding({"url": "http://t/a", "param": "q", "payload": "<x>"}))
    print(await client.synthesize_payloads({"url": "http://t/a", "param": "q"}, n=2))


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_demo())
