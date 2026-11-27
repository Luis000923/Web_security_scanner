# Fine-tuned triage/synthesis model: inference pipeline, evaluation harness, and hybrid resilience

**Date:** 2026-09-30
**Branch:** `feat/redteam-corpus-fullfinetune` (merged with `main` at commit `c2130a4`)
**Scope:** evaluation + inference-serving layer for the model `ai_module/` fine-tunes — *not* a report of a completed fine-tuning run's accuracy numbers. See [Status and what was actually measured](#status-and-what-was-actually-measured) for exactly what is and is not verified below.

## 1. What this adds

Three new files, on top of the existing `ai_module/` AI subsystem (`agent_inference.py`'s `AgentClient`, `evaluate_golden.py`'s golden-dataset harness, `structured_inference.py`'s JSON-schema decoding):

| File | Role |
|---|---|
| `ai_module/inference_client.py` | Hybrid local/web inference client with three-tier resilient fallback and defense-in-depth payload sanitisation. |
| `ai_module/evaluate_model.py` | Base-model-vs-fine-tuned-model comparison harness, bridging `evaluate_golden.py`'s 3-class (TP/FP/UNCERTAIN) results into `core/ieee_metrics.py`'s Accuracy/Recall/F1/Precision(class-matched) machinery. |
| `tests/unit/test_model_inference.py` | 24 tests: local-quantized wiring, web HTTP mocked at 200/500/timeout, the fallback chain, sanitisation, and `evaluate_model.py`'s pure bridging functions. |

## 2. Architecture: why a new client layer, not a rewrite

`AgentClient` (`ai_module/agent_inference.py`) already owns every backend's raw mechanics: `openai` (remote, `aiohttp`), `transformers` (in-process, quantizable via `bitsandbytes`), `echo` (offline stub); per-backend retry/backoff; a circuit breaker for the `openai` backend; and a `healthcheck()` readiness probe the scanner's own orchestrator already calls before committing to a backend. Rebuilding that would duplicate a lot of already-hardened code for no reason.

`InferenceClient` is a **thin façade** over one or two `AgentClient` instances, adding exactly what the task needs and `AgentClient` does not itself provide:

```
InferenceClient.local(model, load_in_4bit=True)   -> AgentClient(backend="transformers", ...)
InferenceClient.web(base_url, model)              -> AgentClient(backend="openai", ...)
InferenceClient.hybrid(web_base_url=..., local_model=..., primary="web")
```

### 2.1 Three-tier fallback: web → local → deterministic heuristic

```
triage_with_fallback(finding, deterministic_fallback=scanner_heuristic)
   │
   ├─ sanitize_finding(finding)              # defense-in-depth, see §2.2
   │
   ├─ tier "web"    (if configured & healthy)  -> AgentClient.triage_finding()
   │     └─ backend-failure contingency? -> fall through
   ├─ tier "local"  (if configured & healthy)  -> AgentClient.triage_finding()
   │     └─ backend-failure contingency? -> fall through
   └─ tier "heuristic" -> deterministic_fallback(finding), or the safe
        UNCERTAIN contingency if none was given
```

This extends — it does not replace — the "transparent degradation" contract `AgentClient`/`base_tester_async.py` already document for the scanner's *existing* single-tier (AI-or-heuristic) integration. The new piece is the **middle tier**: today the scanner has no notion of "try the remote endpoint, then fall back to a local quantized copy before giving up on the model entirely" — that is the literal hybrid-inference requirement this task asked for, and it did not exist before this change.

A tier is skipped when unconfigured, when its `AgentClient.healthcheck()` fails (cached for `healthcheck_ttl` seconds — default 30s — so a scan of many findings does not re-probe a live backend on every single one), or when a healthy tier's call still comes back carrying `AgentClient`'s own internal "backend call failed" contingency marker for a transient reason. Every path returns a `HybridTriageResult` recording which tier actually answered (`tier`), every tier that was attempted (`tiers_tried`), whether the final answer is degraded (`degraded`), and the measured `latency_s` / `overhead_s` — see §2.3.

The function **never raises**. A `deterministic_fallback` callable that itself raises is caught and mapped to the same safe `UNCERTAIN` contingency, so the fallback tier can never become the one place the "never raise" contract breaks.

### 2.2 Payload sanitisation (defense in depth)

`AgentClient.triage_finding()` does not itself sanitise `finding` before embedding it in the prompt. Today that only works because the scanner's one existing caller, `base_tester_async._ai_triage()`, remembers to wrap the response-body text through `ai_module/prompt_guard.py`'s `sanitize_untrusted()` first. A client *library* should not depend on every future caller remembering that.

`InferenceClient.triage_with_fallback()` sanitises the known untrusted text fields (`response_excerpt`, `response`, `body`, `text`, `raw_response`) itself, before the finding ever reaches the network — so this module's own `evaluate_model.py`, and any future caller, gets the same indirect-prompt-injection defense for free. Structural fields (`url`, `parameter`, the tool's own decision) are left untouched. `sanitize_untrusted`'s wrapping is idempotent/self-escaping, so double-wrapping an already-sanitised field is safe, not corrupting.

### 2.3 The 50ms latency budget: honestly scoped, not faked

The task asked for "< 50 ms por petición". A real LLM generation call — local or remote, quantized or not — routinely takes hundreds of milliseconds to low seconds depending on token count and hardware; claiming a literal 50ms round-trip for full triage generation on any backend this module targets would be a fabricated number. `latency_budget_s` (default `0.05`) is therefore recorded and **reported**, never enforced as a hard cutoff: `HybridTriageResult` separates `overhead_s` (sanitisation + tier selection + cached-healthcheck lookup — the part of the call path that genuinely can and should stay under 50ms) from `latency_s` (the real inference call, whatever tier answered). A caller or dashboard can compare `overhead_s` against the budget honestly; comparing `latency_s` against it would not be.

## 3. `evaluate_model.py`: base vs. fine-tuned, reusing existing metrics

Rather than re-deriving accuracy/precision/recall arithmetic a third time in this codebase, `evaluate_model.py` bridges two already-existing, independently-tested pieces:

1. **`ai_module/evaluate_golden.py`** — the existing 3-class (`TRUE_POSITIVE`/`FALSE_POSITIVE`/`UNCERTAIN`) golden-dataset harness. Reused verbatim (`load_golden_dataset`, `run_eval`, its own `compute_metrics`) so this script can never drift from that harness's own definitions of FNR / TP-degradation / FP-recall.
2. **`web_security_scanner/core/ieee_metrics.py`** — the task's explicitly-named metrics module (Accuracy, Recall, F1, **Precision (class-matched)**). `_to_ieee_inputs()` reshapes each golden-eval run's rows into that module's `Finding`/`GroundTruth` shape:
   - key = `(endpoint, parameter)` from the golden row's `finding` dict;
   - a `TRUE_POSITIVE` verdict → one `Finding` (a claim), tagged with the model's own reported/suspected class;
   - `FALSE_POSITIVE` *and* `UNCERTAIN` → no claim reported. `ieee_metrics` has no "hedged" bucket, only a claim or its absence; folding `UNCERTAIN` into absence is the semantically correct read (the model was not confident enough to confirm) and correctly costs recall on a genuinely vulnerable golden row, without misusing the module's separate `untested` channel (reserved for points the *scan infrastructure* could not measure at all — a different failure mode).
   - `category`/`suspected_class` in the golden schema already match `core/vuln_classes.py`'s canonical names (`sqli`/`xss`/`pathtraver`/`cmdi`/...) 1:1, so `precision_class_matched` is scoreable without any extra mapping.

`evaluate_one()` runs this for each of the `base`/`tuned` model configurations (any mix of `echo`/`openai`/`transformers` backends), and `_delta()` reports `tuned − base` for every numeric metric on both sides — propagating `None` rather than treating an unmeasurable metric as `0.0` on either side (e.g. a golden set with no class labels never fabricates a 0.0-point "improvement" in `precision_class_matched`).

### CLI

```bash
python -m ai_module.evaluate_model \
    --dataset data/golden_dataset.jsonl \
    --base-backend openai  --base-endpoint  http://127.0.0.1:8001/v1 --base-model  Qwen2.5-1.5B-Instruct \
    --tuned-backend openai --tuned-endpoint http://127.0.0.1:8000/v1 --tuned-model runs/triage-qlora/merged \
    --out metrics/model_comparison.json --verbose
```

Prints a base/tuned/delta table for both metric families, then the full `evaluate_golden.py` table per side under `--verbose` (confusion matrix, per-category breakdown), and writes the complete comparison (including every per-row result) to `--out`.

## 4. Verification performed this session

| Check | Result |
|---|---|
| `pytest tests/` (excl. `tests/differential/`, unrelated pre-existing WIP) | **1384 passed, 3 skipped, 0 failed** |
| `pytest tests/unit/test_model_inference.py` | **24/24 passed** |
| `ruff check .` | clean |
| `mypy` | clean, 114 source files |

`test_model_inference.py` covers, with no network and no real model load:

- **Local quantized inference** — `InferenceClient.local()`'s `AgentClient` wiring (defaults to `load_in_4bit=True`), faked at the `transformers`-backend seam (`AgentClient._build_hf_pipeline` / `_generate_hf`) the existing `test_ai_agent_integration.py` suite already uses — no real torch/model load, matching that suite's own established mocking idiom rather than inventing a new one.
- **Web HTTP mocked at `aiohttp.ClientSession`** for:
  - **200 OK** — a real verdict is decoded and returned from the `web` tier;
  - **500 Server Error** (`aiohttp.ClientResponseError(status=500)`) — falls through to the `local` tier in a `hybrid()` client;
  - **timeout** (`TimeoutError`) — falls through all the way to the `heuristic` tier when only `web` is configured.
- **The fallback chain itself** — no tiers configured + no fallback → safe `UNCERTAIN`; a plain boolean, a dict, and a raising callable as `deterministic_fallback`; the healthcheck cache actually avoiding a second probe within the TTL; `healthcheck_all()` bypassing that cache on demand.
- **Sanitisation** — an untrusted `response_excerpt` is demonstrably wrapped before it reaches the mocked HTTP layer (asserted against the exact JSON payload the fake `aiohttp` session captured), and a clean finding with no untrusted fields is passed through byte-for-byte.
- **`evaluate_model.py`'s pure functions** — `_to_ieee_inputs()`'s three mapping rules (TRUE_POSITIVE → Finding, UNCERTAIN → absence not untested, inference errors dropped) and `_delta()`'s None-propagation, all without touching a network or a model; plus an end-to-end CLI run against the `echo` backend on both sides (`data/golden_dataset.example.jsonl`), confirming the whole argument-parsing → evaluation → JSON-export path is wired correctly.

## 5. Status and what was actually measured

**This report does not contain a real base-model-vs-fine-tuned-model accuracy/F1 delta**, and it would be dishonest to present fabricated numbers here. What "verified" means above is strictly: *the evaluation and inference-serving code is correct and its failure modes degrade exactly as designed* — proven with mocked backends, per the standard pattern this codebase already uses for testing `AgentClient` itself.

Producing a real comparison requires:

1. A completed full-fine-tune or QLoRA training run producing an actual checkpoint (`ai_module/train_qlora.py --full-finetune` or the LoRA path — both already exist and were separately verified end-to-end on real hardware, see `ai_module/AUDIT.md`'s 2026-09-30 entry, but that verification was of the *training mechanics*, not of a checkpoint trained to convergence);
2. That checkpoint served (locally via `--ai-backend transformers`, or behind a vLLM/OpenAI-compatible endpoint);
3. `python -m ai_module.evaluate_model` pointed at that endpoint and at the untuned base checkpoint, over a golden dataset larger and more adversarial than the 16-row `data/golden_dataset.example.jsonl` wiring fixture used above (see `ai_module/evaluate_golden.py`'s own docstring for the golden-dataset schema and curation guidance).

None of those three steps were run in this session. The deliverable here is the harness that makes that comparison possible and trustworthy once they are.
