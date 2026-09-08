# ai_module — agentic AI subsystem

The **default engine** of the async DAST scanner (disable with `--ai-no`).
Two capabilities:

1. **Finding triage** — classify scanner candidates as true / false positive.
2. **Dynamic payload synthesis** — propose the next confirmation probes.

Both are *advisory*: results carry a confidence score, the scanner only drops
a finding on a high-confidence false-positive verdict, and if the local
inference backend is unreachable the scan transparently falls back to the
deterministic heuristics. Intended for **authorized** engagements only.

## Layout

| Path | Purpose |
|------|---------|
| `dataset_generator.py` | telemetry JSONL → SFT dataset (alpaca / sharegpt / chatml) |
| `train_qlora.py` | QLoRA / Unsloth fine-tuning, tuned for RTX 5090 (sm_120) |
| `agent_inference.py` | async client: `openai` / `transformers` / `echo` backends |
| `prompts/` | system prompts + reasoning guidelines |

Everything is import-safe without the ML stack: `--help`, `--dry-run` and the
test suite work with only the core scanner installed.

---

# Runbook — university workstation (RTX 5090 + i9)

Blackwell / `sm_120` needs **CUDA 12.8+** wheels. Copy-paste in order.

The whole flow is driven by [`uv`](https://docs.astral.sh/uv/) — do **not** use
`pip` or `python -m venv` directly. `uv run` executes inside the project
environment (creating/syncing it from `uv.lock` on demand), so no manual
`activate` is needed.

### 0. Clone this branch

```bash
git clone -b ai-agent https://github.com/Luis000923/Web_security_scanner.git
cd Web_security_scanner
uv venv                       # creates .venv with the pinned interpreter
source .venv/bin/activate     # optional; uv run works without it
uv sync                       # core scanner deps + dev group, from uv.lock
```

### 1. PyTorch with CUDA 12.8

The Blackwell build lives on a dedicated index, so install it explicitly into
the uv environment before the rest of the ML stack:

```bash
uv pip install torch --index-url https://download.pytorch.org/whl/cu128
uv run python -c "import torch; print(torch.__version__, torch.cuda.is_available(), torch.cuda.get_device_name(0))"
# expect: 2.x.x+cu128  True  NVIDIA GeForce RTX 5090
```

### 2. Project + ML stack

```bash
uv pip install -e ".[ai]"              # transformers, peft, trl, bitsandbytes, datasets…
uv pip install -e ".[ai,ai-unsloth]"   # optional: fused kernels (~2x, less VRAM)
uv pip install -e ".[ai,ai-serve]"     # optional: vLLM for the OpenAI-compatible endpoint
```

Then confirm the environment is uv-managed and the critical deps are resolved:

```bash
bash ai_module/verify_uv_env.sh
```

Unsloth is **off by default** on Blackwell / `sm_120` (its Triton kernels and
pinned bitsandbytes tend to lag a new GPU arch). Once `ai-unsloth` is installed
and validated, opt in with `--use-unsloth`; if its kernels fail to import or
build the trainer auto-falls back to the `transformers + peft + trl` path.
Attention defaults to PyTorch **SDPA**; pass `--flash-attn` only if a
`flash-attn` wheel for CUDA 12.8 / `sm_120` is installed.

### 3. Build & curate the training set from our telemetry

The 20-run testbed sweep under `testbed/results/**/telemetry_*.jsonl` (plus any
OWASP Benchmark runs) is the raw material; the OWASP Benchmark CSV is the
ground-truth oracle. The generator runs a 4-stage curation pipeline:
**ingest+enrich → clean (noise drop / body normalisation / dedup) → structure →
balance+stratified split**.

```bash
# one shot: both tasks, oracle-labelled, 1:1 balanced triage, 90/10 split,
# + a JSON curation manifest (rows dropped, dedup count, class balance, sizes)
uv run python -m ai_module.dataset_generator \
    --telemetry testbed/results \
    --benchmark-csv testbed/.cache/benchmark/expectedresults-1.2.csv \
    --task both --format alpaca \
    --split 0.9 --synthetic-multiplier 40 \
    --out data/sft.jsonl --report data/curation.json

# triage only, keeping noisy rows for inspection, bigger evidence budget
uv run python -m ai_module.dataset_generator \
    --telemetry testbed/results reports/telemetry \
    --benchmark-csv testbed/.cache/benchmark/expectedresults-1.2.csv \
    --task triage --format chatml --balance \
    --max-body-bytes 4096 --keep-noise \
    --out data/triage.jsonl --split 0.9 --report data/triage.clean.json

# payload synthesis: trajectory-reconstructed, weak-labelled (no oracle needed)
uv run python -m ai_module.dataset_generator \
    --telemetry testbed/results \
    --task payload --format alpaca \
    --out data/payload.jsonl --split 0.95
```

`--task both` writes `data/sft.triage.{train,val}.jsonl` and
`data/sft.payload.{train,val}.jsonl`; a single `--task` writes
`data/<name>.{train,val}.jsonl` (or one file when `--split 1.0`). Each line is
`{"instruction","input","output","meta"}` (`--format sharegpt` →
`{"conversations":[…]}`, `chatml` → `{"messages":[…]}`).

**Cleaning knobs**

| Flag | Effect |
|------|--------|
| *(default)* | drops rows with `missing_url` / transport error / timeout / `truncated_empty` / `server_error` / `implausible_latency` |
| `--keep-noise` | keep those rows (still counted in the manifest) |
| `--max-body-bytes N` | response-body evidence budget; long bodies are cut to the reflection windows around the payload / canary markers (default 2048) |
| `--no-dedup` | keep identical `(payload, response, class, verdict)` samples |
| `--balance` / `--balance-ratio R` | downsample majority TP/FP class to `≤ R×` the minority (triage) |
| `--split F` | stratified train/val split so val keeps both classes |
| `--report PATH` | write the curation manifest JSON |

**Anti-leak curation (always on)**

- **Endpoint anonymised** — the model input only ever sees `/app/target_endpoint/`
  and parameter `p`. The OWASP Benchmark encodes the vuln class *and* verdict in
  the URL path, so training on it lets the model shortcut the label; that path
  is now kept only in private (`_url`) metadata.
- **Dynamic triage output** — the verdict / confidence / reasoning are built
  from the actual evidence (latency delta vs. run baseline, verbatim reflection,
  interpreter errors, a-priori & scanner confidence), not from fixed templates.
  Non-discriminating probes get `UNCERTAIN`; endpoints whose ground truth
  conflicts under an identical evidence profile are reconciled to `UNCERTAIN`.
- **Junk payloads filtered** — structureless blobs >120 chars and <15-char
  strings with no injection tokens are dropped from the payload task; rationale
  and `confirm_signal` are keyed to the payload *family*, not a generic string.
- **Semantic split** — dedup runs on the *observable* key (anonymised prompt +
  latency bucketed to `faster/noise/slower/much_slower`), so millisecond jitter
  can't leak a near-identical row across the train/val boundary.

> Note: once the URL shortcut is removed, single-app (OWASP Benchmark-only)
> telemetry collapses to ~26 genuinely-distinct triage instances (no HTTP
> bodies in the base telemetry). Use `--synthetic-multiplier` to lift that.

**Synthetic body-enriched triage (`--synthetic-multiplier N` / `--enable-synthetic`)**

Takes each unique real probe *seed* (class / payload / context / a-priori
confidence / run baseline latency) and crosses it with a catalogue of mocked
HTTP response bodies to synthesise ~`N` samples per seed, driven to a balanced
**TP / FP / UNCERTAIN** split:

| scenario | body | verdict |
|---|---|---|
| `xss_verbatim_reflection` | payload unescaped in an HTML/JS context | TP |
| `sql_error_disclosure` | MySQL/PG/SQLite/MSSQL/Oracle syntax error | TP |
| `sql_time_oracle` | normal page + latency far over baseline | TP |
| `path_traversal_file_read` | `/etc/passwd` / `win.ini` / `hosts` contents (encoding-aware note) | TP |
| `cmd_injection_output` | `uid=…` / `uname` / `ipconfig` output | TP |
| `cmd_injection_time_oracle` | normal page + injected `sleep`/`ping` delay over baseline | TP |
| `xss_output_encoded` | payload HTML-entity-escaped | FP |
| `generic_500_page` | framework 500 / Whitelabel page | FP |
| `path_traversal_blocked` | generic "file not found", traversal not honoured | FP |
| `cmd_injection_filtered` | shell metacharacters stripped, ordinary lookup | FP |
| `waf_block_page` | 403 / Cloudflare / ModSecurity block | FP |
| `blank_response` | empty 200 | FP |
| `xss_partial_filter` | payload reflected with `<>"'` stripped | UNCERTAIN |
| `path_traversal_within_root` | traversal normalised away, in-webroot listing returned | UNCERTAIN |
| `cmd_injection_echoed_arg` | OS payload echoed as a literal HTML argument, no execution | UNCERTAIN |
| `reflection_irrelevant_to_class` | non-XSS payload echoed in `<title>` | UNCERTAIN |
| `weak_boolean_differential` | tiny, unstable content-length delta | UNCERTAIN |

**Standalone seeds (`--no-standalone-seeds` to opt out).** The base testbed
sweep only exercised the SQLi and XSS testers, so Path Traversal and OS Command
Injection had *zero* real probe seeds and their scenarios never fired. The
generator now injects a hardcoded catalogue of realistic GET-parameter payloads
for any standalone class the telemetry doesn't cover — relative/absolute
traversal across several URL-encoding layers plus NUL-byte truncation, and
shell-metacharacter / newline / backtick / `$()` command injection — so those
classes always get balanced TP / FP / UNCERTAIN coverage. `--standalone-all-seeds`
adds them even for classes the telemetry already covers. The curation manifest
records `synthetic.telemetry_seed_classes`, `synthetic.seed_classes`,
`synthetic.standalone_seeds` and `synthetic.suspected_class_counts`.

`response_excerpt` is rendered as its own fenced block in the prompt, and each
sample's `reasoning` cites the concrete body evidence (the specific DBMS error,
the entity-encoding, the block-page marker, the timing delta). Every synthetic
label is cross-checked against the same `_assess_evidence()` the real path uses,
so an intended TP with no discriminating signal (or an FP that does discriminate)
is dropped rather than mislabelled. Synthetic rows carry
`meta.synthetic=true` + `meta.scenario` for filtering/traceability.

Without any `--benchmark-csv` / `--ground-truth` the generator falls back to
weak labels from the scanner's own `decision` / `confidence_final` columns.

### 4. Smoke-test the hardware (≈1 min)

Runs a real 5-step optimisation loop — validates CUDA, bitsandbytes 4-bit,
LoRA attach and the data pipeline before you commit hours to a full run.

```bash
uv run python -m ai_module.train_qlora \
    --dataset data/triage.train.jsonl \
    --output-dir runs/_smoke --max-steps 5
# -> "smoke test OK — NVIDIA GeForce RTX 5090 (sm_120) ... adapter not saved"
```

`uv run python -m ai_module.train_qlora --dry-run` prints the resolved config without importing torch at all.

### 5. Full fine-tune

```bash
uv run python -m ai_module.train_qlora \
    --base-model unsloth/Qwen2.5-7B-Instruct-bnb-4bit \
    --dataset data/triage.train.jsonl --eval data/triage.val.jsonl \
    --output-dir runs/triage-qlora \
    --epochs 3 --batch-size 8 --grad-accum 2 --max-seq-len 2048 \
    --merge-adapter
```

The Blackwell knobs (bf16 compute, TF32 matmul, NF4 + double-quant, paged
8-bit AdamW, SDPA attention, expandable CUDA segments) are applied
automatically; add `--flash-attn` / `--use-unsloth` to opt in to those.

The defaults above are already the small-dataset recipe (~800 examples of
~700 tokens): 3 epochs, 2048-token sequences, `lora_alpha = 2 * --lora-r`,
`--lora-dropout 0.05`. Passing `--eval` also turns on per-epoch validation,
`load_best_model_at_end` on `eval_loss`, `--save-total-limit 2` and an early
stop after `--early-stopping-patience 2` evals without improvement — so the
saved adapter is the best checkpoint, not the last one. Without `--eval` there
is no metric to select on and both are off; `--early-stopping-patience 0`
disables the callback explicitly.
Output:

- `runs/triage-qlora/adapter/` — LoRA adapter (small, for the `transformers` backend)
- `runs/triage-qlora/merged/` — merged fp16 model (`--merge-adapter`, for vLLM)

Repeat step 3–5 with `--task payload` for the payload-synthesis adapter.

### 6. Serve the adapter (OpenAI-compatible)

```bash
uv run python -m vllm.entrypoints.openai.api_server \
    --model runs/triage-qlora/merged \
    --served-model-name local-security-agent \
    --port 8000
```

Or run in-process with no server: `--ai-backend transformers` and
`AI_AGENT_HF_MODEL=runs/triage-qlora/merged`.

### 7. Run the scanner — the AI agent is the default engine

As of the `ai-agent` branch the LLM agent runs on **every** scan: no opt-in
flag is needed.

```bash
export AI_AGENT_BACKEND=openai
export AI_AGENT_BASE_URL=http://127.0.0.1:8000/v1
export AI_AGENT_MODEL=local-security-agent

uv run python -m web_security_scanner.cli scan https://target.example \
    --ai-fp-threshold 0.75 \
    --telemetry-dir reports/telemetry
```

On startup the orchestrator builds the `AgentClient` and runs
`healthcheck()`. If it passes you get `AI engine active (backend=openai …)`;
if the inference server is down (or `ai_module` isn't installed) you get one
warning line and the scan falls back to the deterministic heuristics — it
never fails because of the agent.

During the scan:

- **Triage** — every heuristic finding goes to `triage_finding()`; a confident
  false positive (≥ `--ai-fp-threshold`) is dropped, the rest are annotated
  with `ai_verdict` / `ai_confidence` / `ai_reasoning`.
- **Synthesis** — when a parameter's static payload list is exhausted with no
  hit, `synthesize_payloads()` proposes adapted vectors that are replayed
  through the cheap checks (still gated by the destructive-payload filter).

Opting out:

| Flag | Effect |
|------|--------|
| `--ai-no` (`--no-ai`) | Disable the agent entirely; pure deterministic engine |
| `--ai-no-verify` | Keep synthesis, skip LLM false-positive triage |
| `--ai-no-synthesize` | Keep triage, never synthesise extra payloads |

Quick offline check without a model server (in-process stub):

```bash
uv run python -m web_security_scanner.cli scan https://target.example --ai-backend echo
uv run python -m ai_module.agent_inference   # echo-backend smoke test
```
