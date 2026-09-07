# ai_module — agentic AI subsystem

Optional add-on to the async DAST scanner. Two capabilities:

1. **Finding triage** — classify scanner candidates as true / false positive.
2. **Dynamic payload synthesis** — propose the next confirmation probes.

Both are *advisory*: results carry a confidence score and never override the
scanner's own logic. Intended for **authorized** engagements only.

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

### 0. Clone this branch

```bash
git clone -b ai-agent https://github.com/Luis000923/Web_security_scanner.git
cd Web_security_scanner
python3.12 -m venv .venv && source .venv/bin/activate
python -m pip install -U pip wheel
```

### 1. PyTorch with CUDA 12.8

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu128
python -c "import torch; print(torch.__version__, torch.cuda.is_available(), torch.cuda.get_device_name(0))"
# expect: 2.x.x+cu128  True  NVIDIA GeForce RTX 5090
```

### 2. Project + ML stack

```bash
pip install -e ".[ai]"                 # transformers, peft, trl, bitsandbytes, datasets…
pip install -e ".[ai,ai-unsloth]"      # optional: fused kernels (~2x, less VRAM)
pip install -e ".[ai,ai-serve]"        # optional: vLLM for the OpenAI-compatible endpoint
```

If `unsloth` resolution fights the pinned deps, skip `ai-unsloth` and pass
`--no-unsloth` to the trainer — the `transformers + peft + trl` path is fully
supported.

### 3. Build the training set from our telemetry

The 20-run testbed sweep under `testbed/results/**/telemetry_*.jsonl` is the
raw material; the OWASP Benchmark CSV is the ground-truth oracle.

```bash
# triage: TP/FP classification (labels joined from the OWASP Benchmark oracle)
python -m ai_module.dataset_generator \
    --telemetry testbed/results \
    --benchmark-csv testbed/.cache/benchmark/expectedresults-1.2.csv \
    --task triage --format alpaca --balance \
    --out data/triage.jsonl --split 0.9

# payload: next-probe synthesis (trajectory-reconstructed, weak-labelled)
python -m ai_module.dataset_generator \
    --telemetry testbed/results \
    --task payload --format alpaca \
    --out data/payload.jsonl --split 0.95
```

Produces `data/triage.train.jsonl` / `data/triage.val.jsonl` (and likewise for
`payload`). Each line is `{"instruction","input","output","meta"}`
(`--format sharegpt` → `{"conversations":[…]}`, `--format chatml` →
`{"messages":[…]}`). Without any `--benchmark-csv` / `--ground-truth` the
generator falls back to weak labels from the scanner's own verdicts.

### 4. Smoke-test the hardware (≈1 min)

Runs a real 5-step optimisation loop — validates CUDA, bitsandbytes 4-bit,
LoRA attach and the data pipeline before you commit hours to a full run.

```bash
python -m ai_module.train_qlora \
    --dataset data/triage.train.jsonl \
    --output-dir runs/_smoke --max-steps 5
# -> "smoke test OK — NVIDIA GeForce RTX 5090 (sm_120) ... adapter not saved"
```

`--dry-run` prints the resolved config without importing torch at all.

### 5. Full fine-tune

```bash
python -m ai_module.train_qlora \
    --base-model unsloth/Qwen2.5-7B-Instruct-bnb-4bit \
    --dataset data/triage.train.jsonl --eval data/triage.val.jsonl \
    --output-dir runs/triage-qlora \
    --epochs 2 --batch-size 8 --grad-accum 2 --max-seq-len 4096 \
    --merge-adapter
```

The Blackwell knobs (bf16 compute, TF32 matmul, NF4 + double-quant, paged
8-bit AdamW, flash-attention-2, expandable CUDA segments) are applied
automatically. Output:

- `runs/triage-qlora/adapter/` — LoRA adapter (small, for the `transformers` backend)
- `runs/triage-qlora/merged/` — merged fp16 model (`--merge-adapter`, for vLLM)

Repeat step 3–5 with `--task payload` for the payload-synthesis adapter.

### 6. Serve the adapter (OpenAI-compatible)

```bash
python -m vllm.entrypoints.openai.api_server \
    --model runs/triage-qlora/merged \
    --served-model-name local-security-agent \
    --port 8000
```

Or run in-process with no server: `--ai-backend transformers` and
`AI_AGENT_HF_MODEL=runs/triage-qlora/merged`.

### 7. Run the scanner with AI verification

```bash
export AI_AGENT_BACKEND=openai
export AI_AGENT_BASE_URL=http://127.0.0.1:8000/v1
export AI_AGENT_MODEL=local-security-agent

python -m web_security_scanner.cli https://target.example \
    --ai-verify --ai-synthesize \
    --ai-fp-threshold 0.75 \
    --telemetry-dir reports/telemetry
```

- `--ai-verify` — every heuristic finding is sent to `triage_finding()`; a
  confident false positive (≥ `--ai-fp-threshold`) is dropped, the rest are
  annotated with `ai_verdict` / `ai_confidence`.
- `--ai-synthesize` — when a parameter's static payload list is exhausted with
  no hit, `synthesize_payloads()` proposes adapted vectors that are replayed.
- If `ai_module` is missing or the endpoint is down, the scan silently
  continues on its traditional heuristics.

Quick offline check without a model:

```bash
python -m web_security_scanner.cli https://target.example --ai-verify --ai-backend echo
python -m ai_module.agent_inference        # echo-backend smoke test
```
