#!/usr/bin/env bash
#
# run_pipeline.sh — master orchestrator for the ai_module QLoRA workflow.
#
# Runs, in order, on the workstation (RTX 5090 / CUDA 12.8 / uv):
#   1. environment + uv verification, with auto-install of the ML stack
#      (bash ai_module/verify_uv_env.sh; on missing deps -> uv pip install -e ".[ai]")
#   2. dataset (re)generation                    (optional, --regen-data)
#   3. hardware profiling + base-model choice    (VRAM tier -> model size)
#   4. base-model cache preparation              (HF snapshot download if missing)
#   5. QLoRA smoke test                          (--max-steps 5, fast CUDA/VRAM check)
#   6. full QLoRA fine-tune                      (--epochs 3 --max-seq-len 2048 --eval)
#
# Any failure aborts the pipeline in red and prints the elapsed time, so a
# half-finished run never corrupts the adapter/output state.
#
# Usage:
#   ./run_pipeline.sh [options]
#
#   --regen-data            regenerate datasets with the synthetic generator
#                           (--synthetic-multiplier 40) before training
#   --task triage|payload   which adapter to train           (default: triage)
#   --epochs N              full fine-tune epochs             (default: 3)
#   --base-model NAME       pin the base model, skipping auto-selection.
#                           By default the model is chosen from the detected
#                           VRAM (see ai_module/auto_select_model.py):
#                             <=7 GB  -> Qwen2.5-1.5B-Instruct-bnb-4bit
#                             <=16 GB -> Qwen2.5-7B-Instruct-bnb-4bit
#                             >16 GB  -> Qwen2.5-14B-Instruct-bnb-4bit
#                           so a 6 GB RTX 4050 and a 32 GB RTX 5090 both work
#                           without editing the script. The same probe also
#                           derives the *training knobs* (see --no-auto-tune):
#                           4-bit weights, fp16 instead of bf16 on pre-Ampere
#                           cards, micro-batch and sequence length.
#   --no-auto-tune          do NOT apply the hardware-derived training knobs
#                           (precision, 4-bit, batch/accum/seq-len, LoRA rank);
#                           fall back to train_qlora.py's own defaults
#   --no-install            do NOT auto-install missing ML deps; abort instead
#   --no-cuda-torch         when auto-installing, skip the explicit CUDA 12.8
#                           torch wheel (use whatever ".[ai]" resolves)
#   --skip-model-dl         do not pre-download the base model
#   --model-retries N       base-model download attempts (default: 3)
#   --no-xet                fetch the base model over plain HTTPS from the start
#                           (disable the Xet accelerator — use on flaky links)
#   --skip-smoke            skip the smoke test (not recommended)
#   --skip-train            stop after the smoke test
#   --no-verify             skip bash ai_module/verify_uv_env.sh (not recommended)
#   --allow-root            permit running as root / under sudo (discouraged)
#   -h, --help              this help
#
# Env:
#   TORCH_INDEX_URL   torch wheel index for the auto-install
#                     (default: https://download.pytorch.org/whl/cu128)
#   TORCH_SPEC        torch requirement to install (default: "torch"). Pin it
#                     when the newest build has dropped your GPU's compute
#                     capability, e.g. TORCH_SPEC="torch==2.7.1".
#
set -Eeuo pipefail

# ---------------------------------------------------------------------------
# presentation helpers
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'
    BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

STEP=0
step()  { STEP=$((STEP + 1)); printf '\n%s%s══ [%d] %s%s\n' "$BOLD" "$CYAN" "$STEP" "$1" "$RESET"; }
info()  { printf '   %s\n' "$1"; }
warn()  { printf '%s   ! %s%s\n' "$YELLOW" "$1" "$RESET"; }
ok()    { printf '%s   ✓ %s%s\n' "$GREEN" "$1" "$RESET"; }

elapsed() {
    local s=$SECONDS
    printf '%dh %02dm %02ds' $((s / 3600)) $(((s % 3600) / 60)) $((s % 60))
}

die() {
    printf '\n%s%s✗ PIPELINE ABORTED%s  %s\n' "$BOLD" "$RED" "$RESET" "${1:-unknown error}" >&2
    printf '%s  elapsed: %s%s\n' "$RED" "$(elapsed)" "$RESET" >&2
    exit 1
}

on_err() {
    local line=$1 cmd=$2
    die "step ${STEP} failed at line ${line}: ${cmd}"
}
trap 'on_err "${LINENO}" "${BASH_COMMAND}"' ERR

# ---------------------------------------------------------------------------
# args
# ---------------------------------------------------------------------------
REGEN_DATA=0
TASK="triage"
EPOCHS=3
BASE_MODEL=""            # empty => auto-select from the detected VRAM
BASE_MODEL_EXPLICIT=0
NO_INSTALL=0
AUTO_TUNE=1
NO_CUDA_TORCH=0
SKIP_MODEL_DL=0
MODEL_RETRIES=3
NO_XET=0
SKIP_SMOKE=0
SKIP_TRAIN=0
NO_VERIFY=0
ALLOW_ROOT=0
TORCH_INDEX_URL="${TORCH_INDEX_URL:-https://download.pytorch.org/whl/cu128}"
TORCH_SPEC="${TORCH_SPEC:-torch}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --regen-data)     REGEN_DATA=1; shift ;;
        --task)           TASK="${2:?}"; shift 2 ;;
        --epochs)         EPOCHS="${2:?}"; shift 2 ;;
        --base-model)     BASE_MODEL="${2:?}"; BASE_MODEL_EXPLICIT=1; shift 2 ;;
        --no-install)     NO_INSTALL=1; shift ;;
        --no-auto-tune)   AUTO_TUNE=0; shift ;;
        --no-cuda-torch)  NO_CUDA_TORCH=1; shift ;;
        --skip-model-dl)  SKIP_MODEL_DL=1; shift ;;
        --model-retries)  MODEL_RETRIES="${2:?}"; shift 2 ;;
        --no-xet)         NO_XET=1; shift ;;
        --skip-smoke)     SKIP_SMOKE=1; shift ;;
        --skip-train)     SKIP_TRAIN=1; shift ;;
        --no-verify)      NO_VERIFY=1; shift ;;
        --allow-root)     ALLOW_ROOT=1; shift ;;
        -h|--help)        awk 'NR>2{ if (!/^#/) exit; sub(/^# ?/, ""); print }' "$0"; exit 0 ;;
        *)                die "unknown option: $1  (try --help)" ;;
    esac
done

case "$TASK" in
    triage|payload) ;;
    *) die "--task must be 'triage' or 'payload', got '${TASK}'" ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# ---------------------------------------------------------------------------
# OS-aware virtualenv layout
#   Linux/macOS : .venv/bin/python3
#   Windows     : .venv/Scripts/python.exe   (Git Bash / MSYS2 / Cygwin)
# The directory is probed first so an existing venv always wins; when no venv
# exists yet we fall back to what `uname` says the platform should create.
# ---------------------------------------------------------------------------
case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT) IS_WINDOWS=1 ;;
    *)                               IS_WINDOWS=0 ;;
esac

VENV_DIR="$ROOT/.venv"
if [[ -d "$VENV_DIR/Scripts" ]]; then
    VENV_BIN="$VENV_DIR/Scripts"
elif [[ -d "$VENV_DIR/bin" ]]; then
    VENV_BIN="$VENV_DIR/bin"
elif [[ "$IS_WINDOWS" -eq 1 ]]; then
    VENV_BIN="$VENV_DIR/Scripts"
else
    VENV_BIN="$VENV_DIR/bin"
fi

# Set VENV_BIN/VENV_PY to the first interpreter that actually exists there.
# VENV_PY stays empty when the venv has not been created yet, so callers can
# bootstrap it with `uv venv` and re-resolve.
resolve_venv_python() {
    if [[ -d "$VENV_DIR/Scripts" ]]; then
        VENV_BIN="$VENV_DIR/Scripts"
    elif [[ -d "$VENV_DIR/bin" ]]; then
        VENV_BIN="$VENV_DIR/bin"
    fi
    VENV_PY=""
    local cand
    for cand in "$VENV_BIN/python.exe" "$VENV_BIN/python3.exe" \
                "$VENV_BIN/python3" "$VENV_BIN/python"; do
        if [[ -x "$cand" || -f "$cand" ]]; then VENV_PY="$cand"; return 0; fi
    done
    return 1
}
resolve_venv_python || true

# Normalise a path for comparison: backslashes -> slashes, "C:/x" -> "/c/x",
# no trailing slash, and case-folded on Windows (its filesystem is too).
norm_path() {
    local p="${1//\\//}"
    p="$(printf '%s' "$p" | sed -e 's#^\([A-Za-z]\):/#/\1/#' -e 's#/\{2,\}#/#g' -e 's#/$##')"
    if [[ "$IS_WINDOWS" -eq 1 ]]; then
        printf '%s' "$p" | tr '[:upper:]' '[:lower:]'
    else
        printf '%s' "$p"
    fi
}

# ---------------------------------------------------------------------------
# permission sanity — running as root corrupts .venv / HF-cache ownership.
# Meaningless under Git Bash on Windows, where MSYS reports uid 0 for an
# ordinary account, so the guard only applies to Unix.
# ---------------------------------------------------------------------------
if [[ "$IS_WINDOWS" -eq 0 && "${EUID:-$(id -u)}" -eq 0 ]]; then
    if [[ "$ALLOW_ROOT" -eq 1 ]]; then
        warn "running as root (--allow-root): files created here may be unusable \
by your normal user"
    else
        die "refusing to run as root / under sudo — this would create .venv and \
the Hugging Face cache as root and break later non-root runs. Re-run as your \
normal user, or pass --allow-root if you really mean it."
    fi
elif [[ "$IS_WINDOWS" -eq 0 && -n "${SUDO_USER:-}" ]]; then
    warn "invoked via sudo by '${SUDO_USER}' — proceeding as uid ${EUID}, but \
prefer a plain (non-sudo) shell for uv work"
fi

TELEMETRY_DIR="testbed/results"
BENCHMARK_CSV="testbed/.cache/benchmark/expectedresults-1.2.csv"
OUT_DIR="runs/${TASK}-qlora"
SMOKE_DIR="runs/_smoke"

printf '%s%sai_module QLoRA pipeline%s  —  task=%s  epochs=%s  regen-data=%s\n' \
    "$BOLD" "$CYAN" "$RESET" "$TASK" "$EPOCHS" "$REGEN_DATA"
printf '   repo : %s\n' "$ROOT"
printf '   model: %s\n' "${BASE_MODEL:-auto (from detected VRAM)}"

# ---------------------------------------------------------------------------
# 1. environment + uv verification
# ---------------------------------------------------------------------------
step "Environment & uv verification"

command -v uv >/dev/null 2>&1 || die "uv is not installed — https://docs.astral.sh/uv/"
ok "uv present: $(uv --version)"

if [[ -z "$VENV_PY" ]]; then
    warn "no interpreter under ${VENV_BIN#$ROOT/} — bootstrapping with uv venv + uv sync"
    uv venv
    uv sync
    resolve_venv_python || true
    ok "environment created"
fi
if [[ -n "$VENV_PY" ]]; then
    ok "venv interpreter: ${VENV_PY#$ROOT/}  ($([[ "$IS_WINDOWS" -eq 1 ]] && echo Windows || echo Unix) layout)"
else
    die "uv venv did not produce an interpreter under ${VENV_BIN#$ROOT/}"
fi

install_ml_stack() {
    info "auto-installing the AI stack into .venv …"
    if [[ "$NO_CUDA_TORCH" -eq 0 ]]; then
        info "  ${TORCH_SPEC} from ${TORCH_INDEX_URL}"
        uv pip install "$TORCH_SPEC" --index-url "$TORCH_INDEX_URL"
    fi
    uv pip install -e ".[ai]"
}

if [[ "$NO_VERIFY" -eq 1 ]]; then
    warn "skipping ai_module/verify_uv_env.sh (--no-verify)"
else
    set +e
    bash ai_module/verify_uv_env.sh
    verify_rc=$?
    set -e
    case "$verify_rc" in
        0)
            ok "verify_uv_env.sh passed"
            ;;
        3)
            if [[ "$NO_INSTALL" -eq 1 ]]; then
                die "AI stack is missing and --no-install was given — run \
'uv pip install -e \".[ai]\"' yourself"
            fi
            warn "AI stack incomplete — attempting automatic install"
            install_ml_stack || die "automatic dependency install failed — see \
the uv output above"
            info "re-checking the environment …"
            bash ai_module/verify_uv_env.sh \
                || die "environment still incomplete after auto-install — see \
[FAIL]/[MISS] lines above"
            ok "AI stack installed and verified"
            ;;
        *)
            die "ai_module/verify_uv_env.sh reported a hard problem (exit ${verify_rc}) \
— see [FAIL] lines above"
            ;;
    esac
fi

# ---------------------------------------------------------------------------
# 1b. can torch actually launch a kernel on this GPU?
#
# torch.cuda.is_available() only proves a driver and a device exist. A wheel
# built after PyTorch retired this GPU's compute capability imports fine,
# reports the device correctly, and then fails at the first launch with "no
# kernel image is available for execution on the device" — after the model
# download and several minutes of setup. One 8-element tensor answers it now.
# ---------------------------------------------------------------------------
step "CUDA kernel check"

# --quiet keeps uv's own "Building ... / Installed n packages" chatter out of
# the capture; the grep is the belt to that braces, since the probe prints
# exactly one line with a known prefix and a traceback prints none.
kernel_raw="$(uv run --quiet python - <<'KERNEL_PROBE_PY' 2>&1 || true
import torch
if not torch.cuda.is_available():
    print("NOCUDA " + torch.__version__)
else:
    try:
        torch.zeros(8, device="cuda").sum().item()
        cap = torch.cuda.get_device_capability()
        print("OK %s sm_%d%d" % (torch.__version__, cap[0], cap[1]))
    except Exception as exc:
        print("FAIL %s %s: %s" % (torch.__version__, type(exc).__name__, exc))
KERNEL_PROBE_PY
)"
kernel_probe="$(printf '%s\n' "$kernel_raw" | grep -E '^(OK|NOCUDA|FAIL) ' | tail -n 1)"
[[ -n "$kernel_probe" ]] || kernel_probe="$kernel_raw"

case "$kernel_probe" in
    OK*)
        ok "torch can launch kernels here (${kernel_probe#OK })"
        ;;
    NOCUDA*)
        warn "torch has no CUDA support (${kernel_probe#NOCUDA }) — training will run on the CPU"
        warn "re-install with: uv pip install torch --index-url ${TORCH_INDEX_URL}"
        ;;
    *"no kernel image"*|*"not compatible with the current PyTorch"*)
        die "torch installed but has no kernels for this GPU:
    ${kernel_probe}
PyTorch drops old compute capabilities as it moves on. Install the last build
that still ships them, then re-run:
    uv pip install 'torch==2.7.1' --index-url ${TORCH_INDEX_URL}"
        ;;
    *)
        warn "CUDA kernel probe inconclusive: ${kernel_probe}"
        ;;
esac

# ---------------------------------------------------------------------------
# 2. dataset (re)generation
# ---------------------------------------------------------------------------
step "Dataset generation"

resolve_dataset() {
    # echo "<train> <val>" for $TASK, or nothing if the pair is missing
    local t v
    for stem in "data/sft.${TASK}" "data/${TASK}"; do
        t="${stem}.train.jsonl"; v="${stem}.val.jsonl"
        if [[ -f "$t" && -f "$v" ]]; then
            echo "$t $v"; return 0
        fi
    done
    return 1
}

if [[ "$REGEN_DATA" -eq 1 ]]; then
    [[ -d "$TELEMETRY_DIR" ]] || die "telemetry dir not found: ${TELEMETRY_DIR}"
    csv_arg=()
    if [[ -f "$BENCHMARK_CSV" ]]; then
        csv_arg=(--benchmark-csv "$BENCHMARK_CSV")
        info "ground-truth oracle: ${BENCHMARK_CSV}"
    else
        warn "benchmark CSV missing — falling back to weak labels"
    fi
    info "regenerating datasets (synthetic-multiplier 40, 90/10 split)…"
    uv run python -m ai_module.dataset_generator \
        --telemetry "$TELEMETRY_DIR" \
        "${csv_arg[@]}" \
        --task both --format alpaca \
        --split 0.9 --synthetic-multiplier 40 \
        --out data/sft.jsonl --report data/curation.json
    ok "datasets regenerated"
else
    info "reuse existing datasets (pass --regen-data to rebuild)"
fi

read -r TRAIN_DS VAL_DS < <(resolve_dataset) || die \
    "no dataset for task '${TASK}' — run again with --regen-data"
ok "train: ${TRAIN_DS}"
ok "eval : ${VAL_DS}"

# ---------------------------------------------------------------------------
# 3. hardware profiling -> base-model selection
#
# A single hard-coded base model cannot serve both machines this project runs
# on: the 7B that fits the 32 GB RTX 5090 OOMs on the 6 GB RTX 4050, and a
# model small enough for the 4050 leaves the 5090 idle. Pick by VRAM instead.
# ---------------------------------------------------------------------------
step "Hardware profiling & base-model selection"

# --format recipe prints KEY=VALUE lines: the model *and* the training knobs
# that fit the probed device. Parsed with a read loop rather than `eval` so a
# surprising value can never execute.
AUTO_VRAM=""; AUTO_TIER=""; AUTO_DEVICE=""; AUTO_STATUS=""; AUTO_CAPABILITY=""
R_LOAD_IN_4BIT=""; R_PRECISION=""; R_BATCH_SIZE=""; R_GRAD_ACCUM=""
R_MAX_SEQ_LEN=""; R_LORA_R=""; R_OPTIM=""; R_NUM_WORKERS=""; R_ATTN_IMPL=""
R_MERGE_ADAPTER=""; R_TF32=""; AUTO_MODEL=""

recipe=""
if ! recipe="$(uv run python -m ai_module.auto_select_model --format recipe --quiet 2>/dev/null)"; then
    recipe=""
fi

if [[ -n "$recipe" ]]; then
    while IFS='=' read -r key value; do
        case "$key" in
            MODEL)                  AUTO_MODEL="$value" ;;
            TIER)                   AUTO_TIER="$value" ;;
            VRAM_GB)                AUTO_VRAM="$value" ;;
            CAPABILITY)             AUTO_CAPABILITY="$value" ;;
            DEVICE)                 AUTO_DEVICE="$value" ;;
            STATUS)                 AUTO_STATUS="$value" ;;
            LOAD_IN_4BIT)           R_LOAD_IN_4BIT="$value" ;;
            PRECISION)              R_PRECISION="$value" ;;
            BATCH_SIZE)             R_BATCH_SIZE="$value" ;;
            GRAD_ACCUM)             R_GRAD_ACCUM="$value" ;;
            MAX_SEQ_LEN)            R_MAX_SEQ_LEN="$value" ;;
            LORA_R)                 R_LORA_R="$value" ;;
            OPTIM)                  R_OPTIM="$value" ;;
            NUM_WORKERS)            R_NUM_WORKERS="$value" ;;
            ATTN_IMPL)              R_ATTN_IMPL="$value" ;;
            MERGE_ADAPTER)          R_MERGE_ADAPTER="$value" ;;
            TF32)                   R_TF32="$value" ;;
        esac
    done <<<"$recipe"
else
    # An older checkout (or a broken ML stack) has no --format recipe. The model
    # id alone is still enough to run with train_qlora.py's own defaults.
    warn "auto_select_model --format recipe unavailable — falling back to the model id only"
    AUTO_TUNE=0
    autosel=""
    if ! autosel="$(uv run python -m ai_module.auto_select_model --format tsv --quiet)"; then
        die "ai_module.auto_select_model failed to run — re-run with an explicit \
'--base-model NAME' to bypass hardware profiling"
    fi
    IFS=$'\t' read -r AUTO_VRAM AUTO_TIER AUTO_MODEL AUTO_DEVICE AUTO_STATUS <<<"$autosel"
fi

if [[ "$BASE_MODEL_EXPLICIT" -eq 1 ]]; then
    ok "base model pinned by --base-model: ${BASE_MODEL}"
    info "model auto-selection skipped (the hardware knobs below still apply)"
else
    [[ -n "$AUTO_MODEL" ]] || die "auto_select_model returned no model name"
    BASE_MODEL="$AUTO_MODEL"
    ok "Auto-selected model: ${BASE_MODEL}"
    info "pass '--base-model NAME' to override this choice"
fi

if [[ "$AUTO_TIER" == "0" ]]; then
    # Step 1 already installed and verified torch, so reaching the CPU tier
    # here means the GPU is not usable — say so instead of quietly
    # fine-tuning a toy model on a workstation that has a 5090 in it.
    warn "no usable GPU detected (${AUTO_STATUS}) — falling back to a CPU-sized model"
    warn "training will be extremely slow; check 'nvidia-smi' and the torch CUDA build"
fi
info "[INFO] Hardware profiling: ${AUTO_VRAM:-?} GB VRAM detected (${AUTO_DEVICE:-?}${AUTO_CAPABILITY:+, sm_${AUTO_CAPABILITY//./}}, tier ${AUTO_TIER:-?})."

# ---------------------------------------------------------------------------
# 3b. hardware-derived training knobs
#
# A 4 GB Turing card and a 32 GB Blackwell card cannot share a batch size, a
# sequence length or even a compute dtype — sm_75 has no bf16 at all. The knobs
# come from the same probe that picked the model, so the two can never drift
# apart, and --no-auto-tune falls back to train_qlora.py's own defaults.
# ---------------------------------------------------------------------------
TRAIN_ARGS=()
if [[ "$AUTO_TUNE" -eq 1 && -n "$R_PRECISION" ]]; then
    TRAIN_ARGS+=(
        --precision   "$R_PRECISION"
        --batch-size  "$R_BATCH_SIZE"
        --grad-accum  "$R_GRAD_ACCUM"
        --max-seq-len "$R_MAX_SEQ_LEN"
        --lora-r      "$R_LORA_R"
        --optim       "$R_OPTIM"
        --num-workers "$R_NUM_WORKERS"
        --attn-impl   "$R_ATTN_IMPL"
    )
    [[ "$R_LOAD_IN_4BIT" == "1" ]] && TRAIN_ARGS+=(--load-in-4bit)
    [[ "$R_TF32" == "1" ]] || TRAIN_ARGS+=(--no-tf32)
    ok "hardware knobs: precision=${R_PRECISION} 4bit=${R_LOAD_IN_4BIT} \
batch=${R_BATCH_SIZE} accum=${R_GRAD_ACCUM} seq=${R_MAX_SEQ_LEN} lora_r=${R_LORA_R}"
    if [[ "$R_PRECISION" == "fp16" && -n "$AUTO_CAPABILITY" ]]; then
        info "sm_${AUTO_CAPABILITY//./} predates Ampere: bf16 and TF32 are off, fp16 is used instead"
    fi
    if [[ "$R_MERGE_ADAPTER" != "1" ]]; then
        info "adapter merging disabled: a LoRA cannot be merged losslessly back \
into 4-bit NF4 weights — serve the adapter on top of the base model instead"
    fi
else
    warn "hardware auto-tuning disabled — using train_qlora.py defaults"
fi

# ---------------------------------------------------------------------------
# 4. base-model cache preparation
# ---------------------------------------------------------------------------
step "Base-model preparation"

if [[ "$SKIP_MODEL_DL" -eq 1 ]]; then
    warn "skipped (--skip-model-dl) — the trainer will fetch it on demand"
elif [[ "$SKIP_SMOKE" -eq 1 && "$SKIP_TRAIN" -eq 1 ]]; then
    info "no training step scheduled — skipping model download"
else
    info "ensuring '${BASE_MODEL}' is in the Hugging Face cache …"
    info "  (flaky transfers are retried with backoff + cache cleanup — this step"
    info "   may pause and re-try before it either succeeds or aborts; that is normal)"
    ebm_args=(--retries "$MODEL_RETRIES")
    [[ "$NO_XET" -eq 1 ]] && ebm_args+=(--no-xet)
    if uv run python -m ai_module.ensure_base_model "$BASE_MODEL" "${ebm_args[@]}"; then
        ok "base model ready in the local cache"
    else
        die "could not obtain the base model '${BASE_MODEL}' after ${MODEL_RETRIES} \
attempts — the partial cache has been purged. Check network / \
'uv run huggingface-cli login' for gated repos, then re-run; a manual \
'HF_HUB_DISABLE_XET=1 uv run python -m ai_module.ensure_base_model ${BASE_MODEL}' \
often gets past Xet/CAS errors."
    fi
fi

# ---------------------------------------------------------------------------
# 5. QLoRA smoke test
# ---------------------------------------------------------------------------
step "QLoRA smoke test (5 steps)"

if [[ "$SKIP_SMOKE" -eq 1 ]]; then
    warn "skipped (--skip-smoke)"
else
    rm -rf "$SMOKE_DIR"
    # Same knobs as the real run: a smoke test that trains at a different batch
    # size or precision proves nothing about whether the real run will fit.
    uv run python -m ai_module.train_qlora \
        --base-model "$BASE_MODEL" \
        --dataset "$TRAIN_DS" \
        --output-dir "$SMOKE_DIR" \
        --max-steps 5 \
        ${TRAIN_ARGS[@]+"${TRAIN_ARGS[@]}"}
    ok "smoke test OK — kernels, bitsandbytes 4-bit and the data pipeline respond"
fi

# ---------------------------------------------------------------------------
# 6. full QLoRA fine-tune
# ---------------------------------------------------------------------------
step "Full QLoRA fine-tune"

if [[ "$SKIP_TRAIN" -eq 1 ]]; then
    warn "skipped (--skip-train)"
else
    merge_args=()
    [[ "$AUTO_TUNE" -eq 0 || "$R_MERGE_ADAPTER" == "1" ]] && merge_args+=(--merge-adapter)

    info "base-model : ${BASE_MODEL}"
    info "output-dir : ${OUT_DIR}"
    info "knobs      : --epochs ${EPOCHS} ${TRAIN_ARGS[*]-} ${merge_args[*]-}"
    uv run python -m ai_module.train_qlora \
        --base-model "$BASE_MODEL" \
        --dataset "$TRAIN_DS" --eval "$VAL_DS" \
        --output-dir "$OUT_DIR" \
        --epochs "$EPOCHS" \
        ${TRAIN_ARGS[@]+"${TRAIN_ARGS[@]}"} \
        ${merge_args[@]+"${merge_args[@]}"}
    ok "fine-tune complete"
    info "adapter : ${OUT_DIR}/adapter/"
    if [[ ${#merge_args[@]} -gt 0 ]]; then
        info "merged  : ${OUT_DIR}/merged/"
    else
        info "no merged model: the 4-bit base cannot absorb the adapter losslessly"
    fi
fi

# ---------------------------------------------------------------------------
# done
# ---------------------------------------------------------------------------
trap - ERR
printf '\n%s%s✓ PIPELINE COMPLETE%s  total time: %s%s%s\n' \
    "$BOLD" "$GREEN" "$RESET" "$BOLD" "$(elapsed)" "$RESET"
