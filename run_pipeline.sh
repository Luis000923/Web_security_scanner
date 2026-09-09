#!/usr/bin/env bash
#
# run_pipeline.sh — master orchestrator for the ai_module QLoRA workflow.
#
# Runs, in order, on the workstation (RTX 5090 / CUDA 12.8 / uv):
#   1. environment + uv verification, with auto-install of the ML stack
#      (bash ai_module/verify_uv_env.sh; on missing deps -> uv pip install -e ".[ai]")
#   2. dataset (re)generation                    (optional, --regen-data)
#   3. base-model cache preparation              (HF snapshot download if missing)
#   4. QLoRA smoke test                          (--max-steps 5, fast CUDA/VRAM check)
#   5. full QLoRA fine-tune                      (--epochs 3 --max-seq-len 2048 --eval)
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
#   --base-model NAME       base model for the full run
#                           (default: Qwen/Qwen2.5-7B-Instruct — native bf16)
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
BASE_MODEL="Qwen/Qwen2.5-7B-Instruct"
NO_INSTALL=0
NO_CUDA_TORCH=0
SKIP_MODEL_DL=0
MODEL_RETRIES=3
NO_XET=0
SKIP_SMOKE=0
SKIP_TRAIN=0
NO_VERIFY=0
ALLOW_ROOT=0
TORCH_INDEX_URL="${TORCH_INDEX_URL:-https://download.pytorch.org/whl/cu128}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --regen-data)     REGEN_DATA=1; shift ;;
        --task)           TASK="${2:?}"; shift 2 ;;
        --epochs)         EPOCHS="${2:?}"; shift 2 ;;
        --base-model)     BASE_MODEL="${2:?}"; shift 2 ;;
        --no-install)     NO_INSTALL=1; shift ;;
        --no-cuda-torch)  NO_CUDA_TORCH=1; shift ;;
        --skip-model-dl)  SKIP_MODEL_DL=1; shift ;;
        --model-retries)  MODEL_RETRIES="${2:?}"; shift 2 ;;
        --no-xet)         NO_XET=1; shift ;;
        --skip-smoke)     SKIP_SMOKE=1; shift ;;
        --skip-train)     SKIP_TRAIN=1; shift ;;
        --no-verify)      NO_VERIFY=1; shift ;;
        --allow-root)     ALLOW_ROOT=1; shift ;;
        -h|--help)        sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
printf '   repo: %s\n' "$ROOT"

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
        info "  torch from ${TORCH_INDEX_URL}"
        uv pip install torch --index-url "$TORCH_INDEX_URL"
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
# 3. base-model cache preparation
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
# 4. QLoRA smoke test
# ---------------------------------------------------------------------------
step "QLoRA smoke test (5 steps)"

if [[ "$SKIP_SMOKE" -eq 1 ]]; then
    warn "skipped (--skip-smoke)"
else
    rm -rf "$SMOKE_DIR"
    uv run python -m ai_module.train_qlora \
        --base-model "$BASE_MODEL" \
        --dataset "$TRAIN_DS" \
        --output-dir "$SMOKE_DIR" \
        --max-steps 5
    ok "smoke test OK — kernels, bitsandbytes 4-bit and the data pipeline respond"
fi

# ---------------------------------------------------------------------------
# 5. full QLoRA fine-tune
# ---------------------------------------------------------------------------
step "Full QLoRA fine-tune"

if [[ "$SKIP_TRAIN" -eq 1 ]]; then
    warn "skipped (--skip-train)"
else
    info "base-model : ${BASE_MODEL}"
    info "output-dir : ${OUT_DIR}"
    info "knobs      : --epochs ${EPOCHS} --max-seq-len 2048 --batch-size 8 --grad-accum 2 --eval --merge-adapter"
    uv run python -m ai_module.train_qlora \
        --base-model "$BASE_MODEL" \
        --dataset "$TRAIN_DS" --eval "$VAL_DS" \
        --output-dir "$OUT_DIR" \
        --epochs "$EPOCHS" --batch-size 8 --grad-accum 2 --max-seq-len 2048 \
        --merge-adapter
    ok "fine-tune complete"
    info "adapter : ${OUT_DIR}/adapter/"
    info "merged  : ${OUT_DIR}/merged/"
fi

# ---------------------------------------------------------------------------
# done
# ---------------------------------------------------------------------------
trap - ERR
printf '\n%s%s✓ PIPELINE COMPLETE%s  total time: %s%s%s\n' \
    "$BOLD" "$GREEN" "$RESET" "$BOLD" "$(elapsed)" "$RESET"
