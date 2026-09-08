#!/usr/bin/env bash
#
# run_pipeline.sh — master orchestrator for the ai_module QLoRA workflow.
#
# Runs, in order, on the workstation (RTX 5090 / CUDA 12.8 / uv):
#   1. environment + uv verification            (bash ai_module/verify_uv_env.sh)
#   2. dataset (re)generation                    (optional, --regen-data)
#   3. QLoRA smoke test                          (--max-steps 5, fast CUDA/VRAM check)
#   4. full QLoRA fine-tune                      (--epochs 3 --max-seq-len 2048 --eval)
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
#                           (default: unsloth/Qwen2.5-7B-Instruct-bnb-4bit)
#   --skip-smoke            skip the smoke test (not recommended)
#   --skip-train            stop after the smoke test
#   --no-verify             skip bash ai_module/verify_uv_env.sh (not recommended)
#   -h, --help              this help
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
BASE_MODEL="unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
SKIP_SMOKE=0
SKIP_TRAIN=0
NO_VERIFY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --regen-data)  REGEN_DATA=1; shift ;;
        --task)        TASK="${2:?}"; shift 2 ;;
        --epochs)      EPOCHS="${2:?}"; shift 2 ;;
        --base-model)  BASE_MODEL="${2:?}"; shift 2 ;;
        --skip-smoke)  SKIP_SMOKE=1; shift ;;
        --skip-train)  SKIP_TRAIN=1; shift ;;
        --no-verify)   NO_VERIFY=1; shift ;;
        -h|--help)     sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)             die "unknown option: $1  (try --help)" ;;
    esac
done

case "$TASK" in
    triage|payload) ;;
    *) die "--task must be 'triage' or 'payload', got '${TASK}'" ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

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

if [[ ! -d .venv ]]; then
    warn ".venv not found — bootstrapping with uv venv + uv sync"
    uv venv
    uv sync
    ok "environment created"
else
    ok ".venv present"
fi

if [[ "$NO_VERIFY" -eq 1 ]]; then
    warn "skipping ai_module/verify_uv_env.sh (--no-verify)"
else
    if bash ai_module/verify_uv_env.sh; then
        ok "verify_uv_env.sh passed"
    else
        die "ai_module/verify_uv_env.sh failed — fix the environment before training \
(run 'uv pip install -e \".[ai]\"', see ai_module/README.md)"
    fi
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
# 3. QLoRA smoke test
# ---------------------------------------------------------------------------
step "QLoRA smoke test (5 steps)"

if [[ "$SKIP_SMOKE" -eq 1 ]]; then
    warn "skipped (--skip-smoke)"
else
    rm -rf "$SMOKE_DIR"
    uv run python -m ai_module.train_qlora \
        --dataset "$TRAIN_DS" \
        --output-dir "$SMOKE_DIR" \
        --max-steps 5
    ok "smoke test OK — kernels, bitsandbytes 4-bit and the data pipeline respond"
fi

# ---------------------------------------------------------------------------
# 4. full QLoRA fine-tune
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
