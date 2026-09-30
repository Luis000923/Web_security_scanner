#!/usr/bin/env bash
# =============================================================================
# run_ai_pipeline.sh — orquestador de la fase de IA (datasets + QLoRA, modelo por VRAM)
#
# Ejecuta, en orden y sin intervención:
#   1. entorno + PYTHONPATH
#   2. instalación del stack ML          (--skip-install para omitir)
#   3. dry-run de configuración
#   4. descarga del modelo base          (--skip-model-dl para omitir)
#   5. generación de datasets SFT        (se salta si ya existen; --regen-data fuerza)
#   6. inyección del conjunto de rechazo (lobotomía cognitiva)
#   7. smoke test de hardware (5 pasos)
#   8. fine-tune completo — adaptador de triage
#   9. fine-tune completo — adaptador de síntesis de payloads
#  10. puerta de aceptación contra el golden set (si existe el dataset)
#  11. (opcional) servidor vLLM OpenAI-compatible   (--serve)
#
# Uso:
#   ./run_ai_pipeline.sh                       # flujo completo (task=both)
#   ./run_ai_pipeline.sh --regen-data          # regenera datasets desde cero
#   ./run_ai_pipeline.sh --task triage         # solo el adaptador de triage
#   ./run_ai_pipeline.sh --smoke-only          # para tras el smoke test
#   ./run_ai_pipeline.sh --skip-install --skip-model-dl
#   ./run_ai_pipeline.sh --epochs 5 --lora-r 64 --lora-alpha 128
#   ./run_ai_pipeline.sh --serve               # al final, levanta vLLM
#   ./run_ai_pipeline.sh --no-auto-hw          # no adaptar al hardware (perfil 32 GB)
#   ./run_ai_pipeline.sh --help
#
# Adaptación al hardware (por defecto): el paso 2b mide la VRAM y elige el
# modelo base y el presupuesto de entrenamiento (batch / grad-accum / seq-len /
# LoRA rank) que caben. El perfil por defecto (7B, batch 8, seq 2048) es el de
# una estación de 32 GB y NO cabe en una portátil de 6 GB. Cualquier valor que
# fijes con flag o variable de entorno se respeta.
# =============================================================================
set -euo pipefail

# ----------------------------------------------------------------------------- #
# rutas y entorno
# ----------------------------------------------------------------------------- #
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$SCRIPT_DIR"

export PYTHONPATH="${PYTHONPATH:-.}"
export HF_HOME="${HF_HOME:-$HOME/.cache/huggingface}"
export TOKENIZERS_PARALLELISM="${TOKENIZERS_PARALLELISM:-false}"

# Índice de wheels de PyTorch acorde a tu CUDA (cambia cu128 si procede).
TORCH_INDEX_URL="${TORCH_INDEX_URL:-https://download.pytorch.org/whl/cu128}"

# ----------------------------------------------------------------------------- #
# parámetros por defecto (sobrescribibles por flag o variable de entorno)
# ----------------------------------------------------------------------------- #
# The training knobs below are the 32 GB-workstation profile. Step 2b probes the
# actual GPU and, for anything smaller, replaces the model and the batch/seq/
# LoRA budget with values that fit — unless you pinned them with an explicit
# flag (or --no-auto-hw). A 6 GB laptop cannot train the 7B in any precision;
# it drops to the 1.5B with a micro-batch. This is why a hard-coded 7B here
# OOMs at 86 % of weight loading on a 4050.
AUTO_HW=1                    # 0 with --no-auto-hw
# An env-var override counts as "pinned by the user" too, so step 2b leaves it
# alone.
BASE_MODEL_SET=$([[ -n "${BASE_MODEL:-}" ]] && echo 1 || echo 0)
BATCH_SET=$([[ -n "${BATCH_SIZE:-}" ]] && echo 1 || echo 0)
ACCUM_SET=$([[ -n "${GRAD_ACCUM:-}" ]] && echo 1 || echo 0)
SEQ_SET=$([[ -n "${MAX_SEQ_LEN:-}" ]] && echo 1 || echo 0)
LORA_R_SET=$([[ -n "${LORA_R:-}" ]] && echo 1 || echo 0)
LORA_ALPHA_SET=$([[ -n "${LORA_ALPHA:-}" ]] && echo 1 || echo 0)

BASE_MODEL="${BASE_MODEL:-unsloth/Qwen2.5-7B-Instruct-bnb-4bit}"
TASK="both"                 # both | triage | payload
EPOCHS="${EPOCHS:-3}"
BATCH_SIZE="${BATCH_SIZE:-8}"
GRAD_ACCUM="${GRAD_ACCUM:-2}"
MAX_SEQ_LEN="${MAX_SEQ_LEN:-2048}"
LORA_R="${LORA_R:-64}"
LORA_ALPHA="${LORA_ALPHA:-128}"
LORA_DROPOUT="${LORA_DROPOUT:-0.05}"

TELEMETRY_DIR="testbed/results"
BENCHMARK_CSV="testbed/.cache/benchmark/expectedresults-1.2.csv"
DATA_DIR="data"
RUNS_DIR="runs"
METRICS_DIR="metrics"
GOLDEN_DATASET="$DATA_DIR/golden_dataset.jsonl"

SKIP_INSTALL=0
SKIP_MODEL_DL=0
REGEN_DATA=0
SMOKE_ONLY=0
NO_EVAL_GATE=0
SERVE=0

# ----------------------------------------------------------------------------- #
# parseo de flags
# ----------------------------------------------------------------------------- #
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-install)   SKIP_INSTALL=1 ;;
        --skip-model-dl)  SKIP_MODEL_DL=1 ;;
        --regen-data)     REGEN_DATA=1 ;;
        --smoke-only)     SMOKE_ONLY=1 ;;
        --no-eval-gate)   NO_EVAL_GATE=1 ;;
        --no-auto-hw)     AUTO_HW=0 ;;
        --serve)          SERVE=1 ;;
        --task)           TASK="${2:?}"; shift ;;
        --base-model)     BASE_MODEL="${2:?}"; BASE_MODEL_SET=1; shift ;;
        --epochs)         EPOCHS="${2:?}"; shift ;;
        --batch-size)     BATCH_SIZE="${2:?}"; BATCH_SET=1; shift ;;
        --grad-accum)     GRAD_ACCUM="${2:?}"; ACCUM_SET=1; shift ;;
        --max-seq-len)    MAX_SEQ_LEN="${2:?}"; SEQ_SET=1; shift ;;
        --lora-r)         LORA_R="${2:?}"; LORA_R_SET=1; shift ;;
        --lora-alpha)     LORA_ALPHA="${2:?}"; LORA_ALPHA_SET=1; shift ;;
        --lora-dropout)   LORA_DROPOUT="${2:?}"; shift ;;
        -h|--help)
            sed -n '2,34p' "$0"; exit 0 ;;
        *) echo "flag desconocido: $1  (usa --help)" >&2; exit 2 ;;
    esac
    shift
done

case "$TASK" in both|triage|payload) ;; *)
    echo "--task debe ser both|triage|payload" >&2; exit 2 ;;
esac

# ----------------------------------------------------------------------------- #
# helpers de log
# ----------------------------------------------------------------------------- #
if [[ -t 1 ]]; then C_B=$'\e[1m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_0=$'\e[0m'
else C_B=; C_G=; C_Y=; C_R=; C_0=; fi
STEP=0
step()  { STEP=$((STEP+1)); echo; echo "${C_B}${C_G}══ [$STEP] $*${C_0}"; }
info()  { echo "${C_Y}·${C_0} $*"; }
die()   { echo "${C_R}✗ $*${C_0}" >&2; exit 1; }
trap 'die "abortado en el paso $STEP (línea $LINENO)"' ERR

START_TS=$(date +%s)

# ----------------------------------------------------------------------------- #
# selección del runner de Python (uv preferente; luego .venv; luego python3)
# ----------------------------------------------------------------------------- #
if command -v uv &>/dev/null && [[ -f uv.lock ]]; then
    PY=(uv run python)
    PIP=(uv pip install)
    info "runner: uv run python"
elif [[ -x .venv/bin/python ]]; then
    PY=(.venv/bin/python)
    PIP=(.venv/bin/python -m pip install)
    info "runner: .venv/bin/python"
else
    PY=(python3)
    PIP=(python3 -m pip install)
    info "runner: python3 (sin entorno aislado)"
fi
run_py() { "${PY[@]}" "$@"; }

# ----------------------------------------------------------------------------- #
# 1. entorno
# ----------------------------------------------------------------------------- #
step "Entorno"
info "PYTHONPATH=$PYTHONPATH   HF_HOME=$HF_HOME"
info "modelo base: $BASE_MODEL"
info "LoRA: r=$LORA_R  alpha=$LORA_ALPHA  dropout=$LORA_DROPOUT   epochs=$EPOCHS"
mkdir -p "$DATA_DIR" "$RUNS_DIR" "$METRICS_DIR"

[[ -d "$TELEMETRY_DIR" ]] || die "no existe la telemetría: $TELEMETRY_DIR"

# ----------------------------------------------------------------------------- #
# 2. instalación del stack ML
# ----------------------------------------------------------------------------- #
step "Stack ML"
if [[ "$SKIP_INSTALL" -eq 1 ]]; then
    info "omitido (--skip-install)"
else
    info "torch desde $TORCH_INDEX_URL"
    "${PIP[@]}" torch --index-url "$TORCH_INDEX_URL"
    "${PIP[@]}" -e ".[ai,ai-local]"
    "${PIP[@]}" "peft>=0.11" "trl>=0.9" "datasets>=2.19" "bitsandbytes>=0.43" "accelerate>=0.30"
fi

info "comprobando CUDA…"
if run_py - <<'PY'
import sys
try:
    import torch
    ok = torch.cuda.is_available()
    print("  torch", torch.__version__, "cuda", ok,
          "-", (torch.cuda.get_device_name(0) if ok else "sin GPU"))
    sys.exit(0 if ok else 1)
except Exception as e:                      # noqa: BLE001
    print("  torch no importable:", e); sys.exit(1)
PY
then :; else
    info "${C_Y}sin GPU utilizable — el entrenamiento será inviable en CPU${C_0}"
fi

# ----------------------------------------------------------------------------- #
# 2b. perfilado de hardware → modelo y presupuesto de entrenamiento
#
# El perfil por defecto (7B, batch 8, seq 2048, r64) es el de la estación de
# 32 GB. En cualquier GPU más pequeña ese 7B ni siquiera carga —OOM al 86 % de
# los pesos—, así que aquí se sustituye por lo que entra: VRAM elige el modelo,
# y el batch/seq/LoRA se recorta en proporción. Cada valor que fijaste
# explícitamente (flag o variable de entorno) se respeta; --no-auto-hw lo
# desactiva por completo.
# ----------------------------------------------------------------------------- #
step "Perfilado de hardware"
if [[ "$AUTO_HW" -eq 0 ]]; then
    info "omitido (--no-auto-hw) — perfil de 32 GB: $BASE_MODEL"
else
    HW_TSV="$(run_py - <<'PY' 2>/dev/null || true
import json, sys
try:
    import torch
    if not torch.cuda.is_available():
        print("0.0\t0\t0.0"); sys.exit(0)
    p = torch.cuda.get_device_properties(0)
    cap = torch.cuda.get_device_capability(0)
    print(f"{p.total_memory / 1024**3:.2f}\t1\t{cap[0]}.{cap[1]}")
except Exception:
    print("0.0\t0\t0.0")
PY
)"
    IFS=$'\t' read -r HW_VRAM HW_HASGPU HW_CAP <<<"${HW_TSV:-0.0	0	0.0}"
    info "VRAM detectada: ${HW_VRAM} GB   compute capability: ${HW_CAP}"

    # (umbral GB, modelo, batch, accum, seq, lora_r)   — el primero que entra gana
    pick() {
        local v="$1"
        awk -v v="$v" 'BEGIN{
            if (v <= 0)        print "unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit\t1\t8\t512\t8";
            else if (v <= 5.0) print "unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit\t1\t16\t512\t16";
            else if (v <= 7.0) print "unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit\t2\t8\t768\t16";
            else if (v <= 16.0) print "unsloth/Qwen2.5-7B-Instruct-bnb-4bit\t4\t4\t1024\t32";
            else               print "unsloth/Qwen2.5-7B-Instruct-bnb-4bit\t8\t2\t2048\t64";
        }'
    }
    IFS=$'\t' read -r HW_MODEL HW_BATCH HW_ACCUM HW_SEQ HW_R <<<"$(pick "$HW_VRAM")"

    [[ "$BASE_MODEL_SET"  -eq 1 ]] || BASE_MODEL="$HW_MODEL"
    [[ "$BATCH_SET"       -eq 1 ]] || BATCH_SIZE="$HW_BATCH"
    [[ "$ACCUM_SET"       -eq 1 ]] || GRAD_ACCUM="$HW_ACCUM"
    [[ "$SEQ_SET"         -eq 1 ]] || MAX_SEQ_LEN="$HW_SEQ"
    [[ "$LORA_R_SET"      -eq 1 ]] || LORA_R="$HW_R"
    [[ "$LORA_ALPHA_SET"  -eq 1 ]] || LORA_ALPHA="$(( LORA_R * 2 ))"

    info "${C_G}modelo:${C_0} $BASE_MODEL"
    info "${C_G}knobs :${C_0} batch=$BATCH_SIZE accum=$GRAD_ACCUM seq=$MAX_SEQ_LEN r=$LORA_R alpha=$LORA_ALPHA"
    if [[ "$HW_HASGPU" -eq 1 ]] && awk -v v="$HW_VRAM" 'BEGIN{exit !(v>0 && v<=7.0)}'; then
        info "${C_Y}nota:${C_0} GPU pequeña — micro-batch; el reintento ante OOM lo reduce más si hace falta"
        export PYTORCH_CUDA_ALLOC_CONF="${PYTORCH_CUDA_ALLOC_CONF:-expandable_segments:True}"
    fi
fi

# ----------------------------------------------------------------------------- #
# 3. dry-run de configuración
# ----------------------------------------------------------------------------- #
step "Dry-run de configuración"
run_py -m ai_module.train_qlora --dry-run \
    --base-model "$BASE_MODEL" \
    --dataset "$DATA_DIR/sft.triage.train.lobotomised.jsonl" \
    --lora-r "$LORA_R" --lora-alpha "$LORA_ALPHA" --lora-dropout "$LORA_DROPOUT" \
    --epochs "$EPOCHS" --batch-size "$BATCH_SIZE" --grad-accum "$GRAD_ACCUM" \
    --max-seq-len "$MAX_SEQ_LEN"

# ----------------------------------------------------------------------------- #
# 4. descarga del modelo base
# ----------------------------------------------------------------------------- #
step "Modelo base"
if [[ "$SKIP_MODEL_DL" -eq 1 ]]; then
    info "omitido (--skip-model-dl)"
else
    run_py -m ai_module.ensure_base_model "$BASE_MODEL"
fi

# ----------------------------------------------------------------------------- #
# 5. generación de datasets
# ----------------------------------------------------------------------------- #
step "Datasets SFT"
NEED_TRIAGE=0; NEED_PAYLOAD=0
[[ "$TASK" == "both" || "$TASK" == "triage" ]]  && NEED_TRIAGE=1
[[ "$TASK" == "both" || "$TASK" == "payload" ]] && NEED_PAYLOAD=1

triage_exists()  { [[ -s "$DATA_DIR/sft.triage.train.jsonl"  && -s "$DATA_DIR/sft.triage.val.jsonl"  ]]; }
payload_exists() { [[ -s "$DATA_DIR/sft.payload.train.jsonl" && -s "$DATA_DIR/sft.payload.val.jsonl" ]]; }

REGEN=0
if [[ "$REGEN_DATA" -eq 1 ]]; then REGEN=1
elif [[ "$NEED_TRIAGE" -eq 1 ]]  && ! triage_exists;  then REGEN=1
elif [[ "$NEED_PAYLOAD" -eq 1 ]] && ! payload_exists; then REGEN=1
fi

if [[ "$REGEN" -eq 1 ]]; then
    BENCH_FLAG=()
    [[ -s "$BENCHMARK_CSV" ]] && BENCH_FLAG=(--benchmark-csv "$BENCHMARK_CSV") \
        || info "sin $BENCHMARK_CSV — se usarán etiquetas débiles"
    run_py -m ai_module.dataset_generator \
        --telemetry "$TELEMETRY_DIR" \
        "${BENCH_FLAG[@]}" \
        --task "$TASK" --format alpaca \
        --split 0.9 --balance --synthetic-multiplier 40 \
        --out "$DATA_DIR/sft.jsonl" --report "$DATA_DIR/curation.json"
else
    info "datasets ya presentes — se reutilizan (usa --regen-data para rehacerlos)"
fi

# Cuando --task no es "both", el generador NO añade el sufijo .triage/.payload.
if [[ "$TASK" != "both" ]]; then
    for part in train val; do
        [[ -s "$DATA_DIR/sft.$part.jsonl" ]] && \
            cp -f "$DATA_DIR/sft.$part.jsonl" "$DATA_DIR/sft.$TASK.$part.jsonl"
    done
fi

# ----------------------------------------------------------------------------- #
# 6. inyección del conjunto de rechazo (solo afecta a triage)
# ----------------------------------------------------------------------------- #
step "Conjunto de rechazo (lobotomía cognitiva)"
if [[ "$NEED_TRIAGE" -eq 1 ]]; then
    triage_exists || die "faltan los ficheros de triage tras la generación"
    run_py -m ai_module.inject_cognitive_noise \
        --input  "$DATA_DIR/sft.triage.train.jsonl" \
        --output "$DATA_DIR/sft.triage.train.lobotomised.jsonl" \
        --input  "$DATA_DIR/sft.triage.val.jsonl" \
        --output "$DATA_DIR/sft.triage.val.lobotomised.jsonl" \
        --noise-ratio 0.10 --seed 1337 --report "$DATA_DIR/lobotomy.json"
else
    info "task=$TASK — no aplica"
fi

# ----------------------------------------------------------------------------- #
# 7. smoke test
# ----------------------------------------------------------------------------- #
step "Smoke test (5 pasos)"
SMOKE_DATA="$DATA_DIR/sft.triage.train.lobotomised.jsonl"
[[ "$NEED_TRIAGE" -eq 1 ]] || SMOKE_DATA="$DATA_DIR/sft.payload.train.jsonl"
# Mismos knobs que el fine-tune real: un smoke test con otro batch/seq no
# prueba si el entrenamiento de verdad cabe en memoria.
run_py -m ai_module.train_qlora \
    --base-model "$BASE_MODEL" \
    --dataset "$SMOKE_DATA" \
    --load-in-4bit \
    --lora-r "$LORA_R" --lora-alpha "$LORA_ALPHA" --lora-dropout "$LORA_DROPOUT" \
    --batch-size "$BATCH_SIZE" --grad-accum "$GRAD_ACCUM" --max-seq-len "$MAX_SEQ_LEN" \
    --output-dir "$RUNS_DIR/_smoke" --max-steps 5

if [[ "$SMOKE_ONLY" -eq 1 ]]; then
    info "--smoke-only: fin"
    exit 0
fi

# ----------------------------------------------------------------------------- #
# fine-tune con reintento único ante CUDA OOM (micro-batch /2, grad-accum x2)
# ----------------------------------------------------------------------------- #
train_adapter() {
    local out="$1" ds="$2" evalf="$3" bs="$BATCH_SIZE" ga="$GRAD_ACCUM"
    local eval_flag=(); [[ -s "$evalf" ]] && eval_flag=(--eval "$evalf")
    for attempt in 1 2; do
        if run_py -m ai_module.train_qlora \
            --base-model "$BASE_MODEL" \
            --dataset "$ds" "${eval_flag[@]}" \
            --output-dir "$out" \
            --load-in-4bit \
            --lora-r "$LORA_R" --lora-alpha "$LORA_ALPHA" --lora-dropout "$LORA_DROPOUT" \
            --epochs "$EPOCHS" --batch-size "$bs" --grad-accum "$ga" \
            --max-seq-len "$MAX_SEQ_LEN" \
            --early-stopping-patience 2 --save-total-limit 2 \
            --merge-adapter
        then return 0; fi
        [[ $attempt -eq 1 ]] || return 1
        bs=$(( bs > 1 ? bs / 2 : 1 )); ga=$(( ga * 2 ))
        info "${C_Y}reintento tras fallo: --batch-size $bs --grad-accum $ga${C_0}"
    done
}

# ----------------------------------------------------------------------------- #
# 8. fine-tune triage
# ----------------------------------------------------------------------------- #
step "Fine-tune — adaptador de triage"
if [[ "$NEED_TRIAGE" -eq 1 ]]; then
    train_adapter "$RUNS_DIR/triage-qlora" \
        "$DATA_DIR/sft.triage.train.lobotomised.jsonl" \
        "$DATA_DIR/sft.triage.val.lobotomised.jsonl" \
        || die "el fine-tune de triage falló"
else
    info "task=$TASK — omitido"
fi

# ----------------------------------------------------------------------------- #
# 9. fine-tune payload
# ----------------------------------------------------------------------------- #
step "Fine-tune — adaptador de síntesis de payloads"
if [[ "$NEED_PAYLOAD" -eq 1 ]]; then
    train_adapter "$RUNS_DIR/payload-qlora" \
        "$DATA_DIR/sft.payload.train.jsonl" \
        "$DATA_DIR/sft.payload.val.jsonl" \
        || die "el fine-tune de payload falló"
else
    info "task=$TASK — omitido"
fi

# ----------------------------------------------------------------------------- #
# 10. puerta de aceptación (golden set)
# ----------------------------------------------------------------------------- #
step "Puerta de aceptación (golden set)"
if [[ "$NO_EVAL_GATE" -eq 1 ]]; then
    info "omitida (--no-eval-gate)"
elif [[ "$NEED_TRIAGE" -ne 1 ]]; then
    info "sin adaptador de triage — no aplica"
elif [[ ! -s "$GOLDEN_DATASET" ]]; then
    info "no existe $GOLDEN_DATASET — se omite (crea el golden set para activar la puerta)"
else
    AI_AGENT_HF_MODEL="$RUNS_DIR/triage-qlora/merged" \
    run_py -m ai_module.evaluate_golden \
        --backend transformers \
        --model "$RUNS_DIR/triage-qlora/merged" \
        --dataset "$GOLDEN_DATASET" \
        --out "$METRICS_DIR/golden_eval_results.json"
    info "métricas -> $METRICS_DIR/golden_eval_results.json"
fi

# ----------------------------------------------------------------------------- #
# cierre
# ----------------------------------------------------------------------------- #
ELAPSED=$(( $(date +%s) - START_TS ))
step "Completado en $((ELAPSED/60))m $((ELAPSED%60))s"
[[ -d "$RUNS_DIR/triage-qlora"  ]] && info "triage : $RUNS_DIR/triage-qlora/{adapter,merged}"
[[ -d "$RUNS_DIR/payload-qlora" ]] && info "payload: $RUNS_DIR/payload-qlora/{adapter,merged}"

# ----------------------------------------------------------------------------- #
# 11. servidor vLLM opcional
# ----------------------------------------------------------------------------- #
if [[ "$SERVE" -eq 1 && "$NEED_TRIAGE" -eq 1 ]]; then
    step "Servidor vLLM (OpenAI-compatible) en :8000  — Ctrl+C para parar"
    info "escáner:  AI_AGENT_BACKEND=openai AI_AGENT_BASE_URL=http://127.0.0.1:8000/v1 \\"
    info "          AI_AGENT_MODEL=local-security-agent  ...  --enable-ai-triaging"
    exec "${PY[@]}" -m vllm.entrypoints.openai.api_server \
        --model "$RUNS_DIR/triage-qlora/merged" \
        --served-model-name local-security-agent \
        --port 8000
fi
