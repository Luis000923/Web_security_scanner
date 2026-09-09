#!/usr/bin/env bash
#
# run_eval.sh — golden-dataset evaluation harness for the DAST triage agent.
#
# Runs ai_module/evaluate_golden.py against a curated "golden" set of
# polyglot vulnerabilities and extreme false-positive scenarios, prints an
# FNR / TP-degradation / FP-recall report, and exports the full result to
# metrics/golden_eval_results.json.
#
# Usage:
#   ./run_eval.sh [options]
#
#   --dataset FILE         golden JSONL (default: data/golden_dataset.jsonl)
#                           schema: {"id","category","expected","finding"} per
#                           line — see data/golden_dataset.example.jsonl
#   --backend NAME         echo|openai|transformers
#                           (default: $AI_AGENT_BACKEND or 'openai' — see
#                           ai_module/agent_inference.py)
#   --base-url URL         OpenAI-compatible server (openai backend only)
#   --model NAME           model id / adapter path
#   --concurrency N         parallel in-flight requests   (default: 4)
#   --timeout SECS          per-row inference timeout      (default: 60)
#   --retries N              retries after a failed row     (default: 1)
#   --out FILE               JSON export path (default: metrics/golden_eval_results.json)
#   --skip-healthcheck       skip the pre-flight server healthcheck
#   --dump-rows              force per-row predictions into the JSON export
#   --quiet                  suppress the progress counter
#   -h, --help               this help
#
# Examples:
#   # smoke-test the harness wiring, no live server needed:
#   ./run_eval.sh --dataset data/golden_dataset.example.jsonl --backend echo
#
#   # evaluate the trained adapter behind a local vLLM / OpenAI-compatible server:
#   ./run_eval.sh --backend openai --base-url http://127.0.0.1:8000/v1 \
#                 --model runs/triage-qlora/adapter
#
set -Eeuo pipefail

if [[ -t 1 ]]; then
    RED=$'\033[31m'; GREEN=$'\033[32m'; CYAN=$'\033[36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    RED=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

die() {
    printf '\n%s%s✗ %s%s\n' "$BOLD" "$RED" "${1:-unknown error}" "$RESET" >&2
    exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

DATASET="data/golden_dataset.jsonl"
PY_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dataset)          DATASET="${2:?}"; shift 2 ;;
        --backend)          PY_ARGS+=(--backend "${2:?}"); shift 2 ;;
        --base-url)         PY_ARGS+=(--base-url "${2:?}"); shift 2 ;;
        --model)            PY_ARGS+=(--model "${2:?}"); shift 2 ;;
        --concurrency)      PY_ARGS+=(--concurrency "${2:?}"); shift 2 ;;
        --timeout)          PY_ARGS+=(--timeout "${2:?}"); shift 2 ;;
        --retries)          PY_ARGS+=(--retries "${2:?}"); shift 2 ;;
        --out)              PY_ARGS+=(--out "${2:?}"); shift 2 ;;
        --skip-healthcheck) PY_ARGS+=(--skip-healthcheck); shift ;;
        --dump-rows)        PY_ARGS+=(--dump-rows); shift ;;
        --quiet)            PY_ARGS+=(--quiet); shift ;;
        -h|--help)          sed -n '3,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)                  die "unknown option: $1  (try --help)" ;;
    esac
done

command -v uv >/dev/null 2>&1 || die "uv is not installed — https://docs.astral.sh/uv/"

if [[ ! -f "$DATASET" ]]; then
    die "golden dataset not found: ${DATASET}
    curate one (schema: {\"id\",\"category\",\"expected\",\"finding\"} per line)
    or start from data/golden_dataset.example.jsonl"
fi

printf '%s%sGolden-dataset evaluation%s  dataset=%s\n' "$BOLD" "$CYAN" "$RESET" "$DATASET"

set +e
uv run python -m ai_module.evaluate_golden --dataset "$DATASET" "${PY_ARGS[@]}"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
    printf '%s✓ evaluation complete%s\n' "$GREEN" "$RESET"
else
    printf '%s✗ evaluation reported problems (exit %d) — see output above%s\n' \
        "$RED" "$rc" "$RESET" >&2
fi
exit $rc
