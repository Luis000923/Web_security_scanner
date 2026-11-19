#!/usr/bin/env bash
# Revision pipeline for the ICMLANT reviewer response (2026-11).
# Sequential on purpose: one client against the target at a time, so wall-clock
# and latency figures are not contaminated by concurrent scans.
set -u
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD"
PY=/home/luis/Documentos/Web_security_scanner/.venv/bin/python
MODEL=/home/luis/Documentos/Web_security_scanner/runs/triage-redteam-qlora/merged
SEED="--global-seed 42"
LOG=testbed/revision_pipeline.log
ts() { date -u +%FT%TZ; }
say() { echo "[$(ts)] $*" | tee -a "$LOG"; }

say "wait for any running sweep to finish"
while pgrep -f "tools/run_experiments.py" >/dev/null; do sleep 30; done

say "PHASE 1 grid (20 runs)"
$PY tools/run_experiments.py --skip-precondition --no-progress \
    --results-dir testbed/results --csv testbed/experiment_results_rev.csv \
    --extra-args "$SEED" >>"$LOG" 2>&1 || say "PHASE 1 exit=$?"

say "PHASE 2 replicate B10,B20 (10 runs)"
$PY tools/run_experiments.py --skip-precondition --no-progress \
    --budgets 10,20 --results-dir testbed/results_rep \
    --csv testbed/experiment_results_rep.csv \
    --extra-args "$SEED" >>"$LOG" 2>&1 || say "PHASE 2 exit=$?"

say "PHASE 3a ai-triage sanity check (6 targets)"
TINY=testbed/results_smoke/tiny
$PY tools/run_experiments.py --skip-precondition --no-progress --force \
    --budgets 10 --conditions ai-triage --target-list $TINY/targets.json \
    --results-dir $TINY --csv $TINY/tiny.csv \
    --extra-args "$SEED --ai-backend transformers --ai-model $MODEL --ai-temperature 0" \
    >>"$LOG" 2>&1
if ! $PY - "$TINY" >>"$LOG" 2>&1 <<'EOF'
import json, sys, glob
reps = [p for p in glob.glob(sys.argv[1] + "/budget10_aitriage/report/scan_*.json") if "enriched" not in p]
b = json.load(open(sorted(reps)[-1])).get("ai_triage") if reps else None
print("[sanity] ai_triage block:", None if b is None else {k: v for k, v in b.items() if k != "decisions"})
print("[sanity] first decisions:", (b or {}).get("decisions", [])[:3])
ok = bool(b and b.get("enabled") and b.get("total_candidates_triaged", 0) > 0)
sys.exit(0 if ok else 1)
EOF
then
    say "PHASE 3a FAILED: no usable ai_triage block; skipping PHASE 3"
    SKIP_AI=1
fi

say "PHASE 3 ai-triage (4 runs)"
[ -n "${SKIP_AI:-}" ] || $PY tools/run_experiments.py --skip-precondition --no-progress \
    --conditions ai-triage --scan-timeout 21600 \
    --results-dir testbed/results --csv testbed/experiment_results_rev.csv \
    --extra-args "$SEED --ai-backend transformers --ai-model $MODEL --ai-temperature 0" \
    >>"$LOG" 2>&1 || say "PHASE 3 exit=$?"

say "PHASE 4 ZAP 2.17.0"
docker rm -f zap_baseline >/dev/null 2>&1
docker run -d --name zap_baseline --network host zaproxy/zap-stable:2.17.0 \
    zap.sh -daemon -host 127.0.0.1 -port 8090 -config api.disablekey=true >>"$LOG" 2>&1
$PY tools/run_zap_baseline.py --zap-url http://127.0.0.1:8090 \
    --out testbed/results/zap_baseline >>"$LOG" 2>&1 || say "PHASE 4 exit=$?"
docker rm -f zap_baseline >/dev/null 2>&1

say "PHASE 5 reanalysis"
$PY tools/reanalysis.py --results testbed/results --replicate testbed/results_rep \
    --zap testbed/results/zap_baseline --out testbed/reanalysis >>"$LOG" 2>&1 \
    || say "PHASE 5 exit=$?"

say "PHASE 6 archive"
ART=/home/luis/Documentos/wss-paper-artifacts
mkdir -p "$ART"
tar -czf "$ART/revision_runs_$(date -u +%Y%m%d).tar.gz" testbed/results testbed/results_rep \
    testbed/reanalysis testbed/experiment_results_rev.csv testbed/experiment_results_rep.csv \
    testbed/revision_pipeline.log >>"$LOG" 2>&1
sha256sum "$ART"/revision_runs_*.tar.gz | tee -a "$LOG"
say "PIPELINE DONE"
