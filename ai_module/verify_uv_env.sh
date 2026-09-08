#!/usr/bin/env bash
# Strict uv-environment check for the ai_module ML stack.
#
# Verifies that:
#   1. `uv` is installed and on PATH.
#   2. `uv.lock` exists and is in sync with `pyproject.toml` (`uv lock --check`).
#   3. the active interpreter is the project's uv-managed .venv (not system pip).
#   4. the critical GPU deps (torch, trl, peft, bitsandbytes) are installed in
#      that environment *and* pinned in uv.lock.
#
# Exit codes:
#   0  environment is uv-managed and the ML stack is complete
#   1  hard problem (no uv, stale/missing lock, wrong interpreter, unmanaged pkg)
#   3  environment is otherwise fine, but critical ML deps are only missing
#      (pinned in uv.lock, not installed) — an orchestrator may auto-install
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
LOCK="$ROOT/uv.lock"
CRITICAL=(torch trl peft bitsandbytes)
fail=0
deps_missing=0

say()  { printf '%s %s\n' "$1" "$2"; }
ok()   { say "  [ OK ]" "$1"; }
bad()  { say "  [FAIL]" "$1"; fail=1; }
miss() { say "  [MISS]" "$1"; deps_missing=1; }

echo "uv environment audit  ($ROOT)"

# 1. uv present
if command -v uv >/dev/null 2>&1; then
    ok "uv present: $(uv --version)"
else
    bad "uv not found on PATH — install from https://docs.astral.sh/uv/"
    exit 1
fi

# 2. lockfile present + in sync
if [[ -f "$LOCK" ]]; then
    ok "uv.lock present ($(wc -l <"$LOCK") lines)"
    if uv lock --check >/dev/null 2>&1; then
        ok "uv.lock is in sync with pyproject.toml"
    else
        bad "uv.lock is stale — run 'uv lock'"
    fi
else
    bad "uv.lock missing — run 'uv lock'"
fi

# 3. active interpreter is the uv-managed venv
PY="$(uv run python -c 'import sys; print(sys.executable)' 2>/dev/null)"
case "$PY" in
    "$ROOT"/.venv/*) ok "interpreter is the project venv: $PY" ;;
    "")              bad "could not resolve a uv-managed interpreter ('uv venv' / 'uv sync')" ;;
    *)               bad "interpreter is outside the project venv: $PY" ;;
esac
if [[ -n "${VIRTUAL_ENV:-}" && "$VIRTUAL_ENV" != "$ROOT/.venv" ]]; then
    bad "VIRTUAL_ENV points elsewhere: $VIRTUAL_ENV"
fi

# 4. critical deps: installed in the env AND pinned in the lockfile
for pkg in "${CRITICAL[@]}"; do
    inst="$(uv pip show "$pkg" 2>/dev/null | awk -F': ' '/^Version/{print $2}')"
    locked=no
    grep -qi "^name = \"$pkg\"$" "$LOCK" 2>/dev/null && locked=yes
    if [[ -n "$inst" && "$locked" == yes ]]; then
        ok "$pkg $inst  (installed, pinned in uv.lock)"
    elif [[ -z "$inst" && "$locked" == yes ]]; then
        miss "$pkg pinned in uv.lock but not installed — run 'uv pip install -e \".[ai]\"'"
    elif [[ -n "$inst" ]]; then
        bad "$pkg $inst installed but NOT in uv.lock — not managed by uv"
    else
        bad "$pkg missing entirely — run 'uv pip install -e \".[ai]\"'"
    fi
done

echo
if [[ "$fail" -ne 0 ]]; then
    echo "RESULT: issues found — see [FAIL] lines above."
    exit 1
elif [[ "$deps_missing" -ne 0 ]]; then
    echo "RESULT: environment OK, but critical ML deps are not installed (see [MISS])."
    exit 3
else
    echo "RESULT: environment is uv-managed and the ML stack is complete."
    exit 0
fi
