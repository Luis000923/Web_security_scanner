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
#    `uv run` on Windows reports a native path (C:\...\.venv\Scripts\python.exe),
#    so both sides are normalised before they are compared.
PY="$(uv run python -c 'import sys; print(sys.executable)' 2>/dev/null)"
VENV_NORM="$(norm_path "$ROOT/.venv")"
if [[ -z "$PY" ]]; then
    bad "could not resolve a uv-managed interpreter ('uv venv' / 'uv sync')"
elif [[ "$(norm_path "$PY")" == "$VENV_NORM"/* ]]; then
    ok "interpreter is the project venv: $PY"
else
    bad "interpreter is outside the project venv: $PY"
fi
if [[ -n "$VENV_PY" ]]; then
    ok "venv layout: ${VENV_BIN#$ROOT/} ($([[ "$IS_WINDOWS" -eq 1 ]] && echo Windows || echo Unix))"
else
    miss "no interpreter under ${VENV_BIN#$ROOT/} — run 'uv venv'"
fi
if [[ -n "${VIRTUAL_ENV:-}" && "$(norm_path "$VIRTUAL_ENV")" != "$VENV_NORM" ]]; then
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
