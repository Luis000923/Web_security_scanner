#!/usr/bin/env python3
"""Claude Code hook: keep ``.context/`` fresh, incrementally, without blocking.

Wired as a ``Stop`` hook in ``.claude/settings.json`` (once per agent turn):
it compares every tracked ``.py`` against the sha256 stored in
``.context/symbols.json`` and re-indexes **only the files that changed**
(full rebuild only when no usable index exists). A per-edit ``PostToolUse``
was measured at ~205 ms per call, above the 150 ms budget, so the work is
batched at the end of the turn instead.

A payload carrying ``tool_input.file_path`` (``PostToolUse`` shape) is still
accepted and re-indexes just that file. Every failure goes to stderr and the
exit code is always 0. Manual use::

    echo '{}' | python3 tools/context_hook.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# Cache the packer's bytecode even when the session exports
# PYTHONDONTWRITEBYTECODE (the module is ~1.5k lines).
sys.dont_write_bytecode = False

from tools import context_packer as cp  # noqa: E402


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0
    if not isinstance(payload, dict):
        return 0
    tool_input = payload.get("tool_input")
    edited = ""
    if isinstance(tool_input, dict):
        edited = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        if not edited.endswith(".py"):
            return 0  # PostToolUse on a non-Python file: nothing to do
    try:
        root = cp.find_repo_root(Path(str(payload.get("cwd") or ".")).resolve())
        counter = cp.TokenCounter("auto")
        if edited:
            cp.safe_resolve(root, edited)  # outside the repo or excluded: ignore
            cp.run_l0_incremental(root, counter, [edited])
        else:
            cp.run_l0_sync(root, counter)
    except cp.PackerError as exc:
        print(f"context hook skipped: {exc}", file=sys.stderr)
    except Exception as exc:  # never break the user's session
        print(f"context hook error: {type(exc).__name__}: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
