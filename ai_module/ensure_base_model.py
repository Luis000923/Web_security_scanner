#!/usr/bin/env python3
"""Ensure a Hugging Face base model is present in the local cache.

Used by ``run_pipeline.sh`` before the smoke test / fine-tune so the (multi-GB)
weights are fetched up front with a visible progress bar instead of stalling —
or timing out — inside the trainer.

    uv run python -m ai_module.ensure_base_model unsloth/Qwen2.5-7B-Instruct-bnb-4bit

Exit codes:
    0  model is available locally (already cached or downloaded now)
    1  download failed / dependency missing
    2  bad usage
"""
from __future__ import annotations

import argparse
import sys


def _human(n: int) -> str:
    f = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if f < 1024 or unit == "TiB":
            return f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} TiB"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("model", help="HF repo id, e.g. unsloth/Qwen2.5-7B-Instruct-bnb-4bit")
    ap.add_argument("--revision", default=None, help="branch / tag / commit (default: main)")
    ap.add_argument(
        "--check-only",
        action="store_true",
        help="report cache status without downloading; exit 1 if not cached",
    )
    args = ap.parse_args(argv)

    try:
        from huggingface_hub import snapshot_download
        from huggingface_hub.errors import GatedRepoError, RepositoryNotFoundError
        from huggingface_hub.utils import scan_cache_dir
    except ImportError:
        print(
            "ensure_base_model: huggingface_hub is not installed — run "
            "'uv pip install -e \".[ai]\"' first",
            file=sys.stderr,
        )
        return 1

    def _cached_size() -> int | None:
        try:
            for repo in scan_cache_dir().repos:
                if repo.repo_id == args.model and repo.repo_type == "model":
                    return repo.size_on_disk
        except Exception:  # noqa: BLE001 - cache scan is best-effort
            pass
        return None

    if args.check_only:
        size = _cached_size()
        if size is None:
            print(f"ensure_base_model: '{args.model}' is NOT in the local cache", file=sys.stderr)
            return 1
        print(f"ensure_base_model: '{args.model}' present in cache ({_human(size)})")
        return 0

    # Not check-only: always let snapshot_download reconcile the cache. It is a
    # cheap no-op when every file is already present and resumes a partial pull,
    # so a half-downloaded repo (e.g. an interrupted earlier run) is completed
    # rather than mistaken for a full cache hit.
    size = _cached_size()
    if size is not None:
        print(f"ensure_base_model: '{args.model}' partially/fully cached ({_human(size)}) — verifying …")
    print(f"ensure_base_model: fetching '{args.model}' into the HF cache …")
    try:
        path = snapshot_download(
            repo_id=args.model,
            revision=args.revision,
            repo_type="model",
        )
    except (RepositoryNotFoundError, GatedRepoError) as exc:
        print(
            f"ensure_base_model: cannot access '{args.model}': {exc}\n"
            "  - check the repo id\n"
            "  - if it is gated, run 'uv run huggingface-cli login' first",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:  # noqa: BLE001 - surface any network/hub failure
        print(f"ensure_base_model: download failed: {exc!r}", file=sys.stderr)
        return 1

    print(f"ensure_base_model: '{args.model}' ready at {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
