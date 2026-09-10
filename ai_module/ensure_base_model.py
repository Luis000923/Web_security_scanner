#!/usr/bin/env python3
"""Ensure a Hugging Face base model is present in the local cache.

Used by ``run_pipeline.sh`` before the smoke test / fine-tune so the (multi-GB)
weights are fetched up front with a visible progress bar instead of stalling —
or timing out — inside the trainer.

    uv run python -m ai_module.ensure_base_model unsloth/Qwen2.5-7B-Instruct-bnb-4bit

Fault tolerance
---------------
Flaky transfers (network drops, Xet / CAS reconstruction errors such as
``CAS Client Error: Request middleware error``, socket timeouts) are retried
with exponential backoff. Before each retry the partial / corrupt artefacts for
this repo are purged from the cache (``*.incomplete`` blobs, stale locks, and —
on the last attempt — the whole repo folder plus the Xet chunk cache), and the
Xet accelerator is disabled so the retry falls back to plain HTTPS range
downloads.

Exit codes:
    0  model is available locally (already cached or downloaded now)
    1  download failed after all retries / dependency missing / repo inaccessible
    2  bad usage
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time

# Retriable failure signatures — matched against the exception type name and
# its stringified message (case-insensitive).
_RETRIABLE_MARKERS = (
    "cas client error",
    "request middleware error",
    "middleware",
    "reqwest",
    "xet",
    "timeout",
    "timed out",
    "connection",
    "connectionerror",
    "connectionreset",
    "incompleteread",
    "chunkedencodingerror",
    "protocolerror",
    "readerror",
    "temporary failure",
    "503",
    "502",
    "504",
    "429",
    "eof occurred",
    "broken pipe",
    "runtimeerror",  # hf_xet surfaces reconstruction faults as bare RuntimeError
)


def _human(n: int) -> str:
    f = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if f < 1024 or unit == "TiB":
            return f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} TiB"


def _is_retriable(exc: BaseException) -> bool:
    blob = f"{type(exc).__name__} {exc}".lower()
    return any(m in blob for m in _RETRIABLE_MARKERS)


def _repo_folder(cache_dir: str, repo_id: str) -> str:
    return os.path.join(cache_dir, "models--" + repo_id.replace("/", "--"))


def _purge_partial(cache_dir: str, repo_id: str, *, aggressive: bool) -> None:
    """Remove partial/corrupt artefacts for ``repo_id`` from the HF cache."""
    repo_dir = _repo_folder(cache_dir, repo_id)
    if not os.path.isdir(repo_dir):
        return

    if aggressive:
        print(f"  cleanup: removing the whole repo cache folder {repo_dir}")
        shutil.rmtree(repo_dir, ignore_errors=True)
        return

    removed = 0
    blobs = os.path.join(repo_dir, "blobs")
    if os.path.isdir(blobs):
        for name in os.listdir(blobs):
            if name.endswith(".incomplete") or name.endswith(".lock"):
                try:
                    os.remove(os.path.join(blobs, name))
                    removed += 1
                except OSError:
                    pass
    # stale cross-process download locks
    locks = os.path.join(cache_dir, ".locks", "models--" + repo_id.replace("/", "--"))
    if os.path.isdir(locks):
        shutil.rmtree(locks, ignore_errors=True)
        removed += 1
    print(f"  cleanup: purged {removed} partial/lock artefact(s) under {repo_dir}")


def _purge_xet_cache() -> None:
    xet_cache = os.environ.get("HF_XET_CACHE") or os.path.join(
        os.path.expanduser("~"), ".cache", "huggingface", "xet"
    )
    if os.path.isdir(xet_cache):
        print(f"  cleanup: clearing Xet chunk cache {xet_cache}")
        shutil.rmtree(xet_cache, ignore_errors=True)


def _disable_xet() -> None:
    """Force plain-HTTPS transfers for the rest of this process."""
    os.environ["HF_HUB_DISABLE_XET"] = "1"
    os.environ["HF_XET_HIGH_PERFORMANCE"] = "0"
    try:
        from huggingface_hub import constants as _c

        _c.HF_HUB_DISABLE_XET = True  # consumed by file_download at call time
    except Exception:  # noqa: BLE001
        pass


def _cached_size(scan_cache_dir, repo_id: str) -> int | None:
    try:
        for repo in scan_cache_dir().repos:
            if repo.repo_id == repo_id and repo.repo_type == "model":
                return repo.size_on_disk
    except Exception:  # noqa: BLE001 - cache scan is best-effort
        pass
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("model", help="HF repo id, e.g. unsloth/Qwen2.5-7B-Instruct-bnb-4bit")
    ap.add_argument("--revision", default=None, help="branch / tag / commit (default: main)")
    ap.add_argument(
        "--check-only",
        action="store_true",
        help="report cache status without downloading; exit 1 if not cached",
    )
    ap.add_argument(
        "--retries",
        type=int,
        default=3,
        metavar="N",
        help="download attempts before giving up (default: 3)",
    )
    ap.add_argument(
        "--no-xet",
        action="store_true",
        help="disable the Xet accelerator from the first attempt (plain HTTPS)",
    )
    args = ap.parse_args(argv)

    # keep progress / retry chatter in order when stdout is a pipe (run_pipeline.sh)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass

    if args.retries < 1:
        print("ensure_base_model: --retries must be >= 1", file=sys.stderr)
        return 2

    if args.no_xet:
        _disable_xet()

    try:
        from huggingface_hub import constants as hf_constants
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

    cache_dir = hf_constants.HF_HUB_CACHE

    if args.check_only:
        size = _cached_size(scan_cache_dir, args.model)
        if size is None:
            print(f"ensure_base_model: '{args.model}' is NOT in the local cache", file=sys.stderr)
            return 1
        print(f"ensure_base_model: '{args.model}' present in cache ({_human(size)})")
        return 0

    size = _cached_size(scan_cache_dir, args.model)
    if size is not None:
        print(
            f"ensure_base_model: '{args.model}' partially/fully cached "
            f"({_human(size)}) — verifying / completing …"
        )

    attempts = args.retries
    for attempt in range(1, attempts + 1):
        xet_state = "off" if hf_constants.HF_HUB_DISABLE_XET else "on"
        print(
            f"ensure_base_model: fetching '{args.model}' "
            f"(attempt {attempt}/{attempts}, xet={xet_state}) …"
        )
        try:
            path = snapshot_download(
                repo_id=args.model,
                revision=args.revision,
                repo_type="model",
            )
            print(f"ensure_base_model: '{args.model}' ready at {path}")
            return 0
        except (RepositoryNotFoundError, GatedRepoError) as exc:
            print(
                f"ensure_base_model: cannot access '{args.model}': {exc}\n"
                "  - check the repo id\n"
                "  - if it is gated, run 'uv run huggingface-cli login' first",
                file=sys.stderr,
            )
            return 1
        except KeyboardInterrupt:
            print("\nensure_base_model: interrupted", file=sys.stderr)
            return 1
        except BaseException as exc:  # noqa: BLE001 - want the retry path for anything transient
            retriable = _is_retriable(exc)
            print(
                f"ensure_base_model: attempt {attempt} failed "
                f"({type(exc).__name__}: {exc})",
                file=sys.stderr,
            )
            if attempt >= attempts or not retriable:
                if not retriable:
                    print(
                        "ensure_base_model: error does not look transient — not retrying",
                        file=sys.stderr,
                    )
                else:
                    print("ensure_base_model: retries exhausted", file=sys.stderr)
                print(
                    "ensure_base_model: leaving the cache purged; re-run the pipeline "
                    "to try again, or pre-fetch manually with HF_HUB_DISABLE_XET=1",
                    file=sys.stderr,
                )
                _purge_partial(cache_dir, args.model, aggressive=True)
                return 1

            # transient: disable Xet, clean up, back off, retry
            last_try = attempt == attempts - 1
            print(
                f"  → transient failure; disabling Xet and cleaning the cache "
                f"before retry {attempt + 1}"
            )
            _disable_xet()
            _purge_partial(cache_dir, args.model, aggressive=last_try)
            if "xet" in f"{type(exc).__name__} {exc}".lower() or last_try:
                _purge_xet_cache()
            backoff = 2 ** attempt
            print(f"  → waiting {backoff}s (exponential backoff) …")
            time.sleep(backoff)

    return 1  # unreachable, keeps type-checkers happy


if __name__ == "__main__":
    raise SystemExit(main())
