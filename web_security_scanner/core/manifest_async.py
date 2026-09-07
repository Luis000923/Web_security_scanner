"""Reproducibility manifest generator (Phase 3).

Every empirical run should be replayable from a single artifact that pins the
*exact* context it executed in: which code, which payload corpus, which RNG
seed and which CLI-derived configuration. This module builds that artifact and
persists it as ``manifest_<run_id>.json`` alongside the telemetry JSONL, right
at the start of the scan lifecycle (before any probe is fired).

The four pillars recorded are:

* **corpus_sha256** — SHA-256 over the concatenated payload corpus
  (``PAYLOAD/data/*.json``), so a changed signature set is detectable.
* **global_seed** — the integer passed to ``--global-seed`` (or ``null``).
* **config** — the full CLI-derived configuration dict driving the scan.
* **git_commit** — ``git rev-parse HEAD`` (or ``"unknown"`` off a repo / with
  no ``git`` on PATH), so the code version is unambiguous.

Only the Python standard library is used. Hashing and disk I/O are CPU/IO-bound
and would stall the event loop, so :func:`write_manifest` offloads them to a
worker thread via ``asyncio.to_thread``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .payload_loader import PAYLOAD_DATA_DIR

_LOG = logging.getLogger(__name__)

# Manifest schema version — bump if the top-level shape changes so downstream
# tooling (the Phase 4 oracle) can branch on it.
MANIFEST_VERSION = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_corpus_hash(data_dir: str | Path | None = None) -> tuple[str, list[str]]:
    """SHA-256 of the payload corpus plus the list of files that fed it.

    The digest is computed over every ``*.json`` file in ``data_dir`` read in
    sorted (deterministic) order, with each file's path name mixed in so a
    rename is not silently invisible. Returns ``(hex_digest, filenames)``. If
    the directory is missing or empty the digest is that of the empty stream
    and ``filenames`` is empty — never raises.
    """
    root = Path(data_dir) if data_dir is not None else PAYLOAD_DATA_DIR
    digest = hashlib.sha256()
    included: list[str] = []
    try:
        files = sorted(root.glob("*.json"))
    except OSError as exc:  # pragma: no cover - unusual FS error
        _LOG.warning("Could not enumerate payload corpus at %s: %s", root, exc)
        files = []
    for path in files:
        try:
            data = path.read_bytes()
        except OSError as exc:  # pragma: no cover - unreadable file
            _LOG.warning("Skipping unreadable corpus file %s: %s", path, exc)
            continue
        # Mix the filename in so structurally identical files in different
        # categories can't collide into the same digest.
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        included.append(path.name)
    return digest.hexdigest(), included


def git_commit() -> str:
    """Return the current ``git`` HEAD commit hash, or ``"unknown"``.

    Never raises: a missing ``git`` binary (``FileNotFoundError``), running
    outside a repository, or any other git error all collapse to ``"unknown"``
    so manifest generation cannot interrupt the scan.
    """
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return "unknown"
    if proc.returncode != 0:
        return "unknown"
    return proc.stdout.strip() or "unknown"


def build_manifest(
    *,
    run_id: str,
    config: dict[str, Any],
    global_seed: int | None,
    corpus_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Assemble the reproducibility metadata dict for one run.

    Pure/synchronous: does the hashing and the git lookup inline. Callers on the
    event loop should prefer :func:`write_manifest`, which offloads this.
    """
    corpus_sha256, corpus_files = compute_corpus_hash(corpus_dir)
    return {
        "manifest_version": MANIFEST_VERSION,
        "run_id": run_id,
        "created_at": _now_iso(),
        "git_commit": git_commit(),
        "global_seed": global_seed,
        "corpus": {
            "sha256": corpus_sha256,
            "files": corpus_files,
            "num_files": len(corpus_files),
        },
        "config": config,
    }


def _write_manifest_sync(directory: Path, manifest: dict[str, Any]) -> Path:
    """Serialise ``manifest`` to ``<directory>/manifest_<run_id>.json``."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"manifest_{manifest['run_id']}.json"
    text = json.dumps(manifest, ensure_ascii=False, indent=2, default=str)
    path.write_text(text + "\n", encoding="utf-8")
    return path


async def write_manifest(
    directory: str | Path,
    *,
    run_id: str,
    config: dict[str, Any],
    global_seed: int | None,
    corpus_dir: str | Path | None = None,
) -> Path:
    """Build and persist the manifest off the event loop; return its path.

    Hashing the corpus and shelling out to git are blocking, so the whole
    build+write runs in a worker thread. Raised by neither a hashing nor a git
    failure (both degrade gracefully); only a genuine disk error propagates,
    and the caller is expected to log-and-continue.
    """
    directory = Path(directory)

    def _job() -> Path:
        manifest = build_manifest(
            run_id=run_id,
            config=config,
            global_seed=global_seed,
            corpus_dir=corpus_dir,
        )
        return _write_manifest_sync(directory, manifest)

    return await asyncio.to_thread(_job)
