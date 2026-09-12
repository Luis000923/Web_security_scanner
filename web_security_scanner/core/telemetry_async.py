"""Granular request telemetry for empirical evaluation (Phase 1).

The scanner is asyncio-single-threaded. Blocking it on a synchronous
``open(..., "a")`` for every probe would serialise the whole scan, so this
module decouples *producing* a telemetry row (cheap, non-blocking) from
*persisting* it (disk I/O, delegated to a worker thread):

    producer (any tester)                consumer (one background task)
    -------------------------            ------------------------------
    worker.record({...})   --enqueue-->  asyncio.Queue  --batch-->  asyncio.to_thread(append JSONL)

``record`` never awaits and never raises into the caller. If the queue is full
(disk slower than the scan can generate rows) the row is dropped and counted in
``dropped`` rather than applying backpressure to the HTTP path.

Only the Python standard library is used — no ``aiofiles``/third-party deps.

JSONL row schema (one row per payload probe, written after the tester's
confirmation heuristics have run):

    run_id, timestamp, tester_id, payload_id, context, confidence_apriori,
    url, method, param, vector, elapsed_time, decision, confidence_final,
    request_index

``vector`` is one of getparam / formparam / jsonparam / header / cookie — the
transport the payload was injected through (Phase 1 multi-vector support).
``method`` is the HTTP verb actually used (POST for the body vectors, GET
otherwise). ``param`` is the mutated field name: a query/form key, a header or
cookie name, or — for ``jsonparam`` — the dotted path to the JSON leaf that was
overwritten (e.g. ``account.roles.0``). The row schema itself is unchanged, so
existing JSONL consumers keep working across the multi-vector extension.

``request_index`` is a 1-based counter over every probe recorded in the run
(the "request number within the budget"). ``timestamp`` is ISO-8601 UTC.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)

# Sentinel pushed by ``stop()`` to tell the consumer to drain and exit.
_SHUTDOWN = object()

# Mandatory keys, in canonical order, so every row serialises consistently.
_ROW_ORDER = (
    "run_id", "timestamp", "request_index", "tester_id", "payload_id",
    "context", "confidence_apriori", "url", "method", "param", "vector",
    "elapsed_time", "decision", "confidence_final",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class TelemetryWorker:
    """Async producer/consumer JSONL telemetry sink.

    Lifecycle::

        worker = TelemetryWorker("reports/telemetry/run.jsonl")
        await worker.start()            # inside the running event loop
        ...
        worker.record({...})           # from any coroutine, fire-and-forget
        ...
        await worker.stop()            # flushes the queue, awaits the writer
    """

    def __init__(
        self,
        path: str | Path,
        *,
        run_id: str | None = None,
        queue_maxsize: int = 20_000,
        batch_size: int = 128,
    ) -> None:
        self.run_id: str = run_id or uuid.uuid4().hex
        self.path: Path = Path(path)
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=max(1, queue_maxsize))
        self._batch_size = max(1, batch_size)
        self._worker_task: asyncio.Task[None] | None = None
        self._started = False
        self._stopped = False
        # Instrumentation counters (surfaced in the scan results dict).
        self.request_index = 0        # rows accepted into the queue
        self.written = 0              # rows actually flushed to disk
        self.dropped = 0              # rows lost to a full queue

    # ---- lifecycle ---------------------------------------------------

    async def start(self) -> None:
        """Create the output file's parent dir and spawn the consumer task."""
        if self._started:
            return
        self._started = True
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._worker_task = asyncio.create_task(
            self._worker_loop(), name="telemetry-worker"
        )

    async def stop(self) -> None:
        """Signal shutdown, wait for the queue to drain and the writer to exit.

        Idempotent. Safe to call even if ``start`` was never reached.
        """
        if self._stopped:
            return
        self._stopped = True
        if not self._started or self._worker_task is None:
            return
        try:
            await self._queue.put(_SHUTDOWN)
        except Exception:  # pragma: no cover - queue never closed here
            self._worker_task.cancel()
        try:
            await self._worker_task
        except asyncio.CancelledError:  # pragma: no cover - defensive
            pass
        except Exception as exc:  # pragma: no cover - defensive
            _LOG.warning("Telemetry writer exited with error: %s", exc)

    # ---- producer --------------------------------------------------

    def record(self, fields: dict[str, Any]) -> None:
        """Enqueue one telemetry row. Non-blocking, never raises.

        ``run_id``, ``request_index`` and ``timestamp`` are stamped here so
        callers only supply the probe-specific fields.
        """
        if self._stopped:
            return
        self.request_index += 1
        row = {
            "run_id": self.run_id,
            "timestamp": _now_iso(),
            "request_index": self.request_index,
            **fields,
        }
        try:
            self._queue.put_nowait(row)
        except asyncio.QueueFull:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 500 == 0:
                _LOG.warning(
                    "Telemetry queue full; %d row(s) dropped so far", self.dropped
                )

    # ---- consumer -------------------------------------------------

    async def _worker_loop(self) -> None:
        """Batch rows off the queue and persist them off the event loop."""
        batch: list[dict[str, Any]] = []
        while True:
            item = await self._queue.get()
            if item is _SHUTDOWN:
                await self._drain_remaining(batch)
                return
            batch.append(item)
            # Opportunistically coalesce whatever else is already queued.
            while len(batch) < self._batch_size:
                try:
                    nxt = self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if nxt is _SHUTDOWN:
                    await self._flush(batch)
                    return
                batch.append(nxt)
            await self._flush(batch)
            batch = []

    async def _drain_remaining(self, batch: list[dict[str, Any]]) -> None:
        """Flush the in-hand batch plus every row still queued, then stop."""
        while True:
            try:
                nxt = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if nxt is _SHUTDOWN:
                continue
            batch.append(nxt)
        await self._flush(batch)

    async def _flush(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        text = "".join(self._serialise(r) for r in rows)
        try:
            await asyncio.to_thread(self._append_text, text)
            self.written += len(rows)
        except Exception as exc:  # pragma: no cover - disk failure
            _LOG.warning("Failed to write %d telemetry row(s): %s", len(rows), exc)

    @staticmethod
    def _serialise(row: dict[str, Any]) -> str:
        ordered = {k: row[k] for k in _ROW_ORDER if k in row}
        ordered.update({k: v for k, v in row.items() if k not in ordered})
        return json.dumps(ordered, ensure_ascii=False, default=str) + "\n"

    def _append_text(self, text: str) -> None:
        # Runs in a worker thread; plain buffered append.
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(text)

    # ---- introspection ------------------------------------------

    def summary(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "path": str(self.path),
            "rows": self.request_index,
            "written": self.written,
            "dropped": self.dropped,
        }
