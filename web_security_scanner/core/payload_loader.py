"""Async, typed, cached payload loader for the vulnerability testers.

The historical approach opened one flat JSON file per tester on every
instantiation and returned a bare ``list[str]`` with no context, confidence or
severity metadata. This module replaces that with:

* a single curated, schema-validated signature file
  (``PAYLOAD/payloads_v5.json`` + ``PAYLOAD/schema.json``),
* an immutable in-memory cache shared process-wide (parsed exactly once),
* strict typing via a frozen :class:`Payload` dataclass, and
* an async access API (:meth:`PayloadLoader.get_payloads`) that performs the
  one-time file read in a worker thread so the event loop never blocks.

Filtering is available by injection ``context``, a-priori ``confidence`` floor,
``waf_bypass`` flag, ``engine`` and ``max_intrusion`` ceiling; destructive
vectors are withheld unless explicitly requested.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "PAYLOAD"
PAYLOAD_FILE = PAYLOAD_DIR / "payloads_v5.json"

# Weakest -> strongest. Mirrors base_tester_async.CONFIDENCE_LEVELS.
CONFIDENCE_LEVELS: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CONFIRMED")
_CONFIDENCE_RANK: dict[str, int] = {name: idx for idx, name in enumerate(CONFIDENCE_LEVELS)}

# Canonical severity labels (Title-case). Any casing is accepted on input and
# normalized to one of these; unknown values fall back to ``Medium``.
SEVERITY_LEVELS: tuple[str, ...] = ("Info", "Low", "Medium", "High", "Critical")
_SEVERITY_CANON: dict[str, str] = {s.upper(): s for s in SEVERITY_LEVELS}

# How intrusive a vector is. ``safe`` = pure detection probe, ``high`` = would
# execute code / read files / mutate nothing but is loud. Weakest -> strongest.
INTRUSION_LEVELS: tuple[str, ...] = ("safe", "low", "medium", "high")
_INTRUSION_RANK: dict[str, int] = {name: idx for idx, name in enumerate(INTRUSION_LEVELS)}

# Shared deterministic canary token. A payload flagged ``"canary": true`` in the
# JSON embeds this exact string, so a tester can confirm reflection/execution
# without guessing.
WSS_CANARY = "WSSc4n4ry7788"

_TIME_MARKERS: tuple[str, ...] = (
    "sleep", "waitfor", "delay", "pg_sleep", "benchmark",
    "ping -c", "ping -n", "timeout /t",
)
_DESTRUCTIVE_MARKERS: tuple[str, ...] = (
    "drop table", "drop database", "delete from", "truncate", "insert into",
    "update ", "shutdown", "rm -rf", "mkfs", "; rm ", "| rm ", "format ",
)


@dataclass(frozen=True, slots=True)
class Payload:
    """A single injection signature with its classification metadata.

    The first nine fields are the historical v5.0 shape; everything after
    ``tags`` is the v5.1 extended schema (all optional, safe defaults) so
    positional construction of the legacy shape keeps working.
    """

    vector: str
    category: str
    context: str = "generic"
    canary: str | None = None
    confidence: str = "LOW"
    severity: str = "Medium"
    time_based: bool = False
    destructive: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)
    # ---- v5.1 extended schema ----------------------------------------
    id: str = ""
    description: str = ""
    cwe: str = ""
    owasp: str = ""
    min_intrusion_level: str = "safe"
    waf_bypass: bool = False
    oob: bool = False
    engines: tuple[str, ...] = field(default_factory=tuple)
    expected_evidence: tuple[str, ...] = field(default_factory=tuple)
    references: tuple[str, ...] = field(default_factory=tuple)


def _normalize_confidence(value: Any) -> str:
    upper = str(value).strip().upper()
    return upper if upper in CONFIDENCE_LEVELS else "LOW"


def _normalize_severity(value: Any) -> str:
    return _SEVERITY_CANON.get(str(value).strip().upper(), "Medium")


def _normalize_intrusion(value: Any) -> str:
    lowered = str(value).strip().lower()
    return lowered if lowered in INTRUSION_LEVELS else "safe"


class PayloadLoader:
    """Loads and caches curated payload signatures.

    Instances are cheap; :func:`get_payload_loader` returns a process-wide
    singleton so the parsed cache is shared. The cache is plain immutable data
    (tuples of frozen dataclasses) with no event-loop affinity, so it is safe
    to reuse across differing asyncio loops (e.g. pytest test cases).
    """

    def __init__(self, source: Path | None = None) -> None:
        self._source = source or PAYLOAD_FILE
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[Payload, ...]] | None = None

    # ---- parsing -------------------------------------------------------

    @staticmethod
    def _parse_entry(category: str, entry: Any) -> Payload | None:
        if isinstance(entry, str):
            vector, data = entry, {}
        elif isinstance(entry, dict) and isinstance(entry.get("vector"), str):
            vector, data = entry["vector"], entry
        else:
            return None
        if not vector:
            return None

        lowered = vector.lower()
        canary_flag = data.get("canary")
        if canary_flag is True:
            canary: str | None = WSS_CANARY
        elif isinstance(canary_flag, str) and canary_flag:
            canary = canary_flag
        else:
            canary = None

        tags = tuple(str(t) for t in data.get("tags", []) if isinstance(t, str))
        engines = tuple(str(e).lower() for e in data.get("engines", []) if isinstance(e, str))
        evidence = tuple(str(e) for e in data.get("expected_evidence", []) if isinstance(e, str))
        references = tuple(str(r) for r in data.get("references", []) if isinstance(r, str))
        time_based = bool(data.get("time_based")) or any(m in lowered for m in _TIME_MARKERS)
        destructive = bool(data.get("destructive")) or any(
            m in lowered for m in _DESTRUCTIVE_MARKERS
        )
        entry_id = str(data.get("id") or "").strip()
        if not entry_id:
            digest = hashlib.sha1(f"{category}\0{vector}".encode()).hexdigest()[:10]
            entry_id = f"{category}.auto.{digest}"
        return Payload(
            vector=vector,
            category=category,
            context=str(data.get("context", "generic")),
            canary=canary,
            confidence=_normalize_confidence(data.get("confidence", "LOW")),
            severity=_normalize_severity(data.get("severity", "Medium")),
            time_based=time_based,
            destructive=destructive,
            tags=tags,
            id=entry_id,
            description=str(data.get("description", "")),
            cwe=str(data.get("cwe", "")),
            owasp=str(data.get("owasp", "")),
            min_intrusion_level=_normalize_intrusion(data.get("min_intrusion_level", "safe")),
            waf_bypass=bool(data.get("waf_bypass")),
            oob=bool(data.get("oob")),
            engines=engines,
            expected_evidence=evidence,
            references=references,
        )

    def _read_source(self) -> dict[str, tuple[Payload, ...]]:
        raw: Any = {}
        try:
            with open(self._source, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            raw = {}
        categories = raw.get("categories", {}) if isinstance(raw, dict) else {}

        result: dict[str, tuple[Payload, ...]] = {}
        for category, entries in categories.items():
            if not isinstance(entries, list):
                continue
            bucket: list[Payload] = []
            seen: set[str] = set()
            for entry in entries:
                payload = self._parse_entry(str(category), entry)
                if payload is None or payload.vector in seen:
                    continue
                seen.add(payload.vector)
                bucket.append(payload)
            result[str(category)] = tuple(bucket)
        return result

    def _ensure_loaded(self) -> dict[str, tuple[Payload, ...]]:
        if self._cache is None:
            with self._lock:
                if self._cache is None:
                    self._cache = self._read_source()
        return self._cache

    # ---- public API ---------------------------------------------------

    async def _load(self) -> dict[str, tuple[Payload, ...]]:
        if self._cache is None:
            return await asyncio.to_thread(self._ensure_loaded)
        return self._cache

    async def get_payloads(
        self,
        vulnerability_type: str,
        *,
        context: str | None = None,
        include_destructive: bool = False,
        min_confidence: str | None = None,
        waf_bypass: bool | None = None,
        engine: str | None = None,
        max_intrusion: str | None = None,
    ) -> tuple[Payload, ...]:
        """Return the cached payloads for ``vulnerability_type``.

        ``context`` restricts to a single injection context (e.g.
        ``"time_based_blind"``). ``min_confidence`` drops signatures whose
        a-priori confidence is below the given level. Destructive vectors are
        excluded unless ``include_destructive`` is true.

        ``waf_bypass`` (when not ``None``) keeps only entries whose
        ``waf_bypass`` flag matches. ``engine`` keeps entries that either
        declare no engine or list the given engine (case-insensitive).
        ``max_intrusion`` drops entries above the given intrusion level
        (``safe`` < ``low`` < ``medium`` < ``high``).
        """
        data = await self._load()
        items = data.get(vulnerability_type, ())
        floor = _CONFIDENCE_RANK.get(_normalize_confidence(min_confidence or "LOW"), 0)
        engine_l = engine.lower() if engine else None
        ceiling = (
            _INTRUSION_RANK[_normalize_intrusion(max_intrusion)]
            if max_intrusion is not None
            else None
        )
        return tuple(
            p
            for p in items
            if (context is None or p.context == context)
            and (include_destructive or not p.destructive)
            and _CONFIDENCE_RANK[p.confidence] >= floor
            and (waf_bypass is None or p.waf_bypass == waf_bypass)
            and (engine_l is None or not p.engines or engine_l in p.engines)
            and (ceiling is None or _INTRUSION_RANK[p.min_intrusion_level] <= ceiling)
        )

    async def get_vectors(
        self,
        vulnerability_type: str,
        *,
        context: str | None = None,
        include_destructive: bool = False,
        min_confidence: str | None = None,
        waf_bypass: bool | None = None,
        engine: str | None = None,
        max_intrusion: str | None = None,
    ) -> list[str]:
        """Convenience wrapper returning only the raw vector strings."""
        payloads = await self.get_payloads(
            vulnerability_type,
            context=context,
            include_destructive=include_destructive,
            min_confidence=min_confidence,
            waf_bypass=waf_bypass,
            engine=engine,
            max_intrusion=max_intrusion,
        )
        return [p.vector for p in payloads]

    async def contexts_for(self, vulnerability_type: str) -> tuple[str, ...]:
        data = await self._load()
        seen: list[str] = []
        for payload in data.get(vulnerability_type, ()):
            if payload.context not in seen:
                seen.append(payload.context)
        return tuple(seen)

    def available_categories(self) -> tuple[str, ...]:
        return tuple(self._ensure_loaded().keys())


_LOADER: PayloadLoader | None = None
_LOADER_LOCK = threading.Lock()


def get_payload_loader() -> PayloadLoader:
    """Return the process-wide :class:`PayloadLoader` singleton."""
    global _LOADER
    if _LOADER is None:
        with _LOADER_LOCK:
            if _LOADER is None:
                _LOADER = PayloadLoader()
    return _LOADER
