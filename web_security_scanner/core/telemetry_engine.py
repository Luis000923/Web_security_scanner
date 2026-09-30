"""Real-time telemetry + adaptive concurrency control (Phase 2, Point 2).

This module is deliberately separate from :mod:`~.telemetry_async`
(``TelemetryWorker``), which persists one JSONL row per *tester probe* to
disk for later offline analysis (Phase 1's experiment pipeline). This module
instead aggregates every raw HTTP attempt the transport layer makes
(including retries a tester never even sees) **in memory**, for two
consumers that need it *live*, inside the running scan:

1. :class:`AdaptiveConcurrencyController` — reads the rate-limiting signal
   this module extracts (429/503, hard transport failure) to grow or shrink
   the scanner's concurrency pool in real time (see below).
2. The enriched JSON report / CLI ``--show-telemetry`` — read a
   point-in-time :meth:`TelemetryEngine.snapshot` at the end of the scan.

Everything here is confined to the single asyncio event-loop thread (the
same discipline :class:`~.scanner_core_async.AsyncResponseCache` documents):
every method is synchronous, non-awaiting, lock-free, and cheap (dict/counter
arithmetic only) — recording a sample can never block the event loop or add
meaningful latency to the request path it instruments.

Operational-phase taxonomy
---------------------------
Every metric is tagged with the scan's current operational phase, one of:

* ``"reconnaissance"`` — the Phase 1 crawl / JS-endpoint-mining / sitemap /
  sensitive-file / server-fingerprint sweep (``ReconEngine.run`` and its
  post-processing steps).
* ``"mapping"`` — the Phase 2 vulnerability-testing sweep over the targets
  Recon discovered (``WebSecurityScanner._dispatch_testers``). Not to be
  confused with the unrelated ``--profile mapping`` CLI choice (a *passive-
  only tester selection*), which is an orthogonal axis.
* ``"exploitation"`` — the adaptive Proof-of-Impact exploit engine's pass
  over CRITICAL/HIGH surface targets (``--enable-exploit-engine``).

The orchestrator calls :meth:`TelemetryEngine.set_phase` at each transition;
every ``record_request``/``record_waf_evasion`` call after that is tagged
with the current phase until the next transition. A scan phase this module
was never told about (or one that runs before the first ``set_phase`` call,
e.g. an early technology-detection GET) is tagged ``"unspecified"`` rather
than silently miscategorized.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

_LOG = logging.getLogger(__name__)

#: Canonical phase tags the orchestrator is expected to use (see module
#: docstring). Not enforced — an unrecognised tag is still accepted and
#: aggregated under its own key, so a future phase never needs a code change
#: here — but these are what :meth:`TelemetryEngine.set_phase` documents.
KNOWN_PHASES = ("reconnaissance", "mapping", "exploitation")
_DEFAULT_PHASE = "unspecified"

#: HTTP statuses treated as an explicit rate-limit / throttle signal.
RATE_LIMIT_STATUSES = frozenset({429, 503})

# Bounded like every other long-lived cache in this package (see
# scanner_core_async's _MAX_RESOLVE_CACHE / _MAX_WARMED_ENDPOINTS): a
# --target-list scan touching thousands of distinct hosts must not grow this
# dict without limit. Oldest-inserted host is evicted first (dict preserves
# insertion order in CPython 3.7+).
_MAX_TRACKED_HOSTS = 512


def _rfc3550_jitter(prev_jitter: float, prev_latency: float | None, latency: float) -> float:
    """RFC 3550 (RTP) smoothed inter-arrival jitter estimator.

    ``J += (|D| - J) / 16`` where ``D`` is the difference between this and
    the previous sample. Cheap (O(1), no history buffer) and standard for
    "how much is round-trip timing wobbling" rather than raw variance, which
    is what an operator actually means by network "jitter".
    """
    if prev_latency is None:
        return 0.0
    d = abs(latency - prev_latency)
    return prev_jitter + (d - prev_jitter) / 16.0


@dataclass
class HostMetrics:
    """Running, O(1)-updated request statistics for one host."""

    host: str
    count: int = 0
    error_count: int = 0            # status_code == 0 (hard transport failure)
    retry_count: int = 0            # attempts beyond the first, this host
    throttle_count: int = 0         # explicit 429/503
    tarpit_suspected_count: int = 0  # abnormally slow but otherwise-clean response
    total_latency: float = 0.0
    min_latency: float = float("inf")
    max_latency: float = 0.0
    jitter: float = 0.0             # RFC 3550-style smoothed jitter (seconds)
    _last_latency: float | None = field(default=None, repr=False)

    def update(self, elapsed: float, status_code: int, *, retried: bool) -> dict[str, bool]:
        """Fold in one HTTP attempt; returns immediate diagnostics."""
        throttled = status_code in RATE_LIMIT_STATUSES

        # Tarpit heuristic, evaluated against the mean *before* this sample
        # (an elevated latency shouldn't dilute its own baseline comparison):
        # a *clean* response (not a throttle, not a hard failure) taking
        # >= 5x this host's running-mean latency, once enough samples exist
        # to trust that mean — the classic slow-drip perimeter defense, as
        # distinct from a one-off network blip.
        tarpit = False
        if (not throttled and status_code != 0 and self.count >= 5
                and self._last_latency is not None):
            mean_before = self.total_latency / self.count
            if elapsed >= 5.0 * max(mean_before, 0.05):
                tarpit = True

        self.count += 1
        if retried:
            self.retry_count += 1
        if status_code == 0:
            self.error_count += 1
        if throttled:
            self.throttle_count += 1
        if tarpit:
            self.tarpit_suspected_count += 1

        self.total_latency += elapsed
        self.min_latency = min(self.min_latency, elapsed)
        self.max_latency = max(self.max_latency, elapsed)
        self.jitter = _rfc3550_jitter(self.jitter, self._last_latency, elapsed)
        self._last_latency = elapsed
        return {"rate_limited": throttled, "tarpit_suspected": tarpit}

    def snapshot(self) -> dict[str, Any]:
        mean = (self.total_latency / self.count) if self.count else 0.0
        return {
            "host": self.host,
            "requests": self.count,
            "errors": self.error_count,
            "retries": self.retry_count,
            "throttled": self.throttle_count,
            "tarpit_suspected": self.tarpit_suspected_count,
            "latency_mean_s": round(mean, 6),
            "latency_min_s": round(self.min_latency, 6) if self.count else 0.0,
            "latency_max_s": round(self.max_latency, 6),
            "jitter_s": round(self.jitter, 6),
        }


@dataclass
class PhaseMetrics:
    """Running statistics for one operational phase (see module docstring)."""

    phase: str
    count: int = 0
    error_count: int = 0
    retry_count: int = 0
    throttle_count: int = 0
    total_latency: float = 0.0

    def update(self, elapsed: float, status_code: int, *, retried: bool,
              throttled: bool) -> None:
        self.count += 1
        self.total_latency += elapsed
        if retried:
            self.retry_count += 1
        if status_code == 0:
            self.error_count += 1
        if throttled:
            self.throttle_count += 1

    def snapshot(self) -> dict[str, Any]:
        mean = (self.total_latency / self.count) if self.count else 0.0
        throttle_rate = (self.throttle_count / self.count) if self.count else 0.0
        return {
            "phase": self.phase,
            "requests": self.count,
            "errors": self.error_count,
            "retries": self.retry_count,
            "throttled": self.throttle_count,
            "throttle_rate": round(throttle_rate, 6),
            "latency_mean_s": round(mean, 6),
        }


@dataclass
class WafEvasionMetrics:
    """Effectiveness/retry counters for the WAF-evasion <-> exploit-engine
    correlation (``--enable-waf-evasion``); see :meth:`TelemetryEngine.record_waf_evasion`.
    """

    probes: int = 0                  # adaptive-retry cycles observed
    perimeter_blocks: int = 0        # cycles that hit an explicit block at all
    bypassed: int = 0                # cycles that eventually got through
    confirmed_blocked: int = 0       # every mutation exhausted, still blocked
    total_mutation_attempts: int = 0  # sum of (attempts - 1) across all cycles
    technique_successes: dict[str, int] = field(default_factory=dict)

    def record(self, *, blocked: bool, success: bool, technique: str | None,
              attempts: int) -> None:
        self.probes += 1
        self.total_mutation_attempts += max(0, attempts - 1)
        if blocked:
            self.perimeter_blocks += 1
        if success:
            self.bypassed += 1
            key = technique or "unknown"
            self.technique_successes[key] = self.technique_successes.get(key, 0) + 1
        elif blocked:
            self.confirmed_blocked += 1

    def snapshot(self) -> dict[str, Any]:
        bypass_rate = (self.bypassed / self.perimeter_blocks) if self.perimeter_blocks else 0.0
        return {
            "probes": self.probes,
            "perimeter_blocks_encountered": self.perimeter_blocks,
            "bypassed": self.bypassed,
            "confirmed_blocked": self.confirmed_blocked,
            "bypass_rate": round(bypass_rate, 6),
            "total_mutation_attempts": self.total_mutation_attempts,
            "technique_success_counts": dict(self.technique_successes),
        }


@dataclass
class AIMetrics:
    """Latency/failure/outcome counters for one stage of the LLM triage
    pipeline (Phase 2, Point 3), broken down by ``stage``:

    * ``"triage"`` -- stage 1, heuristic-finding verification
      (``--enable-ai-triaging``): the agent's TRUE/FALSE_POSITIVE verdict.
    * ``"cross_validation"`` -- stage 2, confirmatory PoC synthesis + replay
      (``--ai-synthesize``) that upgrades a surviving finding to
      ``CONFIRMED`` before it is formally reported.
    * ``"payload_synthesis"`` -- adapted-payload proposals when a
      parameter's static corpus is exhausted with no hit (also
      ``--ai-synthesize``, a different call site/purpose than cross-validation).
    """

    calls: int = 0
    failures: int = 0          # the backend call raised / degraded
    total_latency: float = 0.0
    dropped_as_false_positive: int = 0   # stage "triage" only
    confirmed: int = 0                   # stage "cross_validation" only

    def record(self, *, elapsed: float, success: bool, dropped: bool = False,
              confirmed: bool = False) -> None:
        self.calls += 1
        self.total_latency += elapsed
        if not success:
            self.failures += 1
        if dropped:
            self.dropped_as_false_positive += 1
        if confirmed:
            self.confirmed += 1

    def snapshot(self) -> dict[str, Any]:
        mean = (self.total_latency / self.calls) if self.calls else 0.0
        failure_rate = (self.failures / self.calls) if self.calls else 0.0
        return {
            "calls": self.calls,
            "failures": self.failures,
            "failure_rate": round(failure_rate, 6),
            "latency_mean_s": round(mean, 6),
            "dropped_as_false_positive": self.dropped_as_false_positive,
            "confirmed": self.confirmed,
        }


@dataclass
class ContainmentMetrics:
    """Forensic-containment counters for the exploit engine's Safety Gate and
    Payload Sandbox (Phase 3, ``--enable-exploit-engine``); see
    :meth:`TelemetryEngine.record_containment_attempt`,
    :meth:`~TelemetryEngine.record_safety_gate_interception` and
    :meth:`~TelemetryEngine.record_scope_deviation`.
    """

    payload_execution_attempts: int = 0     # every probe the engine actually sent
    contained_simulation_attempts: int = 0  # sent as an inert sandboxed echo
    controlled_execution_attempts: int = 0  # sent as the real low-intrusion probe
    total_vector_latency: float = 0.0
    safety_gate_interceptions: int = 0      # CLI/engine-boundary aborts before any request
    scope_deviation_alerts: int = 0         # in-run target skipped for being out of scope
    scope_deviation_hosts: list[str] = field(default_factory=list)

    def record_attempt(self, *, elapsed: float, contained: bool) -> None:
        self.payload_execution_attempts += 1
        self.total_vector_latency += elapsed
        if contained:
            self.contained_simulation_attempts += 1
        else:
            self.controlled_execution_attempts += 1

    def record_safety_gate_interception(self) -> None:
        self.safety_gate_interceptions += 1

    def record_scope_deviation(self, host: str) -> None:
        self.scope_deviation_alerts += 1
        if host and host not in self.scope_deviation_hosts:
            self.scope_deviation_hosts.append(host)

    def snapshot(self) -> dict[str, Any]:
        mean = (
            self.total_vector_latency / self.payload_execution_attempts
            if self.payload_execution_attempts else 0.0
        )
        return {
            "payload_execution_attempts": self.payload_execution_attempts,
            "contained_simulation_attempts": self.contained_simulation_attempts,
            "controlled_execution_attempts": self.controlled_execution_attempts,
            "attack_vector_latency_mean_s": round(mean, 6),
            "safety_gate_interceptions": self.safety_gate_interceptions,
            "scope_deviation_alerts": self.scope_deviation_alerts,
            "scope_deviation_hosts": list(self.scope_deviation_hosts),
        }


class TelemetryEngine:
    """In-memory, non-blocking real-time metrics collector.

    One instance lives on :class:`~.scanner_core_async.AsyncScannerCore` for
    the whole scan. Confined to the event-loop thread; every method is
    synchronous and never awaits, so it is safe to call from anywhere in the
    request path without risking a stall.
    """

    def __init__(self) -> None:
        self._phase = _DEFAULT_PHASE
        self._hosts: dict[str, HostMetrics] = {}
        self._phases: dict[str, PhaseMetrics] = {}
        self._waf = WafEvasionMetrics()
        self._ai: dict[str, AIMetrics] = {}
        self._concurrency_log: list[dict[str, Any]] = []
        self._containment = ContainmentMetrics()
        self._start = time.monotonic()

    def reset(self) -> None:
        """Clear all counters for a fresh scan (object identity is kept, so
        anything already holding a reference — e.g. an
        :class:`AdaptiveConcurrencyController` — keeps working)."""
        self._phase = _DEFAULT_PHASE
        self._hosts.clear()
        self._phases.clear()
        self._waf = WafEvasionMetrics()
        self._ai.clear()
        self._concurrency_log.clear()
        self._containment = ContainmentMetrics()
        self._start = time.monotonic()

    # ---- phase tracking ----------------------------------------------------

    def set_phase(self, phase: str) -> None:
        """Tag every subsequent recording call with ``phase`` until the next
        call. See the module docstring for the canonical phase tags."""
        self._phase = str(phase) or _DEFAULT_PHASE

    @property
    def current_phase(self) -> str:
        return self._phase

    # ---- request-level recording --------------------------------------------

    def record_request(self, host: str, elapsed: float, status_code: int, *,
                       retried: bool = False, phase: str | None = None
                       ) -> dict[str, bool]:
        """Record one raw HTTP attempt (including retries the tester layer
        never observes directly). Returns ``{"rate_limited": bool,
        "tarpit_suspected": bool}`` so a caller (the adaptive concurrency
        controller, primarily) can react without a second pass over the data.
        """
        host = host or "unknown"
        phase = phase or self._phase
        if host not in self._hosts and len(self._hosts) >= _MAX_TRACKED_HOSTS:
            self._hosts.pop(next(iter(self._hosts)), None)
        metrics = self._hosts.setdefault(host, HostMetrics(host=host))
        diag = metrics.update(elapsed, status_code, retried=retried)

        phase_metrics = self._phases.setdefault(phase, PhaseMetrics(phase=phase))
        phase_metrics.update(elapsed, status_code, retried=retried,
                             throttled=diag["rate_limited"])
        return diag

    # ---- WAF-evasion <-> exploit-engine correlation -------------------------

    def record_waf_evasion(self, *, technique: str | None, success: bool,
                           blocked: bool, attempts: int = 1,
                           phase: str | None = None) -> None:
        """Record one adaptive WAF-evasion retry cycle (see
        :meth:`~.modules.waf_evasion.WafEvasionEngine.send_with_evasion`),
        correlated with the exploit engine's own attempt."""
        del phase  # reserved for a future per-phase WAF breakdown
        self._waf.record(blocked=blocked, success=success, technique=technique,
                         attempts=attempts)

    # ---- adaptive-concurrency audit trail -----------------------------------

    def record_concurrency_adjustment(self, *, old_limit: int, new_limit: int,
                                      reason: str) -> None:
        self._concurrency_log.append({
            "phase": self._phase,
            "t_s": round(time.monotonic() - self._start, 3),
            "old_limit": old_limit,
            "new_limit": new_limit,
            "reason": reason,
        })

    # ---- LLM triage pipeline (Phase 2, Point 3) ------------------------------

    def record_ai_call(self, stage: str, *, elapsed: float, success: bool,
                       dropped: bool = False, confirmed: bool = False) -> None:
        """Record one call into the LLM triage pipeline. See
        :class:`AIMetrics` for the ``stage`` taxonomy (``triage`` /
        ``cross_validation`` / ``payload_synthesis``)."""
        metrics = self._ai.setdefault(stage, AIMetrics())
        metrics.record(elapsed=elapsed, success=success, dropped=dropped,
                       confirmed=confirmed)

    # ---- exploit-engine containment (Phase 3) --------------------------------

    def record_containment_attempt(self, *, elapsed: float, contained: bool) -> None:
        """Record one payload the exploit engine actually sent (or simulated).

        ``contained`` is ``True`` when the vector was rewritten by
        :class:`~...modules.containment_core.PayloadSandbox` into an inert
        verification echo (``ContainmentVector.CONTAINED_SIMULATION``),
        ``False`` for the engine's already-vetted real low-intrusion probe
        (``ContainmentVector.CONTROLLED_EXECUTION``).
        """
        self._containment.record_attempt(elapsed=elapsed, contained=contained)

    def record_safety_gate_interception(self) -> None:
        """Record one Safety Gate refusal -- a target the exploit engine was
        never allowed to send a single request to."""
        self._containment.record_safety_gate_interception()

    def record_scope_deviation(self, host: str) -> None:
        """Record one in-run scope-deviation alert: a target discovered mid-scan
        (e.g. via ``--target-list`` or a redirect) that fell outside the
        Safety Gate's lab scope and was skipped rather than probed."""
        self._containment.record_scope_deviation(host)

    # ---- export --------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Full nested snapshot: per-phase and per-host stats, WAF-evasion
        effectiveness, the LLM triage pipeline's own metrics, and the
        concurrency-adjustment log. Consumed by the enriched JSON report
        (``report_engine.build_enriched_report``) and the CLI's
        ``--show-telemetry``."""
        return {
            "elapsed_s": round(time.monotonic() - self._start, 3),
            "phases": {p: m.snapshot() for p, m in self._phases.items()},
            "hosts": {h: m.snapshot() for h, m in self._hosts.items()},
            "waf_evasion": self._waf.snapshot(),
            "ai_triage": {stage: m.snapshot() for stage, m in self._ai.items()},
            "concurrency_adjustments": list(self._concurrency_log),
            "containment": self._containment.snapshot(),
        }


class AdaptiveSemaphore:
    """A resizable counting semaphore for a single-threaded asyncio event loop.

    ``asyncio.Semaphore`` has no public resize operation. This reimplements
    the same wait/wake algorithm CPython's ``asyncio.Semaphore`` uses
    (a FIFO waiter queue of futures, one woken per freed unit) with an added
    :meth:`resize` that can grow or shrink the limit at any time, including
    while permits are currently held.

    Shrinking never revokes an in-flight permit — it only raises the bar new
    acquisitions must clear, so the pool drains down to the new limit as
    in-flight requests finish and call :meth:`release` naturally. Growing
    wakes waiters one at a time, exactly as if that many extra ``release()``
    calls had happened.

    Not thread-safe — single event-loop discipline, same as the rest of this
    package.
    """

    def __init__(self, limit: int) -> None:
        self._limit = max(1, int(limit))
        self._value = self._limit
        self._waiters: deque[asyncio.Future] = deque()

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def value(self) -> int:
        """Permits currently available (may be negative right after a
        shrink — that many releases must happen before a new acquire can
        proceed)."""
        return self._value

    async def acquire(self) -> None:
        if self._value > 0 and not self._waiters:
            self._value -= 1
            return
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._waiters.append(fut)
        try:
            await fut
        except asyncio.CancelledError:
            if fut.cancelled():
                try:
                    self._waiters.remove(fut)
                except ValueError:
                    pass
            else:
                # Already handed the slot but cancelled before resuming --
                # pass it on instead of leaking a permit.
                self._wake_next()
            raise
        else:
            self._value -= 1

    def release(self) -> None:
        self._value += 1
        self._wake_next()

    def resize(self, new_limit: int) -> int:
        """Change the concurrency ceiling; returns the previous limit.

        Implemented as ``delta`` virtual releases (delta > 0) so growth wakes
        waiters exactly like ``delta`` normal ``release()`` calls would;
        shrinking (delta < 0) only lowers ``_value`` -- never revokes an
        already-held permit.
        """
        new_limit = max(1, int(new_limit))
        old_limit = self._limit
        delta = new_limit - old_limit
        self._limit = new_limit
        if delta > 0:
            for _ in range(delta):
                self._value += 1
                self._wake_next()
        else:
            self._value += delta
        return old_limit

    def _wake_next(self) -> None:
        while self._waiters:
            fut = self._waiters.popleft()
            if not fut.done():
                fut.set_result(None)
                return

    async def __aenter__(self) -> None:
        await self.acquire()

    async def __aexit__(self, *exc: object) -> None:
        self.release()


class AdaptiveConcurrencyController:
    """AIMD (Additive-Increase / Multiplicative-Decrease) concurrency governor.

    Borrows TCP congestion control's core idea: probe the concurrency ceiling
    upward gently while the target stays healthy, and back off hard and fast
    the moment it signals distress (a 429/503 response, or a hard transport
    failure that often means a tarpit/overload dropping connections). A scan
    that self-throttles this way avoids both network saturation and the
    false negatives a target serves once it starts rate-limiting a scan
    that keeps hammering it at a fixed pace.

    Every ``window`` outcomes (default 20) the accumulated distress rate is
    evaluated once:

    * ``>= high_watermark`` (default 20%) -> halve the limit (floored at
      ``minimum``) — multiplicative decrease, reacts fast to real trouble.
    * ``<= low_watermark`` (default 2%) -> add one permit (capped at
      ``maximum``) — additive increase, a cautious probe back up.
    * otherwise -> no change ("stable").

    Not thread-safe (single event-loop discipline) — :meth:`on_outcome` must
    only ever be called from the scanner's own event loop, and is
    synchronous (cheap counter arithmetic + an occasional semaphore resize)
    so it never needs to be awaited.
    """

    def __init__(self, *, initial: int, minimum: int = 2, maximum: int | None = None,
                window: int = 20, high_watermark: float = 0.2,
                low_watermark: float = 0.02,
                telemetry: TelemetryEngine | None = None) -> None:
        self.minimum = max(1, int(minimum))
        self.maximum = max(self.minimum, int(maximum if maximum is not None else initial))
        initial = min(self.maximum, max(self.minimum, int(initial)))
        self.semaphore = AdaptiveSemaphore(initial)
        self.window = max(1, int(window))
        self.high_watermark = high_watermark
        self.low_watermark = low_watermark
        self._telemetry = telemetry
        self._window_total = 0
        self._window_distress = 0

    @property
    def current_limit(self) -> int:
        return self.semaphore.limit

    def on_outcome(self, *, throttled: bool, transient: bool) -> None:
        """Feed one request outcome into the current AIMD window.

        ``throttled`` — the response was an explicit 429/503.
        ``transient`` — the request failed at the transport layer
        (``status_code == 0``): a timeout, connection reset, or refused
        connection, which under load-induced distress looks identical to a
        target quietly dropping connections instead of answering them.
        """
        self._window_total += 1
        if throttled or transient:
            self._window_distress += 1
        if self._window_total < self.window:
            return

        distress_rate = self._window_distress / self._window_total
        old_limit = self.current_limit
        new_limit = old_limit
        reason = f"stable (distress_rate={distress_rate:.2f})"
        if distress_rate >= self.high_watermark:
            new_limit = max(self.minimum, old_limit // 2)
            reason = f"multiplicative-decrease (distress_rate={distress_rate:.2f})"
        elif distress_rate <= self.low_watermark:
            new_limit = min(self.maximum, old_limit + 1)
            reason = f"additive-increase (distress_rate={distress_rate:.2f})"

        self._window_total = 0
        self._window_distress = 0
        if new_limit != old_limit:
            self.semaphore.resize(new_limit)
            if self._telemetry is not None:
                self._telemetry.record_concurrency_adjustment(
                    old_limit=old_limit, new_limit=new_limit, reason=reason,
                )
