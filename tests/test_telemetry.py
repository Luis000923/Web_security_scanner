"""Tests for the real-time telemetry + adaptive concurrency subsystem
(web_security_scanner.core.telemetry_engine), and its wiring into
AsyncScannerCore / WebSecurityScanner / ExploitEngine.

Covers:
* HostMetrics / PhaseMetrics: latency mean/min/max, RFC 3550 jitter,
  retry/error/throttle counters, tarpit heuristic.
* WafEvasionMetrics: bypass-rate / confirmed-block accounting correlated
  with the exploit engine's adaptive-retry cycles.
* TelemetryEngine facade: phase tagging, per-host bounding (memory safety
  under a high host cardinality / simulated high load), snapshot shape,
  reset().
* AdaptiveSemaphore: resizable semaphore correctness (grow/shrink, FIFO
  waiters, never exceeds its limit) under concurrent load.
* AdaptiveConcurrencyController: AIMD multiplicative-decrease under a
  distressed target, additive-increase under a clean one, floor/ceiling
  respected, concurrency-adjustment audit trail.
* AsyncScannerCore integration: default (fixed semaphore, opt-out) behavior
  is unchanged; opting in records telemetry and can resize concurrency.
* Resistance under simulated high load: many concurrent acquire/release
  cycles never over-admit past the current limit, and recording thousands
  of samples stays bounded and fast (no blocking of the event loop).
"""

import asyncio
import time

import pytest

from web_security_scanner.core.scanner_core_async import AsyncScannerCore, ScanConfig
from web_security_scanner.core.telemetry_engine import (
    _MAX_TRACKED_HOSTS,
    AdaptiveConcurrencyController,
    AdaptiveSemaphore,
    HostMetrics,
    PhaseMetrics,
    TelemetryEngine,
    WafEvasionMetrics,
    _rfc3550_jitter,
)

# ---------------------------------------------------------------------------
# HostMetrics
# ---------------------------------------------------------------------------


def test_host_metrics_latency_mean_min_max():
    hm = HostMetrics(host="a.test")
    for elapsed in (0.1, 0.3, 0.2):
        hm.update(elapsed, 200, retried=False)
    snap = hm.snapshot()
    assert snap["requests"] == 3
    assert snap["latency_mean_s"] == pytest.approx(0.2, abs=1e-6)
    assert snap["latency_min_s"] == pytest.approx(0.1)
    assert snap["latency_max_s"] == pytest.approx(0.3)


def test_host_metrics_counts_errors_retries_throttles():
    hm = HostMetrics(host="a.test")
    hm.update(0.1, 200, retried=False)
    hm.update(0.1, 0, retried=True)      # hard transport failure, a retry
    hm.update(0.1, 429, retried=True)    # explicit rate limit, a retry
    snap = hm.snapshot()
    assert snap["errors"] == 1
    assert snap["retries"] == 2
    assert snap["throttled"] == 1


def test_host_metrics_update_reports_rate_limited_diagnostic():
    hm = HostMetrics(host="a.test")
    diag = hm.update(0.1, 503, retried=False)
    assert diag["rate_limited"] is True
    diag = hm.update(0.1, 200, retried=False)
    assert diag["rate_limited"] is False


def test_host_metrics_tarpit_heuristic_flags_abnormally_slow_clean_response():
    hm = HostMetrics(host="a.test")
    # Establish a stable ~0.1s baseline over several clean requests.
    for _ in range(5):
        diag = hm.update(0.1, 200, retried=False)
        assert diag["tarpit_suspected"] is False
    # A response taking >=5x the running mean, but still a clean 200 (not a
    # throttle status) -- the slow-drip tarpit signature.
    diag = hm.update(1.0, 200, retried=False)
    assert diag["tarpit_suspected"] is True
    assert hm.tarpit_suspected_count == 1


def test_host_metrics_tarpit_heuristic_ignores_throttle_responses():
    hm = HostMetrics(host="a.test")
    for _ in range(5):
        hm.update(0.1, 200, retried=False)
    # Slow AND explicitly throttled -- this is rate-limiting, not a tarpit;
    # must not double-count it as both.
    diag = hm.update(1.0, 429, retried=False)
    assert diag["tarpit_suspected"] is False
    assert diag["rate_limited"] is True


def test_rfc3550_jitter_zero_on_first_sample():
    assert _rfc3550_jitter(0.0, None, 0.5) == 0.0


def test_rfc3550_jitter_converges_toward_stable_delta():
    # Constant inter-arrival difference of 0.1s -> jitter should climb toward
    # (but never overshoot) that delta as more samples arrive.
    jitter = 0.0
    prev = 0.1
    for _ in range(200):
        nxt = prev + 0.1
        jitter = _rfc3550_jitter(jitter, prev, nxt)
        prev = nxt
    assert 0.09 <= jitter <= 0.1


# ---------------------------------------------------------------------------
# PhaseMetrics
# ---------------------------------------------------------------------------


def test_phase_metrics_throttle_rate():
    pm = PhaseMetrics(phase="mapping")
    pm.update(0.1, 200, retried=False, throttled=False)
    pm.update(0.1, 429, retried=False, throttled=True)
    snap = pm.snapshot()
    assert snap["requests"] == 2
    assert snap["throttle_rate"] == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# WafEvasionMetrics
# ---------------------------------------------------------------------------


def test_waf_evasion_metrics_bypass_rate_and_technique_counts():
    waf = WafEvasionMetrics()
    waf.record(blocked=False, success=False, technique=None, attempts=1)  # NOT_BLOCKED
    waf.record(blocked=True, success=True, technique="random_case", attempts=2)
    waf.record(blocked=True, success=False, technique=None, attempts=5)  # CONFIRMED_BLOCKED
    snap = waf.snapshot()
    assert snap["probes"] == 3
    assert snap["perimeter_blocks_encountered"] == 2
    assert snap["bypassed"] == 1
    assert snap["confirmed_blocked"] == 1
    assert snap["bypass_rate"] == pytest.approx(0.5)
    assert snap["technique_success_counts"] == {"random_case": 1}
    # attempts - 1 summed across all three probes: 0 + 1 + 4 = 5
    assert snap["total_mutation_attempts"] == 5


# ---------------------------------------------------------------------------
# TelemetryEngine facade
# ---------------------------------------------------------------------------


def test_telemetry_engine_tags_requests_with_current_phase():
    engine = TelemetryEngine()
    engine.set_phase("reconnaissance")
    engine.record_request("a.test", 0.1, 200)
    engine.set_phase("exploitation")
    engine.record_request("a.test", 0.2, 200)
    snap = engine.snapshot()
    assert set(snap["phases"]) == {"reconnaissance", "exploitation"}
    assert snap["phases"]["reconnaissance"]["requests"] == 1
    assert snap["phases"]["exploitation"]["requests"] == 1


def test_telemetry_engine_default_phase_is_unspecified():
    engine = TelemetryEngine()
    assert engine.current_phase == "unspecified"
    engine.record_request("a.test", 0.1, 200)
    assert "unspecified" in engine.snapshot()["phases"]


def test_telemetry_engine_per_call_phase_override():
    engine = TelemetryEngine()
    engine.set_phase("mapping")
    engine.record_request("a.test", 0.1, 200, phase="exploitation")
    snap = engine.snapshot()
    assert "exploitation" in snap["phases"]
    assert "mapping" not in snap["phases"]


def test_telemetry_engine_host_cardinality_is_bounded():
    engine = TelemetryEngine()
    for i in range(_MAX_TRACKED_HOSTS + 200):
        engine.record_request(f"host-{i}.test", 0.01, 200)
    assert len(engine.snapshot()["hosts"]) <= _MAX_TRACKED_HOSTS


def test_telemetry_engine_reset_clears_counters_but_keeps_identity():
    engine = TelemetryEngine()
    engine.set_phase("mapping")
    engine.record_request("a.test", 0.1, 200)
    engine.record_waf_evasion(technique="x", success=True, blocked=True)
    engine.record_concurrency_adjustment(old_limit=10, new_limit=5, reason="test")
    engine.reset()
    snap = engine.snapshot()
    assert snap["phases"] == {}
    assert snap["hosts"] == {}
    assert snap["waf_evasion"]["probes"] == 0
    assert snap["concurrency_adjustments"] == []
    assert engine.current_phase == "unspecified"


def test_telemetry_engine_waf_evasion_correlation_snapshot():
    engine = TelemetryEngine()
    engine.record_waf_evasion(technique="double_encode", success=True, blocked=True, attempts=3)
    snap = engine.snapshot()
    assert snap["waf_evasion"]["bypassed"] == 1
    assert snap["waf_evasion"]["technique_success_counts"] == {"double_encode": 1}


def test_telemetry_engine_concurrency_adjustment_log_records_phase():
    engine = TelemetryEngine()
    engine.set_phase("mapping")
    engine.record_concurrency_adjustment(old_limit=10, new_limit=5, reason="multiplicative-decrease")
    log = engine.snapshot()["concurrency_adjustments"]
    assert len(log) == 1
    assert log[0]["phase"] == "mapping"
    assert log[0]["old_limit"] == 10
    assert log[0]["new_limit"] == 5


# ---------------------------------------------------------------------------
# AdaptiveSemaphore
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adaptive_semaphore_basic_acquire_release():
    sem = AdaptiveSemaphore(2)
    await sem.acquire()
    await sem.acquire()
    assert sem.value == 0
    sem.release()
    assert sem.value == 1
    sem.release()
    assert sem.value == 2


@pytest.mark.asyncio
async def test_adaptive_semaphore_third_acquire_blocks_until_release():
    sem = AdaptiveSemaphore(1)
    await sem.acquire()
    order = []

    async def waiter():
        await sem.acquire()
        order.append("acquired")
        sem.release()

    task = asyncio.create_task(waiter())
    await asyncio.sleep(0.01)
    assert not task.done()  # still blocked: only 1 permit, held by the caller
    sem.release()
    await asyncio.wait_for(task, timeout=1.0)
    assert order == ["acquired"]


@pytest.mark.asyncio
async def test_adaptive_semaphore_never_over_admits_under_concurrent_load():
    """Simulated high load: 200 concurrent workers hammering a limit of 8 --
    the number in flight must never exceed the limit."""
    sem = AdaptiveSemaphore(8)
    in_flight = 0
    max_seen = 0

    async def worker():
        nonlocal in_flight, max_seen
        await sem.acquire()
        try:
            in_flight += 1
            max_seen = max(max_seen, in_flight)
            await asyncio.sleep(0.001)
        finally:
            in_flight -= 1
            sem.release()

    await asyncio.gather(*(worker() for _ in range(200)))
    assert max_seen <= 8


@pytest.mark.asyncio
async def test_adaptive_semaphore_resize_grow_admits_more_immediately():
    sem = AdaptiveSemaphore(1)
    await sem.acquire()  # value == 0, fully held

    async def waiter():
        await sem.acquire()
        return "in"

    task = asyncio.create_task(waiter())
    await asyncio.sleep(0.01)
    assert not task.done()

    old = sem.resize(2)  # grow by 1 -> should wake the waiter without a release()
    assert old == 1
    result = await asyncio.wait_for(task, timeout=1.0)
    assert result == "in"


@pytest.mark.asyncio
async def test_adaptive_semaphore_resize_shrink_does_not_revoke_held_permits():
    sem = AdaptiveSemaphore(4)
    await sem.acquire()
    await sem.acquire()
    assert sem.value == 2
    sem.resize(1)  # shrink below what's currently held
    assert sem.limit == 1
    # The 2 permits already held are untouched (no forced release), but the
    # ceiling now sits below in-use, so a new acquire must wait.
    acquired = False

    async def try_acquire():
        nonlocal acquired
        await sem.acquire()
        acquired = True

    task = asyncio.create_task(try_acquire())
    await asyncio.sleep(0.01)
    assert not acquired  # can't get in: value is negative post-shrink

    sem.release()
    sem.release()
    await asyncio.wait_for(task, timeout=1.0)
    assert acquired


@pytest.mark.asyncio
async def test_adaptive_semaphore_used_as_async_context_manager():
    sem = AdaptiveSemaphore(1)
    async with sem:
        assert sem.value == 0
    assert sem.value == 1


# ---------------------------------------------------------------------------
# AdaptiveConcurrencyController (AIMD)
# ---------------------------------------------------------------------------


def test_aimd_multiplicative_decrease_under_distress():
    telemetry = TelemetryEngine()
    ctrl = AdaptiveConcurrencyController(
        initial=16, minimum=2, maximum=32, window=10,
        high_watermark=0.2, low_watermark=0.02, telemetry=telemetry,
    )
    # 3/10 = 30% distress rate -> above the 20% high watermark.
    for _ in range(3):
        ctrl.on_outcome(throttled=True, transient=False)
    for _ in range(7):
        ctrl.on_outcome(throttled=False, transient=False)
    assert ctrl.current_limit == 8  # halved from 16
    log = telemetry.snapshot()["concurrency_adjustments"]
    assert len(log) == 1
    assert "multiplicative-decrease" in log[0]["reason"]


def test_aimd_additive_increase_when_clean():
    ctrl = AdaptiveConcurrencyController(initial=4, minimum=2, maximum=32, window=10)
    for _ in range(10):
        ctrl.on_outcome(throttled=False, transient=False)
    assert ctrl.current_limit == 5  # +1


def test_aimd_stays_stable_between_watermarks():
    ctrl = AdaptiveConcurrencyController(
        initial=10, minimum=2, maximum=32, window=10,
        high_watermark=0.5, low_watermark=0.05,
    )
    # 1/10 = 10% distress: between 5% and 50% -> no change.
    ctrl.on_outcome(throttled=True, transient=False)
    for _ in range(9):
        ctrl.on_outcome(throttled=False, transient=False)
    assert ctrl.current_limit == 10


def test_aimd_never_shrinks_below_minimum():
    ctrl = AdaptiveConcurrencyController(initial=4, minimum=2, maximum=32, window=4)
    # Hammer with 100% distress across several windows.
    for _ in range(40):
        ctrl.on_outcome(throttled=True, transient=False)
    assert ctrl.current_limit >= 2


def test_aimd_never_grows_above_maximum():
    ctrl = AdaptiveConcurrencyController(initial=4, minimum=1, maximum=6, window=4)
    for _ in range(80):
        ctrl.on_outcome(throttled=False, transient=False)
    assert ctrl.current_limit <= 6


def test_aimd_transient_transport_failures_also_count_as_distress():
    ctrl = AdaptiveConcurrencyController(initial=16, minimum=2, maximum=32,
                                         window=10, high_watermark=0.2)
    for _ in range(5):
        ctrl.on_outcome(throttled=False, transient=True)
    for _ in range(5):
        ctrl.on_outcome(throttled=False, transient=False)
    assert ctrl.current_limit == 8


def test_aimd_current_limit_matches_semaphore_limit():
    ctrl = AdaptiveConcurrencyController(initial=5, minimum=1, maximum=10, window=100)
    assert ctrl.current_limit == ctrl.semaphore.limit == 5


# ---------------------------------------------------------------------------
# AsyncScannerCore integration
# ---------------------------------------------------------------------------


def test_scanner_core_default_semaphore_is_plain_asyncio_semaphore():
    core = AsyncScannerCore(ScanConfig(max_concurrency=7))
    assert isinstance(core._semaphore, asyncio.Semaphore)
    assert core._concurrency_controller is None


def test_scanner_core_opt_in_adaptive_concurrency_uses_controller():
    core = AsyncScannerCore(ScanConfig(max_concurrency=7, adaptive_concurrency=True))
    assert core._concurrency_controller is not None
    assert isinstance(core._semaphore, AdaptiveSemaphore)
    assert core._semaphore.limit == 7


def test_scanner_core_always_has_telemetry_engine():
    core = AsyncScannerCore(ScanConfig())
    assert isinstance(core.telemetry_engine, TelemetryEngine)


def test_scanner_core_set_max_concurrency_rebuilds_fixed_semaphore():
    core = AsyncScannerCore(ScanConfig(max_concurrency=5))
    core.set_max_concurrency(10)
    assert core.config.max_concurrency == 10
    assert isinstance(core._semaphore, asyncio.Semaphore)


def test_scanner_core_set_max_concurrency_preserves_adaptive_mode():
    core = AsyncScannerCore(ScanConfig(max_concurrency=5, adaptive_concurrency=True))
    original_controller = core._concurrency_controller
    core.set_max_concurrency(20)
    assert core._concurrency_controller is original_controller
    assert core._semaphore.limit == 20
    assert core._concurrency_controller.maximum == 20


@pytest.mark.asyncio
async def test_scanner_core_request_records_telemetry(monkeypatch):
    core = AsyncScannerCore(ScanConfig())

    async def fake_following(method, url, follow_redirects, caller_headers, kwargs):
        return {"status_code": 200, "text": "", "headers": {}, "url": url, "elapsed": 0.05}

    monkeypatch.setattr(core, "_request_following", fake_following)
    await core.start()
    await core.request("GET", "http://telemetry.test/x", use_cache=False)
    await core.close()

    snap = core.telemetry_engine.snapshot()
    assert snap["phases"]["unspecified"]["requests"] == 1
    assert "telemetry.test" in snap["hosts"]


@pytest.mark.asyncio
async def test_scanner_core_adaptive_concurrency_shrinks_under_simulated_throttling(monkeypatch):
    core = AsyncScannerCore(ScanConfig(
        max_concurrency=16, adaptive_concurrency=True,
        adaptive_concurrency_min=2, adaptive_concurrency_window=5,
        adaptive_concurrency_high_watermark=0.2,
    ))

    async def fake_following(method, url, follow_redirects, caller_headers, kwargs):
        return {"status_code": 429, "text": "", "headers": {}, "url": url, "elapsed": 0.01}

    monkeypatch.setattr(core, "_request_following", fake_following)
    await core.start()
    for _ in range(5):
        await core.request("GET", "http://throttled.test/x", use_cache=False)
    await core.close()

    assert core._semaphore.limit < 16
    assert core.telemetry_engine.snapshot()["concurrency_adjustments"]


# ---------------------------------------------------------------------------
# High-load resistance
# ---------------------------------------------------------------------------


def test_telemetry_engine_handles_thousands_of_samples_quickly():
    """Recording is O(1) per call and must never meaningfully stall the
    event loop even under a heavy simulated request volume."""
    engine = TelemetryEngine()
    engine.set_phase("mapping")
    start = time.perf_counter()
    for i in range(20_000):
        engine.record_request(f"host-{i % 50}.test", 0.01 + (i % 7) * 0.001, 200 if i % 11 else 429)
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0
    snap = engine.snapshot()
    assert snap["phases"]["mapping"]["requests"] == 20_000
    assert len(snap["hosts"]) == 50


@pytest.mark.asyncio
async def test_adaptive_semaphore_high_concurrency_stress_no_deadlock():
    sem = AdaptiveSemaphore(5)
    completed = 0

    async def worker(i):
        nonlocal completed
        async with sem:
            await asyncio.sleep(0.0005)
            completed += 1

    await asyncio.wait_for(
        asyncio.gather(*(worker(i) for i in range(500))), timeout=10.0
    )
    assert completed == 500
