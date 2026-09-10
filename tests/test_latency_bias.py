"""JVM latency-bias mitigations: warm-up, robust variance, 2-sample confirm."""

import pytest
from conftest import MockScanner

from web_security_scanner.events.event_emitter import ScanEventEmitter
from web_security_scanner.modules.vulnerability_testers.base_tester_async import (
    RollingLatency,
    VulnerabilityTester,
)
from web_security_scanner.modules.vulnerability_testers.sql_injection_async import (
    SQLInjectionTester,
)


class _Dummy(VulnerabilityTester):
    name = "dummy"
    description = "dummy"

    async def run_test(self, target_url, **kwargs):  # pragma: no cover
        return None


def _tester(cls=_Dummy, scanner=None, **config):
    return cls(scanner or MockScanner(lambda *a, **k: {}), ScanEventEmitter(), config)


# ---- RollingLatency ------------------------------------------------------


def test_rolling_latency_upper_bound_ignores_a_single_spike():
    clean = RollingLatency(12, seed=[0.10, 0.11, 0.09, 0.10, 0.12, 0.10])
    spiked = RollingLatency(12, seed=[0.10, 0.11, 0.09, 0.10, 0.12, 5.00])
    # One 5s GC spike must barely move the robust (median+MAD) bound.
    assert spiked.upper_bound() < clean.upper_bound() + 0.15


def test_rolling_latency_window_is_bounded():
    win = RollingLatency(3)
    win.extend([1, 2, 3, 4, 5])
    assert len(win) == 3
    assert win.median == 4


def test_rolling_latency_needs_two_samples_for_a_bound():
    assert RollingLatency(12, seed=[0.2]).upper_bound() == 0.0


# ---- adaptive_time_threshold (robust form) -----------------------------


def test_adaptive_threshold_robust_to_spike_vs_clean():
    clean = [0.1, 0.1, 0.1, 0.1]
    spiked = [0.1, 0.1, 0.1, 5.0]
    floor = VulnerabilityTester.adaptive_time_threshold(clean)
    with_spike = VulnerabilityTester.adaptive_time_threshold(spiked)
    # median/MAD ignores the lone outlier -> both collapse to the 4.0s floor.
    assert floor == pytest.approx(4.0)
    assert with_spike == pytest.approx(4.0)


def test_adaptive_threshold_widens_on_genuinely_jittery_target():
    jittery = [1.0, 3.0, 1.0, 3.0, 1.0, 3.0]
    assert VulnerabilityTester.adaptive_time_threshold(jittery) > 4.0


# ---- warmup_point ------------------------------------------------------


class _WarmScanner:
    def __init__(self):
        self.warmups = []
        self.requests = []
        self._warmed = set()

    async def warmup(self, url, n, *, method="GET", **kwargs):
        key = url.split("?")[0]
        if key in self._warmed:
            return 0
        self._warmed.add(key)
        self.warmups.append((url, n))
        return n

    async def request(self, method, url, **kwargs):
        self.requests.append(url)
        return {"status_code": 200, "text": "", "headers": {}, "url": url,
                "elapsed": 0.1}


@pytest.mark.asyncio
async def test_warmup_point_fires_before_baseline_and_once_per_point():
    sc = _WarmScanner()
    t = _tester(scanner=sc, warmup_requests=5)
    await t.get_baseline("http://h/x?q=1", "q")
    await t.sample_baseline_latency("http://h/x?q=1", "q")
    assert len(sc.warmups) == 1  # deduped across get_baseline + sample_*
    assert sc.warmups[0][0].startswith("http://h/x") and sc.warmups[0][1] == 5
    assert sc.requests  # real baseline requests happened after the warm-up


@pytest.mark.asyncio
async def test_warmup_point_noop_without_scanner_support():
    t = _tester(warmup_requests=5)  # MockScanner has no .warmup
    assert await t.warmup_point("http://h/x?q=1", "q") == 0


# ---- two-sample confirm_time_based -----------------------------------


@pytest.mark.asyncio
async def test_confirm_needs_every_replay_slow():
    # Endpoint slow on the FIRST replay only, then fast: must NOT confirm.
    state = {"n": 0}

    def responder(method, url, kwargs):
        from conftest import param_value
        p = param_value(url, "q").lower()
        if any(k in p for k in ("sleep", "waitfor")):
            state["n"] += 1
            return {"text": "ok", "elapsed": 5.0 if state["n"] == 1 else 0.1}
        return {"text": "ok", "elapsed": 0.1}

    t = _tester(SQLInjectionTester, MockScanner(responder))
    verdict = await t.confirm_time_based(
        "http://h/x?q=1", "q", "' AND SLEEP(5)--", baseline=0.1, threshold=4.0)
    assert verdict == "LOW"


@pytest.mark.asyncio
async def test_confirm_confirms_when_all_replays_slow():
    def responder(method, url, kwargs):
        from conftest import param_value
        p = param_value(url, "q").lower()
        slow = any(k in p for k in ("sleep", "waitfor"))
        return {"text": "ok", "elapsed": 5.0 if slow else 0.1}

    t = _tester(SQLInjectionTester, MockScanner(responder))
    verdict = await t.confirm_time_based(
        "http://h/x?q=1", "q", "' AND SLEEP(5)--", baseline=0.1, threshold=4.0)
    assert verdict == "CONFIRMED"
