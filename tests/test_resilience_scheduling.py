"""
Tests for the resilience layer added on top of the async core scheduler:
bounded retries on transient transport failure, per-host adaptive throttling
on 429/503 (honouring ``Retry-After``), and the Phase 3 anomaly engine no
longer scoring a rate-limit response as a vulnerability signal.

Both features default OFF (``max_retries=0``, ``adaptive_throttle=False``),
so every test here opts in explicitly; the historical single-attempt
behaviour is already covered by test_core_async.py.
"""

import asyncio

import pytest

from tests.test_core_async import FakeResponse, make_core
from web_security_scanner.core.scanner_core_async import HostBackoff
from web_security_scanner.modules.vulnerability_testers.base_tester_async import (
    assess_anomaly,
)

pytestmark = pytest.mark.asyncio


async def test_transient_failure_is_retried_and_then_succeeds():
    calls = {"n": 0}

    def handler(method, url, kwargs):
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectionResetError("boom")
        return FakeResponse(200, {}, "ok")

    core = make_core(handler, max_retries=3, retry_backoff_base=0.0, retry_backoff_max=0.0)
    result = await core.request("GET", "http://target.example/")
    assert result["status_code"] == 200
    assert calls["n"] == 3


async def test_retries_are_bounded_then_give_up():
    calls = {"n": 0}

    def handler(method, url, kwargs):
        calls["n"] += 1
        raise ConnectionResetError("boom")

    core = make_core(handler, max_retries=2, retry_backoff_base=0.0, retry_backoff_max=0.0)
    result = await core.request("GET", "http://target.example/")
    assert result["status_code"] == 0
    assert calls["n"] == 3  # first attempt + 2 retries, no more


async def test_without_opt_in_transient_failure_is_not_retried():
    calls = {"n": 0}

    def handler(method, url, kwargs):
        calls["n"] += 1
        raise ConnectionResetError("boom")

    core = make_core(handler)  # max_retries=0 default
    result = await core.request("GET", "http://target.example/")
    assert result["status_code"] == 0
    assert calls["n"] == 1


async def test_429_is_retried_and_backs_off_when_throttle_enabled():
    calls = {"n": 0}

    def handler(method, url, kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeResponse(429, {"Retry-After": "0"}, "slow down")
        return FakeResponse(200, {}, "ok")

    core = make_core(
        handler, max_retries=1, adaptive_throttle=True, throttle_backoff_max=0.01,
    )
    result = await core.request("GET", "http://target.example/a")
    assert result["status_code"] == 200
    assert calls["n"] == 2


async def test_throttle_is_scoped_per_host_not_global():
    """A cooldown on host A must not delay a concurrent request to host B."""
    core = make_core(lambda m, u, k: FakeResponse(200, {}, "ok"), adaptive_throttle=True)
    # Host A is already cooling down hard...
    core._host_backoff.penalize("host-a.example", retry_after="5")
    # ...but a fresh request to an unrelated host must not wait on it.
    elapsed_start = asyncio.get_event_loop().time()
    result = await core.request("GET", "http://host-b.example/")
    elapsed = asyncio.get_event_loop().time() - elapsed_start
    assert result["status_code"] == 200
    assert elapsed < 0.5


async def test_host_backoff_state_is_bounded():
    backoff = HostBackoff(ceiling=1.0, max_hosts=4)
    for i in range(10):
        backoff.penalize(f"host-{i}.example")
    assert len(backoff._state) <= 4


async def test_429_scores_zero_and_is_flagged_throttled_not_a_finding():
    sig = assess_anomaly(
        {"status_code": 429, "text": ""}, {"status_code": 200, "text": ""},
    )
    assert sig.score == 0.0
    assert sig.throttled is True
    assert not sig.interesting


async def test_503_also_flagged_throttled_instead_of_server_error():
    sig = assess_anomaly(
        {"status_code": 503, "text": ""}, {"status_code": 200, "text": ""},
    )
    assert sig.throttled is True
    assert sig.score == 0.0


async def test_500_is_unaffected_and_still_scores_as_server_error():
    sig = assess_anomaly(
        {"status_code": 500, "text": "ok"},
        {"status_code": 200, "text": "ok", "length": 2},
    )
    assert sig.throttled is False
    assert sig.score >= 2.0
    assert any("server-error" in r for r in sig.reasons)
