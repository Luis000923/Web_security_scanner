"""Dedicated unit tests for idor_tester_async.IDORTester.

Complements the alternate-ID smoke coverage in test_testers.py (distinct-
object detection, replay-confirmed CONFIRMED, no-corroboration MEDIUM, 404-
text no-false-positive) with:

* the new authenticated cross-session (A-vs-B) diff, gated on
  ``config['identity_pool']`` (a :class:`~web_security_scanner.core.
  session_async.IdentityPool`-shaped object) — the multi-identity feature
  this file exists to pin down;
* echo-vs-no-echo confidence-tier edge cases for the pre-existing alternate-ID
  path that were not yet covered explicitly.
"""

from typing import Any

from conftest import MockScanner, collect_vulns, param_value

from web_security_scanner.events.event_emitter import ScanEventEmitter
from web_security_scanner.modules.vulnerability_testers.idor_tester_async import IDORTester

TARGET = "http://target/page?q=1&id=1"


class _FakeSecondaryCore:
    """Stand-in for the ``AsyncScannerCore`` a secondary identity in
    ``IdentityPool`` owns. Same request-dict contract as ``MockScanner``."""

    def __init__(self, responder):
        self._responder = responder
        self.calls: list[str] = []

    async def request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(url)
        resp = self._responder(method, url, kwargs)
        resp.setdefault("status_code", 200)
        resp.setdefault("text", "")
        return resp


class _FakeIdentityPool:
    """Stand-in for ``session_async.IdentityPool``: exposes exactly the
    surface ``IDORTester._cross_session_check`` consumes (``secondary_roles``
    + ``get``), nothing else — keeps this test decoupled from the pool's real
    login/transport machinery, which is covered separately in
    test_session_async.py."""

    def __init__(self, secondary: dict[str, Any]):
        self._cores = {role: _FakeSecondaryCore(r) for role, r in secondary.items()}

    @property
    def secondary_roles(self) -> list[str]:
        return sorted(self._cores)

    def get(self, role: str):
        return self._cores.get(role)


def _tester(responder, *, identity_pool=None) -> tuple[IDORTester, list[dict], ScanEventEmitter]:
    from web_security_scanner.events.event_emitter import ScanEventType
    em = ScanEventEmitter()
    found: list[dict] = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k.get("vulnerability")))
    cfg: dict[str, Any] = {"payload_delay": 0, "max_payloads": 8}
    if identity_pool is not None:
        cfg["identity_pool"] = identity_pool
    tester = IDORTester(MockScanner(responder), em, cfg)
    return tester, found, em


DATA_BODY = "email owner@corp.com username owner profile " + "x" * 100


# ---- cross-session A-vs-B diff -----------------------------------------------

async def test_cross_session_confirmed_when_second_identity_reads_same_data():
    def primary_r(m, u, kw):
        return {"status_code": 200, "text": DATA_BODY}
    def role_b_r(m, u, kw):
        return {"status_code": 200, "text": DATA_BODY}

    pool = _FakeIdentityPool({"B": role_b_r})
    tester, found, _ = _tester(primary_r, identity_pool=pool)
    await tester.run_test(TARGET)

    assert len(found) == 1
    assert found[0]["confidence"] == "CONFIRMED"
    assert found[0]["payload"] == "cross-session:B"
    assert found[0]["url"] == TARGET


async def test_cross_session_no_finding_when_second_identity_properly_isolated():
    def primary_r(m, u, kw):
        return {"status_code": 200, "text": DATA_BODY}
    def role_b_r(m, u, kw):
        # Role B's own (different) data, or an access-denied page: not a hit.
        return {"status_code": 403, "text": "forbidden"}

    pool = _FakeIdentityPool({"B": role_b_r})
    tester, found, _ = _tester(primary_r, identity_pool=pool)
    await tester.run_test(TARGET)

    assert found == []


async def test_cross_session_no_finding_when_content_materially_differs():
    def primary_r(m, u, kw):
        return {"status_code": 200, "text": DATA_BODY}
    def role_b_r(m, u, kw):
        # 200 + data-bearing, but a clearly different (much shorter) resource
        # -- role B looking at their own profile, not owner's.
        return {"status_code": 200, "text": "email bob@corp.com"}

    pool = _FakeIdentityPool({"B": role_b_r})
    tester, found, _ = _tester(primary_r, identity_pool=pool)
    await tester.run_test(TARGET)

    assert found == []


async def test_cross_session_skips_alternate_id_sweep_once_confirmed():
    """Once the strongest (cross-session) signal fires, the noisier
    alternate-ID sweep must not run at all -- exactly one probe per
    identity, not one per test id."""
    primary_calls = {"n": 0}
    def primary_r(m, u, kw):
        primary_calls["n"] += 1
        return {"status_code": 200, "text": DATA_BODY}
    def role_b_r(m, u, kw):
        return {"status_code": 200, "text": DATA_BODY}

    pool = _FakeIdentityPool({"B": role_b_r})
    tester, found, _ = _tester(primary_r, identity_pool=pool)
    await tester.run_test(TARGET)

    assert len(found) == 1
    assert primary_calls["n"] == 1                       # no alternate-ID sweep
    assert pool._cores["B"].calls == [TARGET]             # single B probe


async def test_no_identity_pool_falls_back_to_alternate_id_heuristic():
    """No ``identity_pool`` in config (the common case): behaviour is
    byte-identical to the pre-multi-identity single-session heuristic."""
    def r(m, u, kw):
        idv = param_value(u, "id")
        if idv == "benign_baseline_123":
            return {"status_code": 200, "text": "profile baseline"}
        return {"status_code": 200, "text": f"email user{idv}@corp.com username u{idv} " + "x" * 100}

    found = await collect_vulns(IDORTester, r, target=TARGET)
    assert len(found) == 1
    assert found[0]["payload"] != "cross-session:B"


async def test_cross_session_noop_when_primary_response_not_data_bearing():
    """Primary identity's own response carries no data indicator (e.g. an
    empty shell / redirect page) -- nothing meaningful to diff, so the check
    must not even ask the secondary identity."""
    def primary_r(m, u, kw):
        return {"status_code": 200, "text": "ok"}
    def role_b_r(m, u, kw):
        raise AssertionError("role B must not be probed when the primary "
                              "response has no data indicator")

    pool = _FakeIdentityPool({"B": role_b_r})
    tester, found, _ = _tester(primary_r, identity_pool=pool)
    await tester.run_test(TARGET)

    assert found == []


async def test_cross_session_unreachable_role_is_skipped_not_crashed():
    """``pool.get(role)`` returning ``None`` (identity failed to start /
    login rejected) must be a silent skip, not an exception."""
    def primary_r(m, u, kw):
        return {"status_code": 200, "text": DATA_BODY}

    class _PoolWithDeadRole:
        secondary_roles = ["B"]
        def get(self, role):
            return None

    tester, found, _ = _tester(primary_r, identity_pool=_PoolWithDeadRole())
    await tester.run_test(TARGET)  # must not raise
    assert found == []


# ---- alternate-ID confidence edge cases (pre-existing heuristic) ------------

async def test_alternate_id_medium_downgrades_without_echo_or_replay_match():
    def r(m, u, kw):
        idv = param_value(u, "id")
        if idv == "benign_baseline_123":
            return {"status_code": 200, "text": "profile baseline"}
        # Data-bearing, but neither the id string nor a stable replay.
        return {"status_code": 200, "text": "email someone@corp.com " + "x" * 100}

    found = await collect_vulns(IDORTester, r, target=TARGET)
    assert len(found) == 1
    assert found[0]["confidence"] == "MEDIUM"


async def test_alternate_id_no_finding_without_data_indicator():
    """A different, longer body that carries none of DATA_INDICATORS must not
    be reported -- the length/content diff alone isn't sufficient."""
    def r(m, u, kw):
        idv = param_value(u, "id")
        if idv == "benign_baseline_123":
            return {"status_code": 200, "text": "baseline"}
        return {"status_code": 200, "text": "totally unrelated content " + "y" * 200}

    found = await collect_vulns(IDORTester, r, target=TARGET)
    assert found == []
