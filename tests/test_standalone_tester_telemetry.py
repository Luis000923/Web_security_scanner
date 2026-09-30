"""Path Traversal / Command Injection / SSRF must record telemetry too.

COVERAGE_AUDIT.md's headline finding: the training/triage dataset has zero
real samples for any class besides SQLi and XSS because the source telemetry
in ``testbed/results/`` only ever contains rows from ``SQLInjectionTester``
and ``XSSTester``. The root cause is upstream of the dataset generator --
``PathTraversalTester`` / ``CommandInjectionTester`` / ``SSRFTester`` never
called ``_emit_telemetry()`` in the first place, so no amount of re-running
the scanner against the testbed could have produced rows for them. These
tests lock in the fix: each tester must record one telemetry row per probe,
independent of whether that probe found anything.
"""
import asyncio

from conftest import MockScanner

from web_security_scanner.events.event_emitter import ScanEventEmitter
from web_security_scanner.modules.vulnerability_testers.command_injection_async import (
    CommandInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.path_traversal_async import (
    PathTraversalTester,
)
from web_security_scanner.modules.vulnerability_testers.ssrf_tester_async import SSRFTester


class FakeTelemetry:
    def __init__(self):
        self.rows = []

    def record(self, row):
        self.rows.append(row)


async def _run_with_telemetry(tester_cls, responder, target="http://t/page?id=1"):
    em = ScanEventEmitter()
    cfg = {"payload_delay": 0, "max_payloads": 4}
    tester = tester_cls(MockScanner(responder), em, cfg)
    telemetry = FakeTelemetry()
    tester.telemetry = telemetry
    await tester.run_test(target)
    return telemetry.rows


def test_path_traversal_emits_telemetry_on_miss():
    rows = asyncio.run(_run_with_telemetry(
        PathTraversalTester, lambda m, u, k: {"text": "nothing interesting here"}))
    assert rows, "PathTraversalTester never called _emit_telemetry"
    assert all(r["tester_id"] == "PathTraversalTester" for r in rows)
    assert all(r["decision"] is False for r in rows)


def test_path_traversal_emits_telemetry_on_hit():
    # This responder leaks the same signature for *every* request, including
    # the double-oracle's benign baseline probe -- an "ambient" leak the
    # payload didn't cause, so the oracle correctly caps confidence at
    # MEDIUM rather than trusting the single-shot signature at face value.
    rows = asyncio.run(_run_with_telemetry(
        PathTraversalTester, lambda m, u, k: {"text": "root:x:0:0:root:/root:/bin/bash"}))
    assert rows and rows[-1]["decision"] is True
    assert rows[-1]["confidence_final"] == "MEDIUM"


def test_path_traversal_confirmed_when_baseline_is_clean():
    # Only a request carrying an actual traversal payload in the query
    # string leaks; the benign baseline value and any non-payload probe
    # come back clean -> both double-oracle checks pass -> CONFIRMED.
    def responder(method, url, kwargs):
        if "etc%2fpasswd" in url.lower() or "etc/passwd" in url.lower() \
                or "win.ini" in url.lower() or "boot.ini" in url.lower():
            return {"text": "root:x:0:0:root:/root:/bin/bash"}
        return {"text": "nothing interesting here"}
    rows = asyncio.run(_run_with_telemetry(PathTraversalTester, responder))
    hits = [r for r in rows if r["decision"] is True]
    assert hits and hits[-1]["confidence_final"] == "CONFIRMED"


def test_command_injection_emits_telemetry_on_miss():
    rows = asyncio.run(_run_with_telemetry(
        CommandInjectionTester, lambda m, u, k: {"text": "a perfectly normal page"}))
    assert rows, "CommandInjectionTester never called _emit_telemetry"
    assert all(r["tester_id"] == "CommandInjectionTester" for r in rows)
    assert all(r["decision"] is False for r in rows)


def test_command_injection_emits_telemetry_on_hit():
    rows = asyncio.run(_run_with_telemetry(
        CommandInjectionTester, lambda m, u, k: {"text": "uid=0(root) gid=0(root)"}))
    assert rows and rows[-1]["decision"] is True
    assert rows[-1]["confidence_final"] == "HIGH"


def test_ssrf_emits_telemetry_on_miss():
    rows = asyncio.run(_run_with_telemetry(
        SSRFTester, lambda m, u, k: {"text": "a perfectly normal page"}))
    assert rows, "SSRFTester never called _emit_telemetry"
    assert all(r["tester_id"] == "SSRFTester" for r in rows)
    assert all(r["decision"] is False for r in rows)


def test_ssrf_emits_telemetry_on_hit():
    rows = asyncio.run(_run_with_telemetry(
        SSRFTester, lambda m, u, k: {"text": "ami-id leaked from metadata service"}))
    assert rows and rows[-1]["decision"] is True
    assert rows[-1]["confidence_final"] == "CRITICAL"
