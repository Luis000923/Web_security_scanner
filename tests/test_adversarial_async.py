"""
Phase 5 — adversarial / robustness tests for the async core's network reads.

These spin up a *real* local aiohttp server that behaves like a scanner trap:
an endpoint that streams an unbounded body, and a tarpit that stalls before
sending anything. The core must survive both without OOM or a hung worker.
"""

import asyncio

import pytest
from aiohttp import web

from web_security_scanner.core.scanner_core_async import (
    AsyncScannerCore,
    ScanConfig,
    MAX_RESPONSE_SIZE,
)


@pytest.fixture
async def hostile_server():
    """Start a local server with hostile endpoints; yield its base URL."""

    async def infinite(request):
        resp = web.StreamResponse(status=200)
        resp.headers["Content-Type"] = "text/html"
        await resp.prepare(request)
        blob = b"A" * (64 * 1024)
        try:
            while True:
                await resp.write(blob)
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        return resp

    async def tarpit(request):
        await asyncio.sleep(6)  # longer than sock_read / total timeout
        return web.Response(text="too late")

    app = web.Application()
    app.router.add_get("/infinite", infinite)
    app.router.add_get("/tarpit", tarpit)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        await runner.cleanup()


def _core():
    # allow_private_redirects so the 127.0.0.1 target isn't SSRF-blocked.
    return AsyncScannerCore(ScanConfig(
        timeout=5, sock_read_timeout=2, sock_connect_timeout=2,
        allow_private_redirects=True,
    ))


async def test_infinite_stream_is_truncated_at_limit(hostile_server):
    core = _core()
    try:
        res = await core.request("GET", f"{hostile_server}/infinite")
    finally:
        await core.close()

    assert res["status_code"] == 200
    assert res["truncated"] is True
    assert len(res["text"]) == MAX_RESPONSE_SIZE
    assert set(res["text"]) == {"A"}


async def test_tarpit_times_out_gracefully(hostile_server):
    core = _core()
    try:
        res = await core.request("GET", f"{hostile_server}/tarpit")
    finally:
        await core.close()

    # Caught and returned as a soft error, not raised.
    assert res["status_code"] == 0
    assert res["error"]
    assert res["truncated"] is False
