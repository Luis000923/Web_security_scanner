"""Una peticion fallida (timeout de lectura) debe reportar el tiempo esperado.

Antes devolvia ``elapsed=0.0``: un objetivo lento para cualquier entrada tenia
una linea base de 0.0s y los testers time-based "confirmaban" un retardo que el
payload no causaba (trampa CMDi BenchmarkTest00907 del OWASP Benchmark).
"""

import asyncio

from web_security_scanner.core.scanner_core_async import AsyncScannerCore, ScanConfig


async def test_peticion_que_expira_reporta_el_tiempo_esperado(monkeypatch):
    core = AsyncScannerCore(ScanConfig(verify_ssl=False, assert_public_target=False))

    async def _slow_then_timeout(*_a, **_k):
        await asyncio.sleep(0.2)
        raise asyncio.TimeoutError("Timeout on reading data from socket")

    monkeypatch.setattr(core, "_request_following", _slow_then_timeout)
    result = await core._request_with_resilience(
        "GET", "http://target/x", True, None, {}, None)
    assert result["status_code"] == 0
    assert result["elapsed"] >= 0.15
