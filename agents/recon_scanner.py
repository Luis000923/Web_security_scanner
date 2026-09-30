"""
FASE 9c — Recon real: descubrimiento de rutas y subdominios.

Sustituye el activo único hardcodeado de `recon_node` por un descubrimiento
real: enumera subdominios comunes (best-effort) del host objetivo y crawlea
cada uno buscando enlaces a casos de prueba reconocibles del laboratorio
(convención documentada de OWASP Benchmark: el último segmento de la URL de
cada caso de prueba, `BenchmarkTestXXXXX`, es también el nombre del
header/cookie que el servlet lee sin sanitizar — verificado manualmente
contra el código fuente de varios casos antes de automatizarlo).

Diseño acotado y fail-safe (no reemplaza a `web_security_scanner/`, que es
la herramienta de recon completa del proyecto): un crawler BFS mínimo,
mismo origen, con límites duros de profundidad/cantidad de URLs. Cualquier
error de red se ignora por host — nunca lanza fuera de `discover_assets`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

# Prefijos de subdominio comunes para un descubrimiento best-effort vía DNS
# antes de crawlear -- no reemplaza una herramienta de OSINT dedicada
# (ver web_security_scanner/modules/recon/ para eso).
_COMMON_SUBDOMAIN_PREFIXES = ("www", "api", "app", "admin", "dev", "staging", "test", "portal")

# Patrón de ruta -> clase de vulnerabilidad, por convención de directorio de
# OWASP Benchmark (.../<categoria>-NN/BenchmarkTestXXXXX).
_VULN_CLASS_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"/pathtraver-\d+/"), "path_traversal"),
    (re.compile(r"/cmdi-\d+/"), "command_injection"),
)
_TEST_CASE_PATTERN = re.compile(r"/(BenchmarkTest\d+)(?:\.html)?(?:\?.*)?$")


@dataclass
class DiscoveredAsset:
    # Ruta absoluta del endpoint real de ataque (sin ".html", sin query
    # string) — lista para pasarse directamente a RealAttackClient.execute().
    url: str
    vulnerability_class: str


def classify_vulnerability_class(path: str) -> str | None:
    for pattern, vuln_class in _VULN_CLASS_PATTERNS:
        if pattern.search(path):
            return vuln_class
    return None


def _normalize_test_case_url(base_url: str, href: str) -> str | None:
    """
    Resuelve un href relativo/absoluto a la URL real del endpoint de ataque
    (sin '.html', sin query string) si apunta a un caso de prueba
    reconocible; None en cualquier otro caso (assets estáticos, páginas de
    índice de categoría, links externos).
    """
    absolute = urljoin(base_url, href)
    parsed = urlparse(absolute)
    if parsed.netloc != urlparse(base_url).netloc:
        return None
    if not _TEST_CASE_PATTERN.search(parsed.path):
        return None
    clean_path = parsed.path[:-5] if parsed.path.endswith(".html") else parsed.path
    return f"{parsed.scheme}://{parsed.netloc}{clean_path}"


async def _crawl(
    session: aiohttp.ClientSession, start_url: str, max_depth: int, max_urls: int
) -> list[DiscoveredAsset]:
    visited: set[str] = set()
    discovered: dict[str, DiscoveredAsset] = {}
    queue: list[tuple[str, int]] = [(start_url, 0)]
    start_netloc = urlparse(start_url).netloc

    while queue and len(visited) < max_urls:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            async with session.get(url, ssl=False) as response:
                if response.status != 200:
                    continue
                if "text/html" not in response.headers.get("Content-Type", ""):
                    continue
                body = await response.text()
        except (aiohttp.ClientError, asyncio.TimeoutError):
            continue

        soup = BeautifulSoup(body, "html.parser")
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"]

            test_case_url = _normalize_test_case_url(url, href)
            if test_case_url:
                vuln_class = classify_vulnerability_class(test_case_url)
                if vuln_class and test_case_url not in discovered:
                    discovered[test_case_url] = DiscoveredAsset(test_case_url, vuln_class)
                continue  # hoja: no se sigue crawleando un endpoint de test case

            if depth >= max_depth:
                continue
            absolute = urljoin(url, href).split("#")[0]
            parsed = urlparse(absolute)
            if parsed.netloc != start_netloc or parsed.scheme not in ("http", "https"):
                continue
            if absolute not in visited:
                queue.append((absolute, depth + 1))

    return list(discovered.values())


async def _resolve_live_subdomains(domain: str, scheme: str, timeout: aiohttp.ClientTimeout) -> list[str]:
    """Best-effort: de los prefijos comunes, cuáles responden HTTP(S) hoy."""
    host_only = domain.split(":")[0]
    try:
        ipaddress.ip_address(host_only)
        return []  # es una IP -> no aplica enumeración de subdominios
    except ValueError:
        pass
    if host_only == "localhost":
        return []

    candidates = [f"{prefix}.{domain}" for prefix in _COMMON_SUBDOMAIN_PREFIXES]
    live: list[str] = []

    connector = aiohttp.TCPConnector(ssl=False)  # NOSONAR – recon scanner must probe hosts with invalid/self-signed certs
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:

        async def _check(host: str) -> None:
            try:
                async with session.head(f"{scheme}://{host}", ssl=False, allow_redirects=True) as resp:  # NOSONAR – intentional: subdomain discovery probes untrusted certs
                    if resp.status < 500:
                        live.append(host)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

        await asyncio.gather(*(_check(host) for host in candidates))

    return live


async def discover_assets(
    target_domain: str,
    base_path: str = "/",
    scheme: str = "https",
    max_depth: int = 3,
    max_urls: int = 200,
    timeout_seconds: float = 8.0,
) -> list[DiscoveredAsset]:
    """
    Descubrimiento real de rutas/subdominios: intenta enumerar subdominios
    comunes de `target_domain`, y crawlea cada host vivo (incluido el
    propio `target_domain`) buscando enlaces a casos de prueba reconocibles.
    """
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    hosts = [target_domain, *await _resolve_live_subdomains(target_domain, scheme, timeout)]

    all_assets: dict[str, DiscoveredAsset] = {}
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        for host in hosts:
            start_url = f"{scheme}://{host}{base_path}"
            try:
                for asset in await _crawl(session, start_url, max_depth=max_depth, max_urls=max_urls):
                    all_assets[asset.url] = asset
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue

    return list(all_assets.values())
