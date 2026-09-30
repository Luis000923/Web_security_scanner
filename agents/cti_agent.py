"""
FASE 7 — Agente de Inteligencia (CTI Agent).

Ingiere inteligencia de vulnerabilidades y la vuelca al Knowledge Graph
(Neo4j) vía GraphDBClient.ingest_cti_vulnerability(), de forma que el
Estratega (planner_node / evaluate_attack_chain) las descubra exactamente
igual que las vulnerabilidades sembradas por recon_node.

Dos fuentes de feed:
  - fetch_mock_feed(): datos hardcodeados, sin red, para desarrollo/CI.
  - fetch_real_feed(): esqueleto contra la API pública de CIRCL CVE Search
    (https://cve.circl.lu/api/), que no requiere API key (a diferencia de
    NIST NVD, cuyo rate-limit sin key es demasiado agresivo para uso
    interactivo).

Uso:
    .venv/bin/python -m agents.cti_agent
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

from db.client import GraphDBClient

CIRCL_CVE_SEARCH_BASE_URL = "https://cve.circl.lu/api/cve"


@dataclass
class ThreatIntelEntry:
    cve: str
    criticidad: str  # "Alta" | "Media" | "Baja" (alineado con schema.cypher)
    cvss_score: float
    epss_score: float
    cpe: str
    tech_name: str


class CTIIngestionAgent:
    """Consume feeds de vulnerabilidades y los proyecta sobre el Knowledge Graph."""

    def __init__(self, db_client: GraphDBClient) -> None:
        self._db = db_client

    # --------------------------------------------------------------
    # Feeds
    # --------------------------------------------------------------

    def fetch_mock_feed(self) -> list[ThreatIntelEntry]:
        """
        Feed hardcodeado de 3 CVEs recientes con CVSS/EPSS simulados y su
        CPE/tecnología afectada — para pruebas inmediatas sin depender de
        red ni de rate-limits de APIs externas.
        """
        return [
            ThreatIntelEntry(
                cve="CVE-2024-1597",
                criticidad="Alta",
                cvss_score=9.8,
                epss_score=0.91,
                cpe="cpe:2.3:a:pgjdbc:pgjdbc:42.7.1",
                tech_name="PostgreSQL JDBC Driver",
            ),
            ThreatIntelEntry(
                cve="CVE-2023-44487",
                criticidad="Alta",
                cvss_score=7.5,
                epss_score=0.94,
                cpe="cpe:2.3:a:apache:http_server:2.4.57",
                tech_name="Apache HTTP Server (HTTP/2 Rapid Reset)",
            ),
            ThreatIntelEntry(
                cve="CVE-2024-3094",
                criticidad="Alta",
                cvss_score=10.0,
                epss_score=0.97,
                cpe="cpe:2.3:a:xz:xz_utils:5.6.0",
                tech_name="XZ Utils (backdoor de supply-chain)",
            ),
        ]

    def fetch_real_feed(self, product: str, limit: int = 10) -> list[ThreatIntelEntry]:
        """
        Esqueleto contra la API pública de CIRCL CVE Search
        (https://cve.circl.lu/api/cve/<vendor>/<product>). No requiere API
        key, pero SÍ está sujeta a disponibilidad/rate-limit del servicio
        público — pensado para invocarse ocasionalmente, no en un loop
        ajustado.

        `product` debe ser el nombre de producto tal como lo indexa CIRCL
        (ej. "http_server" para Apache). Devuelve una lista vacía si la
        API no responde o el esquema de la respuesta no es el esperado —
        fail-safe: un feed externo caído nunca debe tumbar el pipeline,
        pero tampoco debe fabricar datos falsos.
        """
        try:
            response = requests.get(
                f"{CIRCL_CVE_SEARCH_BASE_URL}/{product}",
                timeout=10,
            )
            response.raise_for_status()
            raw_entries: list[dict[str, Any]] = response.json()
        except (requests.RequestException, ValueError):
            return []

        entries: list[ThreatIntelEntry] = []
        for raw in raw_entries[:limit]:
            try:
                cve_id = raw["id"]
                cvss = float(raw.get("cvss") or 0.0)
                cpe = (raw.get("vulnerable_configuration") or [None])[0] or f"cpe:2.3:a:unknown:{product}:*"
            except (KeyError, TypeError, ValueError):
                continue

            entries.append(
                ThreatIntelEntry(
                    cve=cve_id,
                    criticidad="Alta" if cvss >= 7.0 else "Media" if cvss >= 4.0 else "Baja",
                    cvss_score=cvss,
                    # CIRCL no expone EPSS directamente en este endpoint;
                    # se deja en 0.0 explícito en vez de inventar un valor.
                    epss_score=0.0,
                    cpe=cpe,
                    tech_name=product,
                )
            )
        return entries

    # --------------------------------------------------------------
    # Ingesta al Knowledge Graph
    # --------------------------------------------------------------

    def ingest(self, entries: list[ThreatIntelEntry]) -> int:
        """Vuelca cada entrada al grafo vía GraphDBClient. Devuelve cuántas se ingirieron."""
        count = 0
        for entry in entries:
            self._db.ingest_cti_vulnerability(
                cve=entry.cve,
                criticidad=entry.criticidad,
                cvss_score=entry.cvss_score,
                epss_score=entry.epss_score,
                cpe=entry.cpe,
                tech_name=entry.tech_name,
            )
            print(
                f"[CTIIngestionAgent] Ingerido: {entry.cve} "
                f"(criticidad={entry.criticidad}, cvss={entry.cvss_score}, "
                f"epss={entry.epss_score}, cpe={entry.cpe})"
            )
            count += 1
        return count


if __name__ == "__main__":
    with GraphDBClient() as db:
        agent = CTIIngestionAgent(db_client=db)

        feed = agent.fetch_mock_feed()
        criticos = [entry for entry in feed if entry.criticidad == "Alta"]
        print(f"[cti_agent] Feed mock: {len(feed)} CVEs totales, {len(criticos)} de criticidad Alta")

        ingested = agent.ingest(criticos)
        print(f"[cti_agent] {ingested} vulnerabilidades ingeridas en Neo4j")

        print("[cti_agent] Verificando en el grafo...")
        for entry in criticos:
            rows = db.evaluate_attack_chain(entry.cve)
            print(f"    evaluate_attack_chain({entry.cve!r}) -> {len(rows)} fila(s)")
