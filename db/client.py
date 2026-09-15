"""
FASE 4 — El Cerebro conectado al Sistema Nervioso.

Cliente de acceso al Knowledge Graph (Neo4j) usado por los nodos reales del
orchestrator (recon_node / planner_node). Encapsula:

  - Escritura idempotente de hallazgos de recon (Host/Technology/Vulnerability
    + relaciones RUNS/AFFECTED_BY).
  - Ejecución de la query estratégica (db/strategic_queries.cypher, leída de
    disco, nunca hardcodeada) para evaluar si una CVE abre una cadena de
    ataque hasta un activo `crown_jewel`.

Fail-safe > fail-silent: si Neo4j no está disponible o la query falla, este
cliente propaga la excepción explícitamente en vez de devolver datos vacíos o
falsos negativos silenciosos (un `[]` fantasma aquí podría hacer que el
Planner subestime el riesgo de una cadena real).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError, ServiceUnavailable

_STRATEGIC_QUERY_PATH = Path(__file__).resolve().parent / "strategic_queries.cypher"


class GraphDBConnectionError(RuntimeError):
    """Neo4j no está disponible o rechazó la conexión/autenticación."""


class GraphDBClient:
    """Cliente delgado sobre el driver oficial `neo4j` para el Knowledge Graph."""

    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
    ) -> None:
        self._uri = uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        self._user = user or os.environ.get("NEO4J_USER", "neo4j")
        self._password = password or os.environ.get("NEO4J_PASSWORD", "redteam_dev_pw")

        try:
            self._driver = GraphDatabase.driver(self._uri, auth=(self._user, self._password))
            # verify_connectivity() fuerza un round-trip real ahora, en vez de
            # descubrir en el primer .execute_query() de un nodo del grafo que
            # Neo4j estaba caído (fail-safe: queremos fallar aquí, temprano y
            # explícito, no en medio de una decisión de ataque).
            self._driver.verify_connectivity()
        except (ServiceUnavailable, Neo4jError) as exc:
            raise GraphDBConnectionError(
                f"No se pudo conectar a Neo4j en {self._uri!r}: {exc}"
            ) from exc

    # --------------------------------------------------------------
    # Context manager
    # --------------------------------------------------------------

    def __enter__(self) -> "GraphDBClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def close(self) -> None:
        self._driver.close()

    # --------------------------------------------------------------
    # Heurística CPE
    # --------------------------------------------------------------

    @staticmethod
    def _derive_cpe(tech: str) -> str:
        """
        Deriva un CPE 2.3 simplificado a partir de un string "Vendor Product Version"
        o "Product Version" de forma heurística, ej.:

            "Apache 2.4.49"        -> cpe:2.3:a:apache:http_server:2.4.49
            "nginx 1.18.0"         -> cpe:2.3:a:nginx:nginx:1.18.0
            "Foo Bar 1.2.3"        -> cpe:2.3:a:foo:foo_bar:1.2.3 (fallback genérico)

        Esto NO es un resolver CPE real (no consulta el diccionario NVD), es
        solo suficiente para mantener consistencia de nodos Technology dentro
        del grafo de este laboratorio. Casos conocidos (Apache) se mapean a
        su vendor/product real; el resto cae en un fallback determinista
        vendor=primera_palabra, product=slug(nombre_completo_sin_version).
        """
        tech = tech.strip()
        match = re.match(r"^(.*?)\s+([\d][\w.\-]*)$", tech)
        if match:
            name_part, version = match.group(1).strip(), match.group(2).strip()
        else:
            name_part, version = tech, "0"

        known_vendors = {
            "apache": ("apache", "http_server"),
            "nginx": ("nginx", "nginx"),
        }
        key = name_part.lower().split()[0] if name_part else "unknown"
        if key in known_vendors:
            vendor, product = known_vendors[key]
        else:
            vendor = key
            product = re.sub(r"[^a-z0-9]+", "_", name_part.lower()).strip("_") or "unknown"

        return f"cpe:2.3:a:{vendor}:{product}:{version}"

    # --------------------------------------------------------------
    # Escritura de hallazgos de Recon
    # --------------------------------------------------------------

    def write_recon_data(self, target_domain: str, ip: str, cve: str, tech: str) -> None:
        """
        MERGE idempotente de Host/Technology/Vulnerability + relaciones
        (Host)-[:RUNS]->(Technology)-[:AFFECTED_BY]->(Vulnerability).

        Idempotente: correr esto N veces con los mismos argumentos no crea
        nodos ni relaciones duplicados (MERGE por clave única en cada caso).
        """
        cpe = self._derive_cpe(tech)
        tech_name, _, tech_version = tech.rpartition(" ")
        tech_name = tech_name or tech

        query = """
        MERGE (h:Host {ip: $ip})
        ON CREATE SET h.first_seen = datetime()
        SET h.last_seen = datetime(),
            h.hostname = coalesce(h.hostname, $target_domain)

        MERGE (t:Technology {cpe: $cpe})
        SET t.name = $tech_name, t.version = $tech_version

        MERGE (v:Vulnerability {cve: $cve})

        MERGE (h)-[:RUNS]->(t)
        MERGE (t)-[:AFFECTED_BY]->(v)
        """
        try:
            self._driver.execute_query(
                query,
                ip=ip,
                target_domain=target_domain,
                cpe=cpe,
                tech_name=tech_name,
                tech_version=tech_version,
                cve=cve,
                database_="neo4j",
            )
        except (ServiceUnavailable, Neo4jError) as exc:
            raise GraphDBConnectionError(
                f"Fallo escribiendo recon data en Neo4j (host={ip}, cve={cve}): {exc}"
            ) from exc

    # --------------------------------------------------------------
    # Evaluación de cadena de ataque estratégica
    # --------------------------------------------------------------

    def evaluate_attack_chain(self, cve_id: str) -> list[dict[str, Any]]:
        """
        Lee db/strategic_queries.cypher desde disco y la ejecuta con
        {"cve_id": cve_id}. Devuelve una lista de dicts, uno por fila,
        con las columnas ya definidas por la query (host_entrada,
        punto_entrada, tecnologia_vulnerable, cve, probabilidad_explotacion,
        mitre_ttp, objetivo_alto_valor, saltos_movimiento_lateral,
        ruta_completa).
        """
        if not _STRATEGIC_QUERY_PATH.exists():
            raise FileNotFoundError(
                f"No se encontró la query estratégica en {_STRATEGIC_QUERY_PATH}"
            )
        query_text = _STRATEGIC_QUERY_PATH.read_text(encoding="utf-8")

        try:
            records, _summary, _keys = self._driver.execute_query(
                query_text,
                cve_id=cve_id,
                database_="neo4j",
            )
        except (ServiceUnavailable, Neo4jError) as exc:
            raise GraphDBConnectionError(
                f"Fallo evaluando cadena de ataque para {cve_id!r}: {exc}"
            ) from exc

        return [record.data() for record in records]

    # --------------------------------------------------------------
    # Ingesta CTI (FASE 7)
    # --------------------------------------------------------------

    def ingest_cti_vulnerability(
        self,
        cve: str,
        criticidad: str,
        cvss_score: float,
        epss_score: float,
        cpe: str,
        tech_name: str | None = None,
        source: str = "CTI_AGENT",
    ) -> None:
        """
        MERGE idempotente de Vulnerability (con severidad/CVSS/EPSS) y
        Technology (por CPE, ya resuelto por el propio feed CTI, sin pasar
        por la heurística `_derive_cpe`), más la relación
        (Technology)-[:AFFECTED_BY]->(Vulnerability) — el mismo patrón de
        `write_recon_data`, para que planner_node/evaluate_attack_chain
        encuentren estas vulnerabilidades exactamente igual que las
        sembradas por recon_node.

        No crea ningún Host: la ingesta CTI aporta conocimiento de
        amenazas a nivel de tecnología, independiente de qué host de nuestra
        superficie corra esa tecnología (esa asociación ya la hace
        write_recon_data vía RUNS).
        """
        query = """
        MERGE (v:Vulnerability {cve: $cve})
        SET v.criticidad = $criticidad,
            v.cvss_score = $cvss_score,
            v.epss_score = $epss_score,
            v.source = $source,
            v.ingested_at = datetime()

        MERGE (t:Technology {cpe: $cpe})
        ON CREATE SET t.name = coalesce($tech_name, $cpe)

        MERGE (t)-[:AFFECTED_BY]->(v)
        """
        try:
            self._driver.execute_query(
                query,
                cve=cve,
                criticidad=criticidad,
                cvss_score=cvss_score,
                epss_score=epss_score,
                cpe=cpe,
                tech_name=tech_name,
                source=source,
                database_="neo4j",
            )
        except (ServiceUnavailable, Neo4jError) as exc:
            raise GraphDBConnectionError(
                f"Fallo ingiriendo CTI en Neo4j (cve={cve}, cpe={cpe}): {exc}"
            ) from exc
