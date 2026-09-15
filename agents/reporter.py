"""
FASE 8 — Agente de Reporte y Remediación (Reporting Agent).

Cierra el ciclo del pipeline: tras un intento de ataque (exitoso, fallido, o
abortado en la cola HITL), genera un informe Markdown determinista que
documenta la cadena de ataque completa (recon -> Neo4j -> fuzzer -> validador
-> ataque/rechazo), pensado para consumo humano (auditoría / cliente del
engagement).

Determinismo: el reporte se construye con f-strings sobre datos ya
existentes en el AgentState y en la fila de `evaluate_attack_chain()` — no
hay generación libre por LLM aquí. Un informe de seguridad no puede variar
de una corrida a otra con los mismos datos de entrada.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# Formato producido por attack_node (orchestrator.py) a partir de
# agents/attacker.py:AttackResult: "target=... status=... exploited=... "
# "rationale='...' snippet='...'". Los valores de rationale/snippet vienen
# entre comillas simples (via !r) y pueden contener espacios.
_EVIDENCE_FIELD_PATTERN = re.compile(
    r"(?P<key>\w+)=(?:'(?P<quoted>[^']*)'|(?P<bare>\S+))"
)

# ============================================================
# Base de conocimiento de remediación por tecnología
# ============================================================
# Heurística determinista, no generada por LLM: mapea el nombre de
# tecnología (tal como lo guarda recon_node/GraphDBClient) a una
# recomendación de remediación concreta a nivel de código/configuración.
# Fallback genérico si la tecnología no está en el mapa.

_REMEDIATION_KNOWLEDGE_BASE: dict[str, str] = {
    "apache 2.4.49": (
        "Actualizar Apache HTTP Server a >= 2.4.51 (parchea CVE-2021-41773/CVE-2021-42013). "
        "Mitigación inmediata: deshabilitar `mod_cgi`/`mod_cgid` si no es imprescindible, y "
        "asegurar `Require all denied` sobre directorios fuera del document root. Añadir "
        "`AllowOverride None` y revisar que `UnixUserDir`/rutas de cgi-bin no acepten "
        "secuencias `../` (validar y canonicalizar rutas antes de abrir el fichero, nunca "
        "confiar en el path tal como llega del cliente)."
    ),
    "apache http server (http/2 rapid reset)": (
        "Actualizar a una versión que mitigue CVE-2023-44487 (HTTP/2 Rapid Reset) y limitar "
        "`Http2MaxConcurrentStreams` / activar rate-limiting a nivel de conexión."
    ),
    "postgresql jdbc driver": (
        "Actualizar pgjdbc a la versión que corrige CVE-2024-1597 (SQL injection vía valores "
        "no saneados en el parseo de queries) y forzar el uso de sentencias preparadas "
        "parametrizadas en toda la capa de acceso a datos."
    ),
    "xz utils (backdoor de supply-chain)": (
        "Purgar inmediatamente cualquier build de xz/liblzma en el rango de versiones "
        "comprometidas (5.6.0/5.6.1, CVE-2024-3094) de todas las imágenes/paquetes; "
        "reconstruir desde una fuente verificada y auditar la cadena de suministro de "
        "dependencias del sistema operativo base."
    ),
}

_GENERIC_REMEDIATION = (
    "Validar y canonicalizar toda entrada de usuario antes de usarla en operaciones de "
    "filesystem/DB/comandos; aplicar el principio de menor privilegio al proceso de la "
    "aplicación; y mantener la tecnología afectada actualizada a la última versión estable "
    "soportada por el proveedor."
)


class ReportingAgent:
    """Genera informes de engagement en Markdown a partir del AgentState y del grafo."""

    def generate_markdown_report(
        self,
        state: dict[str, Any],
        attack_chain_data: list[dict[str, Any]],
    ) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        exploited, evidence_lines = self._parse_attack_evidence(state.get("attack_evidence", ""))
        exec_status = self._executive_status(state, exploited)

        chain_section = self._render_attack_chain(attack_chain_data)
        mitre_section = self._render_mitre(attack_chain_data)
        remediation_section = self._render_remediation(state.get("discovered_tech", ""))

        return f"""# Informe de Engagement — Red Team Autónomo

**Generado:** {timestamp}
**Target:** {state.get('target_domain', 'N/A')}

---

## 1. Resumen Ejecutivo

- **Estado de explotación:** {exec_status}
- **Activo(s) descubierto(s):** {', '.join(state.get('discovered_assets', [])) or 'N/A'}
- **CVE analizado:** {state.get('discovered_cve', 'N/A')}
- **Tecnología afectada:** {state.get('discovered_tech', 'N/A')}
- **Decisión de la cola HITL:** {"Aprobado por humano" if state.get('human_approval') else "Rechazado / no aplicable"}
- **Ruta de validación del Escudo:** `{state.get('validation_status', 'N/A')}`

---

## 2. Cadena de Ataque (Knowledge Graph)

{chain_section}

---

## 3. Payload Utilizado

```
{state.get('current_payload', 'N/A')}
```

**Evidencia de ejecución:**

{evidence_lines}

---

## 4. Tácticas y Técnicas MITRE ATT&CK

{mitre_section}

---

## 5. Estrategia de Remediación

{remediation_section}

---

*Informe generado automáticamente por ReportingAgent (FASE 8). El status de*
*explotación y la evidencia provienen de la ejecución real registrada en*
*`attack_evidence`; la cadena de ataque proviene de una consulta en vivo al*
*Knowledge Graph (Neo4j), no de datos hardcodeados.*
"""

    # --------------------------------------------------------------
    # Helpers de renderizado
    # --------------------------------------------------------------

    @staticmethod
    def _parse_attack_evidence(attack_evidence: str) -> tuple[bool | None, str]:
        """
        Extrae `exploited=True/False` del string de evidencia producido por
        attack_node (agents/attacker.py: AttackResult formateado a texto), y
        devuelve también el bloque completo formateado como cita Markdown.
        Si no hubo ejecución (payload rechazado en HITL), devuelve (None, "").
        """
        if not attack_evidence:
            return None, "*No se ejecutó ningún ataque real (payload rechazado o no alcanzó attack_node).*"

        fields = {
            m.group("key"): m.group("quoted") if m.group("quoted") is not None else m.group("bare")
            for m in _EVIDENCE_FIELD_PATTERN.finditer(attack_evidence)
        }

        exploited_raw = fields.get("exploited")
        exploited = {"True": True, "False": False}.get(exploited_raw)

        formatted = "\n".join(f"- **{key}:** {value}" for key, value in fields.items())
        return exploited, formatted or "*Evidencia presente pero con formato no reconocido.*"

    @staticmethod
    def _executive_status(state: dict[str, Any], exploited: bool | None) -> str:
        if exploited is True:
            return "**ÉXITO** — la explotación fue confirmada contra el objetivo."
        if exploited is False:
            return "**FALLO** — el payload se ejecutó pero no logró explotar la vulnerabilidad."
        if state.get("validation_status") == "BLOQUEADO":
            return "**BLOQUEADO** — el payload fue detenido por el Escudo antes de cualquier ejecución."
        if state.get("validation_status") == "COLA_HITL" and not state.get("human_approval"):
            return "**ABORTADO** — el payload fue rechazado por un humano en la cola HITL."
        return "**INDETERMINADO** — no se registró evidencia de ejecución."

    @staticmethod
    def _render_attack_chain(rows: list[dict[str, Any]]) -> str:
        if not rows:
            return (
                "*No se encontró una cadena de ataque activa en el Knowledge Graph "
                "para este CVE (sin ruta de movimiento lateral hasta un activo crítico "
                "conocido en el momento del engagement).*"
            )

        lines = []
        for row in rows:
            ruta = " → ".join(row.get("ruta_completa") or []) or "N/A"
            lines.append(
                f"- **Host de entrada:** `{row.get('host_entrada', 'N/A')}` "
                f"vía `{row.get('punto_entrada', 'N/A')}`\n"
                f"  - Tecnología vulnerable: {row.get('tecnologia_vulnerable', 'N/A')}\n"
                f"  - CVE: `{row.get('cve', 'N/A')}` "
                f"(EPSS: {row.get('probabilidad_explotacion', 'N/A')})\n"
                f"  - Objetivo de alto valor (`crown_jewel`): "
                f"`{row.get('objetivo_alto_valor') or 'ninguno encontrado'}`\n"
                f"  - Saltos de movimiento lateral: {row.get('saltos_movimiento_lateral', 'N/A')}\n"
                f"  - Ruta completa: `{ruta}`"
            )
        return "\n".join(lines)

    @staticmethod
    def _render_mitre(rows: list[dict[str, Any]]) -> str:
        ttps = sorted({row.get("mitre_ttp") for row in rows if row.get("mitre_ttp")})
        if not ttps:
            return "*Ninguna técnica MITRE ATT&CK asociada encontrada en el Knowledge Graph.*"

        # Mapa mínimo técnica -> nombre/táctica; en el grafo (db/schema.cypher)
        # T1190 ya está sembrado como "Exploit Public-Facing Application" /
        # "Initial Access". Se documenta aquí el mismo par por consistencia
        # de lectura del informe sin depender de una consulta adicional.
        known = {"T1190": ("Exploit Public-Facing Application", "Initial Access")}
        lines = []
        for ttp_id in ttps:
            name, tactic = known.get(ttp_id, ("(no catalogado en este informe)", "N/A"))
            lines.append(f"- **{ttp_id}** — {name} (Táctica: {tactic})")
        return "\n".join(lines)

    @staticmethod
    def _render_remediation(tech: str) -> str:
        if not tech:
            return _GENERIC_REMEDIATION
        recommendation = _REMEDIATION_KNOWLEDGE_BASE.get(tech.strip().lower())
        return recommendation or _GENERIC_REMEDIATION
