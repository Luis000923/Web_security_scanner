"""
FASE 3 — El Sistema Nervioso Central.

Chasis de orquestación con LangGraph: conecta los nodos de Recon, Planner y
Validador (Capa Híbrida de la FASE 2) alrededor de un estado global de misión,
con un punto de interrupción nativo (HITL) cuando el Validador enruta un
payload a COLA_HITL.

FASE 5: el planner_node ya no hardcodea payloads — invoca al AdaptiveFuzzer
(agents/fuzzer.py), que comparte el mismo modelo local
(Qwen2.5-1.5B-Instruct-bnb-4bit) cargado una sola vez para el Validador,
evitando duplicar VRAM.

Uso:
    .venv/bin/python orchestrator.py
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, TypedDict
from urllib.parse import urlparse

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from agents import docker_telemetry, recon_scanner
from agents.attacker import BENCHMARK_BASE_URL, RealAttackClient
from agents.fuzzer import AdaptiveFuzzer
from agents.reporter import ReportingAgent
from db.client import GraphDBClient
from load_llm import load_model
from security.validator import HybridPayloadValidator, RiskAssessment

# ============================================================
# ESTADO GLOBAL DE LA MISIÓN
# ============================================================


class AgentState(TypedDict):
    target_domain: str
    discovered_assets: list[str]
    current_payload: str
    validation_status: str  # "EJECUCION_AUTOMATICA" | "COLA_HITL" | "BLOQUEADO" | ""
    human_approval: bool
    # FASE 4: CVE descubierto por recon_node y consumido por planner_node para
    # consultar el Knowledge Graph. Campo añadido de forma retrocompatible:
    # el resto de nodos que no lo usan lo ignoran, y build_graph()/AgentState
    # no rompe ningún consumidor previo del TypedDict.
    discovered_cve: str
    # FASE 5: tecnología descubierta por recon_node, consumida por planner_node
    # para que el AdaptiveFuzzer adapte el payload al stack específico.
    discovered_tech: str
    # FASE 6: evidencia de la ejecución real de attack_node contra el
    # laboratorio (OWASP Benchmark). "" hasta que attack_node corre.
    attack_evidence: str
    # FASE 8: ruta del informe Markdown generado por reporting_node.
    report_path: str
    # FASE 9b: clase de vulnerabilidad resuelta a partir de discovered_tech
    # (_TECH_VULNERABILITY_CLASS_MAP) — determina qué caso de prueba real del
    # laboratorio ataca attack_node y qué vectores pide el planner al Fuzzer.
    vulnerability_class: str
    # FASE 9c: cola de activos reales descubiertos por recon_node
    # (agents/recon_scanner.py) aún sin atacar, y activo que planner_node
    # está planificando/attack_node está atacando en la iteración actual.
    # Permite aplicar el ciclo planner->validator->attack/hitl a TODAS las
    # rutas encontradas, no solo a un único endpoint fijo.
    pending_targets: list[dict[str, str]]
    current_target: dict[str, str]
    # Resultado acumulado por cada activo ya procesado (éxito, fallo,
    # bloqueado o rechazado en HITL) — consumido por reporting_node para
    # documentar el escaneo completo, no solo el último activo atacado.
    attack_results: list[dict[str, Any]]


# ============================================================
# MODELO LOCAL COMPARTIDO (Qwen2.5-1.5B-Instruct-bnb-4bit)
# Cargado UNA sola vez a nivel de proceso y reutilizado tanto por la Capa 2
# del Validador Híbrido (FASE 2) como por el AdaptiveFuzzer (FASE 5) — nunca
# se duplica la huella de VRAM. Si no hay GPU disponible, load_model()
# devuelve (None, None) y ambos componentes caen a su camino fail-safe.
# ============================================================

_llm_model, _llm_tokenizer = load_model()

_validator = HybridPayloadValidator(llm_model=_llm_model, llm_tokenizer=_llm_tokenizer)
_fuzzer = AdaptiveFuzzer(model=_llm_model, tokenizer=_llm_tokenizer)
_reporter = ReportingAgent()

# FASE 8: carpeta de informes de engagement (gitignored — pueden contener
# evidencia sensible de explotación real contra el laboratorio).
_REPORTS_DIR = Path(__file__).resolve().parent / "reports"

# FASE 9b: mapa tecnología descubierta -> clase de vulnerabilidad atacable
# por RealAttackClient (agents/attacker.py). Cualquier tecnología no listada
# cae en "path_traversal" (fail-safe hacia el único caso de prueba sembrado
# hoy en el Knowledge Graph, agents/attacker.py:_execute_path_traversal).
_TECH_VULNERABILITY_CLASS_MAP: dict[str, str] = {
    "apache 2.4.49": "path_traversal",
    "owasp benchmark cmdi": "command_injection",
}
_DEFAULT_VULNERABILITY_CLASS = "path_traversal"

# FASE 9c: tope duro de activos realmente atacados por corrida. El
# laboratorio expone cientos de casos de prueba reales (ver
# agents/recon_scanner.py); cada uno agresivo pasa por COLA_HITL, así que
# sin este tope una corrida requeriría cientos de aprobaciones humanas
# manuales. discovered_assets sigue listando TODO lo encontrado -- este
# límite solo acota cuántos se atacan de verdad.
_MAX_SCAN_TARGETS = 8

# Etiqueta de tecnología usada solo para el prompt del Fuzzer y la búsqueda
# en la base de conocimiento de remediación (agents/reporter.py) -- una por
# vulnerability_class, ya que el escaneo completo no tiene una tecnología
# Neo4j individual por cada activo descubierto por el crawler.
_VULN_CLASS_TECH_LABEL: dict[str, str] = {
    "path_traversal": "Apache 2.4.49",
    "command_injection": "OWASP Benchmark CMDI",
}


# ============================================================
# NODOS
# ============================================================


async def recon_node(state: AgentState) -> AgentState:
    """
    Descubrimiento de superficie de ataque sobre target_domain, escrito
    realmente en el Knowledge Graph (Neo4j) vía GraphDBClient, MÁS (FASE 9c)
    descubrimiento real de rutas/subdominios vía agents/recon_scanner.py
    contra el laboratorio autorizado (mismo host que ataca RealAttackClient),
    para poblar la cola de activos que el ciclo planner->validator->attack
    va a recorrer completo, no solo un único endpoint fijo.

    El hallazgo Neo4j sigue reutilizando deliberadamente los datos seed ya
    presentes en el grafo (Host 10.0.4.12, Apache 2.4.49, CVE-2021-41773)
    para que la consulta estratégica del planner_node encuentre la ruta
    de movimiento lateral hasta el crown_jewel (10.0.4.50) ya sembrada; el
    crawler real es una fuente de activos independiente y adicional.
    """
    discovered = f"api.{state['target_domain']}"
    ip = "10.0.4.12"
    tech = "Apache 2.4.49"
    cve = "CVE-2021-41773"

    with GraphDBClient() as db:
        db.write_recon_data(target_domain=state["target_domain"], ip=ip, cve=cve, tech=tech)

    vulnerability_class = _TECH_VULNERABILITY_CLASS_MAP.get(tech.lower(), _DEFAULT_VULNERABILITY_CLASS)

    lab_host = urlparse(BENCHMARK_BASE_URL).netloc
    try:
        real_assets = await recon_scanner.discover_assets(
            target_domain=lab_host, base_path="/benchmark/", scheme="https"
        )
    except Exception as exc:  # fail-safe: el crawler nunca debe tumbar el pipeline
        print(f"[recon_node] Descubrimiento real falló ({exc!r}), sin activos adicionales.")
        real_assets = []

    pending_targets = [
        {"url": asset.url, "vulnerability_class": asset.vulnerability_class}
        for asset in real_assets[:_MAX_SCAN_TARGETS]
    ]

    print(
        f"[recon_node] Activo descubierto: {discovered} "
        f"(host={ip}, tech={tech}, cve={cve}) -> escrito en Neo4j (MERGE idempotente)"
    )
    print(
        f"[recon_node] Crawler real: {len(real_assets)} activo(s) encontrado(s) en {lab_host} "
        f"({len(pending_targets)} seleccionados para ataque, tope={_MAX_SCAN_TARGETS})"
    )

    discovered_asset_labels = [f"{a['vulnerability_class']}: {a['url']}" for a in pending_targets]

    return {
        **state,
        "discovered_assets": [discovered, *discovered_asset_labels],
        "discovered_cve": cve,
        "discovered_tech": tech,
        "vulnerability_class": vulnerability_class,
        "pending_targets": pending_targets,
        "attack_results": [],
    }


async def planner_node(state: AgentState) -> AgentState:
    """
    El Estratega: consulta la cadena de ataque real en el Knowledge Graph
    para el CVE descubierto por recon_node y decide la intención (agresiva
    vs. pasiva) en función de si existe una ruta de movimiento lateral hasta
    un activo `crown_jewel`. El payload en sí ya no está hardcodeado (FASE 5):
    se le pide al AdaptiveFuzzer que lo genere dinámicamente con el modelo
    local, adaptado a la tecnología descubierta.

      - Ruta encontrada (objetivo_alto_valor no nulo en al menos una fila):
        intención agresiva -> RCE/SQLi con mutación de estado. Se espera que
        el Validador lo enrute a COLA_HITL (blast radius incluye un activo
        crítico).
      - Sin ruta: intención pasiva -> reconocimiento de solo lectura, se
        espera EJECUCION_AUTOMATICA.
    """
    cve = state["discovered_cve"]

    # FASE 9c: siguiente activo de la cola poblada por recon_node. Cada
    # llamada a planner_node consume uno -- el ciclo completo (loop back
    # desde attack_node/blocked_node/rejected_node) vuelve a entrar aquí
    # hasta vaciar pending_targets (ver route_after_attack/etc.).
    pending = state["pending_targets"]
    current_target = pending[0]
    remaining = pending[1:]
    vulnerability_class = current_target["vulnerability_class"]
    tech = _VULN_CLASS_TECH_LABEL.get(vulnerability_class, state["discovered_tech"])

    print(
        f"[planner_node] Planificando payload para {current_target['url']} "
        f"(clase={vulnerability_class}, cve={cve}, "
        f"{len(remaining)} activo(s) restantes tras este)"
    )

    with GraphDBClient() as db:
        rows = db.evaluate_attack_chain(cve)

    print(f"[planner_node] Resultado de la query estratégica para {cve} ({len(rows)} fila(s)):")
    for row in rows:
        print(f"    {row}")

    has_crown_jewel_path = any(row.get("objetivo_alto_valor") is not None for row in rows)

    reason = (
        "existe ruta de movimiento lateral hasta un activo crown_jewel "
        "-> se pide al Fuzzer una intención agresiva para forzar revisión humana (COLA_HITL)"
        if has_crown_jewel_path
        else "no se encontró ruta a ningún activo crown_jewel "
        "-> se pide al Fuzzer una intención pasiva de solo lectura"
    )
    print(f"[planner_node] Intención: {'AGRESIVA' if has_crown_jewel_path else 'PASIVA'} — razón: {reason}")

    payload = _fuzzer.generate_payload(
        technology=tech,
        cve=cve,
        aggressive=has_crown_jewel_path,
        vulnerability_class=vulnerability_class,
    )
    print(f"[planner_node] Payload generado dinámicamente por el Fuzzer: {payload!r}")

    return {
        **state,
        "current_payload": payload,
        "current_target": current_target,
        "pending_targets": remaining,
        "vulnerability_class": vulnerability_class,
    }


async def validator_node(state: AgentState) -> AgentState:
    """Evalúa current_payload con el Validador Híbrido y fija validation_status."""
    assessment: RiskAssessment = _validator.classify(state["current_payload"])
    route = _validator.route(assessment)
    print(
        f"[validator_node] payload={state['current_payload']!r} -> "
        f"category={assessment.category} confidence={assessment.confidence} "
        f"layer={assessment.layer} route={route}"
    )
    return {**state, "validation_status": route}


async def attack_node(state: AgentState) -> AgentState:
    """
    FASE 6 + FASE 9c: ejecuta el payload autorizado de verdad contra el
    laboratorio autorizado (OWASP Benchmark local, contenedor
    `owasp-benchmark`), atacando el activo real (`current_target`)
    descubierto por recon_node/recon_scanner.py, no un único endpoint fijo.
    Se alcanza solo con EJECUCION_AUTOMATICA directa o tras aprobación
    humana en la cola HITL — nunca con un payload no autorizado.
    """
    target = state["current_target"]
    client = RealAttackClient()
    result = await client.execute(
        state["current_payload"],
        vulnerability_class=state["vulnerability_class"],
        test_path=target.get("url"),
    )

    evidence = (
        f"target={result.target_url} status={result.http_status} "
        f"exploited={result.exploited} rationale={result.rationale!r} "
        f"snippet={result.response_snippet!r}"
    )
    print(f"[attack_node] Payload ejecutado contra {target.get('url')}: {state['current_payload']!r}")
    print(f"[attack_node] Evidencia: {evidence}")

    result_entry = {
        "target": target.get("url", "N/A"),
        "vulnerability_class": state["vulnerability_class"],
        "payload": state["current_payload"],
        "validation_status": state["validation_status"],
        "outcome": "EXPLOTADO" if result.exploited else "EJECUTADO_SIN_EXITO",
        "rationale": result.rationale,
    }

    return {
        **state,
        "attack_evidence": evidence,
        "attack_results": [*state["attack_results"], result_entry],
    }


async def blocked_node(state: AgentState) -> AgentState:
    """Nodo terminal para payloads DESTRUCTIVE — nunca ejecuta nada."""
    target = state["current_target"]
    print(f"[blocked_node] Payload bloqueado, no se ejecuta: {state['current_payload']!r}")

    result_entry = {
        "target": target.get("url", "N/A"),
        "vulnerability_class": state["vulnerability_class"],
        "payload": state["current_payload"],
        "validation_status": state["validation_status"],
        "outcome": "BLOQUEADO",
        "rationale": "Bloqueado por el Escudo (categoría DESTRUCTIVE) antes de cualquier ejecución.",
    }
    return {**state, "attack_results": [*state["attack_results"], result_entry]}


async def hitl_node(state: AgentState) -> AgentState:
    """
    Pausa el grafo con `interrupt()` (breakpoint nativo de LangGraph) hasta que
    un humano apruebe o rechace el payload. Al reanudar con `Command(resume=...)`,
    el valor devuelto por `interrupt()` es la decisión humana.
    """
    decision = interrupt(
        {
            "reason": "Payload requiere aprobación humana (COLA_HITL)",
            "payload": state["current_payload"],
            "target": state["target_domain"],
        }
    )
    approved = bool(decision)
    print(f"[hitl_node] Decisión humana recibida: {'APROBADO' if approved else 'RECHAZADO'}")
    return {**state, "human_approval": approved}


async def rejected_node(state: AgentState) -> AgentState:
    """Nodo terminal cuando el humano rechaza el payload en la cola HITL."""
    target = state["current_target"]
    print(f"[rejected_node] Humano rechazó el payload: {state['current_payload']!r}")

    result_entry = {
        "target": target.get("url", "N/A"),
        "vulnerability_class": state["vulnerability_class"],
        "payload": state["current_payload"],
        "validation_status": state["validation_status"],
        "outcome": "RECHAZADO_HITL",
        "rationale": "Un humano rechazó la ejecución en la cola HITL.",
    }
    return {**state, "attack_results": [*state["attack_results"], result_entry]}


async def reporting_node(state: AgentState) -> AgentState:
    """
    FASE 8: cierra el engagement generando un informe Markdown determinista
    (ReportingAgent), consultando la cadena de ataque en vivo desde Neo4j
    (mismo método evaluate_attack_chain() que usa el planner_node) para que
    el informe refleje el grafo real, no una copia estática de lo que vio
    el planner en su momento.

    Se alcanza tanto tras attack_node (ataque ejecutado, éxito o fallo)
    como tras rejected_node (payload abortado en HITL) o blocked_node
    (payload bloqueado por el Escudo antes de cualquier ejecución) — un
    intento abortado también se documenta.
    """
    cve = state.get("discovered_cve", "")
    attack_chain_data: list[dict] = []
    if cve:
        with GraphDBClient() as db:
            attack_chain_data = db.evaluate_attack_chain(cve)

    # FASE 9: telemetría de infraestructura Docker (fail-safe: listas vacías
    # si el daemon no está disponible, nunca lanza).
    containers = docker_telemetry.list_containers()
    container_stats = docker_telemetry.get_container_stats()
    topology = docker_telemetry.get_network_topology()

    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    assets_dir = _REPORTS_DIR / "assets"

    resource_chart_path = docker_telemetry.render_resource_usage_chart(
        container_stats, assets_dir / f"docker_resources_{timestamp}.png"
    )
    topology_chart_path = docker_telemetry.render_network_topology_chart(
        topology, assets_dir / f"docker_topology_{timestamp}.png"
    )

    markdown = _reporter.generate_markdown_report(
        state,
        attack_chain_data,
        containers=containers,
        container_stats=container_stats,
        topology=topology,
        resource_chart_path=resource_chart_path,
        topology_chart_path=topology_chart_path,
        report_dir=_REPORTS_DIR,
    )

    report_path = _REPORTS_DIR / f"engagement_report_{timestamp}.md"
    report_path.write_text(markdown, encoding="utf-8")

    print(f"[reporting_node] Informe generado: {report_path}")
    return {**state, "report_path": str(report_path)}


# ============================================================
# ENRUTAMIENTO CONDICIONAL
# ============================================================


def route_after_validation(state: AgentState) -> Literal["attack_node", "hitl_node", "blocked_node"]:
    status = state["validation_status"]
    if status == "BLOQUEADO":
        return "blocked_node"
    if status == "EJECUCION_AUTOMATICA":
        return "attack_node"
    return "hitl_node"  # COLA_HITL (y cualquier estado no reconocido, fail-safe)


def route_after_hitl(state: AgentState) -> Literal["attack_node", "rejected_node"]:
    return "attack_node" if state["human_approval"] else "rejected_node"


def route_after_recon(state: AgentState) -> Literal["planner_node", "reporting_node"]:
    """FASE 9c: si el crawler no encontró (o no pudo atacar) ningún activo real, saltar directo al informe."""
    return "planner_node" if state["pending_targets"] else "reporting_node"


def route_after_asset_cycle(state: AgentState) -> Literal["planner_node", "reporting_node"]:
    """
    FASE 9c: tras terminar con un activo (atacado, bloqueado o rechazado),
    seguir con el siguiente de la cola o cerrar el engagement si ya no
    quedan activos pendientes. Compartida por attack_node/blocked_node/
    rejected_node -- misma decisión, mismo criterio (pending_targets).
    """
    return "planner_node" if state["pending_targets"] else "reporting_node"


# ============================================================
# CONSTRUCCIÓN Y COMPILACIÓN DEL GRAFO
# ============================================================


def build_graph():
    graph = StateGraph(AgentState)

    graph.add_node("recon_node", recon_node)
    graph.add_node("planner_node", planner_node)
    graph.add_node("validator_node", validator_node)
    graph.add_node("attack_node", attack_node)
    graph.add_node("blocked_node", blocked_node)
    graph.add_node("hitl_node", hitl_node)
    graph.add_node("rejected_node", rejected_node)
    graph.add_node("reporting_node", reporting_node)

    graph.add_edge(START, "recon_node")
    graph.add_conditional_edges(
        "recon_node",
        route_after_recon,
        {"planner_node": "planner_node", "reporting_node": "reporting_node"},
    )
    graph.add_edge("planner_node", "validator_node")

    graph.add_conditional_edges(
        "validator_node",
        route_after_validation,
        {
            "attack_node": "attack_node",
            "hitl_node": "hitl_node",
            "blocked_node": "blocked_node",
        },
    )
    graph.add_conditional_edges(
        "hitl_node",
        route_after_hitl,
        {
            "attack_node": "attack_node",
            "rejected_node": "rejected_node",
        },
    )

    # FASE 9c: los tres nodos terminales de un ciclo por activo vuelven a
    # planner_node mientras queden activos en pending_targets, cerrando en
    # reporting_node solo cuando la cola se vacía (escaneo completo).
    for terminal_node in ("attack_node", "blocked_node", "rejected_node"):
        graph.add_conditional_edges(
            terminal_node,
            route_after_asset_cycle,
            {"planner_node": "planner_node", "reporting_node": "reporting_node"},
        )
    graph.add_edge("reporting_node", END)

    checkpointer = MemorySaver()
    return graph.compile(checkpointer=checkpointer)


# ============================================================
# SCRIPT DE PRUEBA
# ============================================================


async def _main() -> None:
    app = build_graph()

    initial_state: AgentState = {
        "target_domain": "target.com",
        "discovered_assets": [],
        "current_payload": "",  # planner_node lo fija en función de la cadena de ataque real
        "validation_status": "",
        "human_approval": False,
        "discovered_cve": "",
        "discovered_tech": "",
        "attack_evidence": "",
        "report_path": "",
        "vulnerability_class": "",  # recon_node lo fija en función de discovered_tech
        "pending_targets": [],  # recon_node lo puebla con el resultado del crawler real
        "current_target": {},
        "attack_results": [],
    }

    thread_config = {"configurable": {"thread_id": str(uuid.uuid4())}}

    print("=" * 60)
    print("EJECUCIÓN — escaneo completo de todos los activos descubiertos")
    print("=" * 60)

    result = await app.ainvoke(initial_state, config=thread_config)

    # FASE 9c: con múltiples activos en cola, cada uno que el Validador
    # enrute a COLA_HITL dispara su propia pausa -- se resuelven una a una
    # en bucle hasta que el grafo llegue a reporting_node/END sin más
    # interrupciones pendientes.
    round_num = 1
    while "__interrupt__" in result:
        interrupt_payload = result["__interrupt__"][0].value
        print(f"\n>>> GRAFO PAUSADO esperando aprobación humana (ronda {round_num}) <<<")
        print(f"    Motivo:  {interrupt_payload['reason']}")
        print(f"    Payload: {interrupt_payload['payload']}")
        print(f"    Target:  {interrupt_payload['target']}")

        # Simulación de input humano por consola (en un HITL real esto vendría
        # de una UI/ticket de la cola, no de stdin bloqueante).
        human_input = (await asyncio.to_thread(input, "\n¿Aprobar ejecución de este payload? [y/N]: ")).strip().lower()
        approve = human_input == "y"

        print("\n" + "=" * 60)
        print(f"REANUDANDO GRAFO — decisión humana: {'APROBAR' if approve else 'RECHAZAR'}")
        print("=" * 60)

        result = await app.ainvoke(Command(resume=approve), config=thread_config)
        round_num += 1

    print("\nEstado final:", result)
    print(f"\nActivos procesados: {len(result.get('attack_results', []))}")
    for entry in result.get("attack_results", []):
        print(f"  - {entry['target']} ({entry['vulnerability_class']}) -> {entry['outcome']}")


if __name__ == "__main__":
    asyncio.run(_main())
