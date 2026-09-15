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
from typing import Literal, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from agents.attacker import RealAttackClient
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


# ============================================================
# NODOS
# ============================================================


async def recon_node(state: AgentState) -> AgentState:
    """
    Descubrimiento de superficie de ataque sobre target_domain, escrito
    realmente en el Knowledge Graph (Neo4j) vía GraphDBClient.

    El hallazgo simulado reutiliza deliberadamente los datos seed ya
    presentes en el grafo (Host 10.0.4.12, Apache 2.4.49, CVE-2021-41773)
    para que la consulta estratégica del planner_node encuentre la ruta
    de movimiento lateral hasta el crown_jewel (10.0.4.50) ya sembrada.
    """
    discovered = f"api.{state['target_domain']}"
    ip = "10.0.4.12"
    tech = "Apache 2.4.49"
    cve = "CVE-2021-41773"

    with GraphDBClient() as db:
        db.write_recon_data(target_domain=state["target_domain"], ip=ip, cve=cve, tech=tech)

    print(
        f"[recon_node] Activo descubierto: {discovered} "
        f"(host={ip}, tech={tech}, cve={cve}) -> escrito en Neo4j (MERGE idempotente)"
    )
    return {
        **state,
        "discovered_assets": [*state["discovered_assets"], discovered],
        "discovered_cve": cve,
        "discovered_tech": tech,
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
    tech = state["discovered_tech"]
    print(f"[planner_node] Planificando payload para {state['discovered_assets'][-1]} (cve={cve})")

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

    payload = _fuzzer.generate_payload(technology=tech, cve=cve, aggressive=has_crown_jewel_path)
    print(f"[planner_node] Payload generado dinámicamente por el Fuzzer: {payload!r}")

    return {**state, "current_payload": payload}


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
    FASE 6: ejecuta el payload autorizado de verdad contra el laboratorio
    autorizado (OWASP Benchmark local, contenedor `owasp-benchmark`),
    usando el caso de prueba real pathtraver-00/BenchmarkTest00001. Se
    alcanza solo con EJECUCION_AUTOMATICA directa o tras aprobación humana
    en la cola HITL — nunca con un payload no autorizado.
    """
    client = RealAttackClient()
    result = await client.execute(state["current_payload"])

    evidence = (
        f"target={result.target_url} status={result.http_status} "
        f"exploited={result.exploited} rationale={result.rationale!r} "
        f"snippet={result.response_snippet!r}"
    )
    print(f"[attack_node] Payload ejecutado contra el laboratorio: {state['current_payload']!r}")
    print(f"[attack_node] Evidencia: {evidence}")

    return {**state, "attack_evidence": evidence}


async def blocked_node(state: AgentState) -> AgentState:
    """Nodo terminal para payloads DESTRUCTIVE — nunca ejecuta nada."""
    print(f"[blocked_node] Payload bloqueado, no se ejecuta: {state['current_payload']!r}")
    return state


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
    print(f"[rejected_node] Humano rechazó el payload: {state['current_payload']!r}")
    return state


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

    markdown = _reporter.generate_markdown_report(state, attack_chain_data)

    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
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
    graph.add_edge("recon_node", "planner_node")
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

    graph.add_edge("attack_node", "reporting_node")
    graph.add_edge("blocked_node", "reporting_node")
    graph.add_edge("rejected_node", "reporting_node")
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
    }

    thread_config = {"configurable": {"thread_id": str(uuid.uuid4())}}

    print("=" * 60)
    print("PRIMERA EJECUCIÓN — hasta el punto de interrupción HITL")
    print("=" * 60)

    result = await app.ainvoke(initial_state, config=thread_config)

    if "__interrupt__" in result:
        interrupt_payload = result["__interrupt__"][0].value
        print("\n>>> GRAFO PAUSADO esperando aprobación humana <<<")
        print(f"    Motivo:  {interrupt_payload['reason']}")
        print(f"    Payload: {interrupt_payload['payload']}")
        print(f"    Target:  {interrupt_payload['target']}")

        # Simulación de input humano por consola (en un HITL real esto vendría
        # de una UI/ticket de la cola, no de stdin bloqueante).
        human_input = input("\n¿Aprobar ejecución de este payload? [y/N]: ").strip().lower()
        approve = human_input == "y"

        print("\n" + "=" * 60)
        print(f"REANUDANDO GRAFO — decisión humana: {'APROBAR' if approve else 'RECHAZAR'}")
        print("=" * 60)

        final_state = await app.ainvoke(Command(resume=approve), config=thread_config)
        print("\nEstado final:", final_state)
    else:
        print("\nEl grafo terminó sin pasar por HITL. Estado final:", result)


if __name__ == "__main__":
    asyncio.run(_main())
