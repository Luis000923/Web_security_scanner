"""
FASE 3 — El Sistema Nervioso Central.

Chasis de orquestación con LangGraph: conecta los nodos de Recon, Planner y
Validador (Capa Híbrida de la FASE 2) alrededor de un estado global de misión,
con un punto de interrupción nativo (HITL) cuando el Validador enruta un
payload a COLA_HITL.

Uso:
    .venv/bin/python orchestrator.py
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Literal, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

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


# ============================================================
# VALIDADOR (Capa Híbrida — FASE 2)
# Instancia única a nivel de módulo: sin llm_model se ejerce el camino
# fail-safe descrito en validator.py (nunca fail-open).
# ============================================================

_validator = HybridPayloadValidator()


# ============================================================
# NODOS
# ============================================================


async def recon_node(state: AgentState) -> AgentState:
    """Simula el descubrimiento de superficie de ataque sobre target_domain."""
    discovered = f"api.{state['target_domain']}"
    print(f"[recon_node] Activo descubierto: {discovered}")
    return {
        **state,
        "discovered_assets": [*state["discovered_assets"], discovered],
    }


async def planner_node(state: AgentState) -> AgentState:
    """Simula la decisión estratégica de qué payload probar contra el asset."""
    print(f"[planner_node] Planificando payload para {state['discovered_assets'][-1]}")
    # El payload ya viene fijado en current_payload por el caller (o un default aquí).
    return state


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
    """Nodo mock de ejecución de ataque (solo alcanzable con EJECUCION_AUTOMATICA)."""
    print(f"[attack_node] Ejecutando payload autorizado: {state['current_payload']!r}")
    return state


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

    graph.add_edge("attack_node", END)
    graph.add_edge("blocked_node", END)
    graph.add_edge("rejected_node", END)

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
        "current_payload": "' OR 1=1--",  # payload "peligroso" -> COLA_HITL (ver FASE 2.4)
        "validation_status": "",
        "human_approval": False,
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
