"""
Script de demostración (no es un test suite formal) para HybridPayloadValidator.

Instancia el validador SIN modelo LLM (llm_model=None) para ejercitar el
camino fail-safe cuando la Capa 1 (determinista) no resuelve un payload y
la Capa 2 (juez semántico) no está disponible.

Los payloads usados son fixtures benignos de triaje (fragmentos de texto),
no ataques reales — sirven solo para validar el comportamiento del
clasificador defensivo.

Ejecutar con: .venv/bin/python test_validator.py
"""

from security.validator import HybridPayloadValidator, RiskCategory

TEST_PAYLOADS = [
    "' OR 1=1--",
    "",
    "(a+)+$",
]


def print_case(payload: str, index: int) -> None:
    validator = HybridPayloadValidator()  # llm_model=None -> Capa 2 en modo fail-safe
    assessment = validator.classify(payload)
    route = validator.route(assessment)

    print(f"--- Caso {index} ---")
    print(f"Payload:     {payload!r}")
    print(f"Category:    {assessment.category}")
    print(f"Confidence:  {assessment.confidence}")
    print(f"Layer:       {assessment.layer}")
    print(f"Rationale:   {assessment.rationale}")
    print(f"Route:       {route}")
    print()

    return assessment, route


def main() -> None:
    print("=" * 60)
    print("Demostración HybridPayloadValidator (llm_model=None)")
    print("=" * 60)
    print()

    for i, payload in enumerate(TEST_PAYLOADS, start=1):
        assessment, route = print_case(payload, i)

        # Aserciones suaves solo donde el comportamiento está 100% garantizado
        # por el código de validator.py cuando el LLM es None:
        # DESTRUCTIVE y SAFE_READ nunca producen la ruta COLA_HITL.
        if payload == "(a+)+$":
            assert assessment.category == RiskCategory.AMPLIFICATION_DOS
            assert route == "COLA_HITL"

    print("Demostración completada sin errores.")


if __name__ == "__main__":
    main()
