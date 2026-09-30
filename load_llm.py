"""
Carga en memoria el juez semántico de la Capa 2 (FASE 2) y lo inyecta en
HybridPayloadValidator para repetir el triaje de los 3 casos de la FASE 2.4,
esta vez con el LLM real disponible en lugar del camino fail-safe.

Modelo: unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit (4-bit, ~1.2GB VRAM residente).
Pensado para GPUs de 6GB — el modelo se carga UNA sola vez a nivel de proceso.

Uso:
    .venv/bin/python load_llm.py
"""

from __future__ import annotations

import sys

from security.validator import HybridPayloadValidator

MODEL_ID = "unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit"

TEST_PAYLOADS = [
    "' OR 1=1--",
    "",
    "(a+)+$",
]


def load_model():
    """Descarga (si hace falta) y carga el modelo en 4-bit sobre GPU."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    if not torch.cuda.is_available():
        print("[load_llm] Aviso: no se detecta CUDA; la carga en 4-bit requiere GPU. Abortando.",
              file=sys.stderr)
        return None, None

    quant_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    print(f"[load_llm] Descargando/cargando {MODEL_ID} en 4-bit...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        quantization_config=quant_config,
        device_map="auto",
    )
    print("[load_llm] Modelo cargado.")
    return model, tokenizer


def main() -> None:
    model, tokenizer = load_model()
    if model is None:
        print("[load_llm] Continuando con llm_model=None (se probará el camino fail-safe).")

    validator = HybridPayloadValidator(llm_model=model, llm_tokenizer=tokenizer)

    for payload in TEST_PAYLOADS:
        assessment = validator.classify(payload)
        route = validator.route(assessment)
        print("-" * 60)
        print(f"payload:    {payload!r}")
        print(f"category:   {assessment.category}")
        print(f"confidence: {assessment.confidence}")
        print(f"layer:      {assessment.layer}")
        print(f"rationale:  {assessment.rationale}")
        print(f"route:      {route}")


if __name__ == "__main__":
    main()
