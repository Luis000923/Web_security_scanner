"""
Validador híbrido de payloads: Capa 1 (determinista, <1ms) + Capa 2 (Qwen2.5-1.5B-4bit, juez semántico).

Diseñado para GPU de 6GB VRAM: el modelo se carga una sola vez, en 4-bit,
y solo se invoca para el subconjunto de payloads que la Capa 1 no logra clasificar con certeza.

FASE 2 — El Escudo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

try:
    import sqlglot  # parsing real de SQL, robusto a ofuscación de mayúsculas/comentarios
except ImportError:
    sqlglot = None

try:
    import yara  # firmas de payloads maliciosos conocidos (webshells, LFI, etc.)
except ImportError:
    yara = None


class RiskCategory(str, Enum):
    SAFE_READ = "SAFE_READ"
    STATE_MUTATION = "STATE_MUTATION"
    AMPLIFICATION_DOS = "AMPLIFICATION_DOS"
    DESTRUCTIVE = "DESTRUCTIVE"
    AMBIGUOUS = "AMBIGUOUS"  # estado interno, nunca se propaga como veredicto final


@dataclass
class RiskAssessment:
    category: RiskCategory
    confidence: float
    layer: str  # "layer1_deterministic" | "layer2_llm" | "fail_safe"
    rationale: str


# ============================================================
# CAPA 1 — Filtros deterministas (regex, AST, YARA)
# ============================================================


class DeterministicLayer:
    _DESTRUCTIVE_PATTERNS = [
        re.compile(r"(?i)\bdrop\s+table\b"),
        re.compile(r"(?i)\btruncate\s+table\b"),
        re.compile(r"(?i)\bxp_cmdshell\b"),
        re.compile(r"(?i);\s*rm\s+-rf\b"),
        re.compile(r"\$\([^)]*\)"),  # command substitution
    ]

    _SAFE_READ_PATTERN = re.compile(r"^[a-zA-Z0-9_]+=[a-zA-Z0-9_\-\.]+$")

    # Heurística de ReDoS: cuantificadores anidados o alternancia solapada,
    # el patrón clásico de complejidad exponencial de backtracking.
    _REDOS_PATTERN = re.compile(r"\([^()]*[+*]\)[+*]|\([^|()]+\|[^|()]+\)[+*]{2,}")
    _AMPLIFICATION_LENGTH_THRESHOLD = 5000  # payload sospechosamente largo

    def __init__(self) -> None:
        self._yara_rules = None
        if yara is not None:
            # Reglas de firma para artefactos conocidos: webshells, LFI wrappers, etc.
            self._yara_rules = yara.compile(
                source=r"""
                rule known_webshell_signature {
                    strings:
                        $a = "eval(base64_decode" nocase
                        $b = "system($_GET" nocase
                    condition:
                        any of them
                }
            """
            )

    def classify(self, payload: str) -> Optional[RiskAssessment]:
        # 1. Firma YARA de payload malicioso conocido -> destructivo/alta confianza
        if self._yara_rules and self._yara_rules.match(data=payload):
            return RiskAssessment(
                RiskCategory.DESTRUCTIVE,
                0.99,
                "layer1_deterministic",
                "Coincidencia con firma YARA de artefacto malicioso conocido",
            )

        # 2. AST real de SQL (más robusto que regex ante ofuscación de mayúsculas/comentarios inline)
        if sqlglot is not None:
            try:
                parsed = sqlglot.parse_one(payload, error_level=None)
                if parsed is not None:
                    stmt_type = type(parsed).__name__.upper()
                    if stmt_type in ("DROP", "DELETE", "TRUNCATETABLE"):
                        return RiskAssessment(
                            RiskCategory.DESTRUCTIVE,
                            0.97,
                            "layer1_deterministic",
                            f"AST SQL identifica sentencia destructiva: {stmt_type}",
                        )
                    if stmt_type in ("INSERT", "UPDATE"):
                        return RiskAssessment(
                            RiskCategory.STATE_MUTATION,
                            0.9,
                            "layer1_deterministic",
                            f"AST SQL identifica sentencia de escritura: {stmt_type}",
                        )
            except Exception:
                pass  # no parseable como SQL -> continúa evaluación

        # 3. Patrones destructivos por regex (comandos de sistema, cierre de sentencia)
        for pattern in self._DESTRUCTIVE_PATTERNS:
            if pattern.search(payload):
                return RiskAssessment(
                    RiskCategory.DESTRUCTIVE,
                    0.95,
                    "layer1_deterministic",
                    f"Patrón destructivo: {pattern.pattern}",
                )

        # 4. Heurística de ReDoS / amplificación
        if self._REDOS_PATTERN.search(payload) or len(payload) > self._AMPLIFICATION_LENGTH_THRESHOLD:
            return RiskAssessment(
                RiskCategory.AMPLIFICATION_DOS,
                0.7,
                "layer1_deterministic",
                "Cuantificadores anidados o payload de longitud anómala",
            )

        # 5. Forma inequívocamente segura
        if self._SAFE_READ_PATTERN.match(payload):
            return RiskAssessment(
                RiskCategory.SAFE_READ,
                0.95,
                "layer1_deterministic",
                "Coincide con patrón clave=valor benigno",
            )

        # Sin veredicto determinista -> escalar a Capa 2
        return None


# ============================================================
# CAPA 2 — Juez semántico (Qwen2.5-1.5B-Instruct-bnb-4bit)
# Salida forzada a JSON vía grammar-constrained decoding (outlines),
# imprescindible en un modelo de 1.5B: evita parseo frágil de texto libre.
# ============================================================


class SemanticVerdict(BaseModel):
    category: RiskCategory
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str


class SemanticJudgeLayer:
    _CONFIDENCE_THRESHOLD = 0.75
    _MODEL_ID = "unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit"

    _SYSTEM_PROMPT = (
        "Eres un clasificador de riesgo de seguridad ofensiva. Dado un payload, "
        "responde EXCLUSIVAMENTE en el esquema JSON solicitado. Categorías válidas: "
        "SAFE_READ (solo lectura, sin efectos), STATE_MUTATION (puede alterar datos/estado/auth), "
        "AMPLIFICATION_DOS (riesgo de consumo desproporcionado de recursos). "
        "Nunca clasifiques como DESTRUCTIVE (esa capa ya fue descartada). "
        "Si el payload está vacío o no aporta señal suficiente, responde STATE_MUTATION "
        "con confidence baja (fail-safe: ante la duda, requiere revisión humana)."
    )

    def __init__(self, model: Any = None, tokenizer: Any = None) -> None:
        # Modelo/tokenizer inyectados: se cargan UNA vez a nivel de proceso
        # (4-bit bnb, ~1.2GB VRAM residente) y se reutilizan entre llamadas.
        # En 6GB de VRAM esto deja margen amplio para el KV cache de prompts cortos.
        self._model = model
        self._tokenizer = tokenizer

    def classify(self, payload: str) -> RiskAssessment:
        if self._model is None:
            # Modelo no disponible (falla de carga, VRAM ocupada, etc.) -> fail-safe, nunca fail-open
            return RiskAssessment(
                RiskCategory.STATE_MUTATION,
                0.0,
                "fail_safe",
                "Juez semántico no disponible; se enruta a HITL por precaución",
            )

        try:
            import outlines

            # API de outlines >= 1.0: se envuelve el modelo/tokenizer de transformers
            # una vez, y el Generator fuerza la salida al esquema Pydantic (JSON-constrained).
            outlines_model = outlines.from_transformers(self._model, self._tokenizer)
            generator = outlines.Generator(outlines_model, SemanticVerdict)
            prompt = f"{self._SYSTEM_PROMPT}\n\nPayload: {payload!r}\n\nJSON:"
            raw = generator(prompt, max_new_tokens=120)
            verdict = SemanticVerdict.model_validate_json(raw) if isinstance(raw, str) else raw
        except Exception:
            return RiskAssessment(
                RiskCategory.STATE_MUTATION,
                0.0,
                "fail_safe",
                "Excepción durante inferencia LLM; se enruta a HITL por precaución",
            )

        if verdict.confidence < self._CONFIDENCE_THRESHOLD:
            return RiskAssessment(
                RiskCategory.STATE_MUTATION,
                verdict.confidence,
                "fail_safe",
                f"Confianza del LLM ({verdict.confidence}) bajo umbral; HITL forzado",
            )

        return RiskAssessment(verdict.category, verdict.confidence, "layer2_llm", verdict.rationale)


# ============================================================
# ORQUESTADOR
# ============================================================


class HybridPayloadValidator:
    def __init__(self, llm_model: Any = None, llm_tokenizer: Any = None) -> None:
        self._layer1 = DeterministicLayer()
        self._layer2 = SemanticJudgeLayer(model=llm_model, tokenizer=llm_tokenizer)

    def classify(self, payload: str) -> RiskAssessment:
        verdict = self._layer1.classify(payload)
        if verdict is not None:
            return verdict
        return self._layer2.classify(payload)

    def route(self, assessment: RiskAssessment) -> str:
        if assessment.category == RiskCategory.DESTRUCTIVE:
            return "BLOQUEADO"
        if assessment.category == RiskCategory.SAFE_READ:
            return "EJECUCION_AUTOMATICA"
        return "COLA_HITL"  # STATE_MUTATION y AMPLIFICATION_DOS siempre pasan por humano
