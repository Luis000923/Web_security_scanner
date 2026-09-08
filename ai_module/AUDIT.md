# Reporte de Auditoría Técnica — Subsistema de IA (`ai_module/`)

- **Rama:** `ai-agent`
- **Fecha:** 2026-09-07
- **Alcance:** `ai_module/agent_inference.py`, `ai_module/dataset_generator.py`,
  `ai_module/train_qlora.py`, `ai_module/prompts/`, y su integración en
  `web_security_scanner/web_security_scanner_async.py` y
  `web_security_scanner/modules/vulnerability_testers/base_tester_async.py`.
- **Estado en el momento de la auditoría:** agente integrado como motor por
  defecto, tubería de curación de datos y generador de triage sintético
  body-enriched (26 → 826 muestras balanceadas TP/FP/UNCERTAIN, 212 tests en
  verde).

Escala de severidad: 🔴 crítico · 🟠 alto · 🟡 medio · 🟢 correcto

---

## 1. Arquitectura y rendimiento del agente

### 1.1 Flujo de inferencia (`agent_inference.py`)

| # | Sev | Hallazgo |
|---|-----|----------|
| 1.1 | 🔴 | **Sin backpressure sobre el backend de IA.** El README indica "call this behind its existing worker-pool backpressure", pero `base_tester_async.report_vulnerability()` invoca `client.triage_finding()` directamente, sin pasar por `core` / `TokenBucket` / `worker_pool`. Una ráfaga de findings concurrentes = ráfaga de requests simultáneos al servidor local de inferencia → riesgo de OOM o colapso justo cuando hay más carga. `batch_triage()` (con `Semaphore`) existe pero no se usa. |
| 1.2 | 🔴 | **Sin retry/backoff ni circuit breaker.** `_chat_openai` hace `resp.raise_for_status()`; cualquier 5xx/timeout transitorio degrada a heurística con solo un `warning`. Si el servidor cae a mitad de scan, cada finding paga el `timeout` completo (60 s) antes de degradar. |
| 1.3 | 🟠 | **`aiohttp.ClientSession` nuevo por llamada** en `_chat_openai` y `healthcheck` — sin keep-alive ni pool reutilizado. |
| 1.4 | 🟠 | **Triage inline y secuencial.** El `await` bloquea la corrutina del tester; no hay fan-out ni agrupación. |
| 1.5 | 🟠 | **`response_format: {"type":"json_object"}` hard-coded.** llama.cpp `--api`, TGI y algunas versiones de vLLM devuelven 400 → deshabilita todo el triage. No está gateado por capacidad del backend. |
| 1.6 | 🔴 | **Backend `transformers`: carga de modelo sin lock.** `_chat_hf` lazy-carga `self._hf`; dos llamadas concurrentes vía `asyncio.to_thread` durante el warm-up construyen el modelo dos veces → doble VRAM / race en la 5090. |
| 1.7 | 🟠 | **Incoherencia de precisión en `transformers`.** `_chat_hf` carga bf16 sin 4-bit (~15 GB) mientras el entrenamiento es NF4 4-bit → train/serve skew de cuantización. |
| 1.8 | 🟡 | **Sin caché de triage.** Findings idénticos se reenvían al LLM. |
| 1.9 | 🟡 | **Sin telemetría de IA.** No se emiten eventos con verdict/confidence/latencia/abortos → imposible auditar calibración o coste en el paper. |
| 1.10 | 🟡 | `_extract_json` usa regex greedy `\{.*\}` (DOTALL), frágil ante texto con llaves alrededor del JSON. |
| 1.11 | 🟢 | Bien: `healthcheck()` con timeout corto, degradación segura que nunca rompe el scan, `is_vulnerable` conservador (UNCERTAIN cuenta como vulnerable). |
| 1.12 | 🟡 | `healthcheck()` se ejecuta una sola vez al arranque; sin re-probe si el servidor muere después. |

### 1.2 Orquestador (`web_security_scanner_async.py`)

- 🟢 Construcción del `AgentClient` + `healthcheck` con fallback limpio.
- 🟠 El cliente se comparte por referencia a todos los testers; correcto para
  `openai`, pero arrastra el race 1.6 en `transformers`.
- 🟠 Las llamadas LLM no pasan por el `core._semaphore` (que solo limita HTTP
  hacia el target). Sin límite explícito de concurrencia contra el backend IA.

---

## 2. Auditoría del dataset sintético y de triage (`dataset_generator.py`)

### 2.1 Robustez de los escenarios y `_assess_evidence()`

| # | Sev | Hallazgo |
|---|-----|----------|
| 2.1 | 🔴 | **Overfitting a formas superficiales.** Solo 5 plantillas de error SQL, 3 de WAF, 3 de página 500, ~3 plantillas HTML de contexto, 6 títulos de shell. El modelo puede aprender literales (`"Whitelabel Error Page"`, `"Cloudflare Ray ID"`, `ORA-01756`) en vez del concepto. La `dedup` limita casi-duplicados pero no la baja cardinalidad de features. |
| 2.2 | 🔴 | **El label sintético ≈ tautología de `_assess_evidence()`.** El guard acepta la muestra solo si el assessor basado en reglas coincide con el verdict del escenario → el SFT destila `_assess_evidence` + prosa plantillada. El LLM no puede superar la heurística que destila. |
| 2.3 | 🔴 | **Mismatch con OWASP Benchmark.** El Benchmark no tiene cuerpos HTTP; entrenas ~97% sobre cuerpos sintéticos. El `val` split sale del mismo generador → accuracy de validación optimista que no predice el comportamiento sobre Benchmark ni sobre hallazgos reales. |
| 2.4 | 🟠 | **Prior de clases 1:1:1 irreal.** El triage DAST real está sesgado a FP (≈5–20:1). Un prior de 33% TP hará que el modelo sobre-declare TP → cae la precisión. |
| 2.5 | 🟠 | **`_sc_xss_escaped` etiqueta FP todo lo escapado con `html.escape(quote=True)`, incluso en contexto `js_string`**, donde escapar entidades HTML no neutraliza la inyección. |
| 2.6 | 🟠 | **`sql_time_oracle`: una sola muestra retardada, sin evidencia de repetibilidad, etiqueta TP conf 0.85** — contradice el system prompt. |
| 2.7 | 🟠 | **Sin pares contrastivos** (mismo cuerpo con/sin payload; mismo payload TP/FP según contexto). |
| 2.8 | 🟡 | Distribuciones distintas del campo `context` entre filas reales y sintéticas → otra señal de skew. |
| 2.9 | 🟡 | Variedad léxica de la línea `Payload sent:` limitada a ~26 seeds. |
| 2.10 | 🟡 | Documentar el comando exacto + `--seed` que produjo el dataset committeado (README muestra `--synthetic-multiplier 40`, default 20, resultado 826). |

### 2.2 Qué falta para simular entornos corporativos

- 🟠 WAFs reales: Akamai, Imperva/Incapsula, F5 ASM, AWS WAF, Azure Front Door.
- 🟠 Errores de framework: ASP.NET YSOD, Rails/Django debug, Express/Spring traces.
- 🟠 Errores de driver/ORM: JDBC, psycopg2, Sequelize, GORM, Hibernate, `.NET SqlException`.
- 🟠 Muros de auth/sesión: 302 a `/login`, páginas con token CSRF, 401/403 OAuth.
- 🟠 APIs JSON/GraphQL: reflexión en cuerpo JSON, `"errors":[...]`, SPA (200 + bundle JS).
- 🟡 429 rate-limit, gzip/chunked, error multi-idioma, reflexión sanitizada por CSP.

---

## 3. Preparación para QLoRA y RTX 5090 (`train_qlora.py`)

| # | Sev | Hallazgo |
|---|-----|----------|
| 3.1 | 🔴 | **API de TRL desalineada — fallo de lanzamiento más probable.** El código llamaba `SFTTrainer(..., tokenizer=, args=TrainingArguments(...), max_seq_length=, packing=)`. TRL ≥0.12 movió `max_seq_length`/`packing`/`dataset_*` a `SFTConfig` y renombró `tokenizer=` → `processing_class=`. Con un TRL reciente crashea al arrancar. |
| 3.2 | 🔴 | **`use_unsloth=True` por defecto + Blackwell.** Los kernels Triton de Unsloth y su pin de bitsandbytes suelen ir por detrás de arquitecturas nuevas. El fallback solo capturaba `ImportError`, no los `RuntimeError`/`NotImplementedError` de compilación de kernels en runtime. |
| 3.3 | 🟠 | **Sub-entrenamiento severo.** ~750 muestras, `epochs=2`, batch efectivo 16 → ≈94 steps; `warmup_ratio=0.03` ≈ 3 steps. Con `packing=True` + `max_seq_len=4096` y prompts de ~500–1500 tokens se empaquetan varias muestras por secuencia → aún menos updates. |
| 3.4 | 🟠 | **`attn_implementation="flash_attention_2"` hard-coded.** Wheels de `flash-attn` para sm_120 muy nuevas; si no está, `from_pretrained` lanza `ImportError` no capturado → aborta. |
| 3.5 | 🟠 | **Hiperparámetros LoRA agresivos para ~800 muestras.** `lora_alpha == r`, `lora_dropout=0.0`, `lr=2e-4`, 2 epochs → memorización probable. Recipe habitual: `alpha=2·r`, `dropout=0.05–0.1`, o `lr=1e-4`. |
| 3.6 | 🟠 | **Sin selección de mejor checkpoint.** Falta `load_best_model_at_end`, `metric_for_best_model`, `save_total_limit`, early stopping. |
| 3.7 | 🟠 | **`padding_side` no fijado a `"right"`** para entrenamiento. |
| 3.8 | 🟠 | **Masking de la parte prompt sin verificar** con formato `messages`. |
| 3.9 | 🟡 | `report_to=["tensorboard"]` crashea si `tensorboard` no está instalado. |
| 3.10 | 🟡 | **`merge_and_unload()` sobre base 4-bit** produce fp16 degradado; preferir `vllm --enable-lora` o merge sobre base fp16 fresco. |
| 3.11 | 🟡 | Pinnear `bitsandbytes>=0.45`; añadir `python -m bitsandbytes` al runbook. |
| 3.12 | 🟢 | Correcto: NF4 + double-quant, `paged_adamw_8bit`, bf16, TF32, `expandable_segments`, imports perezosos, `--dry-run` / `--max-steps 5`. **VRAM no es el riesgo** (7B 4-bit ≈ 4.5 GB en 32 GB); el riesgo es under-training. |

---

## 4. Plan de acción priorizado

### P0 — bloqueantes de lanzamiento

1. **Alinear el stack ML para sm_120** (3.1, 3.2, 3.4, 3.11): migrar
   `train_qlora.py` a `SFTConfig` (`processing_class`, `max_seq_length`,
   `packing`, `dataset_text_field`) con filtrado de kwargs por firma; pinnear
   `trl`/`bitsandbytes>=0.45`; `attn_implementation="sdpa"` por defecto con
   `--flash-attn` opt-in; `use_unsloth=False` por defecto con `--use-unsloth`
   opt-in y `except (ImportError, RuntimeError, NotImplementedError)`.
2. **Corregir hiperparámetros para dataset pequeño** (3.3, 3.5, 3.6, 3.7):
   `max_seq_len` 1536–2048, `epochs` 3–5, `lora_alpha=2·r`, `lora_dropout=0.05`,
   `padding_side="right"`, `load_best_model_at_end` + `metric_for_best_model` +
   `save_total_limit`, evaluar `packing=False`.
3. **Set de evaluación real y honesto** (2.3): etiquetar a mano 40–80 hallazgos
   reales (Benchmark + testbed, con cuerpo donde exista). Prohibido meter
   sintético en `val`. Reportar precisión/recall/ECE sobre ese set.
4. **Robustez del backend en `agent_inference.py`** (1.1–1.5, 1.9): sesión
   `aiohttp` compartida, retry con backoff, circuit breaker por scan,
   `response_format` opt-out por backend, telemetría de latencia/abortos de IA.

### P1 — antes de confiar en producción

5. Enrutar triage/synthesis por un `Semaphore` propio del `AgentClient` (o el
   worker-pool del core) y cablear `batch_triage()` (1.1, 1.4).
6. Caché de resultados de triage por `(vuln_class, param, payload, body-hash)` (1.8).
7. `asyncio.Lock` en la carga del backend `transformers` + cargar 4-bit;
   o `vllm --enable-lora` en vez de merge (1.6, 1.7, 3.10).
8. Diversificar escenarios sintéticos (2.1, 2.5, 2.8): WAFs reales, errores de
   framework/ORM, redirect de auth, JSON/GraphQL, 429, CSP, escaping sensible
   al contexto; añadir pares contrastivos (2.7).
9. Recalibrar el prior de clases hacia el sesgo FP real (2.4) con
   `--balance-ratio` o pesos de muestra; medir over/under-calling.

### P2 — calidad e investigación

10. Alinear cada `reason` de escenario con el system prompt;
    `sql_time_oracle` debe exigir repetibilidad (2.6).
11. Emitir decisiones de IA a telemetría para el análisis de calibración (1.9).
12. Documentar comando + seed del dataset committeado; hash del manifiesto (2.10).
13. Romper el techo de destilación (2.2): incluir casos "duros" adjudicados por
    humano donde `_assess_evidence` se equivoca.

---

## 5. Resumen ejecutivo

El subsistema está bien encapsulado y degrada con seguridad, pero hay **tres
riesgos críticos**:

- **(a)** las llamadas al backend de IA no tienen backpressure ni breaker y
  pueden convertirse en un cuello de botella de minutos si el servidor de
  inferencia flaquea;
- **(b)** `train_qlora.py` casi con seguridad no arrancaba contra un TRL
  reciente (API `SFTConfig`) y está configurado para sub-entrenar ~800
  muestras;
- **(c)** el dataset destila la heurística y se evalúa contra sí mismo, así que
  las métricas de validación no predicen el rendimiento sobre OWASP Benchmark
  ni sobre hallazgos reales.

Resolver **P0** antes de llevar el código a la estación de trabajo.

---

## 6. Registro de remediación

| Fecha | Bloque | Acción |
|-------|--------|--------|
| 2026-09-07 | P0-1 | `train_qlora.py` migrado a `trl.SFTConfig` con filtrado de kwargs por firma (`_supported_kwargs`); `processing_class` con fallback a `tokenizer=`; `dataset_text_field="text"` renderizando el chat template del tokenizer; `use_unsloth=False` por defecto + flag `--use-unsloth`; `except (ImportError, RuntimeError, NotImplementedError)` en la construcción del modelo; `attn_impl="sdpa"` por defecto + flag `--flash-attn`; `padding_side="right"`; `report_to=["tensorboard"]` gateado por disponibilidad. `pyproject.toml`: `trl>=0.13.0,<0.24`. README runbook actualizado. `--dry-run` OK, 212 tests en verde. |
