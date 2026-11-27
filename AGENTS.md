# AGENTS.md — Contexto de trabajo para agentes de IA

> Este archivo es el **punto de entrada único**. No leas el repo entero.
> Está diseñado para que 3 agentes trabajen **en paralelo sobre tracks distintos**
> sin pisarse y sin releer ~58k líneas de Python.
>
> Funciona con: OpenCode (Zen), Antigravity CLI, Claude Code.

---

## 0. Qué es este proyecto

**Web Security Scanner v5.2.0** — DAST asíncrono (asyncio + aiohttp) con sistema de
plugins, bus de eventos y motor dual de informes JSON/PDF. 25 testers de
vulnerabilidad, ~2.300 payloads curados, 1458 tests (verificado 2026-11-26,
`.venv/bin/python -m pytest -q`: 1458 passed, 3 skipped).

**Investigación IEEE en curso desde hace ~2 meses.** Objetivo: publicar sobre
eficiencia y exactitud del escáner (recall por request vs. coste).

### Regla 0 — NO explores el repo entero

Navega por divulgación progresiva L0 → L1 → L2 (§2 quater y `CLAUDE.md`):
`.context/repomap.md` sustituye al mapa manual de "qué archivo leer".

---

## 1. Estado de la investigación

Movido a [`research/notes/shared-estado-investigacion.md`](research/notes/shared-estado-investigacion.md)
(conserva la numeración §1.1–§1.6). Léelo antes de proponer experimentos,
citar cifras del paper o tocar la instrumentación de evasión.

---

## 2. Los tres tracks disponibles

Cada agente **reclama un track**. No hay track 4 sin acordarlo antes.

### Track A — Evasión de WAF bajo presupuesto de requests

**Pregunta:** ¿la mutación léxica adaptativa restaura el recall de un DAST
detrás de un WAF perimetral, y a qué coste en requests?

- Núcleo: `modules/waf_evasion.py` (236 l.), `core/transforms/` (600 l.),
  `core/payload_mutator.py` (335 l.)
- Ya hay 75 tests (32 + 25 + 18). Motor completo, no stub.
- Falta: WAF en el testbed, cablear `EvasionCounters`, medir.
- Grid propuesto: `{sin-waf, crs-p1, crs-p2} × {sin-evasion, static-chain,
  adaptive-entropy} × presupuestos {10,20,50,∞}`
- **Ángulo que salva la revisión por pares:** el aporte no son los transforms
  individuales (eso es conocido). Es que `binary_safe` existe porque mutar un
  gadget chain de deserialización o un id de IDOR **lo corrompe en silencio**:
  el scan continúa, no lanza excepción, y deja de probar lo que dice probar.
  Eso es un falso negativo silencioso. `payload_mutator.py:100-119` ya lo lanza;
  falta medir su prevalencia.

### Track B — Semántica de parámetros y evidencia dura

**Pregunta:** ¿cuánto del recall perdido ante un objetivo endurecido se recupera
exigiendo evidencia causal en vez de divergencia diferencial?

- Núcleo: `core/param_semantics.py` (234 l.), gateado en
  `base_tester_async.py` vía `_apply_param_semantics` (≈630-679; verifica con
  `grep -n`)
- **0 tests.** Solo **2 de 25 testers** emiten `evidence_kind`
  (`sql_injection_async.py` y par). La política casi nunca dispara.
- Sin flag de CLI: siempre-on e inauditable.
- Requiere un corpus con parámetros de flow-control — el benchmark actual
  **no tiene ninguno**.
- Complementario de A: A ataque la pérdida en la capa de transporte, B en la de
  evidencia. Juntos dan un paper coherente.

### Track C — Orquestación multi-agente autónoma

**Pregunta:** ¿el pipeline LangGraph (attacker / adaptive-fuzzer / CTI /
reporting) merece evaluación propia como sujeto experimental?

- Núcleo: `agents/`, `orchestrator.py` (572 l.)
- El §Future Work item 8 del paper lo nombra explícitamente.
- Riesgo: interfaz aún inestable; difícil de encuadrarlo como evaluación.

---

## 2 bis. Skills y agentes disponibles

Hay **6 skills** y **4 agentes revisores** instalados. Se generan desde
`tools/gen_agents.py` (fuente única de verdad — si divergen entre proveedores,
regenéralos).

### Skills (cargan automáticamente según la tarea)

| Skill | Cuándo se carga sola | Para qué |
|---|---|---|
| `track-a-waf-evasion` | mencionas `waf_evasion`, `EvasionCounters`, CRS, paranoia level | Procedimiento completo del Track A: hipótesis pre-registradas, cableado de `EvasionCounters`, grid, amenazas a la validez |
| `track-b-evidence-semantics` | mencionas `param_semantics`, `evidence_kind`, `redirect_uri`, flow-control | Procedimiento del Track B: flag de ablation, tests, mapa de 25 testers, corpus que falta |
| `track-c-agent-orchestration` | mencionas `orchestrator.py`, LangGraph, multi-agente | Procedimiento del Track C, con un **go/no-go honesto** antes de invertir |
| `phd-thesis-framing` | escribes la introducción, o preguntas "¿da para doctorado?" | Tesis unificadora, escalera N1-N5, los 8 ataques del tribunal |
| `experiment-protocol` | diseñas un grid, interpretas un p-valor | RCBD, potencia, elección de test, confounders reales del repo |
| `claim-verification` | antes de enviar algo a revisión, o si alguien dice "el resultado es bueno" | Trazabilidad de cada cifra, prior art, checklist de rechazo IEEE |

**Carga la skill de tu track al empezar.** No re-derives el procedimiento que
ya está escrito.

### Agentes revisores (invócalos; son read-only, no editan nada)

| Agente | Para qué | Cuándo |
|---|---|---|
| `experiment-auditor` | Traza cada cifra a su fuente cruda y recalculada | Antes de enviar cualquier sección |
| `methodology-reviewer` | Revisa diseño, potencia, tests, confounders | Al diseñar un grid o leer un p-valor |
| `paper-reviewer` | Revisión adversarial de nivel tribunal | Para saber si el trabajo sostiene su afirmación |
| `literature-scout` | Prior art y verificación de novelty | Antes de reclamar cualquier novedad |

Los cuatro están disponibles como subagente en los tres proveedores.

---

## 2 quater. Contexto de código: L0 → L1 → L2 (obligatorio para tocar código)

No leas archivos `.py` completos a ciegas. `tools/context_packer.py` (solo stdlib)
genera el contexto de forma determinista:

| Nivel | Comando | Qué da |
|---|---|---|
| L0 | `python3 tools/context_packer.py --mode l0` | `.context/repomap.md` (firmas tipadas, ~8 % de los tokens) + `.context/symbols.json` |
| L1 | `... --mode l1 --symbols ruta::Qual` o `--range A..B` | diff + callers/callees a 1 salto |
| budget | `... --mode budget [--range A..B \| --staged]` | bundle podado a ≤ 60 % del baseline; exit 3 si no cabe |

`.context/` está en `.gitignore` y se sincroniza solo, re-indexando únicamente los
`.py` cuyo sha256 cambió (hook `Stop` en `.claude/settings.json`, ~0.3 s por turno).
`make context-check` dice si está obsoleto.

Micro-skills (≤ 700 tokens): `context-navigation`, `diff-code-review`,
`scoped-testing`, `debt-isolation`. Agentes (generados por `tools/gen_agents.py`):
`context-indexer` → `architect-planner` → `scoped-coder` → `diff-reviewer`, y
`eval-token-auditor` (`python3 tools/token_benchmark.py --gates`, métricas en
`.context/metrics.jsonl`).

---

## 2 ter. Asignación por proveedor

| Proveedor | Área asignada | Track | Skill principal |
|---|---|---|---|
| **OpenCode (Zen)** | **Track A** — evasión de WAF bajo presupuesto. Es el track con más valor ya construido (75 tests, motor completo, métrica muerta lista para cablear). | A | `track-a-waf-evasion` |
| **Claude Code** | **Track B** — semántica de parámetros y evidencia causal. Es el track que más paper produce (taxonomía HARD/SOFT de 25 testers + corpus de flow-control nuevo). | B | `track-b-evidence-semantics` |
| **Antigravity CLI** | **Track C** — orquestación multi-agente. Asignado por defecto, pero **es el más débil** (ver skill: el §Future Work item 8 ya lo descartó). | C | `track-c-agent-orchestration` |

**Todos los proveedores, sin importar el track:**
- Leen `phd-thesis-framing` antes de escribir cualquier documento.
- Corren `experiment-auditor` sobre sus propios números antes de reportarlos.
- Usan `literature-scout` antes de escribir "nadie ha hecho X".

**Si quieres reasignar**, edita esta tabla y el claim correspondiente. No hace
falta acuerdo previo — solo que no haya dos proveedores en el mismo track.

---

## 3. Cómo reclamar un track (sin condición de carrera)

**No edites una tabla compartida.** Cada proveedor crea su propio archivo:

```
research/agents/<proveedor>.md
```

Con este contenido mínimo:

```markdown
# Claim — <proveedor>  ·  <fecha>
Track: A | B | C
Estado: claimed | in-progress | blocked | done

## Archivos que toco
- ruta/uno.py
- ruta/dos.py

## Skills que cargo
- track-a-waf-evasion
- experiment-protocol

## Notas
Una línea por milestone.
```

Reglas:

1. Un archivo tocado por un claim pertenece a ese agente. **No lo edites.**
2. Si necesitas tocar un archivo de otro track, dilo en tu archivo y espera
   confirmación del humano.
3. Directorio compartido permitido: `research/agents/` (cada uno su archivo),
   `research/notes/`.
4. **Escribe tu hipótesis pre-registrada antes de la primera corrida** →
   `research/notes/<track>-prereg.md`. Sin eso no hay resultado defendible.

---

## 4. Fronteras de propiedad

Aunque tu track toque `base_tester_async.py`, **no edites** las secciones de
otro track sin claim explícito.

**Localiza por NOMBRE DE FUNCIÓN, no por número de línea.** El archivo tiene
2.074 líneas (2026-11-26) y los refactors de §6 ya movieron todo 50-150 líneas. El
nombre es estable; la línea no. Antes de editar, verifica:

```bash
grep -n "async def _apply_param_semantics" \
  web_security_scanner/modules/vulnerability_testers/base_tester_async.py
```

| Sección (buscar por nombre) | Rango a 2026-09-29 | Track |
|---|---|---|
| `assess_anomaly` / `_WAF_BLOCK_STATUSES` | 282–629 | A |
| `_apply_param_semantics` | 630–679 | B |
| `_ai_triage` / `_ai_cross_validate` | 680–1181 | C |
| `confirm_time_based` / `adaptive_time_threshold` | 1182–1251 | — (ya publicado) |
| `confirm_double_oracle` / `oracle_confidence` | 1252–1924 | — (ya publicado) |

**Intocables** salvo decisión explícita del humano (son el resultado ya
publicado del paper):
`core/adaptive_metrics.py`, `tools/eval_oracle.py`,
`paper/submission/sections/00_abstract.tex`, `04_evaluacion.tex`.

---

## 5. Reglas de la casa

```bash
# Suite completa (1458 tests, ~70s)
.venv/bin/python -m pytest -q

# Solo los tests de tu track
.venv/bin/python -m pytest tests/test_waf_evasion.py tests/test_evasion_transforms.py -q

# Lint y tipos (CI corre ambos en py3.10/3.11/3.12)
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy
```

- **1458 tests pasan** (3 skipped) a 2026-11-26. Si rompes ese número, es tu bug.
  Historial: 909 → 938 → 1294 → 1458 a medida que el refactor de §6 se consolidó
  (5 módulos nuevos en `core/`) y se integraron los componentes de métricas
  (`differential_stats`, `benchmark_ground_truth`, `ieee_metrics`,
  `evasion_ab`, `vuln_classes`) con sus propios arneses de test
  (`tests/differential/`, `tests/test_evasion_ab.py`,
  `tests/unit/test_ieee_metrics.py`). El número sube solo; si *baja*, es tuyo.
- CI corre en Python 3.10, 3.11 y 3.12. `pyproject.toml` declara `>= 3.9`, pero
  la imagen de desarrollo es 3.12. No introduzcas sintaxis 3.12+.
- El CI también corre Bandit + Semgrep (`.semgrep.yml`, `bandit.yaml`). No
  introduzcas patrones que disparen SAST.
- Documentstrings y comentarios **en inglés** (convención existente en todo
  `web_security_scanner/`). Comentarios de commit también en inglés.
- Excepciones: los hallazgos de `tests/` y `tools/` son en español.

---

## 6. Trampas verificadas

| Trampa | Detalle |
|---|---|
| **Refactor consolidado (commit `7cba5e5`, verificado 2026-09-30)** | Los 5 módulos extraídos (`core/http_client.py`, `differential_analyzer.py`, `dom_xss_analyzer.py`, `injection_point.py`, `response_filter.py`) ya están integrados y commiteados en `base_tester_async.py`. El archivo tiene **2.074 líneas** (2026-11-26) — creció por código de integración, no porque el refactor se revirtiera. `response_filter.py` tiene cambios locales sin commitear de otro track (déjalo, no es tuyo). **Los números de línea de §4 siguen obsoletos** — localiza siempre por nombre de función. |
| **Números de línea son inestables** | Nunca edites `base_tester_async.py` por número de línea. Localiza por nombre de función (§4) y confirma con `grep -n` justo antes de editar. |
| `testbed/THREATS_TO_VALIDITY.md` | **No existe.** Los docstrings de `base_tester_async.py` lo citan. Crear o quitar referencias. |
| `Makefile` en `main` | **Corregido** (verificado 2026-09-30): `make evaluate` ya no da traceback crudo. Ahora hace `test -f tools/analyze_results.py` y, si falta, imprime a stderr qué rama tiene el pipeline y el comando `git worktree add` para correrlo, saliendo con código 1. Sigue "fallando" en `main` por diseño — el pipeline vive en `feat/ai-triage-mainline`. |
| `_datos.tex` vs `experiment_results.csv` | **Discrepancia de recall (70.6 % vs 64.4 %).** Ver `research/notes/shared-estado-investigacion.md` §1.5 antes de citar cifras. |
| `EvasionCounters` | Sin callers en producción. Muerto desde siempre. |
| `param_semantics` | Sin flag, sin tests, 2/25 testers la activan. |
| `evidence_kind` | Solo 2 testers lo emiten. Los otros 23 no pueden pasar el gate. |
| `CI` | Solo corre en `main` y `master`. Ramas de investigación no se testean solas. |
| Framing | "Evasión de WAF" tiene tensión de doble uso. Encuadra como **evaluación de fidelidad del escáner y de defensa**, nunca como desarrollo de bypass. Resuélvelo en la introducción, no después. |

---

## 7. Pregunta abierta para el humano

Antes de escribir la introducción del paper, resolver:

1. ¿Se mantiene OWASP Benchmark como testbed, o se migra a uno con WAF y
   parámetros de flow-control?
2. ¿El paper actual se extiende (Track A+B como nuevos arms) o se sustituye?
3. ¿Quién es el autor de correspondencia y cuál es el venue objetivo
   (SACS, WAES, RAID, o journal)?

Ver `research/agents/` para el estado actual de los claims.
