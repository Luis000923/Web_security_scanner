---
name: Track C — Multi-Agent Orchestration Evaluation
description: Procedimiento para el Track C — determinar si el pipeline LangGraph de agentes (attacker / adaptive-fuzzer / CTI / reporting) merece evaluación propia como sujeto experimental, y cómo medir su aporte sobre el mismo escáner. Úsala cuando la tarea mencione orchestrator.py, agents/, LangGraph, multi-agente, CTI, adaptive-fuzzer, o "orquestación".
---

# Track C — Orquestación multi-agente como sujeto experimental

## Pregunta de investigación

> El pipeline multi-agente promete superseded el escáner monolítico. ¿Hay
> evidencia controlada de que la orquestación aporta algo que el pipeline
> determinista no ya hace, y a qué coste?

## Honestidad upfront — lee esto antes de invertir un día

**Track C es el más débil de los tres para una tesis doctoral.** Razones:

1. `agents/` + `ai_module/` son 7.224 líneas — la mayor base de código de todo el
   repo, y la menos testeada. Empezar por aquí es empezar por lo caro.
2. La interfaz aún no está estable. Un resultado sobre una interfaz que va a
   cambiar en tres meses no es un resultado publicable.
3. El §Future Work item 8 del paper **ya lo nombra**, lo que significa que el
   propio trabajo previo.identifier lo descartó como digno de evaluación. Eso
   es una señal, no un detalle.
4. Evaluar un sistema multi-agente con LLM dentro de un diseño RCBD es
   caro (cada corrida cuesta tokens además de requests) y ruidoso (los LLM son
   no deterministas; necesitas replicar o reportar la varianza intra-arm).

**Recomendación: no                                                                     este track primero.** Si los otros dos están bloqueados, hazlo
como ingeniería de soporte, no como capítulo de tesis.

## Si de todas formas lo tomas

### Fase 0 — ¿Es evaluable? (go/no-go, 1 día máximo)

Responde con sí/no:
- ¿Tiene una métrica de salida comparable a TP/FP/FN del escáner? Si no, no hay
  ground truth y no hay experimento.
- ¿Es determinista? Si no, ¿cuántas réplicas por celda y cómo se reporta la
  varianza?
- ¿El coste (tokens + requests) se mide por corrida?

**Si falla el go/no-go, vuelve a Track A o B y dilo en `research/notes/`.** Eso
es un resultado válido, no un fracaso.

### Fase 1 — Aísla la contribución

La comparación honesta no es "multi-agente vs nada". Es:

```
base (pipeline determinista actual)
  vs
  +orchestrator (mismo escáner, con agentes)
  vs
  −orchestrator (mismo escáner, agentes desactivados)
```

Si solo mides vs nada, cualquier reviewer pregunta qué parte del resultado es
el orquestador y qué parte es simplemente "el escáner ya funcionaba solo".
Cada condición debe aislar **una** variable.

### Fase 2 — Reusa el stack, no lo reescribas

- `tools/run_experiments.py` — orquestador RCBD, idempotente, `--dry-run`
- `tools/eval_oracle.py` — oráculo, sin dependencias externas
- `tools/analyze_results.py` — Friedman/Nemenyi/Wilcoxon-BH/Cliff's δ, AUC,
  curva First-TP
- `tools/run_zap_baseline.py` — baseline ZAP 2.17.0 vía REST API

El coste por corrida es **mayor** que el del escáner puro (5-9 min acotado
base; aquí escala con el número de agentes y de turnos). Muéstralo antes de
lanzar el grid.

### Fase 3 — La métrica difícil

La eficiencia de un orquestador no es requests: es **decisiones por unidad de
hallazgo útil**. Define:

```
coste_por_hallazgo = (requests + tokens + turnos_de_agente) / TP
```

y reporta la Pareto frontier coste_por_hallazgo vs recall, no un punto único. Un
orquestador que sube el recall 3% y multiplica el coste por 5 no es un
resultado positivo; es un trade-off que hay que mostrar explícitamente.

## Amenazas a la validez (las más severas de los tres tracks)

- **No determinismo del LLM**: la varianza intra-arm puede exceder el efecto
  entre-arm. Mide y reporta ambas. Si no puedes, el resultado no es interpretable.
- **Sesgo del prompt**: si el orquestador usa las mismas señales de confianza
  que el pipeline determinista, estás midiendo la implementación dos veces.
  Audita qué información ve cada brazo.
- **Coste oculto**: reportar solo requests cuando hay tokens es cherry-picking
  de la métrica más favorable.

## Archivos que tocas

```
orchestrator.py
agents/
ai_module/
```

**No toques** `core/adaptive_metrics.py` (intocable) ni las secciones de
`base_tester_async.py` de otros tracks (ver §4 AGENTS.md; `_ai_triage` /
`_ai_cross_validate` desde línea 764 son de este track).

## Antes de dar el track por terminado

- [ ] Go/no-go documentado con sí/no y justificación
- [ ] Cada condición aísla **una** variable
- [ ] `coste_por_hallazgo` definido y reportado como frontera de Pareto
- [ ] Varianza intra-arm (no determinismo del LLM) medida y publicada
- [ ] Coste en tokens reportado junto a requests, no solo requests
- [ ] `research/agents/<tu-proveedor>.md` actualizado a `done`
