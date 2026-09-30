---
name: Track B — Evidence Semantics and False-Positive Suppression
description: Procedimiento para el Track B — medir cuánta pérdida de recall ante un objetivo endurecido se recupera exigiendo evidencia causal (evidence_kind) en vez de divergencia diferencial, y cuánto FP suprime el gate de param_semantics. Úsala cuando la tarea mencione param_semantics, evidence_kind, HARD_EVIDENCE_KINDS, is_flow_control_point, redirect_uri, flow-control, o "falsos positivos por parámetro".
---

# Track B — Evidencia causal en vez de divergencia diferencial

## Pregunta de investigación

> La divergencia diferencial (la respuesta cambia cuando muto el input) es un
> oráculo débil: produce falsos positivos sobre parámetros cuyo valor de control
> legítimamente cambia la respuesta. ¿Cuánto del recall perdido se recupera
> exigiendo evidencia causal, y a costa de cuántos falsos positivos?

## Hipótesis pre-registrada (ANTES de medir)

```
H1  Los parâmetros de flow-control (next, redirect_uri, returnTo, url, dest)
    producen FPs que son indistinguibles de vulns por divergencia.
    → medible como: FP con esos params / FP totales.
H2  El gate de evidencia dura (HARD_EVIDENCE_KINDS) mata esos FPs
    con pérdida de recall despreciable sobre vulns reales.
H3  La pérdida de recall actual NO viene del gate: viene de que 23 de 25
    testers nunca emiten evidence_kind, así que el gate no puede activarse.
```

**H3 es la hipótesis estructural y probablemente la más fuerte.** Verifícala
primero — es barata y determina si el resto del track vale la pena.

## Estado verificado del código (2026-09-29)

| Hecho | Evidencia |
|---|---|
| El módulo existe y tiene lógica | `core/param_semantics.py` (234 l.) |
| **0 tests** | `grep` en `tests/` no devuelve nada |
| Gateado en el tester base | `base_tester_async.py` vía `_apply_param_semantics` (≈630-679 a 2026-09-29) |
| **Solo 2 de 25 testers emiten `evidence_kind`** | `sql_injection_async.py:127-191` y `:245-271` |
| **Sin flag de CLI** | siempre-on e inauditable. No se puede hacer ablation |
| **El corpus actual no tiene flow-control** | `ground_truth.json`: 338 params, **todos** `BenchmarkTest*`, cero `next`/`redirect_uri`/`returnTo` |

**Consecuencia:** el track está bloqueado por dos cosas independientes, y
ninguna es el algoritmo. Son (a) no se puede ablar, (b) no hay corpus que
produzca el fenómeno. Arregla esas dos antes de tocar la lógica.

## Procedimiento

### Fase 0 — Hacerlo abable (prerrequisito absoluto)

Sin flag, no hay ablation, no hay condición `no-param-semantics` en el grid, y
por tanto no hay experimento. Esto es bloqueante, no opcional.

Añade `--no-param-semantics` a la CLI siguiendo el patrón de las otras flags de
ablation que ya existen (`--no-interleave`, `--no-priority`,
`--no-runtime-confirm`, `--no-adaptive-sorting` en `cli.py`). Mantén el
comportamiento actual por defecto para no romper los defaults.

Un revisor va a preguntar "¿cómo separas tu contribución de la del pipeline de
ablation que ya publicaste?" La respuesta tiene que ser un flag que apaga tu cosa.

### Fase 1 — Tests (0 → todos)

`param_semantics.py` no tiene un solo test y es *intocable por fear of breaking
it*. Eso es/peor es exactamente el perfil de código donde un bug pasa
desapercibido, porque nada lo ejercita en producción más allá de 2 testers.

Mínimo, y en español (convención de `tests/`):
- `is_flow_control_point` sobre una tabla de nombres de parámetro
- El path de redirect: ¿se permite o se bloquea un `next=` malicioso?
- `HARD_EVIDENCE_KINDS` vs `SOFT_EVIDENCE_KINDS`: qué pasa con cada uno
- El gate con `evidence_kind=None` (el caso de los otros 23 testers)
- Regresión: el comportamiento actual no cambia con el flag activo

### Fase 2 — Propagar `evidence_kind` a los testers que falta

23 de 25 testers no pueden pasar el gate porque no emiten el campo. Esto no es
un bug, es una **decisión de diseño no tomada**. Para cada tester decide
explícitamente: ¿puede producir evidencia causal o no?

- Si sí → implementa `evidence_kind` y clasifícalo HARD/SOFT.
- Si no → déjalo y **documenta por qué**. Un tester que solo puede hacer
  divergencia no debe fingir que tiene evidencia causal.

Este mapa (25 testers × HARD/SOFT/none) es en sí mismo un resultado publicable:
es una taxonomía de la fuerza de evidencia por clase de vulnerabilidad.

### Fase 3 — Construir el corpus que falta

El benchmark actual no tiene ni un parámetro de flow-control. Sin él, mides
nada. Necesitas un corpus nuevo o extender el existente con vulnerable+traps de
flow-control. Esto es trabajo de testbed, no de código del escáner.

**Es la parte más cara del track y probablemente la que va al doctorado**, porque
construir un corpus con ground truth de flow-control es una contribución
reutilizable por la comunidad, no solo un input.

## Relación con Track A

Complementarios, no redundantes. A ataca la pérdida de recall en la **capa de
transporte** (el WAF corta la request antes de que llegue). B ataca la pérdida
en la **capa de evidencia** (la request llega pero el oráculo no la reconhece).
Un punto puede fallar por ambos motivos y son independientes. Juntos dan un
paper coherente con dos capítulos; separados dan dos notas marginales.

## Amenazas a la validez

- **El gate es always-on**: cualquier resultado que no lo controle por diseño
  es ininterpretable. Por eso Fase 0 va primero.
- **Survivorship**: si solo propagas `evidence_kind` a los testers donde el
  gate aprueba, el recall sube por selección, no por causalidad. Audita eso.
- **Ground truth del corpus nuevo**: la misma trampa de 2 FPs sobre 144 trampas
  puede repetirse. Reporta FPR con denominador explícito.

## Archivos que tocas

```
core/param_semantics.py
cli.py                          ← solo para el flag de ablation
modules/vulnerability_testers/*.py   ← los 23 que faltan
tests/test_param_semantics.py   ← nuevo, en español
```

**No toques** `_apply_param_semantics` de otro track: esa función ES de este
track (≈630-679; verifica con `grep -n`), mientras que `assess_anomaly` es de
Track A y `_ai_triage`/`_ai_cross_validate` son de Track C.

## Antes de dar el track por terminado

- [ ] `--no-param-semantics` existe y hay una condición de ablation en el grid
- [ ] `tests/test_param_semantics.py` con cobertura de los 4 caminos del gate
- [ ] Mapa de los 25 testers: HARD / SOFT / none, con justificación
- [ ] Corpus con flow-control y ground truth, con FPR y denominador
- [ ] H1-H3 escritas **antes** de los datos, con fecha
- [ ] `research/agents/<tu-proveedor>.md` actualizado a `done`
