---
name: Track A — WAF Evasion Under Request Budget
description: Procedimiento completo para el Track A de la investigación — medir si la mutación léxica adaptativa restaura el recall de un DAST detrás de un WAF perimetral, y a qué coste en requests. Úsala cuando la tarea mencione waf_evasion, EvasionCounters, AdaptiveEntropyTransform, ModSecurity, CRS, paranoia level, PERIMETER_BLOCK_STATUSES, block rate, o "fidelidad del escáner frente a WAF".
---

# Track A — Fidelidad del DAST bajo WAF perimetral

## Pregunta de investigación

> Ante un objetivo protegido por un WAF perimetral, ¿qué fracción del recall
> que el escáner pierde por bloqueo puede recuperar la mutación léxica
> adaptativa, y cuál es el coste en requests adicional por punto recuperado?

## Hipótesis pre-registrada (escribirla ANTES de medir)

```
H1  La mutación adaptativa (AdaptiveEntropyTransform) recupera recall
    significativamente frente a no-evasión, bajo el mismo presupuesto.
H2  El coste en requests por punto recuperado es monotónico: escala
    con el nivel de paranoia del WAF.
H3  bin_safe no es cosmético: mutar una categoría sensible produce un falso
    negativo SILENCIOSO (no una excepción), y su prevalencia es medible.
```

**Regla dura:** escribe estas hipótesis en
`research/notes/A-preregistration.md` con fecha, ANTES de la primera corrida.
Si las cambias después de ver los datos, es p-hacking y un revisor lo va a
detectar. Si una hipótesis cae, se reporta — un null honesto publica.

## Estado verificado del código (2026-09-29)

| Hecho | Evidencia |
|---|---|
| El motor está completo, no es un stub | `modules/waf_evasion.py` (236 l.), `core/transforms/` (600 l.), `core/payload_mutator.py` (335 l.) |
| Hay 75 tests pasando | 32 `test_waf_evasion` + 25 `test_evasion_transforms` + 18 `test_payload_mutator` |
| **La métrica A/B existe y está MUERTA** | `core/adaptive_metrics.py:56-93` define `EvasionCounters` con `baseline_block_rate()`, `mutated_block_rate()`, `effectiveness()`. `grep` confirma cero callers fuera de su test. |
| El propio código pide que se cablee | docstring de `modules/waf_evasion.py:34`: el caller debe suministrar los counters |
| El testbed no tiene WAF | `testbed/docker-compose.yml` solo levanta `owasp-benchmark` + `wavsep` |

**Consecuencia:** el trabajo de implementación es mínimo. El trabajo real es
experimental. No reescribas el motor; cámbialo solo si una métrica lo exige.

## Procedimiento

### Fase 0 — Cablear la instrumentación muerta — HECHO 2026-09-30

`EvasionCounters` ya calcula lo que el experimento necesita, y **los datos que
necesita ya se estaban recolectando**. Corrección a la planificación original
de esta skill, que decía "cablear en `exploit_engine.py:603`":

`WafEvasionMetrics` (`core/telemetry_engine.py:189-225`) ya acumula los cuatro
números que `EvasionCounters` requiere, y `record_waf_evasion` está vivo y
alimentado desde producción. Lo que faltaba era el **álgebra**:

```
baseline_total   = probes
baseline_blocked = perimeter_blocks_encountered
mutated_total    = total_mutation_attempts
mutated_blocked  = total_mutation_attempts - bypassed
```

Un ciclo `BYPASSED` aporta exactamente un retry no bloqueado; todos los demás
mutated retries fueron bloqueados. De ahí la resta.

**Hecho:** `core/evasion_ab.py` (función pura, testeada) +
`WafEvasionMetrics.snapshot()` ahora emite un bloque `ab` con
`effectiveness`. 20 tests en `tests/test_evasion_ab.py`; el de regresión se
verificó que falla sin el cableado.

**Lección para el resto de tracks:** antes de asumir que falta instrumentación,
`grep` los productores de datos. `EvasionCounters` parecía "muerto" porque nada
lo *construía*, no porque nadie *midiera* lo que necesita. Distinguir "no se
construye" de "no se recopila" evita rehacer trabajo ya hecho. Revisa si a Track
B le pasa lo mismo con `evidence_kind`.

### Fase 1 — Levantar el WAF en el testbed

El escáner habla con el host en `127.0.0.1`, no por la red del compose
(`docker-compose.yml` publica `127.0.0.1:8443`). Por tanto el WAF va **entre**
el benchmark y el puerto publicado, y **no** tocas `scanner_core_async.py`.

Paranoia level del CRS como factor experimental (PL1 / PL4 como extremos
razonables; PL2 es el default y casi no bloquea).

Healthcheck obligatorio: antes de cada corrida, confirmar que el WAF está
realmente bloqueando con un payload canónico. Si el WAF no bloquea, la condición
`crs-p1` es idéntica a `sin-waf` y toda la condición es un punto vacío.

### Fase 2 — El grid

```
{waf: sin-waf, crs-p1, crs-p2} × {evasion: no-evasion, static-chain, adaptive-entropy} × {budget: 10, 20, 50, ∞}
```

**Coste real, medido de los timestamps del CSV existente:** 5-9 min por corrida
con presupuesto acotado; **~45 min** con `--max-payloads 0`. Un grid completo de
36 corridas con presupuesto ilimitado son **~27 h de reloj**. Decide el
presupuesto ANTES de lanzar. Empieza con un subgrid 3×2 en budget 20 (~1 h) para
ver si hay señal; si no la hay, no escales.

`tools/run_experiments.py` es idempotente: salta directorios existentes salvo
`--force`. Acepta `--budgets`, `--conditions`, `--extra-args`, `--dry-run`.
**Usa siempre `--dry-run` primero.**

### Fase 3 — Variables y control

- **Corpus hash + git commit + config completa**: ya se escriben solos en cada
  scan (`web_security_scanner_async.py:204` → `manifest_async.py:write_manifest`).
- **`--global-seed`** existe (`cli.py:278`) y va en **toda** corrida que vaya al
  paper. Sin seed no hay replicabilidad y es punto de rechazo automático.
- Un scan por corrida, sin concurrencia: el WAF tiene estado y las corridas
  paralelas se contaminan entre sí.

## La hipótesis H3 — el ángulo que salva la revisión por pares

El aporte **no** son los transforms individuales. Eso es literaturaknown
(WAFBooster, BWAFSQLi evalúan el WAF vía TRR/TAR, no la recuperación de recall
de un DAST). El ángulo defendible es otro:

`binary_safe` existe porque mutar un gadget chain de deserialización o un id de
IDOR **lo corrompe en silencio**. El scan no lanza excepción, no falla, termina
"con éxito" — y ha dejado de probar lo que dice probar. Eso es un **falso
negativo silencioso**, una clase de bug que nadie publica porque no es visible.

`payload_mutator.py:100-119` ya lanza `UnsafeTransformError` para
`SENSITIVE_CATEGORIES = {"deserialization", "idor"}`. Falta **medir su
prevalencia**: ¿en qué fracción de puntos el scanner creyó estar probando algo
que en realidad no probó?

Esto es lo que convierte una evaluación de eficacia en una contribución.

## Amenazas a la validez (escríbelas tú, no esperes a que las encuentre el revisor)

- **Construct validity**: ¿bloquear 403 es "falso negativo"? El WAF bloquea pero
  la vulnerabilidad existe. El ground truth sigue diciendo vulnerable. Define
  explícitamente qué cuenta como recall recuperado.
- **External validity**: OWASP Benchmark es un target. Un panel revisor va a
  preguntar por WAFs reales (Cloudflare, AWS WAF) y apps reales. Planea al menos
  una discusión con un segundo corpus.
- **Confound — presupuesto**: ya se vio en el CSV previo que FP **sube** (71→94)
  con el presupuesto mientras el recall se congela en 125 desde budget 20. El
  presupuesto extra solo añade ruido sobre puntos ya resueltos. Mide FP en cada
  celda del grid, no solo recall.
- **Cobertura del corpus**: la confianza de los payloads es mayoritariamente
  `LOW` (sql_injection: 519 LOW / 16 MEDIUM). Si los transforms solo mutan
  payloads LOW, estás midiendo el subconjunto más débil.

## Encuadre de doble uso — resolverlo en la introducción, no después

"Evasión de WAF" tiene tensión de doble uso. Encuadra esto como **evaluación de
fidelidad del escáner y evaluación de defensa**: la pregunta es si un DAST sigue
siendo una herramienta de medición válida cuando el objetivo tiene defensas, y si
las defensas se comportan de forma predecible. Nunca como desarrollo de bypass.
El mismo corpus sirve para defender: un WAF que bloquea payloads inofensivos
(los `LOW` confidence) tiene un coste de falsos positivos operacional real.

## Archivos que tocas

```
modules/waf_evasion.py
core/adaptive_metrics.py        ← INTOCABLE (§4 AGENTS.md). Si necesitas
                                  extenderlo, dilo en tu claim primero.
core/telemetry_engine.py
core/transforms/
core/payload_mutator.py
testbed/docker-compose.yml      ← en feat/ai-triage-mainline
tools/run_experiments.py        ← NO editar; usar sus flags
```

## Antes de dar el track por terminado

- [ ] `EvasionCounters` tiene callers en producción y test que falla sin él
- [ ] El WAF bloquea de verdad (healthcheck con payload canónico, log del WAF)
- [ ] Todas las corridas con `--global-seed` y manifiesto escrito
- [ ] H1-H3 escritas **antes** de los datos, con fecha
- [ ] FP reportado por celda, no solo recall
- [ ] Las amenazas a la validity están escritas, no implícitas
- [ ] `research/agents/<tu-proveedor>.md` actualizado a `done`
