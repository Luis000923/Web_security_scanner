# Claim — OpenCode (Zen) · 2026-09-29

Track: **A** — Evasión de WAF bajo presupuesto de requests
Estado: **claimed**

## Área asignada

Track A completo. Es el track con más valor construido: 75 tests pasando, motor
completo (`waf_evasion.py` + `transforms/` + `payload_mutator.py`), y la métrica
A/B del experimento (`EvasionCounters`) ya escrita pero muerta.

## Archivos que toco

```
web_security_scanner/core/evasion_ab.py             (NUEVO — la álgebra A/B)
web_security_scanner/core/telemetry_engine.py       (bloque `ab` en snapshot())
web_security_scanner/cli.py                         (SOLO región ~1179-1194:
                                                     el print de `--show-telemetry`)
web_security_scanner/modules/waf_evasion.py
web_security_scanner/core/transforms/
web_security_scanner/core/payload_mutator.py
web_security_scanner/tests/test_evasion_ab.py       (NUEVO)
testbed/docker-compose.yml                          (rama feat/ai-triage-mainline)
```

**Aviso de conflicto en `cli.py`:** Track B necesita `cli.py` para su flag
`--no-param-semantics` (en `_build_parser`, ~línea 640-660 y ~1000). Yo toco
**solo** el bloque de impresión de telemetría (~1179-1194), que es otra región
del archivo. Si Track B edita otra zona no hay solape; si aparece conflicto de
merge, es que alguien tocó las dos.

**Intocables** (ver AGENTS.md §4): `core/adaptive_metrics.py`,
`tools/eval_oracle.py`, secciones de `paper/submission/sections/`.
Confirmado: no edité ninguno. Construyo `EvasionCounters` desde fuera.

## Skills que cargo

- `track-a-waf-evasion` — al empezar
- `experiment-protocol` — antes de lanzar el grid
- `phd-thesis-framing` — antes de escribir cualquier documento
- `claim-verification` — antes de reportar cifras

## Primer paso (BLOQUEANTE — hecho)

Cablear `EvasionCounters` (`core/adaptive_metrics.py:56-93`) al pipeline.

**Corrección a la hipótesis inicial:** el plan decía "cablear en
`exploit_engine.py:603`". Falso. Al leer el código, los datos **ya se estaban
recolectando** ahí: `WafEvasionMetrics` (`core/telemetry_engine.py:189-225`) ya
acumula `probes`, `perimeter_blocks`, `total_mutation_attempts` y `bypassed`
— los cuatro números que `EvasionCounters` necesita. `record_waf_evasion` está
vivo y alimentado desde producción.

Lo que faltaba era (a) la **álgebra** que dobla esos totales a la forma A/B, y
(b) construir un `EvasionCounters` en producción. El álgebra:

```
baseline_total   = probes
baseline_blocked = perimeter_blocks_encountered
mutated_total    = total_mutation_attempts
mutated_blocked  = total_mutation_attempts - bypassed
```

Porque un ciclo `BYPASSED` aporta exactamente un retry no bloqueado; todos los
demás mutated retries fueron bloqueados.

## Estado: in-progress

- [x] **Fase 0** — `core/evasion_ab.py` (nuevo, puro, testeado):
      `evasion_counters_from_metrics()` + `evasion_counters_from_snapshot()`
- [x] Cableado en `WafEvasionMetrics.snapshot()` → bloque `ab`. Viaja solo a
      CLI y report engine por el dict existente.
- [x] `tests/test_evasion_ab.py` — 20 tests. El de regresión **verificado que
      falla sin el cableado** (`KeyError: 'ab'`).
- [x] `core/adaptive_metrics.py` **intocado** (construyo `EvasionCounters` desde
      fuera, no edito el archivo protegido).
- [x] **`--show-telemetry` imprime `effectiveness`** (`cli.py:1179-1194`). Es lo
      que permite sanity-checkear un pilot run antes de comprometer 27 h de grid.
      Cuando no hay baseline bloqueado, no imprime nada (en vez de 0.0).
- [ ] **Levantar ModSecurity/CRS** en `testbed/docker-compose.yml` (rama
      `feat/ai-triage-mainline`) — bloqueado por decisión del humano.
- [ ] Grid — bloqueado por decisión del humano (27 h de reloj con budget ∞).

## Pendiente de decisión humana

1. ¿Rama de trabajo? `main` no tiene `testbed/`. Necesito worktree desde
   `feat/ai-triage-mainline` para el WAF.
2. ¿OWASP Benchmark se queda o se migra? (AGENTS.md §7 q1)
3. ¿Presupuesto del grid? 36 corridas con budget ∞ ≈ 27 h.

## Notas

- 2026-09-29 — Claim creado.
- 2026-09-29 — Fase 0 completada. `EvasionCounters` deja de ser código muerto:
  por primera vez se construye en producción y `effectiveness()` se calcula
  desde un scan real.
