---
name: reuse-before-write
description: Anti-duplicación con tools/dup_guard.py - --lookup antes de escribir una función de 8+ líneas, --check-diff antes de cerrar o aprobar un cambio.
---

# Reutiliza antes de escribir

`tools/dup_guard.py` es determinista: no releas el repo buscando parecidos.

## 1. Antes de escribir (planner, coder)
Función o helper nuevo de ≥ 8 líneas lógicas:
`python3 tools/dup_guard.py --lookup "<nombre o 2-4 palabras del propósito>"`
- Hit que cubre el caso: impórtalo; no lo copies.
- Hit parcial: extiéndelo con un parámetro opcional cuyo default conserve
  el comportamiento de los callers. Si rompe contratos, no lo fuerces.
- Sin hits tras dos formulaciones: créala.
- El spec lista, por cada símbolo "nuevo", el hit descartado y el motivo.

## 2. Antes de "hecho" (coder) o de aprobar (reviewer)
`python3 tools/dup_guard.py --check-diff` (worktree) o `--staged` (index).
- `exit 0` limpio; `exit 2` duplicado nuevo: cada línea dice qué
  reutilizar; `exit 1` error: repórtalo literal.
- Solo cuenta lo que introduce el diff; la deuda previa no bloquea.
- Reviewer: `exit 2` sin justificar = HIGH CONFIRMED
  (`ruta:linea - duplica <símbolo> -> reutilízalo`).

## 3. Cuándo NO fusionar
- Dominios distintos que hoy se parecen: testers de otra clase de
  vulnerabilidad, oráculos, adaptadores con formato de salida propio.
- Contratos de plugin (`run_test`, `parse`, `build_command`, `evaluate`):
  mismo nombre = interfaz, no copia.
- Fixtures de `tests/`: el aislamiento vale más que las líneas.
- Intocables (`core/adaptive_metrics.py`, `tools/eval_oracle.py`) o código
  que fija cifras del paper.
- Si fusionar exige flags booleanos que bifurcan el cuerpo, no es reuso.

## 4. Excepción justificada
`# dup-guard: ignore -- <motivo>` en la línea del `def` o encima; para un
grupo, `tools/dup_allowlist.json` con `members` (`ruta::Qual`) y `reason`.
Sin motivo escrito no hay excepción.

## 5. Auditoría
`make dup-scan`: ranking (tipo, similitud, riesgo, líneas ahorrables).
Solo riesgo Bajo, en commit `refactor(dedup)` aparte (skill `debt-isolation`).
