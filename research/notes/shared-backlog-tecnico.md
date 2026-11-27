# Backlog técnico (deuda de contexto y tooling) — 2026-11-26

Fuera del alcance del cambio de optimización de contexto. Nada de esto se ha
tocado; cada punto es un PR propio (skill `debt-isolation`).

| # | Item | Evidencia | Propuesta | Esfuerzo |
|---|---|---|---|---|
| 1 | Skills `track-*` exceden el límite de 700 tokens de las micro-skills | cl100k: `track-a-waf-evasion` 2645, `track-b-evidence-semantics` 1900, `track-c-agent-orchestration` 1409 | Partir en un `SKILL.md` ≤ 700 (regla + flujo) y `reference.md` cargado bajo demanda | M |
| 2 | Otras skills de investigación también exceden 700 tokens | `phd-thesis-framing` 2177, `experiment-protocol` 2143, `claim-verification` 1994 | Mismo patrón que #1 | M |
| 3 | Skills que citan `AGENTS.md` §1.5 | `claim-verification`, `experiment-protocol`, `phd-thesis-framing` (§1 se movió a `shared-estado-investigacion.md`; el stub de `AGENTS.md` §1 redirige) | Actualizar la ruta al partir cada skill (#1/#2) | S |
| 4 | `scripts/evaluate.py` (347 líneas, `main`) vs `tools/analyze_results.py` (1173 líneas, rama `feat/ai-triage-mainline`) | Ambos derivan métricas IEEE de informes/CSV | Revisar solapamiento; decidir un único punto de entrada antes de mergear la rama de investigación | M |
| 5 | Rangos de líneas de `AGENTS.md` §4 obsoletos | La tabla cita rangos de 2026-09-29; `base_tester_async.py` tiene 2.074 líneas | Sustituir rangos por `grep -n` sobre `.context/symbols.json` | S |
| 6 | `main` local diverge de `origin/main` | `git merge-tree` predice 11 conflictos en `vulnerability_testers/*` (commits `03b2844`, `e1ed3d8` vs `69a4252`) | Integración manual decidida por el humano | L |
| 7 | Frontera de la bóveda Obsidian | `~/Documentos/Obsidian/claude/00-Sistema/ADR_BOUNDARY.md` | Archivar (no borrar) las notas marcadas "reemplazada" cuando el humano lo apruebe | S |
