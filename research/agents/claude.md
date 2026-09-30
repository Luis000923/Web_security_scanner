# Claim — Claude Code · 2026-09-29

Track: **B** — Semántica de parámetros y evidencia causal
Estado: **claimed**

## Área asignada

Track B completo. Es el track que más paper produce por unidad de esfuerzo:
- El mapa HARD/SOFT/none de los 25 testers es en sí mismo una contribución
  publicable (taxonomía de fuerza de evidencia por clase de vulnerabilidad).
- El corpus de flow-control que hay que construir es reutilizable por la
  comunidad, no un input interno.

## Archivos que toco

```
web_security_scanner/core/param_semantics.py
web_security_scanner/cli.py                          (solo flag de ablation)
web_security_scanner/modules/vulnerability_testers/*.py   (los 23 que faltan)
web_security_scanner/tests/test_param_semantics.py   (nuevo, en español)
research/notes/B-prereg.md
```

**No tocar** las secciones de `base_tester_async.py` de otros tracks.
Localízalas por **nombre de función**, no por línea — el archivo se está
refactorizando y las líneas se mueven:

```bash
grep -n "async def _apply_param_semantics" \
  web_security_scanner/modules/vulnerability_testers/base_tester_async.py
```

La mía es `_apply_param_semantics` (≈630-679). `assess_anomaly` es de Track A
y `_ai_triage`/`_ai_cross_validate` son de Track C.

## Skills que cargo

- `track-b-evidence-semantics` — al empezar
- `experiment-protocol` — antes de lanzar el grid
- `phd-thesis-framing` — antes de escribir cualquier documento
- `claim-verification` — antes de reportar cifras

## Orden de trabajo (el orden importa)

1. **`--no-param-semantics` en la CLI.** Sin flag no hay ablation, y sin
   ablation no hay condición de control y no hay experimento. Bloqueante.
2. **`tests/test_param_semantics.py`.** El módulo tiene 0 tests y solo 2 de 25
   testers lo ejercitan. Ese perfil es donde un bug pasa desapercibido.
3. **Propagar `evidence_kind`.** 23 testers no pueden pasar el gate. Para cada
   uno: implementarlo, o documentar explícitamente por qué no puede.
4. **Corpus de flow-control.** El más caro. Antes: correr
   `literature-scout` para verificar que no existe ya.

## Advertencia

Antes de invertir días construyendo el corpus de flow-control, **verifica que no
existe ya**. El track asume que no hay ninguno. Si lo hay, se reusa.

## Notas

- 2026-09-29 — Claim creado. Sin trabajo iniciado aún.
