---
name: scoped-testing
description: Validación acotada antes de concluir una tarea - pytest -k, ruff y mypy sólo sobre los módulos afectados, con la suite completa como puerta final. Úsala tras cualquier cambio de código y antes de decir "hecho".
---

# Testing acotado

## Intérprete
`.venv/bin/python` del checkout (Python 3.12, con dependencias). En un
worktree sin `.venv`, usa el del checkout principal. Nunca el `python3` del
sistema para tests: no tiene dependencias. `tools/context_packer.py` sí corre
con `python3` (sólo stdlib).

## Flujo
1. Archivos tocados:
   `git diff --name-only HEAD -- '*.py'` (+ `git ls-files --others --exclude-standard '*.py'`).
2. Tests relevantes: sección "Tests referencing changed symbols" del bundle
   (`--mode budget`), que ya trae la línea `Scoped run: pytest ... -k "..."`.
   Si un archivo cambiado tiene `tests/test_<nombre>.py`, añádelo.
3. Ejecuta en este orden, parando en el primer rojo:
   ```bash
   .venv/bin/python -m ruff check <archivos>
   .venv/bin/python -m mypy <archivos>
   .venv/bin/python -m pytest <tests> -k "<expr>" -q -x
   ```
   `mypy` respeta `[tool.mypy]` de `pyproject.toml`; no añadas flags que
   cambien el veredicto de CI.
4. Puerta final, una vez, antes de declarar terminado:
   `.venv/bin/python -m pytest -q` (≈1400 tests, ~70 s). El número de tests
   que pasan sólo puede subir; si baja, es regresión tuya.

## Reporte
```
ruff: OK | mypy: OK (N archivos) | pytest scoped: X passed | suite: Y passed, Z skipped
```
Pega solo la línea de resumen y, si falla, el primer error exacto (archivo,
línea, mensaje). No pegues logs completos.

## Reglas
- No marques tests como `skip`/`xfail` para pasar la puerta.
- Test nuevo por cada bug arreglado o rama nueva de comportamiento.
- Un fallo preexistente (también rojo en `HEAD` sin tus cambios) se reporta
  aparte como deuda, no se arregla de paso: ver skill `debt-isolation`.
- Tests flaky por tiempo (oráculos time-based, JVM warm-up): repite una vez
  aislado antes de concluir nada.
