---
name: debt-isolation
description: Aislar limpieza y deuda técnica de los cambios funcionales - en commits, PRs y reportes separados. Úsala al planificar, commitear o reportar cuando aparezca refactor, formateo, renombrado, borrado de código muerto o arreglos "de paso".
---

# Aislamiento de deuda técnica

## Regla
Un cambio funcional y una limpieza nunca comparten commit. Si comparten PR,
van en secciones separadas y commits distintos; si la limpieza supera ~50
líneas o toca archivos ajenos al cambio, va en PR propio.

## Qué es deuda/limpieza
- Formateo, orden de imports, renombrados sin cambio de comportamiento.
- Código muerto, archivos huérfanos, duplicados, comentarios obsoletos.
- Tipado añadido a código que no cambia de comportamiento.
- Documentación que no describe el cambio funcional en curso.
- Fallos preexistentes de `ruff`/`mypy`/`pytest` que ya estaban en `HEAD`.

## Qué es funcional
Todo lo que cambia comportamiento observable: lógica, CLI, salidas, formatos,
nuevos módulos, tests que fijan ese comportamiento nuevo.

## Flujo
1. Al planificar: lista las tareas en dos bloques, `Funcional` y `Deuda`.
2. Al editar: si notas deuda fuera del alcance, no la toques; anótala en el
   bloque `Deuda` con `ruta:línea — qué y por qué`.
3. Al commitear: primero los commits funcionales (`feat:`/`fix:`), luego los
   de limpieza (`chore:`/`refactor:`/`style:`), cada uno verde por sí solo.
   `git add -p` para separar hunks mezclados en un mismo archivo.
4. Al reportar: dos secciones con sus propias listas de archivos.

## Prohibido sin aprobación explícita del humano
- Borrar archivos existentes (código de negocio, notas de Obsidian, datos,
  corpus de payloads).
- Reescribir historia (`rebase -i`, `push --force`) o mover ramas.
- "Arreglar" tests rotos que no rompiste.

## Formato del bloque de deuda
```
## Limpieza y deuda técnica (no incluida en este cambio)
- ruta:línea — problema → propuesta (esfuerzo S/M/L)
```
