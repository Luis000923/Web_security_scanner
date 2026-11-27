---
name: context-navigation
description: Navegación de código por divulgación progresiva L0 → L1 → L2. Úsala SIEMPRE antes de abrir un archivo .py completo, al explorar el repo, buscar dónde está un símbolo, entender un módulo o preparar un cambio. Obliga a consultar .context/repomap.md y .context/symbols.json primero y a justificar cada lectura completa.
---

# Navegación de contexto (L0 → L1 → L2)

## Regla
No leas un `.py` completo sin pasar antes por L0 y L1. Cada salto a L2
(lectura completa) se justifica en una línea antes de hacerlo.

## Niveles
- **L0** `.context/repomap.md`: firmas, clases, imports (~8 % del código).
  `.context/symbols.json`: spans y llamadas, para `jq`/`grep`.
- **L1** `tools/context_packer.py --mode l1|budget`: diff + callers/callees a 1 salto.
- **L2** `Read` con `offset`/`limit` del span. Caro: sólo justificado.

## Flujo
1. Frescura: `python3 tools/context_packer.py --mode l0 --check`; si sale 1,
   sincroniza con `--mode l0 --sync` (el hook `Stop` lo hace al cerrar cada turno).
2. Localiza: `grep -n "<símbolo>" .context/repomap.md` (no leas el mapa entero).
3. Span exacto:
   `jq -r '.files["<ruta>"].symbols[] | select(.qualname=="<Q>") | "\(.lineno)-\(.end_lineno)"' .context/symbols.json`
4. Contexto de un símbolo sin diff:
   `python3 tools/context_packer.py --mode l1 --symbols <ruta>::<Qual> --out -`
5. Contexto de un cambio: `--mode budget` (worktree vs HEAD, `--range A..B`
   o `--staged`). Garantiza ≤ 60 % del baseline; código 3 = divide el cambio.
6. L2 sólo si L1 no basta: lee el span, no el archivo entero.

## Justificación L2 (escríbela antes del `Read`)
`L2: <ruta>:<a>-<b> — <qué falta en L1: cuerpo de X / invariante Y / estado global Z>`

Válido: cuerpo exacto para editar; estado de módulo, metaclases o imports
dinámicos; callers omitidos por el tope. Inválido: "para tener contexto".

## Límites conocidos del AST
- `getattr`, `importlib`, plugins registrados por nombre y callbacks no son
  aristas: `grep` antes de concluir "sin callers".
- `obj.run()` se resuelve por nombre; un nombre repetido sólo enlaza archivos
  que importan el módulo dueño.
- Error de sintaxis: `! parse error`, sin símbolos.
