# Claim — Antigravity CLI · 2026-09-29

Track: **C** — Orquestación multi-agente autónoma
Estado: **claimed** (con reserva — ver abajo)

## Área asignada

Track C. Asignado por defecto porque es el que queda, **no** porque sea el mejor.

## Advertencia honesta antes de empezar

Track C es el más débil de los tres para una tesis doctoral:

1. `agents/` + `ai_module/` son 7.224 líneas — la mayor base de código del repo y
   la menos testeada.
2. La interfaz aún no está estable. Un resultado sobre una interfaz que cambia
   en tres meses no es publicable.
3. El §Future Work item 8 del paper previo **ya lo nombra**, lo que significa
   que el trabajo previo lo descartó como digno de evaluación. Es una señal.
4. Evaluar un sistema multi-agente con LLM dentro de un RCBD cuesta tokens
   además de requests, y el no-determinismo del LLM puede exceder el efecto
   entre condiciones.

**Si prefieres no gastar un mes en esto, intercambia con OpenCode.** Está permitido:
solo actualiza la tabla de asignación en `AGENTS.md` §2 ter y tu claim aquí.

## Archivos que toco

```
orchestrator.py
agents/
ai_module/
```

**No tocar** `core/adaptive_metrics.py` (intocable) ni las secciones de
`base_tester_async.py` de otros tracks. Localízalas por **nombre de función**,
no por línea (el archivo se está refactorizando y las líneas se mueven):

```bash
grep -n "async def _ai_triage" \
  web_security_scanner/modules/vulnerability_testers/base_tester_async.py
```

Las mías son `_ai_triage` y `_ai_cross_validate` (≈680-1181).

## Skills que cargo

- `track-c-agent-orchestration` — al empezar (trae el go/no-go de 1 día)
- `experiment-protocol` — antes de lanzar cualquier grid
- `phd-thesis-framing` — antes de escribir cualquier documento
- `claim-verification` — antes de reportar cifras

## Orden de trabajo

1. **Go/no-go, 1 día máximo.** ¿Tiene métrica comparable a TP/FP/FN? ¿Es
   determinista? ¿El coste se mide por corrida? Si falla alguno, vuelve a
   Track A o B y déjalo escrito en `research/notes/`. Eso es un resultado
   válido, no un fracaso.
2. Si pasa el go/no-go: aislar la contribución con las tres condiciones
   (`base` / `+orchestrator` / `−orchestrator`).
3. Definir `coste_por_hallazgo` y reportar la frontera de Pareto, no un punto
   único.

## Notas

- 2026-09-29 — Claim creado. Sin trabajo iniciado aún. Reserva anotada.
