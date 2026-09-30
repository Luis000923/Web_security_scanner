---
name: Claim Verification and Adversarial Review
description: Verificación adversarial de afirmaciones — comprobar que cada número de un documento traza a su fuente, buscar prior art antes de reclamar novedad, y aplicar la checklist de rechazo de revisores IEEE. Úsala antes de enviar cualquier sección a revisión, cuando alguien afirme que un resultado es "bueno", o para decidir si un claim es publicable.
---

# Verificación adversarial

## Principio

Un documento de investigación es un grafo de afirmaciones. Cada número es un
nodo con una arista hacia su fuente. **Antes de publicar, toda arista debe
verificarse de punta a punta.** La mayoría de los rechazos no vienen de
resultados malos — vienen de resultados buenos que no resisten una comprobación.

## Fase 1 — Trazabilidad de cada número

Para cada cifra de cualquier borrador:

| Campo | Ejemplo |
|---|---|
| Afirmación | "recall techo 70.6 %" |
| Fuente | `testbed/experiment_results.csv`, fila `0,baseline` |
| Recalculado | 125 TP / 194 positivos = 0.6443 |
| **¿Cuadra?** | **NO — 70.6 % implicaría TP=137, el CSV nunca pasa de 125** |
| Acción | reconciliar o retirar la afirmación |

Este es un fallo **real y actual** en el repo (`AGENTS.md` §1.5). No es
hipotético. Pasa hoy, en el abstract, en `_datos.tex` y en la comparación con
ZAP. Resuélvelo antes de escribir cualquier documento nuevo, porque copiar una
macro discrepante a un documento nuevo multiplica el error.

**Método:** nunca leas las macros para saber un resultado. Lee el CSV, recalcula
desde TP/FP/FN, y solo entonces escribe la macro.

## Fase 2 — Búsqueda de prior art (antes de reclamar novedad)

El repositorio ya tiene contexto: WAFBooster (arXiv 2501.14008) y BWAFSQLi
evalúan el **WAF** vía TRR/TAR, no la capacidad de un DAST de recuperar recall
tras evasión. Ese es el hueco a posicionar.

**El hueco ≠ la contribución.** Antes de escribir "nadie ha hecho X":

1. Busca el término técnico, no el del paper. Si el paper dice "fidelidad
   bajo defensas", nadie más va a usar esa palabra. Busca "DAST recall
   degradation WAF", "security tool evaluation defensive layers", "scanner
   fidelity adversarial mitigation".
2. Busca en la literatura que los revisores de seguridad leen: IEEE S&P, USENIX
   Security, NDSS, CCS, RAID, WAES, SACS. También ACNSS (Applied Network
   Security Symposiums) — es donde se publica benchmarking de DAST en la práctica.
3. Busca artefactos, no solo papers: OWASP Benchmark extensions, ZAP add-ons,
   nuclei templates, Metasploit. Alguien pudo publicar un corpus de flow-control
   que no conozco y que ya hace mi Track B.
4. **Documenta la búsqueda, no solo el resultado.** Una sección de novelty sin
   el término exacto usado y dónde se buscó es más débil que una con él.

**Riesgo activo:** construí un corpus de flow-control (Fase 3 de Track B) sobre
la premisa de que no existe. Verifica esa premisa antes de invertir días
construyendo algo que ya está hecho.

## Fase 3 — La checklist de rechazo de revisores IEEE

Ejecuta esto contra tu borrador. Cada ítem que falla es un rechazo probable.

### Integridad numérica
- [ ] Toda cifra del abstract aparece en una tabla del cuerpo
- [ ] Toda tabla se recalcula desde la fuente, no se copia
- [ ] Los denominadores son explícitos ("de 194", "de 144", "sobre 338")
- [ ] p-valores acompañados de tamaño de efecto y n
- [ ] Las unidades son comparables entre condiciones

### Validez interna
- [ ] La condición de control es **idéntica** salvo la variable de interés
- [ ] Existe healthcheck que demuestra que cada condición hace lo que dice
      (p. ej. que el WAF bloquea de verdad; si no bloquea, esa celda es un
      punto vacío y hay que decirlo)
- [ ] Las réplicas son las declaradas
- [ ] El código no cambió entre celdas del mismo grid (manifiesto lo prueba)

### Validez externa
- [ ] Más de un target, o la limitación está declarada como trabajo futuro con
      plan
- [ ] La versión del WAF / corpus / dependencia está fijada (tag de docker,
      no `latest`)
- [ ] El ground truth cubre el mapa que el escáner exploró, o la diferencia
      está reportada

### Construct validity
- [ ] Las métricas miden lo que dicen medir
- [ ] El recall "recuperado" por evasión no se confunde con vulnerabilidad
      nueva
- [ ] El FPR está definido con su denominador

### Presentación
- [ ] El título dice el hallazgo, no el tema
- [ ] El abstract es autocontenido (no requiere leer el paper)
- [ ] Las amenazas a la validez tienen su propia sección
- [ ] El artefacto es reproducible con un comando

## Fase 4 — El ataque del revisor escéptico

Simula al revisor que solo lee abstract + intro + conclusión, y que tiene
40 minutos. Escribe las tres preguntas más probables:

1. "¿Cuál es el hallazgo?" → Si no se puede responder en una frase, el paper
   no tiene hallazgo.
2. "¿Qué pasa si el resultado es que no hay efecto?" → Si la respuesta es
   "no podemos concluir nada", el diseño no está terminado. Un null
   publicable tiene un alcance: "bajo estas condiciones, este mecanismo no
   aporta". Eso es un resultado, no una ausencia.
3. "¿Por qué no probar X?" → X = corpus sintético, otro WAF, POST además de
   GET, otro escáner como baseline. Si X es barato y no lo hiciste, es un
   problema. Si X es caro, dilo y explica el coste.

## Fase 5 — Checklist de "esto es publicable"

```
[ ] El hallazgo es una frase, no un párrafo
[ ] Es contraintuitivo o al menos no obvio  (si es obvio, es ingeniería)
[ ] Alguien lo mediría de otra forma y obtendría distinto (si no, no hay
    contribución metodológica)
[ ] Hay artefacto reproducible
[ ] Las cifras son trazables a su fuente
[ ] Las limitaciones son honestas y están declaradas antes de que las encuentre
    el revisor
[ ] La novelty está verificada contra la literatura real, no solo recordada
```

## Anti-patrones de investigación

| Antipatrón | Por qué mata el paper |
|---|---|
| Correr primero, hipótesis después | p-hacking, aunque sea inconsciente |
| Ajustar la métrica hasta que dé positivo | El revisor pide la métrica original |
| Comparar contra un baseline que sabes débil | ZAP está bien; no lo debilites artificialmente |
| Reportar solo p-valores | Con n=4, p≪0.001 y δ<0.02 es un no-resultado disfrazado |
| Ocultar el FP que sube con el presupuesto | Ya se vio en el CSV: FP 71→94 con recall congelado |
| Correr el grid completo sin `--dry-run` | 27 h de reloj evaporadas en un typo |

## Cómo usar esta skill

1. Antes de escribir: Fase 2 (prior art) + Fase 3 (checklist).
2. Después de escribir, antes de enviar: Fase 1 (trazabilidad) + Fase 4.
3. Cuando alguien del equipo diga "ese resultado es bueno": Fase 1 y Fase 4
   antes de celebrarlo. Casi siempre el número no es lo que parece.
