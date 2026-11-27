---
name: PhD Thesis Framing
description: Encuadre doctoral de la investigación — la tesis unificadora, la escalera de niveles de contribución, qué diferencia un doctorado de una maestría, y los ataques previsibles del tribunal. Úsala al escribir o revisar la introducción, al decidir si un resultado es publicable, o cuando la pregunta sea "¿esto da para un doctorado?".
---

# Encuadre doctoral

## Respuesta corta a "¿esto da para doctorado?"

**Sí, pero no por lo que está hecho ahora.** 2 meses de trabajo es el
comienzo de un doctorado (que dura 3-5 años), no un doctorado. Lo que sí es
importante: **la tesis se define ahora, los capítulos se construyen por
partes.** Lo que hay hoy es un primer capítulo con un null result honesto y un
problema bien diagnosticado. Eso es una base buena. Un null result bien
diagnosticado vale más que un resultado positivo mal construido.

## La tesis unificadora

> **Los escáneres DAST se evalúan sobre objetivos sin defensas. Esta tesis
> caracteriza, formaliza y mitiga cómo las capas defensivas degradan la
> fidelidad del escáner, y establece una metodología de medición consciente del
> coste para cuantificarlo.**

Tres capítulos = tres capas defensivas, independientes y acumulativas:

| Capítulo | Capa | Track | Pérdida de recall ocurre en… |
|---|---|---|---|
| 1 | Transporte | A | La request nunca llega al objetivo (WAF la bloquea) |
| 2 | Evidencia | B | La request llega pero el oráculo no la reconoce (divergencia ≠ causalidad) |
| 3 | Orquestación | C | La decisión de qué probar se toma mal (agente vs heurística) |

**Por qué esto es una tesis y no tres papers sueltos:** las tres capas compiten
por el mismo presupuesto de requests y interactúan. Un WAF que bloquea hace que
el orquestador mal calibrado gaste más presupuesto en mutación. Esa interacción
es el objeto de estudio, y no existiría si los tracks fueran independientes.

## La escalera de contribución — sé honesto sobre dónde estás

Un doctorado no se sostiene sobre un solo peldaño. Estos son los niveles, de
menos a más:

| Nivel | Qué es | ¿Lo tienes? |
|---|---|---|
| **N1 — Artefacto** | Una herramienta que funciona y es reproducible | ✅ Sí. 938 tests, manifiesto SHA-256, baseline ZAP, pipeline RCBD completo. Esto es más de lo que la mayoría de papers aporta y no lo están explotando. |
| **N2 — Método** | Una técnica nueva que mejora lo medible | ⏳ Tracks A y B. La mutación adaptativa y el gate de evidencia causal. |
| **N3 — Teoría** | Un modelo formal del fenómeno | ❌ **No lo tienes. Es lo que falta.** |
| **N4 — Generalización** | El hallazgo sobrevive fuera de un benchmark | ❌ No lo tienes. Y es exactamente la debilidad que un revisor va a atacar primero. |
| **N5 — Impacto** | Cambia cómo la comunidad mide DAST | ❌ Posible a 5 años, no ahora. |

**El gap crítico es N3.** Ahora mismo tienes un gran N1 y un N2 en
construcción, sobre un N4 inexistente. Sin N3 y sin N4, es una maestría
excelente — y hay muchas. La tesis se completa con N3 y N4.

### Cómo consigues N3 (modelo formal)

Propuesta concreta, no lipstick: un modelo de la relación entre **defensa
externa**, **coste de request**, y **fidelidad de la detección**. Define:

```
D(W, e)   = revisión de request tras aplicar defensa W y evasión e ∈ [0,1]
Recall(b) = recall con presupuesto b requests, sobre capa de evidencia fija
Costo(d)  = requests consumidos para recuperar d recall perdido
```

La tesis defendible sería: **existe un mínimo coste de recuperación por capa, y
las capas no son conmutativas** (evadir el WAF sin evidencia causal no produce
recall, porque el punto sigue sin reconocerse). Eso es una afirmación falsable
y no trivial, y explica por qué A solo, B solo, o C solo dan resultados
marginales mientras el conjunto no.

Esto se formaliza mejor **después** de tener los datos, no antes. Pero reserva
el hueco ahora, o después no hay dónde ponerlo.

### Cómo consigues N4 (generalización)

Imprescindible, y es la pregunta abierta nº1 de `AGENTS.md` §7. Un solo
benchmark no generaliza. Mínimo dos de:

- Un segundo corpus con WAF real (no solo CRS)
- Un corpus con flow-control — **track B ya lo necesita**, así que es doble
  retorno
- OWASP Benchmark en su versión con POST además de GET (hoy solo 338 GET)

## Qué diferencia un doctorado de una maestría (respuesta blunt)

| Maestría | Doctorado |
|---|---|
| "Lo medí en un benchmark y mejoró X%" | "Fenómeno caracterizado, modelo formal, validado en N targets" |
| Contribución = la herramienta | Contribución = el **conocimiento**; la herramienta es el instrumento |
| El resultado es el punto final | El resultado abre una línea que sigue después de terminar |
| Revisión = 2-3 revisores anónimos | Revisión = tribunal que pregunta "¿y por qué no…?" |

La columna de la derecha es un examen oral, no un paper. **Empieza a practicar
las preguntas del tribunal ahora**, no al final.

## Los ocho ataques previsibles del tribunal

Ensáyalos. Cada uno tiene ya una respuesta parcial en el repo:

1. **"Un solo benchmark."** → N4. Es el ataque más fuerte y el más difícil de
   responder. Empieza a construir el segundo corpus temprano.
2. **"¿No es esto únicamente detección deucus?"** → Sí, y hay que decirlo. La
   contribución es *medir* la fidelidad, no *prevenir* a nadie. El paper de
   defenders de DAST necesita escáneres honestos; sesgados, no.
3. **"El resultado es nulo."** → Sí, y es un null *informativo*: demuestra que un
   pipeline anti-FP contra un objetivo sin ruido no aporta. Eso es un hallazgo
   sobre la metodología de evaluación, publicable en sí mismo.
4. **"Tus macros no cuadran con tu CSV."** → **Ocurre hoy** (§1.5 de AGENTS.md:
   recall 70.6% declarado vs 64.4% del CSV). Resuélvelo ANTES de escribir
   cualquier documento nuevo. Un revisor que lo encuentre te descarta.
5. **"Seleccionaste el benchmark que te da la razón."** → Justifica el
   benchmark con criterios *a priori*, no *a posteriori*. Documenta que la
   elección del corpus precede a la elección del track.
6. **"Eso ya está publicado."** → Por eso existe la skill `novelty-audit`.
7. **"Los WAF cambian rápido; tus resultados envejecen."** →.Versiona el CRS
   usado (imagen docker con tag) y demuestra la tendencia como resultado, no
   como peaked.
8. **"¿Por qué no un corpus sintético controlado?"** → Extensión legítima.
   Un corpus sintético con defensas inyectadas da control experimental total y
   elimina el confound de "el benchmark no tiene lo que necesitas".

## Qué hacer ahora, esta semana

1. **Escribir la tesis en 4 líneas** en `research/notes/thesis.md`, y dejarla
   fija. Todo lo que hagás debe servirla o descartarse.
2. **Resolver §7 q1** (¿OWASP Benchmark se queda o se migra?). Bloquea
   A, B y C por igual.
3. **Reconciliar §1.5** (macros vs CSV). Es una deuda que se paga cara si
   espera.
4. **Empezar el segundo corpus** antes de terminar el primero. Es lo que más
   tiempo toma y bloquea N4.

## Anti-patrón a evitar

**No conviertas el doctorado en "más módulos del escáner".** El repo tiene
41k líneas y 25 testers. Añadir otro tester no sube el nivel de contribución —
sube la tabla de resultados de un taller. La tesis se construye alrededor de
**un fenómeno** (degradación de fidelidad por capas defensivas), no alrededor de
la herramienta.
