---
name: Experiment Protocol and Statistical Validity
description: Protocolo experimental reproducible — diseño RCBD, elección de test estadístico, potencia, control de confounders, modelo de coste, y disciplina de semilla/manifiesto. Úsala al diseñar un grid, al interpretar un p-valor, al decidir cuántas réplicas correr, o cuando la pregunta sea "¿este resultado es real?".
---

# Protocolo experimental

## Regla 0 — antes de correr nada

```
1. Escribe la hipótesis con fecha          → research/notes/<track>-prereg.md
2. Escribe el power analysis              → abajo
3. Corre con --dry-run                     → ver el plan, no ejecutarlo
4. Decide el presupuesto total ANTES      → 5-9 min/corrada acotada, ~45 min ∞
5. Lanza con --global-seed                 → cli.py:278
6. Verifica el manifiesto después de 1    → corpus SHA-256 + commit + config
```

Un resultado sin hipótesis escrita antes es una anécdota, no un hallazgo.

## Diseño — RCBD (ya implementado, no lo reescribas)

`tools/run_experiments.py` ya es un RCBD: bloque = condición, tratamiento =
configuración. Es lo correcto para este problema porque cada corrida comparte
el mismo target y solo cambia la configuración del escáner.

**Idempotente**: salta directorios existentes salvo `--force`. Eso hace el
experimento reanudable. Acepta `--budgets`, `--conditions`, `--extra-args`,
`--dry-run`.

**El bloque importa**: si una corrida se ejecuta con distinta carga de máquina
que otra, ese ruido entra en el análisis. Corre en lotes secuenciales, no en
paralelo — el WAF y el benchmark tienen estado.

## Potencia — hazla ANTES, no después

Esto es lo que separa un diseño correcto de uno que se quedó corto.

Para Wilcoxon signed-rank con dos grupos emparejados de tamaño n, la potencia
≈ 0.8 requiere aproximadamente **n ≥ 6 por grupo** para detectar un *shift*
mediano con Cohen's d ≈ 0.9. Para efectos más pequeños, más réplicas.

Los 4 bloques del diseño RCBD actual dan n=4 por condición. **n=4 es
marginal.** Y el paper previo ya mostró que |δ| < 0.02 en tres de cuatro
condiciones — o sea, se buscaron efectos minúsculos con potencia de detectar
efectos grandes. Con n=4, un null no distingue "no hay efecto" de "no hay
potencia".

**Opciones:**
- **Réplicas dentro de bloque** (lo que deberías hacer): correr la misma
  condición 3 veces, usar la mediana como el valor del bloque.
- Más bloques (5 condiciones × 5 bloques = n=5) — mejora poco.
- Aceptar que solo detectarás efectos grandes y dimensionar la afirmación en
  consecuencia: "no encontramos diferencia" NO es "son iguales".

**Escribe el resultado del power analysis antes de correr.** Si después reportas
un null, el revisor preguntará si tenías potencia. La respuesta honesta ("no, y
aquí está el cálculo") es aceptable. La inventada no.

## Test estadístico — elige por estructura de datos

`tools/analyze_results.py` ya implementa la batería completa. Usa:

| Situación | Test | Por qué |
|---|---|---|
| >2 condiciones, misma unidad experimental | **Friedman** + posthoc **Nemenyi** con CLD | Datos emparejados, no paramétrico, estándar en benchmarking de seguridad |
| 2 condiciones emparejadas | **Wilcoxon signed-rank** + corrección **BH** para FDR | Emparejado; BH controla el FDR cuando mides muchas cosas |
| Tamaño del efecto | **Cliff's δ** | Rango [−1,+1], interpretable, resistente a outliers |
| Orden de detección vs requests | Curva First-TP + AUC | Mide eficiencia, no solo efecto final |

**Regla sobre p-valores:** un p ≪ 0.001 con |δ| < 0.02 (exactamente lo que
pasó en el paper previo) **no es un resultado positivo**. Significa que el
diseño es sensible pero el efecto es trivialmente pequeño en la práctica.
Reporta ambos, siempre. El revisor que solo lee p-valores se lo va a cobrar.

**Reporta siempre:** p, δ, IC y n. Corrige FDR: si pruebas 5 hipótesis,
α = 0.05/5.

## Confounders — la lista real de este repo

| Confound | Cómo lo manejas |
|---|---|
| **Presupuesto vs ruido** | Ya observado: FP sube 71→94 al crecer el presupuesto mientras recall se congela en 125 desde budget 20. Mide FP por celda, no solo recall. El presupuesto extra solo añade ruido sobre puntos ya resueltos. |
| **Orden de ejecución** | RCBD con bloque; si la máquina carga, el bloque lo absorbe. No paralelizar si el WAF tiene estado. |
| **Seed** | `--global-seed` en **toda** corrida que vaya al paper. Sin esto no hay replicabilidad. |
| **Corpus** | El hash SHA-256 va en el manifiesto automáticamente. Verifícalo. |
| **Código** | El commit git va en el manifiesto. Cambiar código entre celdas del mismo grid invalida el grid. |
| **Ritmo de requests** | Si cambias requests-per-second cambias el resultado temporal (time-based SQLi usa umbral de 4 s). Mismo entorno para todas las celdas. |

## La discrepancia que ya existe — no la repitas

`AGENTS.md` §1.5 documenta que las macros de `_datos.tex` (recall 70.6 %) **no**
cuadran con el CSV (64.4 %). Antes de reportar cualquier resultado nuevo:

```
1. Lee el CSV crudo (testbed/experiment_results.csv), no las macros.
2. Recalcula TP/P/R/F1/FPR desde TP/FP/FN.
3. Compara con las macros. Si no cuadran, reconcilia antes de escribir.
```

Un revisor que encuentre una tabla que no cuadra con su fuente descarta el resto
del documento. Es el fallo más barato de prevenir y el más caro de ignorar.

## Falsos positivos que el FPR no cuenta

`tools/eval_oracle.py` calcula el FPR **restringido a trampas**: solo cuenta FPs
en puntos que el ground truth marca como no vulnerable. Los FPs en URLs o
parámetros que el ground truth **no menciona** se cuentan en FP pero **no** en
FPR.

Consecuencia medida: FP=93 pero FPR=0.0139 (2 trampas de 144). Los otros 91 FPs
caen fuera del ground truth. **El FPR de 1.4 % subestima brutalmente el FP
real** si el ground truth no cubre todo el mapa que el escáner exploró.

Cuando reportes FPR, di siempre el denominador **y** el FP absoluto. La pregunta
"1.4 % de qué sobre qué" tiene que tener respuesta en el primer párrafo.

## Coste — el modelo que el paper vende

La tesis es "eficiencia y exactitud". La eficiencia se mide como:

```
coste_por_hallazgo = requests_consumidos / TP
```

y se reporta como **frontera de Pareto** recall vs coste, no como punto único.
Un pipeline que sube recall 3 % y multiplica el coste por 5 es un trade-off,
no una mejora.

El paper previo ya mostró la forma de esa frontera: recall **saturando en
budget 20** y staying ahí, mientras FP seguía creciendo hasta budget 50. La
frontera es casi vertical a partir de 20 requests. Ese es el resultado
económico central y merece su propia figura.

## Checklist de fin de experimento

- [ ] Hipótesis escrita con fecha, **antes** de los datos
- [ ] Power analysis escrita antes de correr
- [ ] Todas las corridas con `--global-seed`
- [ ] Manifiesto verificado en las 20 corridas (corpus hash + commit idénticos)
- [ ] p **y** δ **y** n **y** IC reportados juntos
- [ ] FDR corregido si hay múltiples comparaciones
- [ ] FP absoluto junto a FPR, con denominador explícito
- [ ] Cifras recalculadas desde el CSV, no copiadas de las macros
- [ ] Amenazas a la validez escritas, no implícitas
