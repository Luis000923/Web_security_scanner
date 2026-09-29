# paper/ — Artículo científico

Fuente LaTeX del artículo sobre eficiencia del DAST asíncrono y reducción de
falsos positivos. **Estructura modular**: `main.tex` solo contiene el preámbulo
y une los módulos de `sections/` con `\input{}`.

## Estructura

| Ruta | Contenido |
|------|-----------|
| `main.tex` | Archivo maestro: clase `IEEEtran`, paquetes, `\input` de las secciones. |
| `sections/_datos.tex` | Macros con TODO valor numérico de resultados (AUC, Friedman, Wilcoxon, Cliff). Reescribir solo este fichero al terminar la barrida. |
| `sections/00_abstract.tex` | Título, autoría, resumen, palabras clave. |
| `sections/01_introduccion.tex` | Desafíos del DAST y contribuciones. |
| `sections/02_arquitectura.tex` | Motor asíncrono, telemetría, pipeline de ablación + diagrama TikZ. |
| `sections/03_metodologia.tex` | Testbed, oráculo, diseño RCBD, reproducibilidad. |
| `sections/04_evaluacion.tex` | Placeholders `figure`/`table` (booktabs) para AUC y estadística. |
| `sections/05_amenazas_validez.tex` | Validez interna (JVM), externa (GET), constructo. |
| `sections/06_conclusion.tex` | Conclusión y trabajo futuro. |
| `refs.bib` | Bibliografía. |
| `figures/` | Figuras generadas por `tools/analyze_results.py` (`fig1..fig3.pdf`). |
| `build/`   | Salida de compilación (PDF, logs). No se versiona. |

`04_evaluacion.tex` usa `\IfFileExists`, de modo que **el documento compila
aunque las figuras y tablas generadas aún no existan**: muestra marcadores de
posición.

## Compilación

La partición `/` está casi llena y el TeX Live del sistema está incompleto, así
que se usa **Tectonic** en el espacio de usuario (`~/.local/bin/tectonic`,
caché en `~/.cache/tectonic`, todo en `/home`).

```bash
cd paper/
tectonic -X compile main.tex --outdir build --keep-logs   # -> build/main.pdf
```

Con un TeX Live completo: `latexmk -pdf -output-directory=build main.tex`.
Nada se escribe en `/`.

## Regenerar figuras y datos

```bash
.venv/bin/python tools/run_experiments.py     # barrida (testbed en marcha)
.venv/bin/python tools/analyze_results.py     # estadística + figuras -> paper/figures/
```

Salidas del análisis: `testbed/analysis/{summary_by_run,stats,detection_cost_matrix,average_ranks}`
y `paper/figures/fig{1,2,3}.{pdf,png}`. `sections/_datos.tex` se reescribe a
mano con los valores de `stats.json`.

## Empaquetar para envío

```bash
bash tools/make_submission.sh      # -> submission.zip en la raíz del repo
```
Incluye `.tex`, `.bib`, `main.bbl` y `figures/*.pdf`; excluye `build/`,
telemetría y auxiliares.
