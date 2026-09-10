#!/usr/bin/env bash
# make_submission.sh — empaqueta paper/ para arXiv / plataforma de conferencia.
#
# Produce  <repo>/submission.zip  con EXACTAMENTE lo necesario para compilar:
#   main.tex, sections/*.tex, refs.bib, main.bbl, figures/*.pdf, README.md
# Excluye: build/, *.png, *.aux/*.log/*.out, telemetría, resultados y todo lo
# que no sea fuente del artículo.
#
# Uso:   bash tools/make_submission.sh [salida.zip]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PAPER_DIR="$REPO_ROOT/paper"
OUT="${1:-$REPO_ROOT/submission.zip}"

cd "$PAPER_DIR"

# --- 1. la bibliografía compilada (.bbl) debe estar fresca --------------------
# arXiv no siempre reejecuta BibTeX de forma fiable; se incluye el .bbl.
if command -v tectonic >/dev/null 2>&1; then
  echo "[make_submission] compilando para regenerar main.bbl ..."
  XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}" \
    tectonic -X compile main.tex --outdir build --keep-intermediates --keep-logs \
    >/dev/null 2>&1 || echo "[make_submission] aviso: la compilación falló; se usa el .bbl existente"
fi
if [[ -f build/main.bbl ]]; then
  cp -f build/main.bbl ./main.bbl
else
  echo "[make_submission] ERROR: no hay build/main.bbl; compila el paper primero" >&2
  exit 1
fi

# --- 2. verificar que las 3 figuras vectoriales existen ---------------------
missing=0
for f in figures/fig1_detection_vs_budget.pdf \
         figures/fig2_ablation_impact.pdf \
         figures/fig3_cd_diagram.pdf; do
  [[ -f "$f" ]] || { echo "[make_submission] ERROR: falta $f" >&2; missing=1; }
done
[[ $missing -eq 0 ]] || { echo "  ejecuta: .venv/bin/python tools/analyze_results.py" >&2; exit 1; }

# --- 3. lista blanca de ficheros a incluir --------------------------------
FILES=(
  main.tex
  refs.bib
  main.bbl
  README.md
  sections/00_abstract.tex
  sections/01_introduccion.tex
  sections/02_arquitectura.tex
  sections/03_metodologia.tex
  sections/04_evaluacion.tex
  sections/05_amenazas_validez.tex
  sections/06_conclusion.tex
  sections/_datos.tex
  figures/fig1_detection_vs_budget.pdf
  figures/fig2_ablation_impact.pdf
  figures/fig3_cd_diagram.pdf
)

rm -f "$OUT"
zip -q "$OUT" "${FILES[@]}"

echo "[make_submission] escrito: $OUT"
unzip -l "$OUT"
