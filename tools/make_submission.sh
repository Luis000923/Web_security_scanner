#!/usr/bin/env bash
# make_submission.sh — empaqueta el artículo para arXiv / plataforma de conferencia.
#
# Produce  <repo>/submission.zip  con EXACTAMENTE lo necesario para compilar:
#   main.tex, todos los sections/*.tex referenciados por \input, refs.bib,
#   main.bbl, las figuras vectoriales incluidas, README.md y —si se
#   encuentran en el sistema— la clase/estilo IEEEtran.
# Excluye: build/, *.png, *.aux/*.log/*.out, telemetría, resultados y todo lo
# que no sea fuente del artículo.
#
# Uso:   bash tools/make_submission.sh [salida.zip]
#        PAPER_DIR=/ruta/al/paper bash tools/make_submission.sh   # forzar origen
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$REPO_ROOT/submission.zip}"

log()  { echo "[make_submission] $*"; }
die()  { echo "[make_submission] ERROR: $*" >&2; exit 1; }

# --- 0. localizar la fuente del artículo ----------------------------------
# La estructura vigente es paper/submission/ (rama `Paper`, versión enviada);
# la antigua era paper/. Se prefiere la primera y se acepta un override.
if [[ -n "${PAPER_DIR:-}" ]]; then
  [[ -f "$PAPER_DIR/main.tex" ]] || die "PAPER_DIR=$PAPER_DIR no contiene main.tex"
elif [[ -f "$REPO_ROOT/paper/submission/main.tex" ]]; then
  PAPER_DIR="$REPO_ROOT/paper/submission"
elif [[ -f "$REPO_ROOT/paper/main.tex" ]]; then
  PAPER_DIR="$REPO_ROOT/paper"
else
  die "no encuentro main.tex ni en paper/submission/ ni en paper/"
fi
PAPER_DIR="$(cd "$PAPER_DIR" && pwd)"
log "fuente del artículo: ${PAPER_DIR#"$REPO_ROOT"/}"
cd "$PAPER_DIR"

# --- 1. la bibliografía compilada (.bbl) debe estar fresca ----------------
# arXiv no siempre reejecuta BibTeX de forma fiable; se incluye el .bbl.
if command -v tectonic >/dev/null 2>&1; then
  log "compilando para regenerar main.bbl ..."
  mkdir -p build   # tectonic v2 exige que --outdir exista
  XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}" \
    tectonic -X compile main.tex --outdir build --keep-intermediates --keep-logs \
    >/dev/null 2>&1 || log "aviso: la compilación falló; se usa el .bbl existente"
fi
if [[ -f build/main.bbl ]]; then
  cp -f build/main.bbl ./main.bbl
elif [[ ! -f main.bbl ]]; then
  die "no hay build/main.bbl ni main.bbl; compila el paper primero"
fi

# --- 2. descubrir los .tex referenciados por \input{...} ------------------
# Se parte de main.tex y se sigue cada \input de forma transitiva, de modo
# que añadir una sección nueva (p.ej. sections/03b_ia_alineacion) no exige
# tocar este script.
declare -A SEEN_TEX=()
TEX_FILES=()
scan_inputs() {  # $1 = fichero .tex a analizar
  local f="$1" ref
  [[ -f "$f" ]] || die "\\input hace referencia a un fichero inexistente: $f"
  [[ -n "${SEEN_TEX[$f]:-}" ]] && return 0
  SEEN_TEX[$f]=1
  TEX_FILES+=("$f")
  # \input{a} , \include{a} , \input a  → captura el argumento, ignora comentarios
  while IFS= read -r ref; do
    ref="${ref%.tex}.tex"
    scan_inputs "$ref"
  done < <(sed 's/\([^\\]\)%.*/\1/' "$f" \
           | grep -oE '\\(input|include)\{[^}]+\}' \
           | sed -E 's/\\(input|include)\{([^}]+)\}/\2/')
}
scan_inputs "main.tex"

# --- 3. descubrir las figuras incluidas ----------------------------------
# graphicspath del artículo: {figures/}{build/}. Se recogen los argumentos de
# \includegraphics y los de \IfFileExists{figures/...}. Se empaqueta siempre
# la variante vectorial (.pdf); build/ nunca se empaqueta como origen.
GRAPHICS_DIRS=(figures .)
FIG_FILES=()
declare -A SEEN_FIG=()
resolve_fig() {  # $1 = nombre citado (con o sin extensión, con o sin figures/)
  local name="$1" base cand d ext
  name="${name#figures/}"; name="${name#./}"
  base="${name%.*}"
  for d in "${GRAPHICS_DIRS[@]}"; do
    for ext in pdf PDF eps png jpg jpeg; do
      cand="$d/$base.$ext"
      if [[ -f "$cand" && "$d" != "build" ]]; then
        [[ -n "${SEEN_FIG[$cand]:-}" ]] && return 0
        SEEN_FIG[$cand]=1
        FIG_FILES+=("$cand")
        return 0
      fi
    done
  done
  die "figura referenciada pero no encontrada: $1 (¿ejecutaste tools/analyze_results.py?)"
}
for tf in "${TEX_FILES[@]}"; do
  while IFS= read -r fig; do
    resolve_fig "$fig"
  done < <(sed 's/\([^\\]\)%.*/\1/' "$tf" \
           | grep -oE '\\includegraphics(\[[^]]*\])?\{[^}]+\}' \
           | sed -E 's/.*\{([^}]+)\}/\1/')
  # \IfFileExists{figures/foo.pdf}{...}{...}
  while IFS= read -r fig; do
    resolve_fig "$fig"
  done < <(sed 's/\([^\\]\)%.*/\1/' "$tf" \
           | grep -oE '\\IfFileExists\{figures/[^}]+\}' \
           | sed -E 's/\\IfFileExists\{figures\/([^}]+)\}/\1/')
done

# --- 4. clase y estilo IEEEtran (best-effort) ---------------------------
# arXiv y la mayoría de plataformas ya los traen; incluirlos evita sorpresas.
CLS_FILES=()
find_texmf() {  # $1 = nombre de fichero (IEEEtran.cls / IEEEtran.bst)
  local hit
  if command -v kpsewhich >/dev/null 2>&1; then
    hit="$(kpsewhich "$1" 2>/dev/null || true)"
    [[ -n "$hit" && -f "$hit" ]] && { echo "$hit"; return 0; }
  fi
  hit="$(find "${XDG_CACHE_HOME:-$HOME/.cache}/Tectonic" \
              "$HOME/.cache/tectonic" -name "$1" -type f 2>/dev/null | head -n1 || true)"
  [[ -n "$hit" && -f "$hit" ]] && { echo "$hit"; return 0; }
  return 1
}
for cls in IEEEtran.cls IEEEtran.bst; do
  if src="$(find_texmf "$cls")"; then
    CLS_FILES+=("$src")
    log "incluyo $cls  ($src)"
  else
    log "aviso: no encuentro $cls en el sistema; la plataforma debe proveerlo"
  fi
done

# --- 5. ficheros sueltos obligatorios / opcionales --------------------
EXTRA_FILES=(refs.bib main.bbl)
[[ -f README.md ]] && EXTRA_FILES+=(README.md)
for e in "${EXTRA_FILES[@]}"; do
  [[ -f "$e" ]] || die "falta el fichero requerido: $e"
done

# --- 6. montar un directorio de staging con la jerarquía final ---------
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
copy_into() {  # $1 = ruta relativa a PAPER_DIR (o absoluta para las clases)
  local src="$1" rel
  if [[ "$src" = /* ]]; then rel="$(basename "$src")"; else rel="$src"; fi
  mkdir -p "$STAGE/$(dirname "$rel")"
  cp -f "$src" "$STAGE/$rel"
  echo "$rel"
}
PACKED=()
for f in "${TEX_FILES[@]}" "${EXTRA_FILES[@]}" "${FIG_FILES[@]}" "${CLS_FILES[@]}"; do
  PACKED+=("$(copy_into "$f")")
done

# --- 7. verificación: ninguna referencia rota -------------------------
# Cada \input y cada figura resuelta debe estar presente en el staging.
fail=0
for tf in "${TEX_FILES[@]}"; do
  while IFS= read -r ref; do
    ref="${ref%.tex}.tex"
    [[ -f "$STAGE/$ref" ]] || { echo "  referencia rota: \\input{$ref}" >&2; fail=1; }
  done < <(sed 's/\([^\\]\)%.*/\1/' "$tf" \
           | grep -oE '\\(input|include)\{[^}]+\}' \
           | sed -E 's/\\(input|include)\{([^}]+)\}/\2/')
done
for fig in "${FIG_FILES[@]}"; do
  [[ -f "$STAGE/$fig" ]] || { echo "  figura no empaquetada: $fig" >&2; fail=1; }
done
grep -q '\\documentclass\[[^]]*\]{IEEEtran}\|\\documentclass{IEEEtran}' "$STAGE/main.tex" \
  || log "aviso: main.tex no declara la clase IEEEtran (revisa el preámbulo)"
[[ $fail -eq 0 ]] || die "el paquete dejaría referencias rotas (ver arriba)"

# --- 8. compilación de humo desde el staging (sin red de figuras) -----
if command -v tectonic >/dev/null 2>&1; then
  log "compilación de verificación desde el staging ..."
  mkdir -p "$STAGE/_smoke"
  ( cd "$STAGE" && XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}" \
      tectonic -X compile main.tex --outdir _smoke --keep-logs >_smoke/build.log 2>&1 ) \
    && log "  OK: el staging compila de forma aislada ($(cd "$STAGE/_smoke" && pdfinfo main.pdf 2>/dev/null | awk '/Pages/{print $2" pp."}'))" \
    || { sed -n 's/^/    /p' "$STAGE/_smoke/build.log" | grep -iE 'error|warning: .*undefined' | head -15 >&2
         die "el staging NO compila de forma aislada; el zip sería inservible"; }
  rm -rf "$STAGE/_smoke"
fi

# --- 9. escribir el zip ---------------------------------------------
rm -f "$OUT"
( cd "$STAGE" && zip -qrD "$OUT" . -x '_smoke/*' )   # -D: sin entradas de directorio
log "escrito: $OUT"
unzip -l "$OUT"
