# CLAUDE.md — reglas globales inmutables

Web Security Scanner: DAST asíncrono (asyncio + aiohttp), testers como
plugins, informes JSON/PDF. Investigación, tracks y claims: `AGENTS.md`.

## Contexto de código: L0 → L1 → L2
- Nunca leas un `.py` completo sin pasar por L0 y L1 (skill `context-navigation`).
- L0: `grep -n <símbolo> .context/repomap.md`; spans exactos en `.context/symbols.json`.
- L1: `python3 tools/context_packer.py --mode l1 --symbols ruta::Qual --out -`.
- Cambio o revisión: `--mode budget [--range A..B | --staged]`, ≤ 60 % del
  baseline; exit 3 = divide el cambio.
- Índice obsoleto: `python3 tools/context_packer.py --mode l0 --sync`.
- L2 (`Read`) solo del span, precedido de `L2: ruta:a-b — motivo`.

## Entorno
- Tests, lint y tipos con `.venv/bin/python` (3.12, con dependencias); en un
  worktree sin `.venv`, el del checkout principal. El `python3` del sistema no
  tiene dependencias.
- `tools/context_packer.py` y `tools/context_hook.py` son solo stdlib.

## Código
- Sintaxis compatible con Python 3.10 (CI: 3.10, 3.11, 3.12).
- Nada que dispare Bandit/Semgrep: `shell=True`, `os.system`, `pickle`,
  `yaml.load` sin `SafeLoader`.
- Docstrings, comentarios y commits en inglés; los mensajes de hallazgos de
  `tests/` y `tools/` en español.
- Localiza código por nombre de función, nunca por número de línea.
- Antes de crear una función de ≥ 8 líneas: `python3 tools/dup_guard.py
  --lookup "<propósito>"`; antes de cerrar: `--check-diff` (skill
  `reuse-before-write`; el hook PreToolUse bloquea `git commit` con exit 2).
- No edites secciones de otro track sin claim (`AGENTS.md` §3–§4).
  Intocables sin decisión humana: `core/adaptive_metrics.py`,
  `tools/eval_oracle.py` y las secciones publicadas del paper.

## Antes de decir "hecho"
- Skill `scoped-testing`: `ruff` → `mypy` → `pytest -k` acotado; después
  `pytest -q` completo. El número de tests que pasan nunca baja.
- Revisión: agente `diff-reviewer` con la skill `diff-code-review`.

## Alcance
- Funcional y deuda técnica en commits separados (skill `debt-isolation`).
- Sin aprobación explícita: no borres archivos, no reescribas historia, no
  hagas push, no toques las notas de Obsidian.
- Agentes: `context-indexer` → `architect-planner` → `scoped-coder` →
  `diff-reviewer`; `eval-token-auditor` mide con
  `python3 tools/token_benchmark.py --gates`.
