# Estado verificado de la investigación (snapshot 2026-09-29)

> Movido desde `AGENTS.md` §1 el 2026-11-26 para que el contexto fijo de los
> agentes no cargue el estado del paper en cada tarea. Se conserva la
> numeración §1.1–§1.6 porque agentes y skills la citan.
> Es un snapshot: verifica contra el árbol antes de citar una cifra.

Estos son los **hechos que debes conocer antes de proponer nada**. No son
opiniones; están verificados contra el árbol de trabajo.

### 1.1 Ya existe un paper IEEE completo — con resultado mayormente nulo

En las ramas `research`, `Paper` y `feat/ai-triage-mainline` hay
`paper/submission/` con 11 secciones LaTeX, `testbed/` con ground truth y
`tools/` con el pipeline experimental. El estudio ya se corrió:

- OWASP Benchmark, 338 parámetros GET, 194 vulnerables / 144 trampas
- Diseño RCBD, Friedman + Nemenyi + Wilcoxon-BH + Cliff's δ, manifiesto SHA-256
- Baseline contra OWASP ZAP 2.17.0

**El abstract del propio paper reporta:** solo la priorización por confianza
produjo efecto. Context interleaving, runtime confirmation y adaptive sorting
movieron el orden de requests (Friedman p≪0.001) pero con |δ|<0.02. El
LLM-triage suprimió **cero** findings.

### 1.2 Por qué salió nulo — la causa está en el testbed

Dos verificaciones:

1. `ground_truth.json`: los 338 parámetros son **todos** `BenchmarkTest*`.
   **Cero** parámetros `next` / `redirect_uri` / `returnTo`.
2. `testbed/docker-compose.yml`: solo `owasp-benchmark` + `wavsep`.
   **No hay WAF en el pipeline.**

Se evaluó un pipeline de reducción de ruido contra un objetivo que no genera
ruido. El null result mide el testbed, no la herramienta. Esto es exactamente lo
que el paper dice en su §Future Work item 2.

### 1.3 `main` no tiene nada de la investigación

Estás trabajando sobre `main`, que **no contiene** `paper/`, `tools/` ni
`testbed/`. El código del escáner sí está. Si tu track es experimental o de
escritura, necesitas cambiar de rama o crear un worktree desde
`feat/ai-triage-mainline`.

> ✅ **Ya no es un bug silencioso (corregido, verificado 2026-09-30):** el
> target `evaluate` del `Makefile` en `main` hace un `test -f
> tools/analyze_results.py` antes de invocarlo. Si falta (como en `main`),
> imprime un diagnóstico explicativo a stderr — qué rama tiene el pipeline y
> el comando exacto de `git worktree add` para correrlo desde ahí — y sale
> con código 1 en vez de un traceback crudo de Python. Sigue fallando en
> `main` porque el pipeline vive en `feat/ai-triage-mainline` (esto es
> esperado, no un defecto), pero ahora falla informativamente.

### 1.4 La instrumentación del experimento de evasión ya existe y está MUERTA

`core/adaptive_metrics.py:56-93` define `EvasionCounters` con
`baseline_block_rate()`, `mutated_block_rate()` y `effectiveness()` — el A/B
exacto para medir evasión de WAF. **`grep` confirma que nada fuera de
`tests/test_adaptive_metrics.py` lo llama jamás.** El docstring de
`modules/waf_evasion.py:34` incluso dice que el caller debe suministrarlo.

Alguien diseñó el experimento y nunca lo ejecutó. Esto es la señal más fuerte
de todo el repo.

---

### 1.5 Los números del paper NO cuadran con el CSV — verifícalo antes de citar

`paper/submission/sections/_datos.tex:26,42` declara recall techo **70.6 %** y
precision baseline **64.0 %**. El CSV de la rama `testbed`
(`testbed/experiment_results.csv`) da, para la mejor corrida:

```
budget 0  baseline  TP=125  FP=93  FN=69  P=0.5734  R=0.6443  FPR=0.0139
```

- 125/194 = **64.4 %**, no 70.6 %. 70.6 % sobre 194 implicaría TP=137.
- La segunda macro del abstract, *"both detect the same 137/194 instances"*,
  también implicaría TP=137. El CSV nunca pasa de 125.
- En cambio `FPR=0.0139` **sí** es coherente: sobre 144 trampas son 2 FPs.
- Y la diferencia `no-priority` en budget 20 (TP 125→119, FP 76→92) **sí**
  cuadra con `\DeltaRecallNoPriority{3.1 p.p.}` y `\NoPriorityVulnPerdidas{6}`.

**Hipótesis (no verificada):** el CSV committeado es una corrida parcial o de
un target-set distinto al usado para el paper; o el recall del paper se calculó
sobre otro denominador. La causa de que FP (71→94) **suba** con el presupuesto
mientras recall se congela en 125 desde budget 20 sugiere que el presupuesto
agota los payloads de los puntos ya detectados y solo añade ruido.

**Acción para cualquier agente que toque experiments: reconciliar antes de
reportar.** No copies las macros de `_datos.tex` a un documento nuevo sin
verificarlas contra `experiment_results.csv`.

### 1.6 Insumos ya disponibles para el track experimental

Verificado en la rama `feat/ai-triage-mainline` (única con `paper/` + `testbed/`
+ `tools/` a la vez):

- `testbed/ground_truth.json` — 338 registros `(url, param, type, vulnerable)`
- `testbed/benchmark_targets.json` — lista de objetivos para ZAP
- `testbed/experiment_results.csv` — 20 corridas calificadas, columnas
  `budget,condition,TP,FP,FN,Precision,Recall,F1,FPR,run_dir,status,timestamp`
- `tools/run_experiments.py` — orquestador RCBD. **Idempotente**: salta
  directorios existentes salvo `--force`. Acepta `--budgets`,
  `--conditions`, `--extra-args`, `--dry-run`.
- `tools/eval_oracle.py` — oráculo sin dependencias externas
- `tools/analyze_results.py` — Friedman/Nemenyi/Wilcoxon-BH/Cliff's δ, AUC,
  curva First-TP, 4 figuras
- `tools/run_zap_baseline.py` — baseline ZAP vía REST API

**Coste real por corrida** (timestamps del CSV): 5-9 min con presupuesto
acotado; **~45 min** con `--max-payloads 0` (ilimitado). Un grid de 36 corridas
con presupuesto ilimitado son ~27 h de reloj. Decide presupuestos antes de
lanzar nada.

Reproducibilidad: `--global-seed` **sí existe** (`cli.py:278`) y el manifiesto
**sí se escribe** en cada scan (`web_security_scanner_async.py:204` →
`core/manifest_async.py:write_manifest`, con SHA-256 del corpus, commit git y
config completa). Usa `--global-seed` en toda corrida que vaya al paper.

**Aislamiento del target:** el escáner habla con el host en `127.0.0.1`, no por
la red del compose (`testbed/docker-compose.yml` publica `127.0.0.1:8443`).
Un WAF en el compose va entre `nginx`/`modsecurity` y el benchmark; el escáner
sigue apuntando al puerto publicado. No necesitas tocar `scanner_core_async.py`.
