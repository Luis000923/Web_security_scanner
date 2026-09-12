# Plan — telemetría real para Path Traversal, Command Injection y SSRF

- **Fecha:** 2026-09-11
- **Motivado por:** `ai_module/COVERAGE_AUDIT.md` §0 y §2 — el dataset de
  triaje/entrenamiento solo tiene señal real de SQLi y XSS.
- **Alcance:** solo diseño + la instrumentación mínima que lo desbloquea.
  Generar y comprometer el dataset resultante es una corrida aparte (horas de
  scan contra el testbed) que no se ejecuta en este cambio.

## 1. Causa raíz (ya corregida en este cambio)

El dataset se ancla a *seeds* extraídos de `testbed/results/**/telemetry_*.jsonl`
vía `ai_module/dataset_generator.py::_triage_seeds()`. Esas filas las escribe
cada tester con `VulnerabilityTester._emit_telemetry()` — pero, al auditar
`web_security_scanner/modules/vulnerability_testers/`, solo
`sql_injection_async.py`, `xss_tester_async.py` e `idor_tester_async.py`
llamaban a `_emit_telemetry()`. `path_traversal_async.py`,
`command_injection_async.py` y `ssrf_tester_async.py` nunca lo hacían: no es
que el escáner no alcanzara esas rutas, es que esos tres testers nunca
escribían la fila de telemetría, sin importar cuántas veces se corriera el
scan. Por eso la telemetría comprometida no tenía "cero filas de Path
Traversal / Command Injection" por falta de cobertura del Benchmark, sino por
un tester mudo.

Ya cableado en este cambio (mismo patrón que `xss_tester_async.py`, un
`await self._emit_telemetry(...)` por intento de payload, antes de la rama
`if vulnerable:`):

- [path_traversal_async.py](../web_security_scanner/modules/vulnerability_testers/path_traversal_async.py)
- [command_injection_async.py](../web_security_scanner/modules/vulnerability_testers/command_injection_async.py)
- [ssrf_tester_async.py](../web_security_scanner/modules/vulnerability_testers/ssrf_tester_async.py)

Cobertura de regresión: `tests/test_standalone_tester_telemetry.py` (6 tests,
hit + miss por tester). **`dataset_generator.py` no necesita ningún cambio**
para consumir esto: `_triage_seeds()` ya lee cualquier `vclass` presente en
las filas de telemetría, y `_merge_standalone_seeds()` ya solo rellena con
seeds sintéticas hardcodeadas las clases que *no* aparecen en `seeds` reales
(`covered = {s["vclass"] for s in seeds}`, ver línea ~1368). En cuanto existan
filas reales de `pathtraver` / `cmdi`, el propio pipeline existente deja de
inventarlas y usa las reales — ese es "el nuevo camino de datos reales" que
pide la Prioridad 2, y ya está en su sitio.

## 2. Fuente de destino: Path Traversal + Command Injection

`testbed/ground_truth.json` (338 objetivos GET, subconjunto ya recortado del
OWASP Benchmark v1.2) **ya tiene** los casos que faltan — no hace falta tocar
`docker-compose.yml` ni levantar nada nuevo:

| Categoría | Instancias en `ground_truth.json` |
|---|---|
| SQLInjection | 113 |
| XSS | 109 |
| **PathTraversal** | **54** |
| **CommandInjection** | **50** |
| LDAPInjection | 12 |

Comando (una vez levantado `owasp-benchmark` vía
`docker compose -f testbed/docker-compose.yml up -d owasp-benchmark` y con el
`.venv` del proyecto activo):

```bash
.venv/bin/python -m web_security_scanner.cli scan \
  --target-list testbed/benchmark_targets.json \
  --no-map \
  -p balanced \
  --telemetry-dir testbed/results/real_seeds_pathtraver_cmdi \
  --max-payloads 40 \
  -o testbed/results/real_seeds_pathtraver_cmdi/report
```

Notas:

- `--target-list` + `--no-map` evita re-crawlear (ya tenemos los 338
  endpoints con su parámetro y método); todos los testers (incluidos
  `PathTraversalTester` / `CommandInjectionTester`, ya instrumentados) corren
  sobre cada objetivo — no existe hoy una forma de acotar por tester vía CLI
  (ver §4), así que esta corrida también regenerará filas de SQLi/XSS/LDAP,
  lo cual es inofensivo y sirve además para verificar que el volumen de esas
  dos clases no se mueve.
- `--max-payloads 40` es suficiente para cubrir los 6 payloads default de
  `path_traversal_async.py` y los 6 de `command_injection_async.py` más los
  que traiga `PAYLOAD/data/path_traversal.json` / `command_injection.json`
  sin recortar la corrida.
- Tiempo estimado: 338 objetivos × ~4 testers relevantes × ~10–40 payloads
  cada uno, todo contra `localhost:8443` → minutos, no horas (a diferencia de
  las corridas de ablación de 20 runs del paper, que sí tardan horas por el
  budget sweep).

Validación post-corrida:

```bash
grep -c '"tester_id": "PathTraversalTester"' testbed/results/real_seeds_pathtraver_cmdi/telemetry_*.jsonl
grep -c '"tester_id": "CommandInjectionTester"' testbed/results/real_seeds_pathtraver_cmdi/telemetry_*.jsonl
# ambos deben ser > 0; con 54 + 50 objetivos x N payloads, se esperan cientos de filas cada uno.
```

## 3. Fuente de destino: SSRF (fuera del Benchmark v1.2)

`ssrf_tester_async.py` ataca metadata endpoints (`169.254.169.254`,
`metadata.google.internal`, `gopher://`, `file://`, IP decimal, etc.) que
OWASP Benchmark y WAVSEP no modelan — `testbed/docker-compose.yml` no trae
hoy ningún servicio con un sumidero SSRF real. Opciones evaluadas:

- **WebGoat** (tiene una lección de SSRF) — imagen pesada, la lección exige
  login/estado de sesión por lección, mal fit para un target-list GET plano.
- **Un microservicio SSRF propio, minimal y determinista** (recomendado) —
  un contenedor Flask de ~30 líneas con:
  - `/fetch?url=<...>` que hace `requests.get(url)` server-side y refleja el
    cuerpo — el sumidero SSRF canónico.
  - Un mock del endpoint de metadata en el mismo compose
    (`http://ssrf-lab:8080/latest/meta-data/...` sirviendo un JSON estático
    con `ami-id` / `instance-id` — los mismos indicadores que ya busca
    `STRONG_INDICATORS` en `ssrf_tester_async.py`) para no depender de una
    nube real ni resolver `169.254.169.254` de verdad.
  - Un segundo parámetro/ruta que valida el host contra una whitelist (p.ej.
    solo `api.internal`) y devuelve 403 — la trampa FP que hoy el dataset no
    tiene para SSRF en absoluto.

  Vive en `testbed/ssrf_lab/` (nuevo, no tocado en este cambio): un
  `app.py` + `Dockerfile` mínimos, y un bloque de servicio nuevo en
  `docker-compose.yml` (`ssrf-lab`, red `testbed_network`, sin exponer más
  puerto que el necesario en `127.0.0.1`). Un `testbed/ssrf_targets.json`
  (mismo esquema que `benchmark_targets.json`) con las rutas `/fetch?url=`
  reales + trampa, para pasarlo por `--target-list`.

  Esto es trabajo de implementación aparte (nuevo servicio + imagen) y no se
  ejecuta en este cambio; se deja documentado como el siguiente paso natural
  una vez validado el punto 2.

## 4. Mejora de tooling que este plan expone (no incluida aquí)

Ahora mismo `webscanner scan` no tiene forma de acotar la corrida a un
subconjunto de testers (todos los `TesterRegistry.discover_testers()` corren
siempre, ver `web_security_scanner_async.py::initialize()`). Para las
corridas de recolección de telemetría dirigida (§2, §3) no hace falta — sobra
con dejar correr todos y quedarse con las filas de interés — pero si el
volumen de tráfico contra el Benchmark se vuelve un problema (rate limiting,
tiempo), un futuro `--only-testers PathTraversalTester,CommandInjectionTester`
evitaría el resto del tráfico. No se implementa aquí por estar fuera del
alcance de la Prioridad 2 (que pide diseñar la recolección de datos, no tocar
el motor de dispatch de testers).

## 5. Incorporar las filas reales a `dataset_generator.py`

Sin cambios de código, una vez exista `testbed/results/real_seeds_pathtraver_cmdi/`
(y, más adelante, la corrida SSRF):

```bash
.venv/bin/python -m ai_module.dataset_generator \
  --telemetry testbed/results \
  --benchmark-csv testbed/.cache/benchmark/expectedresults-1.2.csv \
  --ground-truth testbed/ground_truth.json \
  --task triage --synthetic-multiplier 20 \
  --balance --out data/sft --split 0.9 --seed 1337 \
  --report data/sft.triage.report.json
```

Verificar en el reporte:

- `synthetic.telemetry_seed_classes` debe mostrar `pathtraver` y `cmdi` con
  conteo > 0 (hoy: ausentes / 0).
- `synthetic.standalone_seeds` debe **bajar** para esas dos clases respecto a
  la corrida anterior (`--no-standalone-seeds` opcional para verificarlo de
  forma aislada: sin bandera sintética hardcodeada, solo lo real + lo
  sintetizado a partir de lo real).
- Confirmar en el reporte / en las muestras sintéticas resultantes que las
  nuevas seeds `pathtraver` / `cmdi` **no** llevan `standalone_seed: True`
  (el flag que `_standalone_triage_seeds()` pone en las hardcodeadas, ver
  `_STANDALONE_SEED_SPECS`) — deben venir de `_triage_seeds()` a partir de
  telemetría real.
- Repetir el split train/val de siempre: 0 solapamiento por clave
  observable (ya garantizado por `write_split`, sin cambios necesarios).

## 6. Orden de trabajo sugerido

1. (Este cambio) Instrumentar los tres testers — hecho, con tests.
2. Levantar `owasp-benchmark`, correr el comando de §2, confirmar filas > 0.
3. Regenerar el dataset (§5), confirmar el reporte y no re-balancear a ciegas
   sin mirar `class_counts_before_balance`.
4. Reentrenar / re-evaluar el triage model contra el nuevo split y comparar
   métricas por clase (`ai_module/evaluate_golden.py`) antes/después.
5. (Trabajo aparte) Construir `testbed/ssrf_lab/`, añadir el servicio a
   `docker-compose.yml`, generar `ssrf_targets.json`, repetir 2–4 para SSRF.
