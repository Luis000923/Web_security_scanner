# Registro de cambios

Todas las novedades relevantes de `web-security-scanner` se documentan en este
archivo. El formato sigue las convenciones de
[Keep a Changelog](https://keepachangelog.com/es/1.1.0/) y el proyecto se adhiere
al versionado semantico.

## [No publicado]

### Anadido

- **Agente de triaje LLM integrado de forma nativa en el pipeline
  (`--enable-ai-triaging`).** El subsistema `ai_module/` (cliente
  `AgentClient` + decodificacion estructurada `TriageOut`/`PayloadOut`) se
  conecta al scanner: cada candidato producido por los testers pasa por
  `triage_finding()` **antes** de emitir el hallazgo. Un veredicto de falso
  positivo con confianza >= `--ai-fp-threshold` (0.75 por defecto) suprime el
  hallazgo; el resto se anotan con `ai_verdict` / `ai_confidence` /
  `ai_reasoning`. Degradacion transparente: si `ai_module` no esta instalado o
  el backend de inferencia no responde a `healthcheck()`, el escaneo continua
  con el motor heuristico deterministico y nunca falla por el agente; los
  errores por llamada a mitad de escaneo degradan igual. Se respeta la
  contrapresion existente (el agente se ejecuta dentro del worker-pool de los
  testers). Nuevo evento `AI_TRIAGE_DECISION` y bloque `ai_triage` en el
  informe con la traza de auditoria de cada decision keep/drop.
  `--ai-synthesize` habilita ademas la sintesis agentica de payloads cuando la
  lista estatica se agota sin acierto (filtrada por la puerta de payloads
  destructivos). Flags: `--ai-backend`, `--ai-base-url`, `--ai-model`,
  `--ai-fp-threshold`, `--ai-no-verify`. Extra de instalacion `.[ai]` /
  `.[ai-local]`. Tests en `tests/test_ai_agent_integration.py`.
- **`tools/eval_oracle.py`, `run_experiments.py` y `analyze_results.py`
  reportan el efecto real del agente.** El oraculo lee el bloque `ai_triage`
  del informe (`--report`) y calcula la **tasa real de supresion de falsos
  positivos** (supresiones que no son positivos del ground truth) y los
  **falsos negativos introducidos por el LLM** (vulnerabilidades reales
  ocultadas), mas `recall` con y sin agente. `run_experiments.py` anade las
  condiciones `ai-triage` / `ai-triage-synth` y las columnas CSV `AI_Triaged`,
  `AI_Suppressed`, `AI_FP_Suppressed`, `AI_FN_Introduced`, `AI_Recall_NoAgent`.
  `analyze_results.py` anade la TASK 2c (supresion de FP vs coste en FN por
  budget, `testbed/analysis/ai_triage.json`).

- **Modulo de transformaciones y mutaciones de payloads.**
  `web_security_scanner/core/transforms/` define la interfaz abstracta
  `BaseTransform` (`transform(value: str) -> str`) y un registro nombre ->
  instancia extensible via el decorador `@register(...)`. Transformadores
  incorporados: `url_encode`, `double_url_encode`, `hex_entity` (`&#xNN;`),
  `html_entity` (`&#NN;`) y `random_case` (evasion de firmas estaticas
  sensibles a mayusculas). `web_security_scanner/core/payload_mutator.py`
  anade `PayloadMutator.mutate(payload, transform_names)`, que devuelve una
  **nueva** instancia inmutable de `Payload` con el `vector` reescrito por la
  cadena de transformaciones y todos los demas metadatos intactos. Tests en
  `tests/test_payload_mutator.py`.
- **`PayloadMutator` integrado en la clase base `VulnerabilityTester`.**
  `__init__` instancia `self.mutator = PayloadMutator()` (o lo acepta por
  inyeccion via `mutator=`) y lee `config['waf_bypass_transforms']` (lista de
  nombres de transformacion). El nuevo helper `_apply_runtime_mutations()`
  reescribe cada vector cargado por `load_payloads()` /
  `load_payload_vectors()` a traves de esa cadena; los nombres desconocidos se
  descartan con un unico `logger.warning` y el vector original se conserva
  (`UnknownTransformError` nunca aborta el escaneo). Los vectores destructivos
  no se mutan salvo `--allow-destructive`, para que la puerta de string de
  `filter_payloads()` los siga detectando. Nuevo flag CLI
  `--waf-bypass-transforms a,b,c`. Tests en `tests/test_base_tester_async.py`.

### Cambiado

- **Priorizacion de payloads antes del recorte `max_payloads`.**
  `base_tester_async.py` define mapas de peso explicitos
  (`CONFIDENCE_WEIGHT`: CONFIRMED 4 / HIGH 3 / MEDIUM 2 / LOW 1;
  `SEVERITY_WEIGHT`: Critical 4 / High 3 / Medium 2 / Low 1 / Info 0) y
  `payload_priority()`. `load_payloads()` ahora: descarta firmas `oob: true`
  cuando no hay `config['oob_domain']` (peticiones sin receptor), intercala por
  `context` y luego aplica un orden estable por peso combinado descendente, de
  modo que el `[:max_payloads]` posterior de `filter_payloads()` conserva las
  firmas CONFIRMED/HIGH sobre las LOW. Tests en `tests/test_payload_loader.py`.
- **Corpus de payloads dividido por categoria.** El fichero agregado
  `web_security_scanner/PAYLOAD/payloads_v5.json` se sustituye por un fichero por
  categoria en `PAYLOAD/data/<categoria>.json` (14 ficheros, 2195 firmas). Los
  metadatos compartidos del corpus (`version`, `canary_token`, `marker_host`,
  lista de categorias) pasan a `PAYLOAD/meta.json`, validado contra el nuevo
  `PAYLOAD/meta.schema.json`. `schema.json` valida ahora un unico fichero de
  categoria. `PayloadLoader` descubre los ficheros con un glob sobre `data/` y
  cachea el corpus una sola vez igual que antes; la API publica
  (`get_payload_loader()`, `get_payloads()`, ...) no cambia.

## [5.2.0] - 2026-09-04

### Anadido

- **Motor de reconocimiento (integracion de `route-mapper`).** Nueva capa
  `web_security_scanner/modules/recon/`:
  - Ingesta automatica de rutas desde `/sitemap.xml` (`--sitemap`), con parser
    endurecido contra XXE y XML bomb.
  - Mineria lexica de endpoints dinamicos (`/api/...`) en bundles JavaScript
    (`--parse-js` / `--no-parse-js`); nunca se ejecuta ni interpreta el codigo.
  - `ScopeEngine` anti-SSRF de 3 capas aplicado a cada URL descubierta:
    normalizacion y rechazo de CRLF, ambito de dominio estricto y verificacion
    pre-flight de que todas las IPs resueltas son publicas.
  - Cumplimiento del `Crawl-delay` de `robots.txt`, descargado a traves del
    nucleo para heredar la guarda SSRF, los timeouts y el tope de cuerpo.
- **Evasion de patron de trafico y timing.**
  - Canalizacion por proxy HTTP/HTTPS (nativo) y SOCKS5 (`--proxy`, SOCKS5
    requiere `aiohttp_socks`).
  - Rotacion dinamica de `User-Agent` desde un archivo (`--ua-file`), aplicada a
    todas las peticiones (recon y testers).
  - Variacion aleatoria de la pausa entre peticiones (`--jitter`).
- **Canalizacion de objetivos (Fase 1 -> Fase 2).** El pipeline se reordena a
  reconocimiento primero; las rutas y parametros descubiertos en la Fase 1
  alimentan automaticamente la cola de escaneo de los 16 testers de
  vulnerabilidades mediante pares `(tester, url)` en el worker pool acotado.
- Nuevos argumentos de CLI: `--sitemap`, `--jitter`, `--parse-js` /
  `--no-parse-js`, `--proxy`, `--ua-file`.
- `tests/test_recon_integration.py`: cobertura de la mineria de JS, el parseo de
  sitemaps, las 3 capas del `ScopeEngine`, el crawl enriquecido y la ingesta
  end-to-end de los objetivos descubiertos por los testers.

### Cambiado

- `AsyncScannerCore` admite `extra_user_agents` y construye un conector SOCKS
  cuando el proxy configurado lo requiere.
- `WebMapperAsync` incorpora la siembra desde sitemap, la mineria de JS, el
  `Crawl-delay`, el `jitter` y `get_scan_targets()` para la Fase 2, manteniendo
  intactos los cortes preventivos ante trampas de arana y los limites de memoria.

## [5.1.0] - 2026-09-03

### Anadido

- Base de firmas ampliada a ~2,195 payloads categorizados en 14 categorias bajo
  la especificacion JSON Schema Draft 2020-12, con tokens de canario
  deterministas y 5 testers asincronos nuevos.
- Pipeline de CI en GitHub Actions que automatiza `pytest`, `ruff` y `mypy`
  sobre `uv` (matriz Python 3.10-3.12).

### Cambiado

- Limpieza de payloads heredados y consolidacion del nucleo asincrono.

Detalle tecnico de las lineas 1.x a 5.x en
[Documentacion/COMPARATIVA_VERSIONES.md](Documentacion/COMPARATIVA_VERSIONES.md)
y [Documentacion/MEJORAS_V5.md](Documentacion/MEJORAS_V5.md).
