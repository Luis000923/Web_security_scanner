# Registro de cambios

Todas las novedades relevantes de `web-security-scanner` se documentan en este
archivo. El formato sigue las convenciones de
[Keep a Changelog](https://keepachangelog.com/es/1.1.0/) y el proyecto se adhiere
al versionado semantico.

## [No publicado]

### Corregido

- **Falsos positivos de inyeccion en parametros de redireccion.** Nuevo modulo
  `web_security_scanner/core/param_semantics.py`: reconoce parametros de
  control de flujo web (`next`, `redirect`, `redirect_uri`, `return_to`, `url`,
  `callback`... por nombre exacto, patron o valor URL/path observado) y aplica
  una politica de evidencia. Los testers de SQLi, NoSQLi y LDAP etiquetan ahora
  el motivo por el que disparan (`evidence_kind`: `error_signature`,
  `time_confirmed`, `differential`...) y `VulnerabilityTester.report_vulnerability`
  descarta cualquier hallazgo que en un parametro de redireccion solo se apoye
  en una divergencia de respuesta (302, validacion de URL, cambio de longitud).
  La evidencia dura (error de motor de base de datos / LDAP / BSON, oraculo
  temporal confirmado, callback OOB) se conserva, pero con la severidad topada
  en `Medium` salvo confianza `CONFIRMED`, de modo que un parametro de flujo
  nunca encabeza un informe con un unico indicio ambiguo. Tests en
  `tests/test_fp_redirect_params.py`.
- **Hallazgos de cabeceras agrupados por dominio.** `HeaderSecurityTester` se
  ejecuta una vez por URL rastreada y emitia N filas identicas de CSP / HSTS /
  X-Frame-Options / X-Content-Type-Options / fuga de `Server`. Ahora publica un
  unico hallazgo por `(origen, cabecera, tipo)` con `scope: "site"`, un contador
  exacto `occurrences` y una muestra acotada de `affected_urls`;
  `report_vulnerability` devuelve el hallazgo emitido para permitirlo.
  `web_security_scanner/reports.py` anade `group_findings()`, que vuelve a
  colapsar por `group_key` cualquier duplicado que llegue de ejecuciones
  anteriores o de otras fuentes, e indica el alcance del hallazgo en el informe
  HTML. Tests en `tests/test_header_grouping.py`.
- **Etiquetado debil del dataset de triage.** `ai_module/dataset_generator.py`
  expone el *rol* del parametro (`parameter_role`) como caracteristica visible
  para el modelo y, sin oraculo, nunca promueve a `TRUE_POSITIVE` una sonda
  sobre un parametro de redireccion cuya unica senal es diferencial.

### Anadido

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
