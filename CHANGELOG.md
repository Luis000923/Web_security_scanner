# Registro de cambios

Todas las novedades relevantes de `web-security-scanner` se documentan en este
archivo. El formato sigue las convenciones de
[Keep a Changelog](https://keepachangelog.com/es/1.1.0/) y el proyecto se adhiere
al versionado semantico.

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
