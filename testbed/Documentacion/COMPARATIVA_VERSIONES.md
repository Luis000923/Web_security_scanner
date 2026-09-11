# Comparativa de versiones

Evolucion historica de `web-security-scanner`. La version 5.2.0 es la linea
soportada; las versiones anteriores se documentan aqui unicamente como
referencia. Las descripciones de las versiones 1.x a 4.x se reconstruyen a
partir del historial del repositorio y de la documentacion retirada en la
consolidacion de la v5.

---

## Tabla comparativa

| Aspecto | v1.0 | v2.x | v3.0 | v4.0 | v5.x |
|---------|------|------|------|------|--------|
| Motor de escaneo | Sincrono, script unico | Sincrono, hilos (`concurrent.futures`) | Sincrono, hilos, crawling mas profundo | Sincrono modular + GUI tkinter | Asincrono (`asyncio` / `aiohttp`), bucle unico |
| Interfaz | CLI basica | CLI | CLI con perfiles de velocidad | CLI + interfaz grafica de escritorio | CLI unica (`webscanner`) |
| Controles anti-SSRF | Ninguno | Ninguno | Ninguno | Ninguno | Guarda por salto: resolucion DNS previa, filtrado de rangos privados / CGNAT / loopback / reservados, revalidacion en cada redireccion |
| Resistencia a respuestas hostiles | Ninguna | Ninguna | Timeouts basicos | Timeouts basicos | Techo de cuerpo 5 MiB, `sock_connect` / `sock_read`, corte de trampas de arana |
| Modulos de vulnerabilidades | Deteccion basica de formularios y parametros | SQLi, XSS | SQLi, XSS, NoSQLi, Open Redirect | + SSRF, Command Injection, Path Traversal, XXE, CSRF, IDOR | 11 testers como plugins con nivel de confianza (`LOW` / `MEDIUM` / `HIGH` / `CONFIRMED`) |
| Precision | Sin control de falsos positivos | Sin control | Ajustes puntuales | Ajustes puntuales | Linea base de latencia, confirmacion temporal, analisis por contexto, tolerancia a cabeceras modernas |
| Deteccion de tecnologias | No | Basica | Firmas de servidor y CMS | Firmas ampliadas (CMS, frameworks JS, analitica) | Fingerprinting por firmas ejecutado fuera del bucle de eventos |
| Sanitizacion de secretos en informes | No | No | No | No | `mask_secrets` (Bearer, Basic, Cookie, JWT) y `html.escape` en todos los campos |
| Sistema de tipos | Sin anotaciones | Sin anotaciones | Parcial | Parcial | `mypy` sin errores en todo `web_security_scanner/` |
| Calidad de codigo | Manual | Manual | Manual | Manual | `ruff check .` limpio, configuracion en `pyproject.toml` |
| Gestion de dependencias | `pip` manual | `requirements.txt` | `requirements.txt` | `requirements.txt` + instalador interactivo | `uv` + `pyproject.toml` + `uv.lock` |
| Formatos de informe | Texto por consola | JSON | JSON, HTML | JSON, HTML, Word y PDF bajo demanda | JSON y HTML asincronos, mas mapa web HTML |
| Internacionalizacion | No | No | No | i18n de la interfaz (en / es) | i18n de la salida (en / es) via `languages.yaml` |
| Pruebas | Ninguna | Ninguna | Ninguna | Ad hoc | Suite `pytest` con `pytest-asyncio`; cada tester cubre un verdadero positivo y sus falsos positivos historicos |

---

## Hitos por version

### v1.0

Version inicial. Deteccion basica de vulnerabilidades sobre formularios y
parametros. Interfaz de linea de comandos minima.

### v2.x

Introduce deteccion avanzada de tecnologias, exportacion de resultados en JSON
y un modo de solo deteccion de tecnologias. Paralelismo mediante hilos.

### v3.0

Perfiles de velocidad de escaneo (bajo, medio, alto) y modo rapido. Payloads de
SQLi y NoSQLi mas robustos. Fuerza bruta de subdirectorios y subdominios con
listas de palabras. Exportacion de informes en HTML.

### v4.0

Refactorizacion a una arquitectura modular con separacion de
responsabilidades. Se anaden seis familias de vulnerabilidades (SSRF, Command
Injection, Path Traversal, XXE, CSRF, IDOR). Interfaz grafica de escritorio con
tkinter, instalador interactivo y sistema de internacionalizacion de la
interfaz. Esta linea quedo marcada como beta.

### v5.2.0

Reescritura del motor a `asyncio` / `aiohttp`. Se elimina la GUI, el nucleo
sincrono y el instalador. Se anade el blindaje anti-SSRF, la resistencia a
respuestas hostiles, la sanitizacion de secretos en los informes, el
cumplimiento de `mypy` y `ruff`, y la gestion de dependencias con `uv`. Los
testers pasan a ser plugins con nivel de confianza. El detalle esta en
[MEJORAS_V5.md](MEJORAS_V5.md).
