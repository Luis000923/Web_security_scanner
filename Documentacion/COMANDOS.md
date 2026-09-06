# Combinaciones de Parametros — `webscanner scan` (v5.2)

Entry point: `webscanner scan <url> [opciones]`

Desde la v5.2 el escaneo tiene dos fases encadenadas:

1. **Fase 1 — Reconocimiento (motor route-mapper).** Crawl asincrono, siembra
   desde `/sitemap.xml`, minado lexico de endpoints en bundles `.js`,
   cumplimiento de `Crawl-delay` de `robots.txt` y `ScopeEngine` anti-SSRF de
   3 capas sobre cada URL.
2. **Fase 2 — Testing de vulnerabilidades.** Las rutas y parametros descubiertos
   en la Fase 1 se encolan automaticamente hacia los 16 testers.

Consecuencia practica: `--no-map` desactiva tambien la canalizacion de
objetivos; con `--no-map` los testers solo reciben la URL semilla. Para
explotar la herramienta al 100% conviene dejar la Fase 1 activa.

---

## Perfiles base

```bash
# Rapido — cabeceras y tech detection, minimos payloads
webscanner scan https://ejemplo.com -p quick

# Balanceado — todos los testers, payloads moderados (DEFAULT)
webscanner scan https://ejemplo.com -p balanced

# Intenso — maximos payloads, testers ruidosos (Log4Shell, deserializacion)
webscanner scan https://ejemplo.com -p intense

# Reconocimiento (Fase 1) + solo checks pasivos de cabeceras (sin payloads)
webscanner scan https://ejemplo.com -p mapping
```

---

## Reconocimiento avanzado (motor route-mapper)

```bash
# Sembrar la cola desde /sitemap.xml (y sitemapindex anidados)
webscanner scan https://ejemplo.com --sitemap

# Minado de endpoints en JavaScript (activo por defecto)
webscanner scan https://ejemplo.com --parse-js

# Desactivar el minado de JS (crawl mas rapido, menos cobertura)
webscanner scan https://ejemplo.com --no-parse-js

# Recon exhaustivo: sitemap + JS + crawl profundo y ancho
webscanner scan https://ejemplo.com --sitemap --parse-js --max-depth 6 --max-urls 4000

# Mapa completo de superficie sin lanzar payloads
webscanner scan https://ejemplo.com -p mapping --sitemap --parse-js \
  --max-depth 8 --max-urls 8000 -f html -o mapa_superficie
```

Salida: el reporte HTML del mapa incluye una seccion "JavaScript endpoints" y
las estadisticas `total_js_endpoints` / `total_sitemap_urls`.

---

## Evasion de WAF / IDS y OPSEC

```bash
# Jitter — variacion aleatoria +/- N s sobre la pausa entre peticiones
webscanner scan https://ejemplo.com --jitter 1.5

# Rate limit + jitter — patron de trafico no periodico
webscanner scan https://ejemplo.com --rate-limit 2 --jitter 1.5

# Rotacion de User-Agent desde archivo (uno por linea, '#' = comentario)
webscanner scan https://ejemplo.com --ua-file agentes.txt

# Proxy HTTP (Burp / mitmproxy / corporativo)
webscanner scan https://ejemplo.com --proxy http://127.0.0.1:8080 --no-verify-ssl

# Proxy SOCKS5 (Tor; requiere 'pip install aiohttp_socks')
webscanner scan https://ejemplo.com --proxy socks5://127.0.0.1:9050

# Sigilo maximo — pocos hilos, ritmo lento e irregular, UA rotado, payloads espaciados
webscanner scan https://ejemplo.com -p balanced \
  --threads 3 --rate-limit 3 --jitter 2 --payload-delay 1.5 \
  --ua-file agentes.txt --max-payloads 25
```

Formato de `agentes.txt` (lo aporta el operador):

```text
# Un User-Agent por linea; las lineas vacias y las que empiezan por '#' se ignoran
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15
```

Sin `--ua-file` la herramienta ya rota sobre un pool interno de agentes de
escritorio actuales.

Notas:
- El `ScopeEngine` anti-SSRF sigue activo aunque el trafico pase por un proxy:
  la politica de destino nunca se delega al proxy.
- `--proxy` afecta a todas las peticiones (Fase 1 y Fase 2).

---

## Integracion con herramientas

```bash
# Burp Suite — enviar todo el trafico al Proxy Listener de Burp
webscanner scan https://ejemplo.com --proxy http://127.0.0.1:8080 --no-verify-ssl -v

# Burp contra un target interno autorizado (SSRF guard OFF para redirects privados)
webscanner scan https://intranet.corp --proxy http://127.0.0.1:8080 \
  --no-verify-ssl --allow-private-redirects -p intense

# OWASP ZAP en 127.0.0.1:8090
webscanner scan https://ejemplo.com --proxy http://127.0.0.1:8090 --no-verify-ssl

# Tor + sigilo para recon de superficie
webscanner scan https://ejemplo.com -p mapping --proxy socks5://127.0.0.1:9050 \
  --jitter 3 --rate-limit 4 --sitemap --parse-js
```

---

## Control de rendimiento

```bash
webscanner scan https://ejemplo.com --threads 30        # concurrencia de requests
webscanner scan https://ejemplo.com --timeout 30        # espera por request (s)
webscanner scan https://ejemplo.com --rate-limit 2      # pausa minima entre requests (s)
webscanner scan https://ejemplo.com --payload-delay 1.5 # delay entre payloads por tester (s)
webscanner scan https://ejemplo.com --max-payloads 100  # payloads por parametro
webscanner scan https://ejemplo.com --max-duration 120  # cap total de tiempo (s)
webscanner scan https://ejemplo.com --waf-bypass-transforms random_case,url_encode  # muta cada vector (evasion WAF)
```

Transformaciones disponibles para `--waf-bypass-transforms` (se aplican en orden,
izquierda -> derecha): `url_encode`, `double_url_encode`, `hex_entity` (`&#xNN;`),
`html_entity` (`&#NN;`), `random_case`. Los vectores destructivos no se mutan
salvo `--allow-destructive`.

---

## Seguridad / acceso

```bash
webscanner scan https://ejemplo.com --no-verify-ssl              # certificado TLS invalido
webscanner scan https://ejemplo.com --allow-private-redirects    # redirects a IP privada (targets internos)
webscanner scan https://ejemplo.com --allow-destructive          # payloads que modifican/eliminan datos
```

---

## Salida y formatos

```bash
webscanner scan https://ejemplo.com -f json -o mi_reporte
webscanner scan https://ejemplo.com -f html -o mi_reporte
webscanner scan https://ejemplo.com -f json,html -o mi_reporte
webscanner scan https://ejemplo.com --lang es
webscanner scan https://ejemplo.com -v      # payloads y respuestas en tiempo real
```

---

## Combinaciones de maxima potencia

```bash
# 1. Auditoria total — recon exhaustivo + todos los testers + cobertura alta
webscanner scan https://ejemplo.com -p intense \
  --sitemap --parse-js --max-depth 6 --max-urls 5000 \
  --threads 20 --timeout 20 --max-payloads 150 \
  -f json,html -o auditoria_total --lang es -v

# 2. Pentest a traves de Burp — trafico interceptable, cobertura completa
webscanner scan https://ejemplo.com -p intense \
  --proxy http://127.0.0.1:8080 --no-verify-ssl \
  --sitemap --parse-js --max-depth 5 --max-urls 3000 \
  --max-payloads 100 -f json,html -o pentest_burp -v

# 3. Red team sigiloso — cobertura alta con perfil de trafico ofuscado
webscanner scan https://ejemplo.com -p balanced \
  --sitemap --parse-js \
  --threads 4 --rate-limit 3 --jitter 2 --payload-delay 1 \
  --ua-file agentes.txt --max-payloads 40 \
  --max-duration 3600 -f json -o redteam --lang es

# 4. Caza de API — priorizar endpoints ocultos en JS y sitemap
webscanner scan https://ejemplo.com -p intense \
  --sitemap --parse-js --max-depth 4 --max-urls 2000 \
  --max-payloads 120 -f json,html -o api_hunt -v

# 5. Objetivo interno autorizado — intranet detras de proxy corporativo
webscanner scan https://intranet.corp -p intense \
  --proxy http://127.0.0.1:8080 --no-verify-ssl --allow-private-redirects \
  --sitemap --parse-js --max-urls 4000 -f json,html -o intranet_audit

# 6. Escaneo destructivo controlado (staging efimero) — cobertura sin limites
webscanner scan https://staging.ejemplo.com -p intense \
  --allow-destructive --no-verify-ssl \
  --sitemap --parse-js --max-payloads 200 --max-duration 5400 \
  -f json,html -o staging_full -v

# 7. Gate de seguridad para CI/CD — recon + testers con presupuesto de tiempo
webscanner scan https://staging.ejemplo.com -p balanced \
  --sitemap --parse-js --max-urls 800 --max-duration 300 \
  -f json -o ci_report

# 8. Mapa de superficie masivo via Tor
webscanner scan https://ejemplo.com -p mapping \
  --proxy socks5://127.0.0.1:9050 --jitter 3 --rate-limit 4 \
  --sitemap --parse-js --max-depth 8 --max-urls 10000 \
  -f html -o mapa_tor
```

---

## Referencia rapida de parametros

| Parametro | Valores | Funcion |
|-----------|---------|---------|
| `-p` / `--profile` | `quick` `balanced` `intense` `mapping` | Perfil — define hilos, payloads y testers activos |
| `--sitemap` | flag | Fase 1: siembra la cola desde `/sitemap.xml` |
| `--jitter` | segundos (ej: `1.5`) | Variacion aleatoria +/- sobre la pausa entre peticiones |
| `--parse-js` / `--no-parse-js` | flag | Activa/desactiva el minado de endpoints en `.js` (default: ON) |
| `--proxy` | URL (`http://h:p` o `socks5://h:p`) | Canaliza todo el trafico; SOCKS5 requiere `aiohttp_socks` |
| `--ua-file` | ruta | Archivo con un `User-Agent` por linea; rotacion por peticion |
| `--threads` | entero (ej: `10`) | Requests concurrentes maximos |
| `--timeout` | segundos (ej: `15`) | Tiempo maximo de espera por request |
| `--rate-limit` | segundos (ej: `2`) | Pausa minima entre requests |
| `--payload-delay` | segundos (ej: `1.5`) | Delay entre payloads dentro de cada tester |
| `--max-payloads` | entero (ej: `50`) | Max payloads probados por parametro |
| `--max-duration` | segundos (ej: `180`) | Tiempo total maximo del escaneo (Fase 2) |
| `--waf-bypass-transforms` | lista (ej: `random_case,url_encode`) | Muta cada vector con la cadena de transformaciones (evasion de firmas WAF) |
| `--no-map` | flag | Omite la Fase 1; los testers solo reciben la URL semilla |
| `--max-depth` | entero (ej: `5`) | Profundidad maxima del crawler |
| `--max-urls` | entero (ej: `500`) | Limite de URLs que visita el crawler |
| `--no-verify-ssl` | flag | Deshabilita verificacion de certificado TLS |
| `--allow-private-redirects` | flag | Permite redirects a IPs privadas (SSRF guard de redirect OFF) |
| `--allow-destructive` | flag | Habilita payloads que pueden modificar datos del target |
| `-o` / `--output` | ruta | Directorio de salida para reportes |
| `-f` / `--format` | `json` `html` `json,html` | Formato(s) de reporte |
| `--lang` | `en` `es` | Idioma de salida |
| `-v` / `--verbose` | flag | Logging detallado en tiempo real |

---

> Solo usar en sistemas con autorizacion explicita y por escrito. Los perfiles
> `intense` y `--allow-destructive` generan carga significativa y son
> facilmente detectables; `--allow-destructive` puede causar perdida de datos.
