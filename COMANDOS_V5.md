# Combinaciones de Parámetros — `webscanner scan` (v5.0)

Entry point: `webscanner scan <url> [opciones]`

---

## Perfiles base

```bash
# Rápido — cabeceras y tech detection, mínimos payloads
webscanner scan https://ejemplo.com -p quick

# Balanceado — todos los testers, payloads moderados (DEFAULT)
webscanner scan https://ejemplo.com -p balanced

# Intenso — máximos payloads, más tiempo de ejecución
webscanner scan https://ejemplo.com -p intense

# Solo mapeo de URLs/estructura, sin vulnerability testing
webscanner scan https://ejemplo.com -p mapping
```

---

## Control de rendimiento

```bash
# Más hilos concurrentes (más rápido, más carga en servidor)
webscanner scan https://ejemplo.com --threads 30

# Timeout alto para servidores lentos (segundos)
webscanner scan https://ejemplo.com --timeout 30

# Rate limiting — esperar N segundos entre requests (evadir WAF/IDS)
webscanner scan https://ejemplo.com --rate-limit 2

# Delay entre payloads por tester (segundos)
webscanner scan https://ejemplo.com --payload-delay 1.5

# Limitar payloads por parámetro
webscanner scan https://ejemplo.com --max-payloads 20

# Cap total de tiempo del escaneo (segundos)
webscanner scan https://ejemplo.com --max-duration 120
```

---

## Opciones de crawling

```bash
# Sin mapa web (más rápido)
webscanner scan https://ejemplo.com --no-map

# Profundidad de crawl (default: 3)
webscanner scan https://ejemplo.com --max-depth 5

# Máximo URLs a visitar (default: 1000)
webscanner scan https://ejemplo.com --max-urls 500
```

---

## Seguridad / acceso

```bash
# Deshabilitar verificación TLS (sitios con certificado inválido)
webscanner scan https://ejemplo.com --no-verify-ssl

# Permitir redirects a IPs privadas (solo targets internos autorizados)
webscanner scan https://ejemplo.com --allow-private-redirects

# Habilitar payloads destructivos (modifica/elimina datos en el target)
webscanner scan https://ejemplo.com --allow-destructive
```

---

## Salida y formatos

```bash
# Solo JSON
webscanner scan https://ejemplo.com -f json -o mi_reporte

# Solo HTML
webscanner scan https://ejemplo.com -f html -o mi_reporte

# Ambos formatos (default)
webscanner scan https://ejemplo.com -f json,html -o mi_reporte

# Idioma español
webscanner scan https://ejemplo.com --lang es

# Idioma inglés (default)
webscanner scan https://ejemplo.com --lang en

# Verbose — ver payloads y respuestas en tiempo real
webscanner scan https://ejemplo.com -v
```

---

## Combinaciones prácticas

```bash
# Auditoría inicial rápida — solo superficie, sin saturar servidor
webscanner scan https://ejemplo.com -p quick --no-map -f json -o quick_report --lang es

# Escaneo sigiloso — evadir WAF, baja carga en servidor
webscanner scan https://ejemplo.com -p balanced --rate-limit 3 --payload-delay 1 --threads 5 --lang es -v

# Escaneo completo con máxima cobertura
webscanner scan https://ejemplo.com -p intense --threads 20 --timeout 15 --max-payloads 100 -f json,html -o full_audit --lang es -v

# Solo mapeo estructural del sitio
webscanner scan https://ejemplo.com -p mapping --max-depth 5 --max-urls 2000 -f html -o sitemap

# Escaneo con SSL inválido (staging/dev sin cert válido)
webscanner scan https://ejemplo.com --no-verify-ssl -p balanced -v

# Escaneo con cap de tiempo para CI/CD (máx 3 minutos)
webscanner scan https://ejemplo.com -p balanced --max-duration 180 -f json -o ci_report

# Escaneo intenso con reporte bilingüe y cap de payloads
webscanner scan https://ejemplo.com -p intense --max-payloads 50 --timeout 20 --threads 15 -f json,html -o auditoria --lang es -v

# Crawl profundo con rate limit (no sobrecargar servidor de producción)
webscanner scan https://ejemplo.com -p mapping --max-depth 8 --max-urls 5000 --rate-limit 1 -f html -o mapa_completo
```

---

## Referencia rápida de parámetros

| Parámetro | Valores | Función |
|-----------|---------|---------|
| `-p` / `--profile` | `quick` `balanced` `intense` `mapping` | Perfil de escaneo — define hilos, payloads y testers activos |
| `--threads` | entero (ej: `10`) | Requests concurrentes máximos |
| `--timeout` | segundos (ej: `15`) | Tiempo máximo de espera por request |
| `--rate-limit` | segundos (ej: `2`) | Pausa mínima entre requests — reduce detección WAF |
| `--payload-delay` | segundos (ej: `1.5`) | Delay entre payloads dentro de cada tester |
| `--max-payloads` | entero (ej: `50`) | Máx payloads probados por parámetro |
| `--max-duration` | segundos (ej: `180`) | Tiempo total máximo del escaneo |
| `--no-map` | flag | Omite crawling/mapeo de URLs |
| `--max-depth` | entero (ej: `5`) | Profundidad máxima del crawler |
| `--max-urls` | entero (ej: `500`) | Límite de URLs que visita el crawler |
| `--no-verify-ssl` | flag | Deshabilita verificación de certificado TLS |
| `--allow-private-redirects` | flag | Permite redirects a IPs privadas (SSRF guard OFF) |
| `--allow-destructive` | flag | Habilita payloads que pueden modificar datos del target |
| `-o` / `--output` | ruta (ej: `reports/scan1`) | Directorio de salida para reportes |
| `-f` / `--format` | `json` `html` `json,html` | Formato(s) de reporte |
| `--lang` | `en` `es` | Idioma de salida |
| `-v` / `--verbose` | flag | Logging detallado en tiempo real |

---

> Solo usar en sitios con autorización explícita. Escaneos intensos pueden generar carga y ser detectados por WAF/IDS.
