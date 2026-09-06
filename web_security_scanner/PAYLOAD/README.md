# Payloads (web-security-scanner v5.1)

## Fuente: `data/<categoría>.json` (+ `schema.json`, `meta.json`)

Todos los testers consumen sus vectores exclusivamente a través de
`web_security_scanner.core.payload_loader.PayloadLoader`, que descubre y lee
todos los ficheros `data/*.json` (uno por categoría) y valida cada uno contra
`schema.json` (JSON Schema draft 2020-12). Los metadatos compartidos del corpus
viven en `meta.json` (validado contra `meta.schema.json`).

### Estructura

`meta.json` — metadatos del corpus:

```json
{
  "version": "5.1.0",
  "schema": "./schema.json",
  "canary_token": "WSSc4n4ry7788",
  "marker_host": "evil-webscanner-test.invalid",
  "categories": ["command_injection", "crlf", "..."]
}
```

`data/<categoría>.json` — un fichero por tipo de vulnerabilidad. El nombre del
fichero *es* la clave de categoría (`data/sql_injection.json` → `sql_injection`);
el campo `category` debe coincidir:

```json
{
  "version": "5.1.0",
  "category": "sql_injection",
  "payloads": [
    {
      "id": "sqli.time.mysql.sleep",
      "vector": "' AND SLEEP(5)-- -",
      "description": "…",
      "context": "time_based_blind",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "canary": false,
      "confidence": "LOW | MEDIUM | HIGH | CONFIRMED",
      "severity": "Info | Low | Medium | High | Critical",
      "time_based": true,
      "min_intrusion_level": "safe | low | medium | high",
      "destructive": false,
      "waf_bypass": false,
      "oob": false,
      "engines": ["mysql", "mariadb"],
      "expected_evidence": ["…"],
      "references": ["https://…"],
      "tags": ["technique:time-based"]
    }
  ]
}
```

El loader también acepta un fichero cuyo contenido sea directamente el array
`[ … ]` (la categoría se toma del nombre del fichero) y un fichero agregado
`{"categories": {…}}` (comodidad para tests).

Campos obligatorios por payload: `id` (punteado, único global), `vector`,
`context`, `confidence`, `severity`. El resto son opcionales con defaults
seguros.

- `canary`: `true` incrusta el token compartido `WSSc4n4ry7788`; también admite
  una cadena marcador explícita (p. ej. el host `evil-webscanner-test.invalid`
  de Open Redirect / SSRF-OOB / Log4Shell).
- `min_intrusion_level`: `safe` = sonda pura; `high` = ejecutaría código / leería
  ficheros / es ruidosa. El loader puede filtrar con `max_intrusion=`.
- `waf_bypass` / `engines`: filtrables vía `get_payloads(..., waf_bypass=True,
  engine="jinja2")`.
- `destructive`: excluido salvo `--allow-destructive`. Sin reverse shells, sin
  `rm -rf`, sin fork bombs; los únicos vectores destructivos son DDL marcadas.
- `oob`: requiere un colaborador out-of-band (no incluido). Los testers
  correspondientes son inertes sin `config['oob_domain']`; `load_payloads`
  descarta estas firmas por defecto cuando no hay dominio OOB configurado
  para no gastar peticiones sin receptor.

### Categorías (14)

`sql_injection`, `xss`, `path_traversal`, `command_injection`, `open_redirect`,
`ssrf`, `nosql_injection`, `xxe`, `idor`, **`ssti`**, **`crlf`**,
**`log4shell`**, **`ldap`**, **`deserialization`**.

CSRF y Header Security no usan vectores de inyección (análisis estructural).

### Origen de las firmas

- **Curado** (metadatos completos y precisos): núcleo 2026 escrito a mano —
  bypasses WAF (Cloudflare/AWS/Imperva/ModSecurity), cadenas `php://filter`,
  IMDS de nube (AWS/GCP/Azure/Oracle/Alibaba), polyglots XSS/mXSS, SSTI por
  motor, obfuscaciones JNDI. Fuentes en `references[]` de cada entrada.
- **`source:legacy`** (`confidence: LOW`, contexto/tags por heurística):
  firmas plegadas desde los antiguos `payloads*.json` planos durante la
  migración a v5.1. Esos ficheros de entrada ya se eliminaron del repo; su
  historial vive en git y cada firma importada conserva el tag `source:legacy`.
  En v5.2 el corpus agregado (`payloads_v5.json`) se dividió en
  `data/<categoría>.json`.

### API

```python
from web_security_scanner.core.payload_loader import get_payload_loader

loader = get_payload_loader()
payloads = await loader.get_payloads("sql_injection", context="time_based_blind")
vectors  = await loader.get_vectors("xss", min_confidence="MEDIUM", waf_bypass=True)
ssti     = await loader.get_payloads("ssti", engine="jinja2", max_intrusion="low")
```

El parseo ocurre una sola vez (cache inmutable en memoria); la primera lectura
de disco (todos los `data/*.json`) se hace en un hilo worker
(`asyncio.to_thread`). Los testers reciben los vectores intercalados por
`context` y luego ordenados por peso combinado (`confidence` ×  `severity`,
descendente y estable) para que un `max_payloads` bajo conserve las firmas de
mayor certeza e impacto sin perder diversidad de técnica.

## Contenido del directorio

- `data/<categoría>.json` — el corpus, un fichero por categoría (14).
- `schema.json` — validación de cada fichero de categoría.
- `meta.json` / `meta.schema.json` — metadatos del corpus y su validación.
- `README.md` — este documento.

Los antiguos `payloads*.json` / `payloads_master.json` se eliminaron en v5.1
(consolidados en `payloads_v5.json`), y `payloads_v5.json` se dividió en
`data/` en v5.2. Las wordlists `subdominios.json` / `subdirectorios.json` se
movieron a `web_security_scanner/wordlists/`
(`subdomains.json` / `directories.json`).
