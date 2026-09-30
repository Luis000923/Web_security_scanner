# Reporte Táctico de Cobertura y Cuellos de Botella — rama `ai-agent`

- **Fecha:** 2026-09-07
- **Alcance:** `ai_module/` (generador de dataset, inferencia, entrenamiento),
  `data/sft.*.jsonl` committeados, telemetría en `testbed/results/`,
  testers en `web_security_scanner/modules/vulnerability_testers/`.
- **Objetivo de referencia:** OWASP Benchmark acotado a **338 objetivos de
  parámetro GET** = **194 instancias vulnerables** + **144 trampas / FP conocidos**.
- **Complementa** (no reemplaza) `ai_module/AUDIT.md`. Aquí el foco es
  *cobertura de clases/payloads* y *cuellos de botella a escala de 338 objetivos*.

Escala: 🔴 crítico · 🟠 alto · 🟡 medio · 🟢 correcto

---

## 0. Hallazgo transversal (contexto para todo lo demás)

**Todo el subsistema de IA está entrenado y evaluado sobre exactamente dos
clases: SQLi y XSS.** La telemetría fuente (1.10 M filas en `testbed/results/`)
proviene únicamente de `SQLInjectionTester` (≈580 k filas) y `XSSTester`
(≈530 k filas). Cero filas de cualquier otro tester. Como el dataset sintético
se ancla a *seeds* extraídos de esa telemetría, **no existe una sola muestra de
Path Traversal, Command Injection, LDAP/XPath Injection, SSRF, XXE, Open
Redirect, SSTI, CRLF, NoSQL ni Log4Shell** en `data/sft.*.jsonl`, pese a que el
escáner tiene 18 testers y `dataset_generator.py` ya define escenarios
sintéticos para `pathtraver` y `cmdi` que nunca se disparan por falta de seeds.

Consecuencia directa sobre el Benchmark: si los 338 objetivos GET se reparten
entre SQLi, XSS, Path Traversal y Command Injection (las cuatro clases del
Benchmark realmente alcanzables por inyección en parámetro GET black-box),
**el agente entra ciego a ~el 100 % de la porción de Path Traversal y Command
Injection** — y Path Traversal es la categoría individual más grande del
Benchmark v1.2.

---

## 1. Auditoría de Cuellos de Botella del Subsistema

### 1.1 Tubería de inferencia (`agent_inference.py`) a escala de 338 objetivos

| # | Sev | Hallazgo | Impacto a escala |
|---|-----|----------|------------------|
| B1 | 🔴 | **Sin backpressure hacia el backend de IA.** `base_tester_async.report_vulnerability()` llama `client.triage_finding()` inline; no pasa por `core._semaphore` / `TokenBucket` / `worker_pool`. `batch_triage()` (con `Semaphore`) está implementado pero **no se invoca en ningún sitio**. | 18 testers × 338 params → ráfagas de decenas de findings concurrentes → decenas de requests simultáneos al `llama-server`/vLLM local. En la 5090 con un 7B esto es contención de KV-cache y colas de segundos, o directamente OOM del servidor si sirve batch dinámico. |
| B2 | 🔴 | **Sin retry/backoff ni circuit breaker.** Un 5xx/timeout transitorio degrada a heurística con un `warning`. `timeout` por request = 60 s. | Si el servidor flaquea a mitad de scan, **cada** finding paga 60 s antes de degradar. Con 100+ findings sospechosos = el scan se cuelga minutos. No hay estado "backend caído → salta el triage por N segundos". |
| B3 | 🟠 | **`aiohttp.ClientSession` nuevo por llamada** en `_chat_openai` y `healthcheck`. Sin connection pool ni keep-alive. | Handshake TCP/TLS por cada triage; a cientos de llamadas es latencia y FD churn evitables. |
| B4 | 🟠 | **Triage secuencial e inline.** El `await client.triage_finding()` bloquea la corrutina del tester; no hay fan-out ni agrupación por lote. | El tester no avanza a su siguiente payload mientras espera al LLM. Serializa el camino crítico del scan con la latencia del modelo. |
| B5 | 🔴 | **Backend `transformers`: carga de modelo sin lock.** `_chat_hf` lazy-carga `self._hf`; dos corrutinas concurrentes vía `asyncio.to_thread` en el warm-up construyen el modelo dos veces. | En la 5090: doble asignación de VRAM (~30 GB de pico en vez de 15) o race → cuelgue del primer scan. |
| B6 | 🟠 | **`response_format={"type":"json_object"}` hard-coded**, sin gate por capacidad del backend. | Algunas versiones de `llama.cpp --api` / TGI devuelven 400 → **todo** el triage cae a heurística en silencio (solo `warning`). |
| B7 | 🟡 | **Sin caché de triage.** Findings con evidencia idéntica (mismo `vclass/param/payload/body-hash`) se reenvían al LLM. | El Benchmark tiene familias enteras de objetivos casi idénticos; se paga inferencia repetida. |
| B8 | 🟡 | **Sin telemetría de IA** (verdict/confidence/latencia/abortos/degradaciones). | Imposible auditar calibración (ECE) ni coste del agente para el paper, ni detectar que el backend se degradó a mitad de corrida. |
| B9 | 🟡 | `healthcheck()` una sola vez al arranque; sin re-probe si el servidor muere después. | Un backend que cae en el minuto 3 nunca se marca como caído. |
| B10 | 🟢 | Correcto: degradación segura que nunca rompe el scan; `is_vulnerable` conservador (UNCERTAIN cuenta como vulnerable); healthcheck con timeout corto. |

### 1.2 Estado compartido y concurrencia

- 🟠 El `AgentClient` se comparte por referencia a todos los testers. Correcto
  para el backend `openai` (stateless HTTP), pero arrastra el race B5 en
  `transformers` y **no hay ningún límite de concurrencia propio del cliente**
  contra el backend (el `core._semaphore` solo limita HTTP hacia el *target*,
  no hacia el modelo).
- 🟠 `payload synthesis` (si se activa) tiene el mismo patrón inline sin
  semáforo → compite por el mismo backend con el triage.

### 1.3 Tubería de datos (`dataset_generator.py`)

- 🟠 **Carga de telemetría en memoria completa.** `rows` = lista con las 1.10 M
  filas de todos los `telemetry_*.jsonl` antes de construir seeds/trayectorias.
  Hoy son ~120 MB; escala lineal con el número de corridas de ablación. Los
  builders (`build_triage_samples`, `build_payload_samples`) hacen varias
  pasadas O(n) + `defaultdict` de trayectorias sobre esa lista.
- 🟡 `_run_baselines(rows)` se recalcula en cada builder en vez de una vez.
- 🟢 Determinismo por `--seed`, dedup por clave observable, split train/val por
  clave observable (no hay fuga train→val).

### 1.4 Recomendaciones de cuellos de botella (prioridad)

1. **P0** — Enrutar `triage_finding()` y `synthesize_payloads()` por un
   `asyncio.Semaphore` propio del `AgentClient` (tamaño configurable, default
   2–4 en la 5090) **y cablear `batch_triage()`** desde el orquestador:
   acumular findings de una fase y despacharlos en lote acotado.
2. **P0** — `aiohttp.ClientSession` única y persistente en el cliente
   (`__aenter__/__aexit__`); retry con backoff exponencial (3 intentos,
   jitter) + **circuit breaker por scan**: tras N fallos consecutivos, saltar
   el triage durante T segundos y emitir un evento.
3. **P0** — `asyncio.Lock` alrededor de la carga lazy de `_chat_hf`; cargar en
   4-bit NF4 (coherente con el entrenamiento), no bf16.
4. **P1** — `response_format` opt-out por backend (probar en `healthcheck` y
   guardar la capacidad); caché LRU de triage por clave
   `(vclass, param, payload, sha1(body[:2k]))`.
5. **P1** — Emitir `AI_TRIAGE` a telemetría: `verdict, confidence, latency_ms,
   degraded, backend`. Alimenta la calibración del paper.
6. **P2** — `dataset_generator`: iterar los `.jsonl` en streaming
   (generador línea a línea) y construir seeds/trayectorias en una sola pasada;
   cachear `_run_baselines`.

---

## 2. Cobertura frente al OWASP Benchmark (338 objetivos GET)

### 2.1 Distribución real de los datasets committeados

**`data/sft.triage.train.jsonl` — 744 muestras · `val` 82**

| Eje | Distribución |
|-----|--------------|
| Clase sospechada | `sqli` 513 (69 %) · `xss` 231 (31 %) · **todo lo demás: 0** |
| Verdict | FALSE_POSITIVE 256 · TRUE_POSITIVE 242 · UNCERTAIN 246 (≈1:1:1) |
| `injection_context` | `html_text` 225 · `time_based_blind` 149 · `boolean_blind` 133 · `error_based` 85 · `js_string` 72 · `union_based` 32 · `auth_bypass` 17 · `html_attribute` 16 · `generic` 10 · `js_template_literal` 5 |
| Escenario sintético | `reflection_irrelevant_to_class` 87 · `weak_boolean_differential` 84 · `sql_time_oracle` 82 · `xss_verbatim_reflection` 81 · `sql_error_disclosure` 77 · `xss_partial_filter` 70 · `waf_block_page` 68 · `xss_output_encoded` 62 · `generic_500_page` 58 · `blank_response` 53 · reales sin escenario 22 |

**`data/sft.payload.train.jsonl` — 1057 muestras · `val` 118**

| Eje | Distribución |
|-----|--------------|
| Clase | `sqli` 530 · `xss` 527 · **todo lo demás: 0** |
| Familia de payload (heurística sobre el texto de salida) | sqli ≈476 · xss ≈357 · `cmd/oob/sleep` ≈89 (mayormente time-based SQLi) · `../` traversal ≈23 · otros ≈112 |

### 2.2 Mapa de cobertura vs. Benchmark

| Familia Benchmark (GET-reachable) | Peso relativo en Benchmark v1.2 | Cobertura en nuestro dataset | Veredicto |
|---|---|---|---|
| **SQLi — error-based** | alto | `sql_error_disclosure` (77) + 5 plantillas de error (ORA-, MySQL, `SQLSTATE`, `psycopg2`, `SQLite`) | 🟠 cubierto pero baja cardinalidad léxica; sin drivers .NET/JDBC/Sequelize/GORM/Hibernate |
| **SQLi — boolean blind** | alto | `weak_boolean_differential` (84, todos UNCERTAIN/FP) | 🟠 **sesgo grave**: casi no hay boolean-blind etiquetado TRUE_POSITIVE con differential estable → el modelo aprenderá a descartar boolean-blind |
| **SQLi — time-based / blind temporal** | alto (muchas trampas de latencia) | `sql_time_oracle` (82) — **una sola muestra retardada, sin repetibilidad, conf 0.85** | 🔴 contradice el system prompt ("needs a repeatable, payload-correlated delay"); no hay pares timed×N ni ruido de red que enseñe a distinguir oracle real de jitter/GC/carga |
| **SQLi — UNION** | medio | `union_based` context: solo 32 filas | 🟠 subrepresentado; sin escenario dedicado (columnas, `NULL` padding, `information_schema`) |
| **SQLi — auth-bypass / login (`' OR '1'='1`)** | presente | `auth_bypass` context: 17 filas | 🟠 muy fino; el Benchmark tiene trampas donde el `OR 1=1` no cambia nada |
| **XSS — reflejado verbatim** | alto | `xss_verbatim_reflection` (81) | 🟢 razonable |
| **XSS — output-encoded (trampa FP)** | alto (mitad de los xss del Benchmark son "safe") | `xss_output_encoded` (62) | 🟠 `_sc_xss_escaped` etiqueta FP **todo** lo escapado con `html.escape(quote=True)`, **incluso en `js_string`** donde escapar entidades no neutraliza → enseña un FP incorrecto |
| **XSS — filtro parcial / stripping** | medio | `xss_partial_filter` (70, UNCERTAIN) | 🟢 ok |
| **XSS — por contexto (attr / href / `<script>` / event handler / CSS)** | alto | `html_attribute` 16 · `js_string` 72 · `js_template_literal` 5 · sin `href`/`javascript:`/CSS/`srcdoc` | 🟠 el discriminador clave del Benchmark XSS (¿el contexto permite ejecución?) está poco muestreado |
| **Path Traversal — básico `../`** | **la categoría más grande** | `path_traversal_file_read` definido pero **0 muestras generadas** | 🔴 **ausente** |
| **Path Traversal — codificaciones** (`%2e%2e%2f`, `..%252f`, `....//`, `..\`, UTF-8 overlong, null byte, absolute path, `/etc/passwd` vs whitelisted) | alto; muchas trampas | 0 | 🔴 **ausente** — es exactamente donde el Benchmark separa 131 reales de sus trampas |
| **Path Traversal — trampas** (filename validado por whitelist, prefijo forzado, `getCanonicalPath` check) | alto | 0 | 🔴 **ausente** |
| **Command Injection — output-based** (`;id`, `| cat`, `` `id` ``, `$(id)`, `&&`, `%0a`) | alto | `cmd_injection_output` definido pero **0 muestras** | 🔴 **ausente** |
| **Command Injection — blind/time/OOB** (`; sleep 5`, `| nslookup x.oob`, `&& ping`) | alto | 0 (algunos payloads `sleep` aparecen pero etiquetados como SQLi) | 🔴 **ausente** |
| **Command Injection — trampas** (input en `ProcessBuilder` con array fijo, arg escapado, comando hardcoded) | alto | 0 | 🔴 **ausente** |
| **LDAP Injection** (`*)(uid=*`, `*)(|(...`) | bajo en Benchmark, pero GET-reachable | `reflection_irrelevant_to_class` acepta `ldapi` como UNCERTAIN, 0 TP/FP reales | 🟠 apenas presente |
| **XPath Injection** (`' or '1'='1`, `count(//*)`) | bajo | igual que LDAP | 🟠 apenas presente |
| **SSRF / XXE en parámetro GET** | fuera del núcleo Benchmark v1.2 estándar, pero el escáner los prueba | 0 | 🟡 fuera de alcance del Benchmark; documentarlo |
| **Trampas transversales** (WAF block, 500 genérico, respuesta vacía, redirect a `/login`, rate-limit 429) | críticas para la precisión | `waf_block_page` 68 · `generic_500_page` 58 · `blank_response` 53 · **sin redirect-auth, sin 429, sin YSOD/Rails/Django debug, sin WAFs reales (Akamai/Imperva/F5/AWS)** | 🟠 parcial |

### 2.3 Sesgos que degradarán la precisión sobre el Benchmark

1. 🔴 **Prior de clase 1:1:1** (TP/FP/UNCERTAIN). El Benchmark GET está ~194:144
   (≈57 % vulnerable) *dentro de lo que el escáner marca*, pero el triage real
   ve muchos más FP porque el escáner sobre-marca. Un modelo entrenado a 33 %
   TP **sobre-declara TP** → cae la precisión y sube el trap-hit rate.
2. 🔴 **Label ≈ tautología de `_assess_evidence()`.** El guard sintético solo
   emite la muestra si el assessor de reglas coincide con el verdict del
   escenario → el SFT destila la heurística. El agente **no puede superar**
   `_assess_evidence` en las trampas donde la heurística ya falla (que son
   justo las 144 del Benchmark diseñadas para engañar reglas).
3. 🔴 **`val` sale del mismo generador** → accuracy de validación optimista que
   no predice el Benchmark. No hay un set de evaluación real y honesto.
4. 🟠 **Cuerpos HTTP sintéticos.** El Benchmark real sí tiene cuerpos, pero de
   apps Java/JSP con firmas propias (Spring, JSP error pages, `struts`), no las
   plantillas Flask/`Whitelabel`/`Cloudflare Ray ID` del generador.
5. 🟠 **Sin pares contrastivos**: mismo cuerpo con/sin payload; mismo payload TP
   en un contexto y FP en otro. El Benchmark está *construido* sobre esa
   distinción (par vulnerable/seguro por cada sink).
6. 🟠 **Time-based sin modelo de ruido**: no hay muestras con latencia alta
   causada por GC/carga/red que deban etiquetarse FP/UNCERTAIN.

---

## 3. Plan de Inyección de Payloads Faltantes (priorizado)

Meta: que el agente distinga con precisión quirúrgica **194 reales vs 144
trampas**. Todo esto entra en `dataset_generator.py` como nuevos `_Scenario`
+ nuevos *seed generators* que **no dependan de telemetría** (seeds sintéticos
directos por clase, ya que la telemetría nunca tendrá pathtraver/cmdi).

### P0 — Clases del Benchmark hoy en cero

| # | Familia | Escenarios TRUE_POSITIVE | Escenarios FALSE_POSITIVE (trampas) | Escenarios UNCERTAIN |
|---|---|---|---|---|
| 1 | **Path Traversal** | `../../../etc/passwd` → body con `root:x:0:0`; `..\..\..\windows\win.ini` → `[fonts]`; codificados `%2e%2e%2f`, `..%252f`, `....//`, overlong UTF-8, null-byte `%00`, absolute `/etc/passwd`, todos con lectura confirmada | filename validado (devuelve el mismo archivo del whitelist / `File not found` / 403); prefijo forzado (`/var/www/images/<payload>` → 404); `getCanonicalPath` rechaza (500 con `Access denied`); traversal reflejado en la página pero sin lectura | secuencia reflejada + 200 genérico sin contenido de archivo; error de I/O ambiguo |
| 2 | **Command Injection — output** | `;id`, `| id`, `` `id` ``, `$(id)`, `& whoami`, `%0aid` → body con `uid=0(root) gid=0`; `; cat /etc/passwd`; Windows `& dir` → `Directory of C:\` | comando hardcoded (siempre el mismo output), input pasado como *arg* a `exec(String[])` (aparece literal en el output, no ejecutado); metacaracteres stripped; `sh: 1: <payload>: not found` (rechazado, no inyectado) | payload reflejado en un mensaje de error sin evidencia de ejecución |
| 3 | **Command Injection — blind/OOB/time** | `; sleep 5` con delay repetible ×3 sobre baseline; `\| nslookup <token>.oob` / `; curl http://<oob>` con callback registrado | `; sleep 5` con **un solo** hit lento y varianza alta (→ FP/UNCERTAIN); latencia por carga del servidor no correlacionada con payload | delay presente una vez, no reproducible |
| 4 | **SQLi time-based (endurecer)** | `WAITFOR DELAY`, `pg_sleep`, `SLEEP()`, `BENCHMARK()` con **delay correlacionado y repetido N veces**, delta ≫ jitter | payload con `sleep` pero delay dentro de jitter; timeout de red; delay presente sin payload (control) | 1 de 3 repeticiones lenta |

### P1 — Refuerzo de clases existentes en sus zonas débiles

| # | Familia | Qué añadir |
|---|---|---|
| 5 | **SQLi boolean-blind TP** | pares `1=1`/`1=2` con differential de content-length **estable y repetido** (TP conf 0.8+), para contrapesar los 84 `weak_boolean_differential` que hoy son todos FP/UNCERTAIN |
| 6 | **SQLi UNION** | escenario dedicado: `ORDER BY n` error → `UNION SELECT NULL,NULL,version()` reflejado; trampa: `UNION` reflejado en un `<input>` sin ejecución de query |
| 7 | **SQLi drivers reales** | plantillas de error para `System.Data.SqlClient.SqlException`, JDBC `SQLState`, `Sequelize`, Hibernate `QuerySyntaxException`, GORM, `psycopg.errors` (más allá de las 5 actuales) |
| 8 | **XSS por contexto** | `href="<payload>"` con `javascript:` (TP) vs `https://` forzado (FP); `<script>var x='<payload>'` con break de comilla (TP) vs escaped (FP); handler `onclick="<payload>"`; `<style>` / CSS `expression`; `srcdoc`; DOM sink `location.hash` → `innerHTML` |
| 9 | **XSS output-encoded (corregir bug)** | `_sc_xss_escaped`: en contexto `js_string`/`js_template_literal`, `html.escape` **no** debe etiquetar FP si la comilla del contexto no está escapada; separar "HTML-escaped en html_text" (FP legítimo) de "HTML-escaped en JS" (sigue siendo TP/UNCERTAIN) |
| 10 | **LDAP / XPath Injection** | LDAP: `*)(uid=*))(|(uid=*` → cambio en nº de resultados (TP) vs `*` literal sin efecto (FP), error `Bad search filter`. XPath: `' or '1'='1` → dump de nodos (TP) vs reflejado en error `XPathException` (UNCERTAIN) |

### P2 — Trampas transversales (precisión sobre las 144)

| # | Escenario | Verdict |
|---|---|---|
| 11 | Redirect 302 → `/login` / `/sso` tras el payload | FALSE_POSITIVE |
| 12 | 429 + `Retry-After` / página de rate-limit | FALSE_POSITIVE |
| 13 | Stack traces de framework: ASP.NET YSOD, Rails `ActionView`, Django `DEBUG`, Spring `Whitelabel` real, Express `Error:` con stack | FALSE_POSITIVE si no hay señal de interpretación del payload; TP si el trace revela SQL con el payload embebido |
| 14 | WAFs reales: Akamai (`Reference #`), Imperva/Incapsula (`Incident ID`), F5 ASM (`The requested URL was rejected`), AWS WAF (403 + `x-amzn`), Azure Front Door | FALSE_POSITIVE |
| 15 | Reflexión sanitizada por CSP (`Content-Security-Policy: script-src 'none'`) | UNCERTAIN / FALSE_POSITIVE según contexto |
| 16 | Cuerpo JSON / GraphQL: payload reflejado dentro de `"q":"<payload>"` sin ejecución; `"errors":[{"message":...}]` | FALSE_POSITIVE / UNCERTAIN |
| 17 | Pares contrastivos: por cada TP generado, emitir el gemelo "safe" (mismo endpoint/param/contexto, payload neutralizado) etiquetado FALSE_POSITIVE | — |

### P3 — Calibración y realismo del prior

- Añadir `--triage-class-prior` (o pesos de muestra) para llevar el ratio a
  ~1 TP : 2–3 FP : 1 UNCERTAIN, más cercano al triage DAST real.
- Inyectar 30–50 casos "duros" **adjudicados a mano** donde `_assess_evidence`
  se equivoca, para romper el techo de destilación (necesario para ganar en las
  144 trampas).
- Construir un `data/sft.triage.eval.jsonl` **fuera del generador**: 60–100
  hallazgos reales del testbed/Benchmark etiquetados a mano, con cuerpo donde
  exista. Prohibido sintético. Reportar precisión / recall / trap-hit / ECE
  sobre ese set — es la única métrica que predice el Benchmark.

---

## 4. Comandos de Verificación

Ejecutar desde la raíz del repo con `.venv/bin/python`.

### 4.1 Distribución de clases, verdicts y contextos (triage)

```bash
.venv/bin/python - <<'EOF'
import json, collections, re, glob
for path in sorted(glob.glob("data/sft.triage.*.jsonl")):
    cls=collections.Counter(); verd=collections.Counter()
    ctx=collections.Counter(); scn=collections.Counter(); src=collections.Counter()
    n=0
    for line in open(path):
        o=json.loads(line); n+=1; inp=o["input"]; out=o.get("output",""); meta=o.get("meta") or {}
        m=re.search(r"Suspected class:\s*(\S+)", inp)
        cls[m.group(1) if m else "??"]+=1
        for v in ("TRUE_POSITIVE","FALSE_POSITIVE","UNCERTAIN"):
            if f'"{v}"' in out: verd[v]+=1
        mc=re.search(r'"injection_context":\s*"([^"]+)"', inp)
        if mc: ctx[mc.group(1)]+=1
        scn[meta.get("scenario","<real>")]+=1
        src[meta.get("label_source","?")]+=1
    print(f"\n### {path}  (n={n})")
    print(" class   :", dict(cls.most_common()))
    print(" verdict :", dict(verd.most_common()), " ratio TP:FP:UNC =",
          ":".join(str(round(verd[v]/max(verd.values()),2)) for v in ("TRUE_POSITIVE","FALSE_POSITIVE","UNCERTAIN")))
    print(" context :", dict(ctx.most_common()))
    print(" scenario:", dict(scn.most_common()))
    print(" source  :", dict(src.most_common()))
EOF
```

### 4.2 Clases y familias de payload (payload dataset)

```bash
.venv/bin/python - <<'EOF'
import json, collections, re, glob
FAMILIES = {
    "xss":        r"<script|onerror|onload|<svg|<img|javascript:|alert\(|confirm\(|prompt\(|srcdoc|<iframe",
    "sqli_union": r"union\s+select|order\s+by\s+\d|information_schema",
    "sqli_error": r"'\s*(or|and)\s|--\s|/\*|extractvalue|updatexml|convert\(",
    "sqli_time":  r"sleep\(|pg_sleep|waitfor\s+delay|benchmark\(",
    "cmdi":       r";\s*(id|whoami|cat|dir|ping|sleep|nslookup|curl)\b|\|\s*(id|cat|whoami)|`[^`]+`|\$\([^)]+\)|&&|%0a",
    "pathtrav":   r"\.\./|\.\.\\|%2e%2e|%252e|\.\.%2f|/etc/passwd|win(dows)?[\\/]win\.ini|boot\.ini|file://",
    "ssti":       r"\{\{.*\}\}|\$\{.*\}|<%=|#\{",
    "ldap_xpath": r"\)\(\||\*\)\(|count\(//|\bor\s+'1'='1",
    "ssrf_redir": r"https?://(127\.|169\.254|localhost|0\.0\.0\.0)|@evil|\bfile:|gopher:|dict:",
}
for path in sorted(glob.glob("data/sft.payload.*.jsonl")):
    cls=collections.Counter(); fam=collections.Counter(); total=0
    for line in open(path):
        o=json.loads(line); inp=o["input"]; out=o.get("output","")
        m=re.search(r"Suspected class:\s*(\S+)", inp) or re.search(r"class[:=]\s*(\w+)", inp)
        cls[m.group(1) if m else "??"]+=1
        for p in re.findall(r'"payload":\s*"((?:[^"\\]|\\.){0,120})"', out):
            total+=1; hit=[f for f,rx in FAMILIES.items() if re.search(rx,p,re.I)]
            fam[hit[0] if hit else "other"]+=1
    print(f"\n### {path}")
    print(" suspected class:", dict(cls.most_common()))
    print(f" payload families (n={total}):", dict(fam.most_common()))
    for f in FAMILIES:
        if fam[f]==0: print(f"   !! ZERO coverage: {f}")
EOF
```

### 4.3 Chequeo rápido de clases ausentes vs. Benchmark (una línea)

```bash
for f in data/sft.triage.train.jsonl data/sft.payload.train.jsonl; do
  echo "== $f =="
  for c in sqli xss pathtraver cmdi ldapi xpathi ssrf xxe redirect ssti crlf nosql; do
    n=$(grep -c -iE "class:? *$c|suspected_class\"? *[:=] *\"?$c" "$f")
    printf '  %-10s %s\n' "$c" "$n"
  done
done
```

### 4.4 ¿La telemetría fuente tiene algo más que SQLi/XSS?

```bash
.venv/bin/python - <<'EOF'
import json, collections, glob
t=collections.Counter()
for f in glob.glob("testbed/results/*/telemetry*.jsonl"):
    for line in open(f):
        try: o=json.loads(line)
        except: continue
        if o.get("tester_id"): t[o["tester_id"]]+=1
print("testers presentes en telemetría:", dict(t.most_common()))
print("--> si solo aparecen SQLInjectionTester/XSSTester, hay que generar")
print("    corridas del testbed con path_traversal_async y command_injection_async")
print("    ANTES de regenerar el dataset, o inyectar seeds sintéticos por clase.")
EOF
```

### 4.5 Verificar fuga train/val y balance tras regenerar

```bash
.venv/bin/python - <<'EOF'
import json, hashlib, glob
def keys(p):
    s=set()
    for line in open(p):
        o=json.loads(line)
        s.add(hashlib.sha1((o["input"]).encode()).hexdigest())
    return s
for task in ("triage","payload"):
    tr=keys(f"data/sft.{task}.train.jsonl"); va=keys(f"data/sft.{task}.val.jsonl")
    print(f"{task}: train={len(tr)} val={len(va)} overlap={len(tr&va)}  (debe ser 0)")
EOF
```

### 4.6 Runbook de regeneración con cobertura completa (objetivo)

```bash
# 1. Generar telemetría de las clases faltantes contra el Benchmark local
python -m web_security_scanner.web_security_scanner_async \
  --target-list testbed/benchmark_get_targets.txt \
  --only-testers PathTraversalTester,CommandInjectionTester,LDAPInjectionTester \
  --telemetry-dir testbed/results/coverage_pathcmd/ --global-seed 1337

# 2. Regenerar ambos datasets con multiplicador y prior recalibrado
.venv/bin/python -m ai_module.dataset_generator \
  --telemetry testbed/results/ \
  --benchmark-csv testbed/expectedresults-1.2.csv \
  --task both --split 0.9 --seed 1337 \
  --synthetic-multiplier 40 --balance --balance-ratio 2.5 \
  --out data/sft --report data/curation.json

# 3. Auditar (4.1–4.5) y confirmar 0 clases en cero + 0 overlap
```

---

## 5. Resumen ejecutivo

| Frente | Estado | Riesgo si se lleva a la 5090 tal cual |
|---|---|---|
| **Cuellos de botella** | Backend de IA sin backpressure, sin breaker, sesión por request, race de doble carga en `transformers`, `batch_triage()` muerto | Un scan de 338 objetivos × 18 testers puede colapsar el servidor de inferencia local o colgarse minutos si el backend flaquea |
| **Cobertura de clases** | **Solo SQLi + XSS.** 0 Path Traversal, 0 Command Injection, 0 LDAP/XPath, en dataset y en telemetría | El agente entra ciego a la porción Path Traversal + Command Injection del Benchmark (la más grande); triage por heurística en esas clases |
| **Cobertura de trampas** | WAF/500/blank sí; redirect-auth, 429, YSOD/Rails/Django, WAFs reales, CSP, JSON — no | Trap-hit rate alto en las 144 trampas del Benchmark |
| **Calibración** | Prior 1:1:1 irreal; label = destilación de `_assess_evidence`; `val` del mismo generador | Sobre-declaración de TP; métricas de validación no predicen el Benchmark |

**Acción mínima antes de la workstation:**
1. P0 de cuellos de botella (semáforo del cliente + `batch_triage` + sesión
   persistente + breaker + lock de carga HF).
2. Generar telemetría de `PathTraversalTester` y `CommandInjectionTester`
   contra el Benchmark local, **o** añadir seeds sintéticos por clase, y
   regenerar el dataset con los escenarios P0/P1/P2 de la §3.
3. Construir el `sft.triage.eval.jsonl` honesto (§3 P3) y no confiar en ninguna
   métrica que no salga de él.
