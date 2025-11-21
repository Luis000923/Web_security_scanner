# Web Security Scanner v4.0 - Arquitectura Mejorada

## 🚀 Mejoras Implementadas

### ✅ Arquitectura Modular
La herramienta ha sido completamente refactorizada con una arquitectura modular y escalable:

- **Core Module** (`core/`): Funcionalidad central del escáner
  - `scanner_core.py`: Motor de solicitudes HTTP con caché, rate limiting y reintentos
  - `config.py`: Sistema de configuración con soporte para YAML
  - `logger.py`: Logging estructurado con rotación de archivos y niveles

- **Vulnerability Testers** (`modules/vulnerability_testers/`): Módulos independientes para cada tipo de vulnerabilidad
  - `base_tester.py`: Clase base abstracta para todos los testers
  - `sql_injection.py`: Detección de inyección SQL
  - `xss_tester.py`: Detección de XSS
  - `nosql_injection.py`: Detección de inyección NoSQL
  - `ssrf_tester.py`: **NUEVO** - Detección de SSRF
  - `command_injection.py`: **NUEVO** - Detección de inyección de comandos
  - `path_traversal.py`: **NUEVO** - Detección de path traversal
  - `xxe_tester.py`: **NUEVO** - Detección de XXE
  - `csrf_tester.py`: **NUEVO** - Detección de CSRF
  - `idor_tester.py`: **NUEVO** - Detección de IDOR
  - `open_redirect.py`: Detección de redirecciones abiertas

- **Technology Detection** (`modules/technology_detector.py`): Detección avanzada de tecnologías
  - Fingerprinting mejorado con niveles de confianza
  - Detección de WAF y CDN
  - Análisis de security headers

### ✅ Nuevas Capacidades de Detección

#### SSRF (Server-Side Request Forgery)
- Payloads para IPs internas, metadata cloud, y protocolos alternativos
- Detección basada en respuestas y timing
- CWE-918 | OWASP A10:2021

#### Command Injection
- Payloads para Unix/Linux y Windows
- Detección time-based y basada en output
- CWE-78 | OWASP A03:2021

#### Path Traversal
- Múltiples técnicas de bypass (encoding, null bytes, mixed slashes)
- Detección de acceso a archivos sensibles
- CWE-22 | OWASP A01:2021

#### XXE (XML External Entity)
- Payloads para file disclosure, SSRF via XXE, y DoS
- Soporte para múltiples formatos (SVG, SOAP, etc.)
- CWE-611 | OWASP A05:2021

#### CSRF (Cross-Site Request Forgery)
- Detección automática de ausencia de tokens CSRF
- Validación de múltiples patrones de tokens
- CWE-352 | OWASP A01:2021

#### IDOR (Insecure Direct Object Reference)
- Detección de referencias directas sin autorización
- Testing automático de parámetros ID
- CWE-639 | OWASP A01:2021

### ✅ Sistema de Configuración Avanzado

Nuevo archivo `config.yaml` con opciones completas:
- Perfiles de escaneo predefinidos (quick, normal, deep, stealth)
- Configuración de rate limiting y timeouts
- Control granular de cada tipo de vulnerabilidad
- Configuración de autenticación
- Opciones de logging y reportería

### ✅ Mejoras de Rendimiento

**Response Cache Inteligente**
- Cache con TTL (Time To Live)
- Eviction automática de entradas antiguas
- Thread-safe con locks

**Rate Limiting**
- Control de velocidad de requests
- Prevención de bloqueos por WAF
- Configurable por perfil

**Retry Logic**
- Reintentos automáticos con backoff
- Manejo robusto de timeouts
- Estadísticas detalladas

### ✅ Logging Avanzado

**Structured Logging**
- Niveles: DEBUG, INFO, WARNING, ERROR, CRITICAL
- Rotación automática de archivos
- Formato colorizado para consola
- Estadísticas de escaneo en tiempo real

### ✅ Autenticación

Soporte para múltiples métodos:
- **Basic Auth**: Usuario y contraseña
- **Bearer Token**: Tokens JWT/OAuth
- **Session**: Cookies de sesión
- **OAuth**: Access tokens

### ✅ Mejoras en Detección de Tecnologías

- **Niveles de confianza**: High, Medium, Low
- **WAF Detection**: Cloudflare, Akamai, Imperva, AWS WAF, etc.
- **CDN Detection**: Cloudflare, CloudFront, Fastly, etc.
- **Security Headers**: CSP, HSTS, X-Frame-Options, etc.
- **Fingerprinting mejorado** con múltiples vectores de detección

## 📋 Estructura del Proyecto

```
Web_security_scanner/
├── config.yaml                          # Configuración principal
├── requirements.txt                     # Dependencias
├── web_security_scanner/
│   ├── core/                           # Módulos core
│   │   ├── __init__.py
│   │   ├── config.py                   # Sistema de configuración
│   │   ├── logger.py                   # Sistema de logging
│   │   └── scanner_core.py             # Motor del escáner
│   ├── modules/
│   │   ├── technology_detector.py      # Detección de tecnologías
│   │   └── vulnerability_testers/      # Testers de vulnerabilidades
│   │       ├── __init__.py
│   │       ├── base_tester.py          # Clase base
│   │       ├── sql_injection.py
│   │       ├── xss_tester.py
│   │       ├── nosql_injection.py
│   │       ├── ssrf_tester.py          # NUEVO
│   │       ├── command_injection.py    # NUEVO
│   │       ├── path_traversal.py       # NUEVO
│   │       ├── xxe_tester.py           # NUEVO
│   │       ├── csrf_tester.py          # NUEVO
│   │       ├── idor_tester.py          # NUEVO
│   │       └── open_redirect.py
│   ├── PAYLOAD/                        # Payloads
│   ├── web_security_scanner.py         # Script principal (legacy)
│   └── ...
```

## 🔧 Instalación

```powershell
# Instalar dependencias
pip install -r requirements.txt

# O con requirements específicos
pip install requests beautifulsoup4 colorama urllib3 pyyaml lxml
```

## 🎯 Uso

### Uso Básico

```powershell
# Escaneo normal
python web_security_scanner.py -u https://example.com

# Con configuración personalizada
python web_security_scanner.py -u https://example.com --config config.yaml

# Usar perfil predefinido
python web_security_scanner.py -u https://example.com --profile quick
python web_security_scanner.py -u https://example.com --profile deep
python web_security_scanner.py -u https://example.com --profile stealth
```

### Opciones Avanzadas

```powershell
# Con autenticación
python web_security_scanner.py -u https://example.com --auth-type bearer --auth-token "your_token"

# Solo detección de tecnologías
python web_security_scanner.py -u https://example.com --tech-only

# Habilitar verbose y logging debug
python web_security_scanner.py -u https://example.com -v --log-level DEBUG

# Exportar resultados
python web_security_scanner.py -u https://example.com -o results.json --html --pdf
```

### Perfiles de Escaneo

#### Quick (Rápido)
- 20 threads
- Timeout 10s
- Profundidad 2
- 30% de payloads

```powershell
python web_security_scanner.py -u https://example.com --profile quick
```

#### Normal (Por defecto)
- 10 threads
- Timeout 35s
- Profundidad 3
- 100% de payloads

```powershell
python web_security_scanner.py -u https://example.com --profile normal
```

#### Deep (Profundo)
- 5 threads
- Timeout 60s
- Profundidad 5
- 200% de payloads

```powershell
python web_security_scanner.py -u https://example.com --profile deep
```

#### Stealth (Sigiloso)
- 2 threads
- Timeout 45s
- Rate limit: 2 req/s
- 100% de payloads

```powershell
python web_security_scanner.py -u https://example.com --profile stealth
```

## 📊 Vulnerabilidades Detectadas

| Vulnerabilidad | Severidad | CWE | OWASP 2021 |
|---------------|-----------|-----|------------|
| SQL Injection | Critical | CWE-89 | A03 - Injection |
| XSS | High | CWE-79 | A03 - Injection |
| NoSQL Injection | Critical | CWE-943 | A03 - Injection |
| SSRF | Critical | CWE-918 | A10 - SSRF |
| Command Injection | Critical | CWE-78 | A03 - Injection |
| XXE | Critical | CWE-611 | A05 - Security Misconfiguration |
| Path Traversal | High | CWE-22 | A01 - Broken Access Control |
| CSRF | High | CWE-352 | A01 - Broken Access Control |
| IDOR | High | CWE-639 | A01 - Broken Access Control |
| Open Redirect | Medium | CWE-601 | A01 - Broken Access Control |

## 🎨 Características de la Nueva Arquitectura

### Extensibilidad
- Fácil agregar nuevos testers de vulnerabilidades
- Sistema de plugins preparado
- Configuración modular

### Mantenibilidad
- Código organizado y documentado
- Separación de responsabilidades
- Tests unitarios preparados

### Performance
- Cache inteligente de respuestas
- Rate limiting configurable
- Ejecución paralela optimizada
- Reintentos automáticos

### Observabilidad
- Logging estructurado
- Métricas detalladas
- Niveles de confianza en detecciones
- Estadísticas de escaneo

## 🔐 Seguridad y Ética

**⚠️ IMPORTANTE**: Esta herramienta es SOLO para:
- Fines educativos
- Testing en infraestructura propia
- Pentesting con autorización explícita

**NO** usar en sitios web sin permiso. El uso no autorizado puede ser ilegal.

## 📝 Próximas Mejoras Sugeridas

1. **Sistema de Plugins**: Arquitectura de plugins para extensibilidad
2. **Base de Datos**: SQLite para historial y comparaciones
3. **API REST**: FastAPI para integraciones
4. **Reportería Mejorada**: Gráficos y visualizaciones
5. **Web UI**: Interfaz web para configuración y resultados
6. **Exportación Avanzada**: SARIF, CSV, XML
7. **Machine Learning**: Detección de falsos positivos
8. **Proxy Support**: Soporte para Burp Suite, ZAP

## 📄 Licencia

Ver archivo LICENSE

## 👥 Contribuciones

Las contribuciones son bienvenidas. Por favor:
1. Fork el repositorio
2. Crea una rama para tu feature
3. Commit tus cambios
4. Push y crea un Pull Request

## 📞 Soporte

Para reportar bugs o sugerir mejoras, crea un issue en GitHub.

---

**Web Security Scanner v4.0** - Herramienta profesional de seguridad web con arquitectura empresarial.
