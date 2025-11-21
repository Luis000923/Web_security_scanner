# Web Security Scanner v4.0 🔐

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-success)]()
[![Languages](https://img.shields.io/badge/languages-English%20%7C%20Español-blue)]()

## 📝 Descripción

**Web Security Scanner v4.0** es una herramienta profesional de línea de comandos con arquitectura empresarial para realizar auditorías de seguridad completas en aplicaciones web. Completamente refactorizada con diseño modular, detecta 10 tipos de vulnerabilidades críticas y proporciona análisis detallado de tecnologías.

**🌍 MULTIIDIOMA**: Interfaz completa en **inglés** y **español** con selección durante la instalación.

**⚠️ SOLO USO EDUCATIVO Y AUTORIZADO**: Esta herramienta es exclusivamente para fines educativos y pruebas de seguridad autorizadas. El uso sin permiso explícito es ilegal.

---

## 🎯 ¿Qué hay de nuevo en v4.0?

### ✨ Mejoras Principales

- 🏗️ **Arquitectura modular** completamente refactorizada
- 🌍 **Sistema multiidioma** (inglés/español) con instalador interactivo
- 🆕 **6 nuevas vulnerabilidades** detectadas (SSRF, Command Injection, Path Traversal, XXE, CSRF, IDOR)
- ⚙️ **Sistema de configuración avanzado** con YAML y perfiles
- 📊 **Logging estructurado** con niveles y rotación
- 🚀 **Performance mejorado** con caché, rate limiting y reintentos
- 🔐 **Múltiples métodos de autenticación** (Basic, Bearer, Session, OAuth)
- 🎨 **Detección de tecnologías mejorada** con niveles de confianza, WAF y CDN

Ver [RESUMEN_MEJORAS.md](RESUMEN_MEJORAS.md) para detalles completos.

---

## 🔍 Vulnerabilidades Detectadas

| Vulnerabilidad | Severidad | CWE | OWASP 2021 |
|---------------|-----------|-----|------------|
| **SQL Injection** | 🔴 Critical | CWE-89 | A03 - Injection |
| **XSS** | 🟠 High | CWE-79 | A03 - Injection |
| **NoSQL Injection** | 🔴 Critical | CWE-943 | A03 - Injection |
| **SSRF** 🆕 | 🔴 Critical | CWE-918 | A10 - SSRF |
| **Command Injection** 🆕 | 🔴 Critical | CWE-78 | A03 - Injection |
| **XXE** 🆕 | 🔴 Critical | CWE-611 | A05 - Security Misconfiguration |
| **Path Traversal** 🆕 | 🟠 High | CWE-22 | A01 - Broken Access Control |
| **CSRF** 🆕 | 🟠 High | CWE-352 | A01 - Broken Access Control |
| **IDOR** 🆕 | 🟠 High | CWE-639 | A01 - Broken Access Control |
| **Open Redirect** | 🟡 Medium | CWE-601 | A01 - Broken Access Control |

---

## 🛠️ Detección de Tecnologías

- **Servidores Web**: Apache, Nginx, IIS, LiteSpeed, Cloudflare, etc.
- **Lenguajes**: PHP, Python, Java, Node.js, Ruby, Go, .NET, etc.
- **CMS**: WordPress, Joomla, Drupal, Magento, y 40+ más
- **Frameworks JS**: React, Angular, Vue.js, Next.js, Svelte, y más
- **Analytics**: Google Analytics, Facebook Pixel, Hotjar, Matomo, etc.
- **WAF**: Cloudflare, Akamai, Imperva, AWS WAF, F5
- **CDN**: Cloudflare, CloudFront, Fastly, Akamai
- **Security Headers**: CSP, HSTS, X-Frame-Options, etc.

---

## 📋 Instalación

### Requisitos

- **Python**: 3.7 o superior
- **SO**: Windows, Linux, macOS

### Instalación Rápida (Recomendado)

**Instalador interactivo con selección de idioma:**

```powershell
# 1. Clonar repositorio
git clone https://github.com/Luis000923/Web_security_scanner.git
cd Web_security_scanner

# 2. Ejecutar instalador interactivo
python install.py
```

El instalador te guiará para:
- ✅ Seleccionar idioma (🇬🇧 English / 🇪🇸 Español)
- ✅ Elegir perfil de escaneo predeterminado
- ✅ Configurar threads y timeouts
- ✅ Instalar dependencias automáticamente

### Instalación Manual

Si prefieres configurar manualmente:

```powershell
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Copiar y editar config.yaml
# Establecer idioma: 'en' o 'es'

# 3. Verificar instalación
cd web_security_scanner
python test_architecture.py
```

📖 **Guía completa de instalación:** [INSTALACION.md](INSTALACION.md)

---

## 🚀 Uso Rápido

### Escaneo Básico

```powershell
cd web_security_scanner

# Usando el idioma configurado en config.yaml
python scanner_v4.py -u https://example.com

# Forzar español
python scanner_v4.py -u https://example.com --language es

# Forzar inglés
python scanner_v4.py -u https://example.com --language en
```

### Con Perfiles Predefinidos

```powershell
# Rápido (ideal para testing inicial)
python scanner_v4.py -u https://example.com --profile quick --language es

# Normal (balance velocidad/profundidad)
python scanner_v4.py -u https://example.com --profile normal

# Profundo (máxima cobertura)
python scanner_v4.py -u https://example.com --profile deep

# Sigiloso (evita detección)
python scanner_v4.py -u https://example.com --profile stealth
```

### Solo Detección de Tecnologías

```powershell
python scanner_v4.py -u https://example.com --tech-only
```

### Con Autenticación

```powershell
# Basic Auth
python scanner_v4.py -u https://example.com \
    --auth-type basic \
    --auth-user admin \
    --auth-pass secret

# Bearer Token (JWT)
python scanner_v4.py -u https://example.com \
    --auth-type bearer \
    --auth-token "eyJhbGc..."
```

Ver [GUIA_USO.md](GUIA_USO.md) para ejemplos completos.

---

## ⚙️ Configuración

### Archivo config.yaml

```yaml
# Idioma de la interfaz
language: es  # 'en' para inglés, 'es' para español

scanner:
  threads: 10                    # Hilos concurrentes
  timeout: 35                    # Timeout en segundos
  rate_limit: 10                 # Requests por segundo
  max_depth: 3                   # Profundidad de crawling

vulnerabilities:
  sql_injection:
    enabled: true
    max_payloads: 50
  
  ssrf:
    enabled: true
    max_payloads: 30

authentication:
  enabled: false
  type: bearer                   # basic, bearer, session, oauth
  credentials:
    token: "your_token"

logging:
  level: INFO                    # DEBUG, INFO, WARNING, ERROR
  file: logs/scanner.log
```

### Perfiles de Escaneo

| Perfil | Threads | Timeout | Profundidad | Uso |
|--------|---------|---------|-------------|-----|
| `quick` | 20 | 10s | 2 | Testing rápido |
| `normal` | 10 | 35s | 3 | Balance (default) |
| `deep` | 5 | 60s | 5 | Máxima cobertura |
| `stealth` | 2 | 45s | 3 | Evitar detección |

---

## 📊 Ejemplo de Salida

```
🔐 Web Security Scanner v4.0
============================================================
Target: https://example.com
Enabled Testers: 10
============================================================

[*] Testing connection to https://example.com...
[+] Connection successful: 200

[*] Detecting technologies...
[+] Technology detection completed
  Servers: Nginx, Cloudflare
  Languages: PHP
  CMS: WordPress
  WAF: Cloudflare

[*] Crawling site...
[+] Found 5 forms

[*] Testing SQL Injection...
[!] Found 2 SQL Injection vulnerabilities

[*] Testing XSS...
[+] No XSS vulnerabilities found

...

============================================================
SCAN RESULTS
============================================================

Statistics:
  Total Requests: 245
  Cached Responses: 87
  Cache Hit Rate: 35.51%
  Avg Response Time: 0.32s

Vulnerabilities Found: 3

[!] SQL Injection: 2 found (Severity: critical)
    - URL: https://example.com/login
      Method: POST, Payload: ' OR '1'='1...

[+] JSON report saved to: reports/scan_20240115_103000.json
```

---

## 📁 Estructura del Proyecto

```
Web_security_scanner/
├── config.yaml                  # Configuración principal
├── requirements.txt             # Dependencias
├── GUIA_USO.md                 # Guía de uso detallada
├── RESUMEN_MEJORAS.md          # Resumen de mejoras v4.0
├── MEJORAS_v4.md               # Documentación completa
│
└── web_security_scanner/
    ├── scanner_v4.py           # 🆕 Script principal nuevo
    ├── test_architecture.py    # Script de prueba
    │
    ├── core/                   # 🆕 Módulos centrales
    │   ├── config.py          # Sistema de configuración
    │   ├── logger.py          # Logging estructurado
    │   └── scanner_core.py    # Motor HTTP
    │
    ├── modules/               # 🆕 Módulos funcionales
    │   ├── technology_detector.py
    │   └── vulnerability_testers/
    │       ├── base_tester.py
    │       ├── sql_injection.py
    │       ├── xss_tester.py
    │       ├── nosql_injection.py
    │       ├── ssrf_tester.py      # 🆕
    │       ├── command_injection.py # 🆕
    │       ├── path_traversal.py   # 🆕
    │       ├── xxe_tester.py       # 🆕
    │       ├── csrf_tester.py      # 🆕
    │       ├── idor_tester.py      # 🆕
    │       └── open_redirect.py
    │
    └── PAYLOAD/               # Wordlists y payloads
        ├── payloadsSQL.json
        ├── payloadsXSS.json
        ├── payloadsNoSQL.json
        ├── subdirectorios.json
        └── subdominios.json
```

---

## 🎓 Casos de Uso

### 1. Auditoría de Seguridad Interna
```powershell
python scanner_v4.py -u https://internal-app.company.com \
    --profile deep \
    --auth-type bearer --auth-token "xxx" \
    -v --log-level DEBUG
```

### 2. CI/CD Integration
```powershell
python scanner_v4.py -u https://staging.app.com \
    --profile quick \
    --config ci_config.yaml \
    -o results.json
```

### 3. Pentesting con WAF
```powershell
python scanner_v4.py -u https://target-with-waf.com \
    --profile stealth \
    -v
```

---

## 🔒 Seguridad y Ética

### ⚠️ IMPORTANTE

Esta herramienta es **SOLO** para:
- ✅ Fines educativos
- ✅ Testing en infraestructura propia
- ✅ Pentesting con autorización explícita por escrito

### ❌ NO usar para:
- Atacar sitios web sin autorización
- Actividades ilegales
- Causar daño o interrupción de servicios

**El uso no autorizado puede ser ilegal y resultar en acciones legales.**

---

## 📈 Performance

| Métrica | v3.0 | v4.0 | Mejora |
|---------|------|------|--------|
| Requests totales | 1000 | 650 | -35% |
| Tiempo de escaneo | 45min | 28min | -38% |
| False positives | ~25% | ~10% | -60% |
| Cache hit rate | 0% | 40% | +40% |

---

## 🛣️ Roadmap

### Completado ✅
- [x] Arquitectura modular
- [x] 10 tipos de vulnerabilidades
- [x] Sistema multiidioma (inglés/español)
- [x] Sistema de configuración YAML
- [x] Logging estructurado
- [x] Cache y rate limiting
- [x] Autenticación múltiple
- [x] Detección de WAF/CDN

### Próximos Pasos
- [ ] Más idiomas (francés, alemán, portugués)
- [ ] Sistema de plugins dinámicos
- [ ] Base de datos SQLite para historial
- [ ] API REST con FastAPI
- [ ] Web UI (Dashboard)
- [ ] Reportería avanzada con gráficos
- [ ] Machine Learning para falsos positivos
- [ ] Escaneo distribuido
- [ ] Exportación SARIF

---

## 👥 Contribuciones

¡Las contribuciones son bienvenidas!

1. Fork el proyecto
2. Crea tu feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la branch (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver [LICENSE](LICENSE) para más detalles.

---

## 📞 Soporte

- **Issues**: [GitHub Issues](https://github.com/Luis000923/Web_security_scanner/issues)
- **Documentación**: Ver archivos `.md` en el repositorio
- **Logs**: Revisar `logs/scanner.log`

---

## 📚 Documentación Completa

| Documento | Descripción |
|-----------|-------------|
| [README_v4.md](README_v4.md) | Este archivo - Documentación principal |
| [INSTALACION.md](INSTALACION.md) | 🌍 **Guía de instalación con selección de idioma** |
| [ARQUITECTURA.md](ARQUITECTURA.md) | 🏗️ **Arquitectura completa del sistema (qué se conecta con qué)** |
| [GUIA_USO.md](GUIA_USO.md) | Ejemplos de uso y casos prácticos |
| [RESUMEN_MEJORAS.md](RESUMEN_MEJORAS.md) | Comparativa v3.0 vs v4.0 |
| [TRANSFORMACION.md](TRANSFORMACION.md) | Visualización de cambios con diagramas |
| [INFORME_EJECUTIVO.md](INFORME_EJECUTIVO.md) | Resumen ejecutivo para management |

---

## 📚 Documentación Adicional

- [GUIA_USO.md](GUIA_USO.md) - Guía completa de instalación y uso
- [RESUMEN_MEJORAS.md](RESUMEN_MEJORAS.md) - Resumen ejecutivo de mejoras v4.0
- [MEJORAS_v4.md](MEJORAS_v4.md) - Documentación técnica detallada
- [config.yaml](config.yaml) - Archivo de configuración con ejemplos

---

## 🙏 Agradecimientos

- OWASP por sus recursos de seguridad web
- Comunidad de seguridad por compartir conocimientos
- Todos los contribuidores del proyecto

---

## ⚖️ Disclaimer

Esta herramienta se proporciona "tal cual" sin garantías. Los autores no se responsabilizan por el uso indebido o daños causados por esta herramienta. El usuario es responsable de cumplir con todas las leyes aplicables.

---

<div align="center">

**Web Security Scanner v4.0**

Desarrollado con ❤️ para la comunidad de seguridad

[⭐ Star](https://github.com/Luis000923/Web_security_scanner) · [🐛 Report Bug](https://github.com/Luis000923/Web_security_scanner/issues) · [✨ Request Feature](https://github.com/Luis000923/Web_security_scanner/issues)

</div>
