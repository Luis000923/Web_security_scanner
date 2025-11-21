# 🚀 GUÍA DE INSTALACIÓN Y CONFIGURACIÓN

## 📥 Instalación Rápida

### Opción 1: Instalador Interactivo (Recomendado)

El instalador te guiará paso a paso, permitiéndote:
- ✅ Seleccionar idioma (inglés o español)
- ✅ Elegir perfil de escaneo predeterminado
- ✅ Configurar threads y timeouts
- ✅ Instalar dependencias automáticamente

```powershell
# 1. Clonar el repositorio
git clone https://github.com/Luis000923/Web_security_scanner.git
cd Web_security_scanner

# 2. Ejecutar instalador interactivo
python install.py
```

**El instalador mostrará:**
```
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║        🔒 WEB SECURITY SCANNER v4.0 - INSTALACIÓN 🔒            ║
    ║                                                                  ║
    ║                  Professional Security Tool                      ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝

  SELECT YOUR LANGUAGE / SELECCIONE SU IDIOMA
  ====================================================================
  
  1. 🇬🇧 English
  2. 🇪🇸 Español
  
  ➤ Select option (1 or 2):
```

### Opción 2: Instalación Manual

Si prefieres configurar manualmente:

```powershell
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Copiar y editar config.yaml
# Editar el archivo config.yaml y establecer:
# language: es  # o 'en' para inglés
```

---

## 🌍 Configuración de Idioma

### Durante la Instalación

El instalador te preguntará el idioma automáticamente. Tu selección se guardará en `config.yaml`.

### Cambiar Idioma Después

**Método 1: Editar config.yaml**

Abre `config.yaml` y modifica:

```yaml
# Configuración de idioma
language: es  # Cambiar a 'en' para inglés o 'es' para español
```

**Método 2: Argumento de línea de comandos**

```powershell
# Forzar inglés
python web_security_scanner/scanner_v4.py -u https://example.com --language en

# Forzar español
python web_security_scanner/scanner_v4.py -u https://example.com --language es
```

### Idiomas Soportados

| Código | Idioma | Estado |
|--------|--------|--------|
| `en` | English (Inglés) | ✅ Completo |
| `es` | Español | ✅ Completo |

---

## ⚙️ Configuración Avanzada

### Perfiles de Escaneo

Durante la instalación, puedes elegir uno de estos perfiles:

#### 1. Quick (Rápido)
```yaml
threads: 20
timeout: 10
rate_limit: 20
```
- **Uso:** CI/CD, pruebas rápidas
- **Velocidad:** ⚡⚡⚡ Muy rápido
- **Cobertura:** ⭐⭐ Básica

#### 2. Normal (Balanceado) - Predeterminado
```yaml
threads: 10
timeout: 35
rate_limit: 10
```
- **Uso:** Auditorías regulares
- **Velocidad:** ⚡⚡ Rápido
- **Cobertura:** ⭐⭐⭐ Completa

#### 3. Deep (Exhaustivo)
```yaml
threads: 5
timeout: 60
rate_limit: 5
```
- **Uso:** Pentesting profundo
- **Velocidad:** ⚡ Lento
- **Cobertura:** ⭐⭐⭐⭐⭐ Máxima

#### 4. Stealth (Sigiloso)
```yaml
threads: 2
timeout: 45
rate_limit: 2
```
- **Uso:** Evadir WAF/IDS
- **Velocidad:** ⚡ Muy lento
- **Cobertura:** ⭐⭐⭐ Completa

### Cambiar Perfil

**Método 1: En config.yaml**
```yaml
default_profile: deep  # quick, normal, deep, stealth
```

**Método 2: Argumento CLI**
```powershell
python web_security_scanner/scanner_v4.py -u https://example.com --profile deep
```

---

## 🔧 Configuración Personalizada

### Estructura de config.yaml

```yaml
# IDIOMA
language: es  # 'en' o 'es'

# SCANNER
scanner:
  threads: 10              # Número de hilos (1-50)
  timeout: 35              # Timeout en segundos (10-120)
  user_agent: WebSecurityScanner/4.0
  verify_ssl: true         # Verificar certificados SSL
  follow_redirects: true
  max_redirects: 5
  rate_limit: 10           # Máximo requests por segundo

# CACHE
cache:
  enabled: true            # Habilitar cache de respuestas
  ttl: 3600                # Time To Live en segundos

# VULNERABILIDADES
vulnerabilities:
  sql_injection:
    enabled: true
    max_payloads: 50       # Máximo de payloads a probar
  xss:
    enabled: true
    max_payloads: 50
  nosql_injection:
    enabled: true
    max_payloads: 30
  ssrf:
    enabled: true
    max_payloads: 40
  command_injection:
    enabled: true
    max_payloads: 45
  path_traversal:
    enabled: true
    max_payloads: 50
  xxe:
    enabled: true
    max_payloads: 14
  csrf:
    enabled: true
  idor:
    enabled: true
    test_count: 5
  open_redirect:
    enabled: true
    max_payloads: 20

# DETECCIÓN DE TECNOLOGÍAS
technology_detection:
  enabled: true
  detect_cms: true         # Detectar CMS (WordPress, Joomla, etc.)
  detect_frameworks: true  # Detectar frameworks (React, Django, etc.)
  detect_server: true      # Detectar servidor web
  detect_waf: true         # Detectar WAF
  detect_cdn: true         # Detectar CDN

# LOGGING
logging:
  level: INFO              # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: logs/scanner.log
  max_size: 10485760       # 10MB
  backup_count: 5
  console_output: true
  colored_output: true

# PERFIL PREDETERMINADO
default_profile: normal    # quick, normal, deep, stealth
```

---

## 📖 Ejemplos de Uso

### Escaneo Básico en Español

```powershell
python web_security_scanner/scanner_v4.py -u https://example.com

# Salida:
# Iniciando escaneo de seguridad...
# Probando URL: https://example.com
# Detectando tecnologías...
# Se encontraron 3 tecnologías
# Probando vulnerabilidades de tipo Inyección SQL...
# ¡Escaneo completado exitosamente!
```

### Escaneo en Inglés

```powershell
python web_security_scanner/scanner_v4.py -u https://example.com --language en

# Output:
# Starting security scan...
# Testing URL: https://example.com
# Detecting technologies...
# Found 3 technologies
# Testing for SQL Injection vulnerabilities...
# Scan completed successfully!
```

### Solo Detección de Tecnologías

```powershell
# En español
python web_security_scanner/scanner_v4.py -u https://example.com --tech-only

# En inglés
python web_security_scanner/scanner_v4.py -u https://example.com --tech-only --language en
```

### Escaneo con Autenticación

```powershell
# Bearer Token
python web_security_scanner/scanner_v4.py -u https://api.example.com \
    --auth-type bearer \
    --auth-token "eyJhbGciOiJIUzI1NiIs..." \
    --language es

# Basic Auth
python web_security_scanner/scanner_v4.py -u https://app.example.com \
    --auth-type basic \
    --auth-user admin \
    --auth-password secret123
```

### Escaneo Profundo con Logging Debug

```powershell
python web_security_scanner/scanner_v4.py -u https://example.com \
    --profile deep \
    --log-level DEBUG \
    -v
```

---

## 🧪 Validación de Instalación

### Test de Arquitectura

```powershell
python web_security_scanner/test_architecture.py
```

**Salida esperada (español):**
```
╔══════════════════════════════════════════════════════════════════╗
║            TEST DE ARQUITECTURA - Web Security Scanner           ║
╚══════════════════════════════════════════════════════════════════╝

[✓] Test 1: Importación de módulos core
[✓] Test 2: Carga de configuración
[✓] Test 3: Sistema de logging
[✓] Test 4: Internacionalización (i18n)
[✓] Test 5: Scanner core
[✓] Test 6: Cache de respuestas
[✓] Test 7: Rate limiter
[✓] Test 8: Technology detector
[✓] Test 9: Vulnerability testers
[✓] Test 10: Integración completa
[✓] Test 11: Dependencias

═════════════════════════════════════════════════════════════════
           RESULTADO: 11/11 tests pasaron ✓
═════════════════════════════════════════════════════════════════
```

### Verificar Idioma Configurado

```powershell
python -c "from web_security_scanner.core import get_i18n; print(get_i18n().get_language())"

# Salida: es  (o 'en')
```

---

## 🔍 Troubleshooting

### Error: "No module named 'yaml'"

**Solución:**
```powershell
pip install pyyaml
```

### Error: "config.yaml not found"

**Solución:**
```powershell
# Re-ejecutar instalador
python install.py

# O copiar manualmente
# El instalador creará el archivo config.yaml automáticamente
```

### Error: "languages.yaml not found"

**Causa:** El archivo languages.yaml no está en el directorio raíz.

**Solución:**
```powershell
# Verificar que existe
ls languages.yaml

# Si no existe, el instalador debería haberlo creado
# Re-ejecutar: python install.py
```

### El scanner muestra mensajes en inglés cuando configuré español

**Solución:**
```powershell
# 1. Verificar config.yaml
cat config.yaml | Select-String "language"

# 2. Debe mostrar: language: es
# Si muestra 'en', editar manualmente o usar --language es

python web_security_scanner/scanner_v4.py -u https://example.com --language es
```

### Error al instalar dependencias

**Solución:**
```powershell
# Actualizar pip
python -m pip install --upgrade pip

# Instalar una por una
pip install requests
pip install beautifulsoup4
pip install colorama
pip install urllib3
pip install pyyaml
pip install lxml
```

---

## 📚 Documentación Adicional

### Arquitectura del Sistema

Lee `ARQUITECTURA.md` para entender:
- Estructura de directorios
- Conexiones entre módulos
- Flujo de datos
- Diagramas detallados

### Guía de Uso Completa

Lee `GUIA_USO.md` para:
- Casos de uso avanzados
- Integración CI/CD
- Personalización de payloads
- Mejores prácticas

### Resumen de Mejoras

Lee `RESUMEN_MEJORAS.md` para:
- Comparativa v3.0 vs v4.0
- Métricas de performance
- Nuevas funcionalidades

---

## 🎯 Quick Reference

### Comandos Principales

```powershell
# Instalación
python install.py

# Escaneo básico
python web_security_scanner/scanner_v4.py -u <URL>

# Escaneo en español
python web_security_scanner/scanner_v4.py -u <URL> --language es

# Escaneo rápido
python web_security_scanner/scanner_v4.py -u <URL> --profile quick

# Escaneo profundo
python web_security_scanner/scanner_v4.py -u <URL> --profile deep

# Solo tecnologías
python web_security_scanner/scanner_v4.py -u <URL> --tech-only

# Con autenticación
python web_security_scanner/scanner_v4.py -u <URL> --auth-type bearer --auth-token <TOKEN>

# Verbose + Debug
python web_security_scanner/scanner_v4.py -u <URL> -v --log-level DEBUG

# Test de instalación
python web_security_scanner/test_architecture.py
```

### Archivos Importantes

| Archivo | Propósito |
|---------|-----------|
| `install.py` | Instalador interactivo con selección de idioma |
| `config.yaml` | Configuración principal (incluye idioma) |
| `languages.yaml` | Traducciones inglés/español |
| `web_security_scanner/scanner_v4.py` | Script principal |
| `ARQUITECTURA.md` | Documentación técnica completa |

---

## 💡 Consejos

1. **Usa el instalador:** Es la forma más fácil de configurar todo correctamente.

2. **Elige el perfil correcto:** 
   - Quick para CI/CD
   - Normal para uso diario
   - Deep para pentesting
   - Stealth para evadir WAF

3. **Configura el idioma una vez:** Quedará guardado en config.yaml.

4. **Revisa los logs:** `logs/scanner.log` tiene información detallada.

5. **Personaliza config.yaml:** Puedes deshabilitar vulnerabilidades específicas.

---

## 🆘 Soporte

Si encuentras problemas:

1. Revisa esta guía
2. Lee `ARQUITECTURA.md` para entender el sistema
3. Ejecuta `test_architecture.py` para validar
4. Revisa los logs en `logs/scanner.log`
5. Abre un issue en GitHub

---

**¡Disfruta escaneando! 🔒**
