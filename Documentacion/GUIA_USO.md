# Guía de Instalación y Uso - Web Security Scanner v4.0
# ESTA EN BETA AHI FUNCIONES NO PROBADAS

## 📦 Instalación

### Paso 1: Requisitos del Sistema

- **Python**: 3.7 o superior
- **Sistema Operativo**: Windows, Linux, macOS
- **Espacio en disco**: 100 MB mínimo

### Paso 2: Instalar Dependencias

Desde el directorio del proyecto:

```powershell
# Opción 1: Usando requirements.txt
pip install -r requirements.txt

# Opción 2: Instalación manual
pip install requests beautifulsoup4 colorama urllib3 pyyaml lxml
```

### Paso 3: Verificar Instalación

```powershell
python -c "import requests, bs4, colorama, yaml; print('All dependencies installed!')"
```

## 🚀 Uso Rápido

### Escaneo Básico

```powershell
cd web_security_scanner
python scanner_v4.py -u https://example.com
```

### Escaneos con Perfiles

```powershell
# Escaneo rápido (ideal para pruebas iniciales)
python scanner_v4.py -u https://example.com --profile quick

# Escaneo normal (balance entre velocidad y profundidad)
python scanner_v4.py -u https://example.com --profile normal

# Escaneo profundo (máxima cobertura)
python scanner_v4.py -u https://example.com --profile deep

# Escaneo sigiloso (evita detección)
python scanner_v4.py -u https://example.com --profile stealth
```

### Solo Detección de Tecnologías

```powershell
python scanner_v4.py -u https://example.com --tech-only
```

### Con Autenticación

```powershell
# Basic Auth
python scanner_v4.py -u https://example.com --auth-type basic --auth-user admin --auth-pass password

# Bearer Token
python scanner_v4.py -u https://example.com --auth-type bearer --auth-token "your_jwt_token_here"

# OAuth Token
python scanner_v4.py -u https://example.com --auth-type oauth --auth-token "your_access_token"
```

### Modo Verbose y Logging

```powershell
# Verbose output
python scanner_v4.py -u https://example.com -v

# Debug logging
python scanner_v4.py -u https://example.com -v --log-level DEBUG

# Warning only
python scanner_v4.py -u https://example.com --log-level WARNING
```

## 📋 Configuración Personalizada

### Crear Tu Propio Perfil

1. Copia `config.yaml` a `my_config.yaml`
2. Edita los valores según tus necesidades
3. Usa tu configuración:

```powershell
python scanner_v4.py -u https://example.com --config my_config.yaml
```

### Configuración de Example

```yaml
# my_config.yaml
scanner:
  threads: 15              # Aumentar threads
  timeout: 45              # Timeout más largo
  rate_limit: 5            # 5 requests por segundo

vulnerabilities:
  sql_injection:
    enabled: true
    max_payloads: 100      # Más payloads
  
  xss:
    enabled: true
    max_payloads: 80
  
  ssrf:
    enabled: false         # Deshabilitar SSRF testing
```

## 🎯 Casos de Uso

### Caso 1: Auditoría de Aplicación Web Interna

```powershell
# Escaneo profundo con autenticación
python scanner_v4.py -u https://internal-app.company.com \
    --profile deep \
    --auth-type bearer \
    --auth-token "eyJhbGciOiJIUzI1NiIs..." \
    -v
```

### Caso 2: Evaluación Rápida de Sitio Público

```powershell
# Quick scan sin autenticación
python scanner_v4.py -u https://example.com --profile quick
```

### Caso 3: Pentesting con Logging Detallado

```powershell
# Deep scan con debug logging
python scanner_v4.py -u https://target.com \
    --profile deep \
    -v \
    --log-level DEBUG \
    --config custom_config.yaml
```

### Caso 4: Verificación de WAF

```powershell
# Stealth mode para evitar WAF
python scanner_v4.py -u https://target-with-waf.com --profile stealth -v
```

## 📊 Interpretación de Resultados

### Severidades

- **CRITICAL**: Requiere atención inmediata (SQL Injection, RCE, SSRF)
- **HIGH**: Riesgo significativo (XSS, CSRF, Path Traversal)
- **MEDIUM**: Debe ser corregido (Open Redirect)
- **LOW**: Mejoras recomendadas

### Formato de Salida

Los resultados se guardan en `reports/scan_YYYYMMDD_HHMMSS.json`

```json
{
  "url": "https://example.com",
  "technologies": {
    "servers": ["Nginx"],
    "languages": ["PHP"],
    "cms": ["WordPress"]
  },
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "critical",
      "url": "https://example.com/login",
      "method": "POST",
      "payload": "' OR '1'='1",
      "cwe": "CWE-89",
      "owasp": "A03:2021"
    }
  ]
}
```

## 🔧 Troubleshooting

### Error: "ModuleNotFoundError"

```powershell
# Reinstalar dependencias
pip install -r requirements.txt --force-reinstall
```

### Error: "Connection timeout"

```powershell
# Aumentar timeout en config.yaml
scanner:
  timeout: 60  # 60 segundos
```

### Error: "Rate limit exceeded"

```powershell
# Reducir rate limit
scanner:
  rate_limit: 2  # 2 requests por segundo
```

### WAF Blocking Requests

```powershell
# Usar perfil stealth
python scanner_v4.py -u https://example.com --profile stealth
```

## 📈 Performance Tips

### Optimizar Velocidad

1. **Aumentar threads** (cuidado con rate limits):
   ```yaml
   scanner:
     threads: 20
   ```

2. **Reducir payloads**:
   ```yaml
   vulnerabilities:
     sql_injection:
       max_payloads: 20
   ```

3. **Usar cache**:
   ```yaml
   cache:
     enabled: true
     max_size: 2000
   ```

### Optimizar Cobertura

1. **Aumentar profundidad**:
   ```yaml
   scanner:
     max_depth: 5
   ```

2. **Más payloads**:
   ```yaml
   vulnerabilities:
     sql_injection:
       max_payloads: 200
   ```

3. **Profile deep**:
   ```powershell
   python scanner_v4.py -u https://example.com --profile deep
   ```

## 🛡️ Seguridad y Ética

### ⚠️ IMPORTANTE

1. **Solo usa en tus propios sistemas** o con autorización explícita por escrito
2. **Respeta los términos de servicio** de los sitios web
3. **No uses en producción** sin coordinación con el equipo
4. **Mantén logs seguros** - pueden contener información sensible
5. **Reporta vulnerabilidades responsablemente**

### Buenas Prácticas

- Obtén permiso por escrito antes de escanear
- Usa perfil `stealth` para minimizar impacto
- Realiza escaneos fuera de horas pico
- Coordina con el equipo de operaciones
- Documenta todos los hallazgos

## 📞 Soporte

### Logs y Debug

Los logs se guardan en:
- `logs/scanner.log` (configurable en config.yaml)

Para ver logs en tiempo real:
```powershell
# En otra terminal
Get-Content logs/scanner.log -Wait
```

### Reportar Bugs

Si encuentras problemas:
1. Revisa `logs/scanner.log`
2. Ejecuta con `-v --log-level DEBUG`
3. Captura el error completo
4. Reporta en GitHub con:
   - Comando ejecutado
   - Logs relevantes
   - Versión de Python
   - Sistema operativo

## 🔄 Actualizaciones

Para actualizar a futuras versiones:

```powershell
git pull origin main
pip install -r requirements.txt --upgrade
```

## 📚 Recursos Adicionales

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **CWE Database**: https://cwe.mitre.org/
- **Payload Examples**: Ver carpeta `PAYLOAD/`
- **Configuration Examples**: Ver `config.yaml`

---

**Web Security Scanner v4.0** - Herramienta profesional para profesionales de seguridad.
