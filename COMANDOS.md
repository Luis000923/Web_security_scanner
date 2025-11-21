# 📋 COMANDOS - Guía de Uso de Web Security Scanner (CLI)

Esta guía muestra todos los comandos disponibles para usar la herramienta **Web Security Scanner** desde la línea de comandos (CLI) sin necesidad de usar la interfaz gráfica (GUI).

---

## 🚀 SCRIPTS PRINCIPALES

La herramienta tiene dos scripts principales para ejecución CLI:

1. **`scanner_v4.py`** - Versión avanzada con más opciones de configuración y perfiles
2. **`web_security_scanner.py`** - Versión clásica con opciones tradicionales

---

## 📘 SCANNER_V4.PY - VERSIÓN AVANZADA

### ✅ Comando Básico (Obligatorio)

```powershell
py scanner_v4.py -u https://ejemplo.com
```

**Explicación de términos:**
- `-u` o `--url`: URL del sitio web objetivo que se va a escanear (OBLIGATORIO)

---

### 🔧 Opciones de Configuración

#### Archivo de configuración personalizado
```powershell
py scanner_v4.py -u https://ejemplo.com --config mi_config.yaml
```

**Explicación:**
- `--config`: Ruta al archivo YAML de configuración personalizado (default: config.yaml)

#### Perfiles de escaneo
```powershell
py scanner_v4.py -u https://ejemplo.com --profile quick
py scanner_v4.py -u https://ejemplo.com --tech-only -es
py scanner_v4.py -u https://ejemplo.com --profile deep
py scanner_v4.py -u https://ejemplo.com --profile stealth
```

**Explicación:**
- `--profile quick`: Escaneo rápido con menos pruebas (ideal para análisis inicial)
- `--profile normal`: Escaneo estándar balanceado (recomendado)
- `--profile deep`: Escaneo profundo con todas las pruebas (tarda más tiempo)
- `--profile stealth`: Escaneo sigiloso con delays para evitar detección WAF/IDS

---

### 🔍 Opciones de Escaneo

#### Modo verbose (información detallada)
```powershell
py scanner_v4.py -u https://ejemplo.com -v
py scanner_v4.py -u https://ejemplo.com --verbose
```

**Explicación:**
- `-v` o `--verbose`: Muestra información detallada durante todo el proceso de escaneo

#### Solo detectar tecnologías (sin pruebas de vulnerabilidades)
```powershell
py scanner_v4.py -u https://ejemplo.com --tech-only
```

**Explicación:**
- `--tech-only`: Ejecuta únicamente la detección de tecnologías (CMS, frameworks, servidores) sin probar vulnerabilidades

#### Generación de mapa web HTML
```powershell
py scanner_v4.py -u https://ejemplo.com --generate-map
py scanner_v4.py -u https://ejemplo.com --no-map
```

**Explicación:**
- `--generate-map`: Genera un mapa interactivo HTML de la estructura del sitio (activado por defecto)
- `--no-map`: Desactiva la generación del mapa web HTML

---

### 🔐 Autenticación

#### Autenticación básica (Basic Auth)
```powershell
py scanner_v4.py -u https://ejemplo.com --auth-type basic --auth-user admin --auth-pass password123
```

**Explicación:**
- `--auth-type basic`: Tipo de autenticación HTTP básica con usuario/contraseña
- `--auth-user`: Nombre de usuario para autenticación
- `--auth-pass`: Contraseña para autenticación

#### Autenticación Bearer Token
```powershell
py scanner_v4.py -u https://ejemplo.com --auth-type bearer --auth-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Explicación:**
- `--auth-type bearer`: Autenticación mediante token Bearer (común en APIs REST)
- `--auth-token`: Token de autenticación

#### Autenticación OAuth
```powershell
py scanner_v4.py -u https://ejemplo.com --auth-type oauth --auth-token oauth_token_aqui
```

**Explicación:**
- `--auth-type oauth`: Autenticación mediante protocolo OAuth
- `--auth-token`: Token OAuth proporcionado por el proveedor

#### Autenticación por sesión
```powershell
py scanner_v4.py -u https://ejemplo.com --auth-type session
```

**Explicación:**
- `--auth-type session`: Utiliza cookies de sesión para mantener autenticación persistente

---

### 📄 Opciones de Salida

#### Especificar archivo de salida
```powershell
py scanner_v4.py -u https://ejemplo.com -o resultados.json
py scanner_v4.py -u https://ejemplo.com --output informe_seguridad.json
```

**Explicación:**
- `-o` o `--output`: Nombre/ruta del archivo donde guardar los resultados del escaneo

#### Nivel de logging
```powershell
py scanner_v4.py -u https://ejemplo.com --log-level DEBUG
py scanner_v4.py -u https://ejemplo.com --log-level INFO
py scanner_v4.py -u https://ejemplo.com --log-level WARNING
py scanner_v4.py -u https://ejemplo.com --log-level ERROR
```

**Explicación:**
- `--log-level DEBUG`: Muestra todos los detalles técnicos (útil para depuración)
- `--log-level INFO`: Muestra información general del proceso (recomendado)
- `--log-level WARNING`: Solo muestra advertencias y errores
- `--log-level ERROR`: Solo muestra errores críticos

---

### 🎯 COMBINACIONES PRÁCTICAS - SCANNER_V4.PY

#### Escaneo rápido con autenticación
```powershell
py scanner_v4.py -u https://ejemplo.com --profile quick --auth-type basic --auth-user admin --auth-pass pass123 -v
```

#### Escaneo profundo con salida detallada
```powershell
py scanner_v4.py -u https://ejemplo.com --profile deep -v --log-level DEBUG -o escaneo_completo.json
```

#### Detección de tecnologías con token Bearer
```powershell
py scanner_v4.py -u https://api.ejemplo.com --tech-only --auth-type bearer --auth-token xyz123 -v
```

#### Escaneo sigiloso sin mapa web
```powershell
py scanner_v4.py -u https://ejemplo.com --profile stealth --no-map -o resultados_stealth.json
```

#### Escaneo normal con configuración personalizada
```powershell
py scanner_v4.py -u https://ejemplo.com --config config_personalizado.yaml --profile normal -v
```

---

## 📗 WEB_SECURITY_SCANNER.PY - VERSIÓN CLÁSICA

### ✅ Comando Básico (Obligatorio)

```powershell
py web_security_scanner.py -u https://ejemplo.com
```

**Explicación de términos:**
- `-u` o `--url`: URL del sitio web objetivo a escanear (OBLIGATORIO)

---

### ⚙️ Opciones de Rendimiento

#### Número de hilos (threads)
```powershell
py web_security_scanner.py -u https://ejemplo.com -t 10
py web_security_scanner.py -u https://ejemplo.com --threads 20
```

**Explicación:**
- `-t` o `--threads`: Número de hilos concurrentes para realizar pruebas (default: 5)
- Más hilos = escaneo más rápido, pero mayor carga en el servidor
- Recomendado: 5-10 hilos para servidores normales, 15-30 para servidores robustos

#### Timeout de solicitudes
```powershell
py web_security_scanner.py -u https://ejemplo.com --timeout 15
```

**Explicación:**
- `--timeout`: Tiempo máximo de espera (en segundos) para cada solicitud HTTP (default: 10)
- Aumentar si el servidor es lento o tiene mala conexión

---

### 🎚️ Modos de Velocidad de Escaneo

#### Escaneo lento (bajo)
```powershell
py web_security_scanner.py -u https://ejemplo.com -Sb
py web_security_scanner.py -u https://ejemplo.com --slow
```

**Explicación:**
- `-Sb` o `--slow`: Modo de escaneo lento
- Configuración: 5 hilos, timeout 2 segundos
- Ideal para evitar detección por sistemas WAF/IDS
- Usa todos los payloads disponibles

#### Escaneo medio
```powershell
py web_security_scanner.py -u https://ejemplo.com -Sm
py web_security_scanner.py -u https://ejemplo.com --medium
```

**Explicación:**
- `-Sm` o `--medium`: Modo de escaneo medio (balanceado)
- Configuración: 15 hilos, timeout 10 segundos
- Equilibrio entre velocidad y sigilo
- Usa hasta 30 payloads por tipo

#### Escaneo rápido (alto)
```powershell
py web_security_scanner.py -u https://ejemplo.com -Sa
py web_security_scanner.py -u https://ejemplo.com --fast
```

**Explicación:**
- `-Sa` o `--fast`: Modo de escaneo rápido
- Configuración: 30 hilos, timeout 10 segundos
- Velocidad máxima pero más detectable
- Usa hasta 20 payloads por tipo

#### Escaneo rápido express
```powershell
py web_security_scanner.py -u https://ejemplo.com --quick
```

**Explicación:**
- `--quick`: Escaneo ultrarrápido con mínimos payloads
- Solo usa los 10 payloads más efectivos por tipo
- Ideal para análisis inicial o pruebas rápidas

---

### 🔍 Opciones de Escaneo

#### Modo verbose (información detallada)
```powershell
py web_security_scanner.py -u https://ejemplo.com -v
py web_security_scanner.py -u https://ejemplo.com --verbose
```

**Explicación:**
- `-v` o `--verbose`: Muestra información detallada durante todo el escaneo
- Incluye: URLs testeadas, payloads ejecutados, respuestas del servidor

#### Solo detectar tecnologías
```powershell
py web_security_scanner.py -u https://ejemplo.com --tech-only
```

**Explicación:**
- `--tech-only`: Ejecuta únicamente detección de tecnologías
- Detecta: servidores web, lenguajes, CMS, frameworks JS, bases de datos, herramientas analytics
- No realiza pruebas de vulnerabilidades

---

### 📄 Opciones de Exportación

#### Exportar a JSON
```powershell
py web_security_scanner.py -u https://ejemplo.com -j
py web_security_scanner.py -u https://ejemplo.com --json
py web_security_scanner.py -u https://ejemplo.com -j -o resultados_custom.json
```

**Explicación:**
- `-j` o `--json`: Exporta resultados en formato JSON
- `-o` o `--output`: Especifica nombre del archivo JSON (default: scan_results.json)
- Formato ideal para integración con otras herramientas

#### Exportar a HTML
```powershell
py web_security_scanner.py -u https://ejemplo.com -H
py web_security_scanner.py -u https://ejemplo.com --html
```

**Explicación:**
- `-H` o `--html`: Genera reporte visual en formato HTML
- Incluye: resumen ejecutivo, vulnerabilidades encontradas, mapa del sitio
- Archivo guardado en: `web_security_scanner/reports/reporte_*.html`

#### Exportar ambos formatos
```powershell
py web_security_scanner.py -u https://ejemplo.com -j -H -o escaneo_completo.json
```

**Explicación:**
- Combina `-j` y `-H` para exportar en ambos formatos simultáneamente

---

### 🎯 COMBINACIONES PRÁCTICAS - WEB_SECURITY_SCANNER.PY

#### Escaneo rápido básico con reporte HTML
```powershell
py web_security_scanner.py -u https://ejemplo.com --quick -H
```

#### Escaneo lento sigiloso con verbose
```powershell
py web_security_scanner.py -u https://ejemplo.com -Sb -v
```

#### Escaneo medio con exportación dual
```powershell
py web_security_scanner.py -u https://ejemplo.com -Sm -j -H -o resultados.json
```

#### Escaneo rápido con muchos hilos
```powershell
py web_security_scanner.py -u https://ejemplo.com -Sa -t 25 -v -H
```

#### Solo detección de tecnologías con JSON
```powershell
py web_security_scanner.py -u https://ejemplo.com --tech-only -j -o tecnologias.json
```

#### Escaneo completo con timeout extendido
```powershell
py web_security_scanner.py -u https://ejemplo.com -t 15 --timeout 20 -v -j -H
```

#### Escaneo ultra-sigiloso (evadir WAF/IDS)
```powershell
py web_security_scanner.py -u https://ejemplo.com -Sb -t 3 --timeout 5 -v
```

#### Escaneo personalizado con parámetros específicos
```powershell
py web_security_scanner.py -u https://ejemplo.com -t 8 --timeout 12 -v -j -o scan_custom.json
```

---

## 📊 COMPARATIVA DE SCRIPTS

| Característica | scanner_v4.py | web_security_scanner.py |
|---------------|---------------|------------------------|
| **Perfiles predefinidos** | ✅ (quick/normal/deep/stealth) | ❌ |
| **Autenticación** | ✅ (basic/bearer/oauth/session) | ❌ |
| **Configuración YAML** | ✅ | ❌ |
| **Niveles de logging** | ✅ (DEBUG/INFO/WARNING/ERROR) | ❌ |
| **Mapa web HTML** | ✅ (--generate-map/--no-map) | ❌ |
| **Modos de velocidad** | ⚠️ (via perfiles) | ✅ (--slow/--medium/--fast/--quick) |
| **Control de hilos** | ⚠️ (via config) | ✅ (-t/--threads) |
| **Exportación JSON** | ✅ (-o) | ✅ (-j -o) |
| **Exportación HTML** | ⚠️ (via config) | ✅ (-H) |
| **Solo tecnologías** | ✅ (--tech-only) | ✅ (--tech-only) |
| **Modo verbose** | ✅ (-v) | ✅ (-v) |

---

## 🛡️ RECOMENDACIONES DE USO

### Para análisis inicial rápido:
```powershell
py scanner_v4.py -u https://ejemplo.com --profile quick --tech-only -v
```

### Para escaneo completo de producción:
```powershell
py scanner_v4.py -u https://ejemplo.com --profile deep -v --log-level INFO -o resultados_completos.json
```

### Para evitar detección WAF/IDS:
```powershell
py web_security_scanner.py -u https://ejemplo.com -Sb -t 3 --timeout 5 -v
```
```powershell
py scanner_v4.py -u https://ejemplo.com --profile stealth -v
```

### Para auditoría completa con autenticación:
```powershell
py scanner_v4.py -u https://ejemplo.com --auth-type basic --auth-user admin --auth-pass pass123 --profile normal -v -o auditoria.json
```

### Para escaneo rápido con máximo rendimiento:
```powershell
py web_security_scanner.py -u https://ejemplo.com -Sa -t 30 --quick -H
```

---

## ⚠️ NOTAS IMPORTANTES

1. **Autorización Legal**: Solo escanea sitios web donde tengas autorización explícita por escrito.

2. **Impacto en el Servidor**: 
   - Escaneos con muchos hilos pueden causar carga excesiva
   - Usar modos lentos (`-Sb`, `--profile stealth`) en servidores de producción

3. **Detección WAF/IDS**:
   - Firewalls modernos pueden bloquear escaneos agresivos
   - Usar `--profile stealth` o `-Sb` para minimizar detección

4. **Timeout**:
   - Aumentar `--timeout` si el servidor tiene latencia alta
   - Servidores lentos pueden necesitar 15-30 segundos

5. **Exportación**:
   - Los reportes HTML se guardan automáticamente en `web_security_scanner/reports/`
   - Los archivos JSON se guardan donde especifiques con `-o`

6. **Verbose Mode**:
   - Usar `-v` para ver el progreso en tiempo real
   - Útil para depuración y entender qué está testeando la herramienta

---

## 📚 RECURSOS ADICIONALES

- **Documentación Completa**: Ver `Documentacion/` para guías detalladas
- **Configuración YAML**: Ver `config.yaml` para opciones avanzadas
- **Payloads**: Ver `PAYLOAD/` para personalizar ataques
- **Código Fuente**: Ver `web_security_scanner/` para entender la arquitectura

---

## 🐛 SOLUCIÓN DE PROBLEMAS

### Error: "ModuleNotFoundError"
```powershell
py -m pip install -r Documentacion/requirements.txt
```

### Error: "Connection timeout"
Aumentar timeout:
```powershell
py web_security_scanner.py -u https://ejemplo.com --timeout 30
```

### Error: "Too many requests" (429)
Reducir hilos y usar modo lento:
```powershell
py web_security_scanner.py -u https://ejemplo.com -Sb -t 2
```

### No genera reporte HTML
Verificar que BeautifulSoup4 esté instalado:
```powershell
py -m pip install beautifulsoup4
```

---

**Desarrollado para uso educativo - Web Security Scanner v4.0**
