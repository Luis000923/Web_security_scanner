# 📋 Guía de Solución - Error de Dependencias

## ✅ Problema Resuelto

### Error Original
```
ModuleNotFoundError: No module named 'openpyxl'
```

### Solución Implementada

Se agregaron todas las dependencias faltantes a `requirements.txt`:
- ✅ `openpyxl>=3.1.0` - Para reportes Excel
- ✅ `python-docx>=1.1.0` - Para reportes Word  
- ✅ `fpdf2>=2.7.0` - Para reportes PDF
- ✅ `flask>=3.0.0` - Para servidor web
- ✅ `pillow>=10.0.0` - Para procesamiento de imágenes

---

## 🚀 Sistema Nuevo - Launcher Inteligente

### ¿Qué hace el Launcher?

El archivo `launcher.py` es ahora el **punto de entrada principal** que:

1. ✅ **Verifica Python 3.7+**
2. ✅ **Detecta dependencias faltantes automáticamente**
3. ✅ **Instala lo que falta (con tu permiso)**
4. ✅ **Crea config.yaml si no existe**
5. ✅ **Decide entre GUI o CLI según argumentos**

### Ventajas

| Antes | Ahora |
|-------|-------|
| `pip install -r requirements.txt` | `python launcher.py` (lo hace todo) |
| `python web_security_scanner.py -u URL` | `python launcher.py URL` (más simple) |
| Editar config.yaml manualmente | GUI visual o install.py interactivo |
| Errores de módulos faltantes | Instalación automática |

---

## 🎯 Cómo Usar Ahora

### Opción 1: Interfaz Gráfica (GUI) - NUEVO ✨

```bash
# Solo ejecuta:
python launcher.py
```

**Se abrirá una ventana gráfica moderna con**:
- 🖥️ Interfaz oscura profesional
- 🎯 Configuración visual (sin editar archivos)
- 📊 Reportes integrados
- 📜 Historial de escaneos
- ⚡ Botones de acción rápida

**Ideal para**: Principiantes, demos, exploración visual

### Opción 2: Línea de Comandos (CLI)

```bash
# Escaneo básico
python launcher.py https://example.com

# Escaneo con perfil
python launcher.py https://example.com --profile deep

# Ver ayuda
python launcher.py --help
```

**Ideal para**: Usuarios avanzados, scripts, CI/CD, SSH

---

## 📦 Instalación Completa

### Paso 1: Clonar Repositorio
```bash
git clone https://github.com/Luis000923/Web_security_scanner.git
cd Web_security_scanner
```

### Paso 2: Ejecutar Launcher
```bash
# Windows
py -3 launcher.py

# Linux/Mac
python3 launcher.py
```

### Paso 3: Instalar Dependencias (Automático)
El launcher detectará si faltan módulos y preguntará:
```
⚠️  Missing dependencies: openpyxl, python-docx, fpdf2, flask, pillow

Would you like to install them now? (Y/n):
```

Presiona **Y** (Enter) y todo se instala automáticamente.

### Paso 4: ¡Listo!
- Si ejecutaste sin argumentos → Se abre la GUI
- Si ejecutaste con URL → Se ejecuta escaneo CLI

---

## 🔧 Comandos Útiles

### Para Windows (PowerShell)
```powershell
# GUI
py -3 launcher.py

# CLI  
py -3 launcher.py https://example.com --profile deep

# Ayuda
py -3 launcher.py --help
```

### Para Linux/Mac
```bash
# GUI
python3 launcher.py

# CLI
python3 launcher.py https://example.com --profile deep

# Ayuda
python3 launcher.py --help
```

---

## 🖥️ Características de la Nueva GUI

### Pestaña 1: Scan (Escaneo)
- Campo URL
- Selector de perfil (Quick/Normal/Deep/Stealth)
- Checkboxes de vulnerabilidades
- Opciones (mapa web, tecnologías, verbose)
- Botón START SCAN
- Output en tiempo real con colores

### Pestaña 2: Config (Configuración)
- Language (English/Español)
- Threads (1-50)
- Timeout (10-120s)
- Max Depth (1-10)
- Rate Limit (0-50 req/s)
- Botón SAVE

### Pestaña 3: Reports (Reportes)
- Selección de formatos (HTML, PDF, Excel, Word, JSON)
- Lista de reportes recientes
- Botones: Refresh, Open, Open Folder

### Pestaña 4: History (Historial)
- Tabla de escaneos anteriores
- Columnas: Date, Target, Profile, Vulnerabilities, Status
- Botones: Refresh, View Details, Clear History

### Menús
- **File**: New Scan, Open Report, Exit
- **Tools**: Settings, Check Updates
- **Help**: Documentation, About

---

## 📁 Estructura de Archivos

```
Web_security_scanner/
├── launcher.py                    # ⭐ NUEVO: Punto de entrada inteligente
├── gui.py                         # ⭐ NUEVO: Interfaz gráfica completa
├── install.py                     # Instalador interactivo (opcional)
├── requirements.txt               # ✅ ACTUALIZADO: Con todas las dependencias
├── config.yaml                    # Configuración (creado automáticamente)
├── README.md                      # ✅ ACTUALIZADO: Documentación principal
├── GUI.md                         # ⭐ NUEVO: Guía completa de la GUI
├── INICIO_RAPIDO.md              # ⭐ NUEVO: Guía rápida
├── SOLUCION_DEPENDENCIAS.md      # Este archivo
├── web_security_scanner/
│   ├── web_security_scanner.py    # Motor de escaneo (CLI)
│   ├── scanner_v4.py              # Scanner moderno
│   ├── i18n.py                    # Sistema multiidioma
│   ├── modules/
│   │   ├── web_mapper.py          # ⭐ NUEVO: Mapeo web + HTML generator
│   │   └── ...
│   ├── PAYLOAD/                   # Payloads de prueba
│   ├── MAPA_WEB.md               # ⭐ NUEVO: Doc de mapeo web
│   └── ...
└── reports/                       # Reportes generados
    ├── scan_*.html
    ├── scan_*.pdf
    ├── scan_*.xlsx
    └── web_map_*.html            # ⭐ NUEVO: Mapas interactivos
```

---

## 🎓 Comparación: Antes vs Ahora

### Instalación

**Antes**:
```bash
pip install requests beautifulsoup4 colorama urllib3 pyyaml lxml
pip install openpyxl  # Oh no, faltaba esto
pip install python-docx  # Y esto
pip install fpdf2  # Y esto también
# Error tras error...
```

**Ahora**:
```bash
python launcher.py
# ¿Falta algo? Y (instalará todo automáticamente)
```

### Uso

**Antes**:
```bash
python web_security_scanner/web_security_scanner.py -u https://example.com -t 10 --timeout 30 -v -j -H
```

**Ahora (CLI)**:
```bash
python launcher.py https://example.com --profile normal
```

**Ahora (GUI)**:
```bash
python launcher.py
# Clicks en interfaz gráfica, sin memorizar comandos
```

### Configuración

**Antes**:
```bash
nano config.yaml  # Editar manualmente
# ¿Qué valor poner en threads?
# ¿Y en timeout?
```

**Ahora**:
```bash
python launcher.py
# GUI → Pestaña Config → Sliders visuales
# O ejecutar: python install.py (interactivo)
```

---

## 🐛 Troubleshooting

### Error: "tkinter not found"
**Causa**: GUI requiere tkinter (viene con Python en Windows)

**Solución Ubuntu/Debian**:
```bash
sudo apt-get install python3-tk
```

**Solución Windows**:
Reinstalar Python desde [python.org](https://www.python.org/downloads/) marcando "tcl/tk and IDLE"

**Alternativa**: Usar CLI
```bash
python launcher.py https://example.com
```

### Error: "pip not found"
**Solución**:
```bash
# Windows
py -3 -m pip install -r requirements.txt

# Linux/Mac
python3 -m pip install -r requirements.txt
```

### GUI se congela durante escaneo
**Causa**: Bug en threading (no debería pasar)

**Solución temporal**: Usar CLI
```bash
python launcher.py https://example.com
```

### Escaneo muy lento
**Solución GUI**: Config → Threads → Aumentar a 20

**Solución CLI**:
```bash
python launcher.py https://example.com -t 20 --profile quick
```

---

## 📊 Estadísticas del Proyecto

### Antes (v3.0)
- ❌ Sin GUI
- ❌ Dependencias manuales
- ❌ Sin mapeo web
- ❌ Configuración manual
- ✅ Solo CLI

### Ahora (v4.0)
- ✅ GUI completa y moderna
- ✅ Instalación automática
- ✅ Mapeo web con D3.js
- ✅ Configuración visual
- ✅ CLI + GUI (híbrido)
- ✅ Sistema multiidioma (EN/ES)
- ✅ Launcher inteligente
- ✅ 5 formatos de reporte
- ✅ Historial de escaneos
- ✅ Documentación exhaustiva

---

## 💡 Consejos Pro

### Para Principiantes
1. Usa la GUI: `python launcher.py`
2. Empieza con perfil "Quick"
3. Lee el output en tiempo real
4. Revisa reportes en pestaña "Reports"

### Para Usuarios Avanzados
1. Usa CLI: `python launcher.py https://target.com`
2. Perfiles Deep o Stealth según necesidad
3. Automatiza con scripts bash/PowerShell
4. Integra con CI/CD pipelines

### Para Pentesters
1. CLI para velocidad
2. `--no-map` si no necesitas reconocimiento
3. `--tech-only` para fingerprinting rápido
4. Ajusta threads según objetivo

---

## 📚 Documentación Relacionada

- [`README.md`](../README.md) - Documentación principal completa
- [`GUI.md`](../GUI.md) - Guía detallada de la interfaz gráfica
- [`INICIO_RAPIDO.md`](../INICIO_RAPIDO.md) - Inicio en 30 segundos
- [`MAPA_WEB.md`](web_security_scanner/MAPA_WEB.md) - Sistema de mapeo web
- [`INSTALACION.md`](../INSTALACION.md) - Guía de instalación detallada

---

## ✅ Checklist de Verificación

Después de instalar, verifica:

- [ ] `python launcher.py` abre la GUI sin errores
- [ ] GUI tiene 4 pestañas visibles
- [ ] Config → Language funciona
- [ ] `python launcher.py --help` muestra ayuda completa
- [ ] `python launcher.py https://example.com` ejecuta escaneo (prueba con sitio autorizado)
- [ ] Reportes se generan en carpeta `reports/`
- [ ] Historial se guarda correctamente

---

## 🎉 ¡Listo para Usar!

Ahora tu Web Security Scanner v4.0 está completamente funcional con:

✅ Todas las dependencias instaladas  
✅ GUI moderna y profesional  
✅ CLI potente para automatización  
✅ Launcher inteligente  
✅ Sistema multiidioma  
✅ Mapeo web interactivo  
✅ 5 formatos de reporte  

**Comando para empezar**:
```bash
python launcher.py
```

**¡Happy Hacking! (Ético, por supuesto)** 🔒

---

**Versión**: 4.0  
**Fecha**: Noviembre 2024  
**Autor**: Luis - Web Security Scanner Team
