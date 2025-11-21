# 🖥️ Interfaz Gráfica de Usuario (GUI)
# ESTA EN BETA AHI FUNCIONES NO PROBADAS

## Descripción General

El Web Security Scanner v4.0 incluye una interfaz gráfica moderna y profesional desarrollada con tkinter, que proporciona acceso completo a todas las funcionalidades del escáner de manera intuitiva y visual.

## Características Principales

### ✨ Diseño Moderno
- **Tema oscuro profesional** con paleta de colores moderna
- **Interfaz responsive** que se adapta a diferentes tamaños de pantalla
- **Tipografía clara** con fuentes Segoe UI
- **Iconos visuales** para mejor identificación de funciones
- **Feedback visual** en tiempo real durante escaneos

### 🎯 Funcionalidades Completas

#### 1. Pestaña de Escaneo
```
Panel Izquierdo (Configuración):
├─ Target URL (entrada de URL objetivo)
├─ Scan Profile (Quick/Normal/Deep/Stealth)
├─ Vulnerability Tests (checkboxes individuales)
│  ├─ SQL Injection
│  ├─ XSS (Cross-Site Scripting)
│  ├─ NoSQL Injection
│  ├─ Open Redirect
│  ├─ SSRF
│  └─ CSRF
├─ Options
│  ├─ Generate Web Map
│  ├─ Detect Technologies
│  └─ Verbose Output
└─ START SCAN (botón principal)

Panel Derecho (Output):
├─ Scan Output (área de texto con scroll)
└─ Progress Bar (barra de progreso animada)
```

**Flujo de Escaneo**:
1. Usuario ingresa URL objetivo
2. Selecciona perfil de escaneo
3. Marca/desmarca tests de vulnerabilidad
4. Configura opciones adicionales
5. Presiona "START SCAN"
6. Output muestra progreso en tiempo real
7. Al finalizar, muestra resumen de resultados

#### 2. Pestaña de Configuración
```
Scanner Configuration (con scroll):
├─ Language / Idioma
│  └─ Dropdown: English / Español
├─ Threads
│  └─ Slider: 1-50
├─ Timeout (seconds)
│  └─ Slider: 10-120
├─ Max Depth
│  └─ Slider: 1-10
├─ Rate Limit (req/s)
│  └─ Slider: 0-50
└─ Save Configuration Button
```

**Configuraciones disponibles**:
- **Language**: Cambia idioma de toda la aplicación
- **Threads**: Concurrencia de peticiones HTTP
- **Timeout**: Tiempo máximo por petición
- **Max Depth**: Profundidad de rastreo web
- **Rate Limit**: Límite de peticiones por segundo

#### 3. Pestaña de Reportes
```
Report Generation:
├─ Format Selection (checkboxes)
│  ├─ HTML - Interactive web report
│  ├─ PDF - Printable document
│  ├─ Excel - Spreadsheet with data
│  ├─ Word - Detailed document
│  └─ JSON - Raw data export
│
├─ Recent Reports (tabla con columnas)
│  ├─ Date
│  ├─ Target
│  ├─ Format
│  └─ Size
│
└─ Actions
   ├─ Refresh
   ├─ Open (abre reporte seleccionado)
   └─ Open Folder (abre carpeta reports/)
```

**Formatos de Reporte**:
- **HTML**: Reporte interactivo con gráficos y navegación
- **PDF**: Documento imprimible profesional
- **Excel**: Datos en hojas de cálculo para análisis
- **Word**: Documento detallado para edición
- **JSON**: Datos crudos para integración con otras herramientas

#### 4. Pestaña de Historial
```
Scan History:
├─ History Table
│  ├─ Date (fecha y hora del escaneo)
│  ├─ Target (URL escaneada)
│  ├─ Profile (perfil usado)
│  ├─ Vulnerabilities (cantidad encontrada)
│  └─ Status (Completed/Failed/Stopped)
│
└─ Actions
   ├─ Refresh
   ├─ View Details
   └─ Clear History
```

**Base de Datos SQLite**:
- Almacena historial completo de escaneos
- Guarda resultados de vulnerabilidades
- Permite consultas y análisis histórico

### 🎨 Paleta de Colores

```python
# Colores de fondo
BG_DARK = "#1e1e2e"      # Fondo principal oscuro
BG_MEDIUM = "#2a2a3e"    # Fondo de tarjetas
BG_LIGHT = "#363649"     # Fondo resaltado

# Colores de texto
FG_PRIMARY = "#ffffff"    # Texto principal
FG_SECONDARY = "#b0b0c0"  # Texto secundario
FG_ACCENT = "#00d4ff"     # Color de acento (azul cyan)

# Colores de estado
SUCCESS = "#00ff88"       # Verde - Éxito
WARNING = "#ffaa00"       # Naranja - Advertencia
ERROR = "#ff4444"         # Rojo - Error
INFO = "#4499ff"          # Azul - Información
```

### 🔧 Componentes Técnicos

#### Barra de Menú
```
File
├─ New Scan (Ctrl+N)
├─ Open Report
├─ ─────────────
└─ Exit

Tools
├─ Settings
└─ Check Updates

Help
├─ Documentation
└─ About
```

#### Barra de Estado
```
[Ready] ─────────────────────────────────── [2024-11-21 15:30:45]
```
- **Lado izquierdo**: Estado actual de la aplicación
- **Lado derecho**: Fecha y hora en tiempo real

#### Header con Acciones Rápidas
```
🔒 Web Security Scanner          [⚡ Quick Scan] [⏹ Stop]
Professional Vulnerability Assessment Tool
```

## Arquitectura del Sistema GUI

### Archivo: `gui.py`

#### Clase Principal: `ScannerGUI`

**Propósito**: Gestiona toda la interfaz gráfica y su lógica

**Atributos principales**:
```python
self.root              # Ventana principal tkinter
self.scanning          # Estado de escaneo (bool)
self.current_scan      # Referencia al escaneo actual
self.scan_history      # Lista de escaneos históricos
self.config            # Configuración cargada de config.yaml
self.i18n              # Sistema de internacionalización
```

**Métodos de inicialización**:
```python
__init__(root)                # Constructor principal
_load_config()                # Carga config.yaml
_save_config()                # Guarda config.yaml
_setup_styles()               # Configura estilos ttk
_create_menu()                # Crea barra de menú
_create_layout()              # Crea layout principal
_center_window()              # Centra ventana en pantalla
```

**Métodos de creación de UI**:
```python
_create_header()              # Encabezado con título y acciones
_create_scan_tab()            # Pestaña de escaneo
_create_config_tab()          # Pestaña de configuración
_create_reports_tab()         # Pestaña de reportes
_create_history_tab()         # Pestaña de historial
_create_statusbar()           # Barra de estado inferior
```

**Métodos de escaneo**:
```python
_start_scan()                 # Inicia escaneo completo
_run_scan(url)                # Ejecuta escaneo en thread
_scan_completed()             # Callback de éxito
_scan_error(error)            # Callback de error
_stop_scan()                  # Detiene escaneo
_quick_scan()                 # Escaneo rápido
```

**Métodos de configuración**:
```python
_get_config_value(key, default)  # Obtiene valor de config
_save_configuration()            # Guarda configuración
```

**Métodos de reportes**:
```python
_load_reports_list()          # Carga lista de reportes
_refresh_reports()            # Refresca lista
_open_selected_report()       # Abre reporte seleccionado
_open_reports_folder()        # Abre carpeta de reportes
```

**Métodos de historial**:
```python
_load_history()               # Carga historial desde DB
_refresh_history()            # Refresca tabla
_view_scan_details()          # Muestra detalles de escaneo
_clear_history()              # Limpia historial
```

**Métodos de menú**:
```python
_new_scan()                   # Nueva ventana de escaneo
_open_report()                # Diálogo de apertura
_show_settings()              # Muestra configuración
_check_updates()              # Verifica actualizaciones
_show_docs()                  # Abre documentación
_show_about()                 # Muestra información
```

**Métodos de utilidad**:
```python
_update_status(msg, color)    # Actualiza barra de estado
_log_output(msg, color)       # Agrega mensaje al output
_update_time()                # Actualiza reloj (cada 1s)
```

### Threading para Escaneos

**Problema**: Tkinter es single-threaded, si ejecutamos el escaneo en el hilo principal, la UI se congela.

**Solución**: Ejecutar escaneo en thread separado
```python
def _start_scan(self):
    # UI thread (principal)
    self.scanning = True
    self.progress_bar.start(10)
    
    # Crear thread para escaneo
    thread = threading.Thread(
        target=self._run_scan,
        args=(url,),
        daemon=True
    )
    thread.start()

def _run_scan(self, url):
    # Worker thread (separado)
    try:
        # Ejecutar escaneo largo...
        scanner.run_scan()
        
        # Actualizar UI desde thread principal
        self.root.after(0, self._scan_completed)
    except Exception as e:
        self.root.after(0, lambda: self._scan_error(str(e)))
```

**Importante**: Usar `self.root.after(0, callback)` para actualizar UI desde threads

### Integración con Scanner Core

```python
# En _run_scan() - Integración real con scanner_v4.py
from web_security_scanner.scanner_v4 import WebSecurityScannerV4

def _run_scan(self, url):
    try:
        # Crear instancia del scanner
        scanner = WebSecurityScannerV4(
            url=url,
            config=self.config,
            verbose=self.verbose_var.get(),
            generate_map=self.map_var.get()
        )
        
        # Configurar callback para output en tiempo real
        scanner.set_output_callback(self._log_output)
        
        # Ejecutar escaneo
        scanner.run_scan()
        
        # Obtener resultados
        results = scanner.get_results()
        
        # Actualizar UI
        self.root.after(0, lambda: self._scan_completed(results))
        
    except Exception as e:
        self.root.after(0, lambda: self._scan_error(str(e)))
```

## Uso de la GUI

### Iniciar GUI

```bash
# Método 1: Usar launcher (recomendado)
python launcher.py

# Método 2: Ejecutar directamente
python gui.py
```

### Flujo de Trabajo Típico

#### 1. Primer Uso
```
1. Ejecutar: python launcher.py
2. Verificación automática de dependencias
3. Si faltan, se instalan automáticamente
4. Se abre la GUI
5. Ir a pestaña "Configuration"
6. Configurar preferencias (idioma, threads, etc.)
7. Guardar configuración
```

#### 2. Escaneo Básico
```
1. Pestaña "Scan"
2. Ingresar URL en "Target URL"
3. Seleccionar "Normal" profile
4. Dejar todos los tests marcados
5. Click "START SCAN"
6. Observar output en tiempo real
7. Esperar a que termine
8. Ir a pestaña "Reports" para ver resultados
```

#### 3. Escaneo Rápido
```
1. Click botón "⚡ Quick Scan" en header
2. Ingresa URL si no está configurada
3. Automáticamente usa profile "quick"
4. Escaneo completo en minutos
```

#### 4. Escaneo Profundo
```
1. Pestaña "Scan"
2. Seleccionar "Deep" profile
3. Marcar todos los vulnerability tests
4. Habilitar "Generate Web Map"
5. Habilitar "Detect Technologies"
6. Click "START SCAN"
7. Puede tomar 30+ minutos dependiendo del sitio
```

#### 5. Ver Reportes
```
1. Pestaña "Reports"
2. Lista muestra reportes recientes
3. Seleccionar un reporte
4. Click "Open" para visualizar
5. O click "Open Folder" para explorar todos
```

#### 6. Revisar Historial
```
1. Pestaña "History"
2. Ver tabla con todos los escaneos
3. Click en un escaneo
4. Click "View Details" para ver completo
5. Comparar vulnerabilidades entre escaneos
```

## Accesibilidad

### Atajos de Teclado
```
Ctrl+N         Nueva pestaña de escaneo
Ctrl+O         Abrir reporte
Ctrl+S         Guardar configuración
Ctrl+Q         Salir
F5             Refresh (según contexto)
Esc            Detener escaneo actual
```

### Navegación con Teclado
- **Tab**: Navegar entre campos
- **Shift+Tab**: Navegar hacia atrás
- **Enter**: Activar botón seleccionado
- **Space**: Toggle checkbox/radiobutton
- **Arrows**: Navegar en tablas y listas

## Personalización

### Cambiar Tema de Colores

Editar clase `ModernStyle` en `gui.py`:
```python
class ModernStyle:
    # Tema claro
    BG_DARK = "#f5f5f5"
    BG_MEDIUM = "#ffffff"
    BG_LIGHT = "#e0e0e0"
    
    FG_PRIMARY = "#000000"
    FG_SECONDARY = "#666666"
    FG_ACCENT = "#0066cc"
```

### Agregar Nueva Pestaña

```python
# En _create_layout()
self.custom_tab = ttk.Frame(self.notebook, style="Modern.TFrame")
self.notebook.add(self.custom_tab, text=f"  🆕 Custom Tab  ")
self._create_custom_tab()

def _create_custom_tab(self):
    container = ttk.Frame(self.custom_tab, style="Card.TFrame")
    container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
    
    ttk.Label(container, text="Custom Content",
             style="Modern.TLabel").pack()
```

### Agregar Nuevo Test de Vulnerabilidad

En `_create_scan_tab()`, agregar a la lista `vulnerabilities`:
```python
vulnerabilities = [
    # ... existentes ...
    ("XXE (XML External Entity)", "xxe"),
    ("Command Injection", "command_injection"),
]
```

## Troubleshooting

### GUI no abre
**Problema**: Error al ejecutar `python gui.py`
**Solución**:
```bash
# Verificar tkinter instalado
python -c "import tkinter"

# En Ubuntu/Debian
sudo apt-get install python3-tk

# En Windows: tkinter viene incluido
# Reinstalar Python desde python.org
```

### Interfaz se congela
**Problema**: GUI no responde durante escaneo
**Causa**: Escaneo ejecutándose en thread principal
**Solución**: Verificar que `_run_scan()` se ejecuta en thread separado

### Colores no se muestran
**Problema**: Interfaz se ve en gris básico
**Causa**: Tema ttk no soportado
**Solución**:
```python
# En _setup_styles(), cambiar tema:
style.theme_use('alt')  # En lugar de 'clam'
```

### Fuentes no se ven bien
**Problema**: Fuentes demasiado pequeñas o grandes
**Solución**: Ajustar en `_setup_styles()`:
```python
font=('Segoe UI', 12)  # Incrementar/decrementar número
```

## Ventajas sobre CLI

| Aspecto | GUI | CLI |
|---------|-----|-----|
| **Curva de aprendizaje** | ✅ Baja - Intuitiva | ⚠️ Media - Requiere conocer argumentos |
| **Visualización** | ✅ Output en tiempo real con colores | ⚠️ Solo texto |
| **Configuración** | ✅ Sliders y checkboxes | ⚠️ Editar archivos manualmente |
| **Reportes** | ✅ Vista previa integrada | ⚠️ Abrir archivos manualmente |
| **Historial** | ✅ Tabla visual con filtros | ⚠️ Consultar base de datos |
| **Velocidad** | ⚠️ Overhead gráfico | ✅ Más rápido |
| **Automatización** | ❌ No scripteable | ✅ Ideal para scripts |
| **Acceso remoto** | ❌ Requiere X11/VNC | ✅ SSH directo |

## Recomendaciones

### Para Principiantes
✅ **Usar GUI**:
- Explorar todas las opciones visualmente
- Ver output en tiempo real
- Configurar fácilmente
- Gestionar reportes gráficamente

### Para Usuarios Avanzados
✅ **Usar CLI**:
- Scripts automatizados
- Integración con CI/CD
- Acceso remoto vía SSH
- Mayor control granular

### Para Ambos
✅ **Usar Launcher**:
- `python launcher.py` → GUI para explorar
- `python launcher.py https://target.com --profile deep` → CLI para producción

## Archivos del Sistema

```
Web_security_scanner/
├── launcher.py               # Punto de entrada inteligente
├── gui.py                    # Interfaz gráfica completa
├── config.yaml               # Configuración (editada por GUI)
├── scans.db                  # Base de datos SQLite (historial)
├── reports/                  # Reportes generados
│   ├── scan_YYYYMMDD_HHMMSS.html
│   ├── scan_YYYYMMDD_HHMMSS.pdf
│   └── scan_YYYYMMDD_HHMMSS.xlsx
└── web_security_scanner/
    ├── scanner_v4.py         # Motor de escaneo (usado por GUI)
    ├── i18n.py               # Sistema de traducciones
    └── GUI.md                # Esta documentación
```

## Futuras Mejoras

### Planeadas v4.1
- [ ] Dark/Light theme toggle
- [ ] Drag & drop para URLs
- [ ] Gráficos de vulnerabilidades (matplotlib)
- [ ] Exportar configuraciones preestablecidas
- [ ] Comparar dos escaneos lado a lado

### Planeadas v4.2
- [ ] Sistema de plugins para la GUI
- [ ] Dashboard con métricas históricas
- [ ] Notificaciones push cuando termine escaneo
- [ ] Modo presentación (fullscreen para demos)

---
**Última actualización**: 2024-11-21
**Versión**: 4.0
**Autor**: Luis - Web Security Scanner Team
