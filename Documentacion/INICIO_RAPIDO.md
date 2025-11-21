# 🚀 Inicio Rápido - Web Security Scanner v4.0

# ESTA EN BETA AHI FUNCIONES NO PROBADAS

## ⚡ Instalación en 30 segundos

```bash
# 1. Clonar
git clone https://github.com/Luis000923/Web_security_scanner.git
cd Web_security_scanner

# 2. Ejecutar
python launcher.py
```

¡Eso es todo! El launcher instala automáticamente todo lo necesario.

---

## 🎯 Dos Formas de Usar

### 🖥️ Modo GUI (Principiantes)
```bash
python launcher.py
```
- ✅ Interfaz visual moderna
- ✅ No necesitas memorizar comandos
- ✅ Todo con clicks

### 💻 Modo CLI (Avanzados)
```bash
python launcher.py https://example.com
```
- ✅ Control total desde terminal
- ✅ Ideal para scripts y automatización

---

## 📖 Primeros Pasos

### 1. Primer Escaneo (GUI)

1. Ejecuta `python launcher.py`
2. Se abre la ventana gráfica
3. Ingresa URL: `https://example.com`
4. Click en "🚀 START SCAN"
5. Espera resultados
6. Ve a pestaña "Reports" para ver HTML

### 2. Primer Escaneo (CLI)

```bash
# Escaneo básico
python launcher.py https://example.com

# Ver ayuda completa
python launcher.py --help
```

---

## 🔧 Configuración Inicial

### Cambiar Idioma

**GUI**: Config → Language → Español  
**CLI**: Editar `config.yaml`:
```yaml
language: es  # o 'en'
```

### Ajustar Velocidad

**GUI**: Config → Threads → Ajustar slider  
**CLI**:
```bash
python launcher.py https://example.com -t 20
```

---

## 📊 Entender Resultados

### En la GUI
- **Output**: Muestra progreso en tiempo real
- **Reports**: Lista de reportes generados
- **History**: Historial de escaneos

### En CLI
El output muestra:
```
✓ Tecnologías detectadas (servidor, CMS, frameworks)
✓ Vulnerabilidades encontradas (SQL, XSS, etc.)
✓ Subdominios descubiertos
✓ Reportes generados (HTML, PDF, Excel, etc.)
```

---

## 🆘 Problemas Comunes

### "ModuleNotFoundError"
```bash
python launcher.py  # Instala automáticamente
```

### "URL inválida"
```bash
# ✅ Correcto
python launcher.py https://example.com

# ❌ Incorrecto
python launcher.py example.com  # Falta https://
```

### GUI no abre
```bash
# Usar CLI en su lugar
python launcher.py https://example.com
```

---

## 📚 Documentación Completa

- **GUI completa**: Ver [`GUI.md`](GUI.md)
- **Mapeo web**: Ver [`MAPA_WEB.md`](web_security_scanner/MAPA_WEB.md)
- **Todo**: Ver [`README.md`](README.md)

---

## ⚖️ Recordatorio Legal

**Solo escanea sitios con permiso escrito.**

✅ Sitios propios  
✅ Bug bounty programs  
❌ Sitios aleatorios

---

## 🎯 Ejemplos Rápidos

```bash
# Escaneo rápido (5 min)
python launcher.py https://example.com --profile quick

# Escaneo completo (30+ min)
python launcher.py https://example.com --profile deep

# Solo tecnologías (1 min)
python launcher.py https://example.com --tech-only

# Con mapa web interactivo
python launcher.py https://example.com --generate-map
```

---

**¿Listo? ¡Empieza ahora!**

```bash
python launcher.py
```
