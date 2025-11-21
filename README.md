# 🔒 Web Security Scanner v4.0 (Async)

###AVIDO LA PARTE DE GUI SIGUE EN DESARROLLO ESTA EN FASE BETA###

## 🚀 Nueva Arquitectura Asíncrona

Esta versión introduce cambios significativos en la arquitectura del escáner para mejorar el rendimiento, la modularidad y la extensibilidad.

### ✨ Novedades en v4.0
- **Core Asíncrono**: Migración a `asyncio` y `aiohttp` para un rendimiento superior.
- **Sistema de Eventos**: Desacoplamiento total entre la lógica de escaneo y la interfaz de usuario.
- **Plugins**: Nuevo sistema de plugins para añadir testers de vulnerabilidades fácilmente.
- **Estructura de Paquete**: Organización moderna del código fuente.

## 📂 Estructura del Proyecto

- `web_security_scanner/`: Código fuente del paquete (Core, GUI, Módulos).
- `Documentacion/`: Documentación completa de versiones anteriores y guías de uso.
- `installer.py`: Script de instalación de dependencias.

## 🛠️ Instalación

1. Ejecuta el instalador para configurar las dependencias:
   ```bash
   python installer.py
   ```

2. Inicia la aplicación (Nueva versión asíncrona):
   ```bash
   python web_security_scanner/launcher_async.py
   ```

## 📚 Documentación

Para ver la documentación detallada de uso, arquitectura y versiones anteriores, consulta la carpeta [Documentacion/](Documentacion/).

---
**Nota**: Este proyecto es para fines educativos y pruebas de seguridad autorizadas.

# Se que no preguntaste pero llego como 4 meses trabajando en esta version y queria compartirla con ustedes :) Espero que les guste y cualquier feedback es bienvenido!