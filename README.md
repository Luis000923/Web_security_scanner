# Web Security Scanner V1.0

## 📝 Descripción

Web Security Scanner es una herramienta de línea de comandos diseñada para realizar pruebas básicas de seguridad en sitios web. Permite identificar vulnerabilidades comunes como inyección SQL, Cross-Site Scripting (XSS), inyección NoSQL y redirecciones abiertas.

**⚠️ AVISO IMPORTANTE**: Esta herramienta está diseñada exclusivamente para fines educativos y pruebas de seguridad autorizadas. Su uso en sitios web sin permiso explícito puede ser ilegal y está estrictamente prohibido.

## ✨ Características

- **Exploración automática** del sitio web objetivo
- **Detección de formularios** y parámetros vulnerables
- **Pruebas de seguridad** para identificar:
  - Inyección SQL
  - Cross-Site Scripting (XSS)
  - Inyección NoSQL
  - Vulnerabilidades de redirección abierta
- **Recopilación de información** básica del servidor
- **Interfaz en consola** con salida en colores para mejor legibilidad
- **Opciones configurables** como número de hilos y tiempos de espera

## 🛠️ Requisitos

- Python 3.x
- Bibliotecas requeridas:
  - requests
  - colorama
  - urllib3
  - concurrent.futures (incluido en Python estándar)
  - re (incluido en Python estándar)
  - argparse (incluido en Python estándar)

## 📋 Instalación

1. Clona este repositorio o descarga el archivo `web_security_scanner.py`

2. Instala las dependencias necesarias:

```bash
pip install requests colorama urllib3
```

## 🚀 Uso

Ejecuta el script con Python proporcionando la URL del sitio objetivo:

```bash
python web_security_scanner.py -u https://ejemplo.com
```

### Opciones disponibles:

```
-u, --url URL       URL del sitio web a escanear (obligatorio)
-t, --threads N     Número de hilos para el escaneo (predeterminado: 5)
--timeout N         Tiempo de espera para las solicitudes en segundos (predeterminado: 10)
-v, --verbose       Mostrar información detallada durante el escaneo
```

### Ejemplo de uso avanzado:

```bash
python web_security_scanner.py -u https://ejemplo.com -t 10 --timeout 15 -v
```

## 📊 Salida

El escáner mostrará:

1. Banner informativo
2. Información básica del servidor objetivo
3. Número de formularios y parámetros encontrados
4. Vulnerabilidades detectadas, organizadas por tipo
5. Resumen final de las pruebas realizadas

## ⚠️ Limitaciones

- El escáner puede generar falsos positivos
- No realiza pruebas profundas o exhaustivas
- Los resultados deben verificarse manualmente para confirmar vulnerabilidades reales
- No incluye todas las categorías de vulnerabilidades posibles (OWASP Top 10)

## 🔒 Consideraciones éticas

- **Obtén siempre autorización** antes de escanear cualquier sitio web
- No utilices esta herramienta para actividades maliciosas o ilegales
- Reporta responsablemente las vulnerabilidades que encuentres
- Sigue las prácticas de divulgación responsable si descubres problemas de seguridad reales

## 📜 Licencia

Este proyecto está disponible bajo la licencia MIT. Consulta el archivo LICENSE para más detalles.

## 👨‍💻 Autor

Creado por VIDES_2GA_2025

## 🤝 Contribuir

Las contribuciones son bienvenidas. Por favor, siente libre de:

1. Abrir un issue para reportar bugs
2. Proponer nuevas características
3. Enviar pull requests para mejorar el código

---

*Nota: Este README es parte de un proyecto educativo para entender conceptos básicos de seguridad web. La herramienta no debe ser utilizada para actividades maliciosas o no autorizadas.*
*no me hago responsable del mal uso de esta herramienta*
*espero traer nuevas actulizaciones*
