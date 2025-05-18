# Web Security Scanner v2.1

## 📝 Descripción

Web Security Scanner es una herramienta avanzada de línea de comandos diseñada para realizar pruebas integrales de seguridad en sitios web. Esta herramienta permite identificar vulnerabilidades comunes de seguridad web y detectar las tecnologías utilizadas en el sitio objetivo.

**⚠️ AVISO IMPORTANTE**: Esta herramienta está diseñada exclusivamente para fines educativos y pruebas de seguridad autorizadas. Su uso en sitios web sin permiso explícito puede ser ilegal y está estrictamente prohibido. Los autores no se hacen responsables del uso indebido de esta herramienta.

## ✨ Características Principales

### 🔍 Detección de Vulnerabilidades
- **Inyección SQL**: Detecta posibles vulnerabilidades de inyección SQL en formularios y parámetros GET
- **Cross-Site Scripting (XSS)**: Identifica vectores de ataque XSS reflejado
- **Inyección NoSQL**: Prueba vulnerabilidades específicas de bases de datos NoSQL
- **Redirección Abierta**: Detecta vulnerabilidades de redirección no validada

### 🛠️ Detección de Tecnologías
- **Servidores web**: Apache, Nginx, IIS, etc.
- **Lenguajes de programación**: PHP, Python, Java, .NET, etc.
- **CMS**: WordPress, Joomla, Drupal, etc.
- **Frameworks JavaScript**: React, Angular, Vue.js, jQuery, etc.
- **Herramientas de análisis**: Google Analytics, Facebook Pixel, etc.
- **Otras tecnologías**: CDNs, librerías, frameworks backend

### 🔧 Funcionalidades Avanzadas
- **Exploración automática** del sitio web objetivo
- **Detección inteligente de formularios** y parámetros
- **Análisis de cabeceras HTTP** para fingerprinting
- **Análisis de contenido HTML** para identificación de tecnologías
- **Interfaz en consola con colores** para mejor legibilidad
- **Exportación de resultados** en formato JSON
- **Modo de detección de tecnologías únicamente**
- **Configuración personalizable** de hilos y timeouts

## 🛠️ Requisitos del Sistema

### Versión de Python
- Python 3.X o superior

### Dependencias Requeridas
- `requests` - Para realizar peticiones HTTP
- `beautifulsoup4` - Para análisis de contenido HTML
- `colorama` - Para salida con colores en terminal
- `urllib3` - Para manejo avanzado de URLs

### Módulos Incluidos en Python Estándar
- `re` - Expresiones regulares
- `argparse` - Análisis de argumentos de línea de comandos
- `sys` - Funciones del sistema
- `urllib.parse` - Análisis de URLs
- `json` - Manejo de datos JSON
- `concurrent.futures` - Ejecución concurrente

## 📋 Instalación

### 1. Clonar o Descargar el Repositorio

1. Clona este repositorio o descarga el archivo `web_security_scanner.py`


### 2. Instalar Dependencias
```bash
pip install requests beautifulsoup4 urllib3 colorama
```

### 3. Archivos de Configuración Requeridos
Asegúrate de tener estos archivos en el mismo directorio que el script principal:
- `PAYLOAD.py` - Contiene los payloads para pruebas de vulnerabilidades
- `redirect_payloads.py` - Payloads específicos para redirección abierta
- `Tecnologias.py` - Firmas para detección de tecnologías
- `js_frameworks.py` - Patrones para frameworks JavaScript
- `cms_fingerprints.py` - Huellas digitales de CMS
- `analytics_patterns.py` - Patrones de herramientas de análisis

## 🚀 Uso

### Uso Básico
```bash
python web_security_scanner.py -u https://ejemplo.com
```

### Opciones Disponibles

| Opción | Descripción | Valor por defecto |
|--------|-------------|------------------|
| `-u, --url` | URL del sitio web a escanear (obligatorio) | - |
| `-t, --threads` | Número de hilos para el escaneo | 5 |
| `--timeout` | Tiempo de espera para solicitudes (segundos) | 10 |
| `-v, --verbose` | Mostrar información detallada | Desactivado |
| `--tech-only` | Realizar solo detección de tecnologías | Desactivado |
| `-o, --output` | Archivo para exportar resultados JSON | - |

### Ejemplos de Uso

#### Escaneo Completo con Configuración Personalizada
```bash
python web_security_scanner.py -u https://ejemplo.com -t 10 --timeout 15 -v
```

#### Solo Detección de Tecnologías
```bash
python web_security_scanner.py -u https://ejemplo.com --tech-only
```

#### Exportar Resultados a JSON
```bash
python web_security_scanner.py -u https://ejemplo.com -o resultados_scan.json
```

#### Escaneo Detallado con Máximos Hilos
```bash
python web_security_scanner.py -u https://ejemplo.com -t 20 --timeout 30 -v -o escaneo_completo.json
```

## 📊 Interpretación de Resultados

### Banner Inicial
El scanner muestra un banner con información básica del objetivo y configuración utilizada.

### Información del Servidor
- **Server**: Tipo de servidor web detectado
- **X-Powered-By**: Tecnología backend identificada
- **Content-Type**: Tipo de contenido principal

### Detección de Tecnologías
Categorías analizadas:
- **Servers**: Servidores web (Apache, Nginx, IIS)
- **Languages**: Lenguajes de programación (PHP, Python, Java)
- **CMS**: Sistemas de gestión de contenido
- **Frontend**: Frameworks y librerías frontend
- **JS Frameworks**: Frameworks JavaScript específicos
- **Analytics**: Herramientas de análisis y marketing
- **Misc**: Otras tecnologías detectadas

### Vulnerabilidades Detectadas
Para cada tipo de vulnerabilidad se muestra:
- **URL afectada**
- **Método HTTP** utilizado (GET/POST)
- **Parámetro vulnerable**
- **Payload** que desencadenó la detección

### Exportación JSON
Los resultados se pueden exportar en formato JSON estructurado que incluye:
```json
{
  "sql_injection": [],
  "xss": [],
  "nosql_injection": [],
  "open_redirect": [],
  "server_info": {},
  "forms_found": 0,
  "parameters_found": [],
  "technologies": {}
}
```

## ⚠️ Limitaciones Importantes

### Detección de Vulnerabilidades
- **Falsos positivos**: El scanner puede reportar vulnerabilidades que no existen
- **Falsos negativos**: Puede no detectar todas las vulnerabilidades existentes
- **Profundidad limitada**: No realiza pruebas exhaustivas o bypass de WAF
- **Cobertura parcial**: No incluye todas las categorías del OWASP Top 10

### Detección de Tecnologías
- **Basada en firmas**: Solo detecta tecnologías con patrones conocidos
- **Puede omitir versiones**: No siempre identifica versiones específicas
- **Tecnologías ocultas**: No detecta tecnologías intencionalmente ocultadas

### Rendimiento
- **Dependiente de la red**: El rendimiento varía según la latencia
- **Limitado por timeouts**: Sitios lentos pueden no ser escaneados completamente
- **Recursos del sistema**: El número de hilos afecta el rendimiento

## 🔒 Consideraciones Éticas y Legales

### ✅ Usos Permitidos
- Pruebas en tus propios sitios web
- Evaluaciones de seguridad autorizadas por escrito
- Entornos de laboratorio y educativos
- Bug bounty programs con alcance definido

### ❌ Usos Prohibidos
- Escanear sitios web sin autorización explícita
- Actividades maliciosas o ilegales
- Explotación de vulnerabilidades encontradas
- Ataques de denegación de servicio

### 📋 Mejores Prácticas
1. **Obtén autorización por escrito** antes de escanear cualquier sitio
2. **Verifica las políticas** de bug bounty o responsible disclosure
3. **Usa configuraciones conservadoras** para evitar impacto en el servicio
4. **Documenta y reporta** responsablemente las vulnerabilidades encontradas
5. **Respeta los términos de servicio** del sitio objetivo

## 🛡️ Descargo de Responsabilidad

Esta herramienta se proporciona "tal como está" sin garantías de ningún tipo. Los autores no se hacen responsables de:
- Daños directos o indirectos causados por el uso de esta herramienta
- Uso inadecuado o ilegal de la herramienta
- Exactitud de los resultados obtenidos
- Interrupciones del servicio en los sitios escaneados

## 📜 Licencia

Este proyecto está disponible bajo la licencia MIT. Consulta el archivo `LICENSE` para más detalles.

## 👨‍💻 Información del Desarrollador

**Desarrollado por**: VIDES_2GA_2025  
**Versión**: 2.1  
**Propósito**: Educativo y pruebas de seguridad autorizadas

## 🤝 Contribuir al Proyecto

### Formas de Contribuir
1. **Reportar bugs** abriendo issues detallados
2. **Sugerir mejoras** para nuevas funcionalidades
3. **Enviar pull requests** con correcciones o mejoras
4. **Mejorar documentación** y ejemplos de uso
5. **Añadir nuevas firmas** de tecnologías o payloads

### Estructura de Contribución
- Mantén el estilo de código existente
- Incluye comentarios descriptivos
- Prueba todos los cambios antes de enviar PR
- Actualiza la documentación según sea necesario

## 📞 Soporte y Contacto

Para soporte, sugerencias o reportar problemas:
- Abre un issue en el repositorio del proyecto
- Incluye detalles específicos del problema
- Proporciona logs o capturas cuando sea posible

---

## 🔄 Historial de Versiones

### v2.1 (Actual)
- Detección avanzada de tecnologías web
- Exportación de resultados en JSON
- Modo de detección de tecnologías únicamente
- Mejoras en la interfaz de usuario
- Optimizaciones de rendimiento

### v1.0 (Versión inicial)
- Detección básica de vulnerabilidades
- Escaneo de formularios y parámetros
- Interfaz de línea de comandos básica

---

*Nota: Este README es parte de un proyecto educativo para entender conceptos básicos de seguridad web. La herramienta no debe ser utilizada para actividades maliciosas o no autorizadas.*