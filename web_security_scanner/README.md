# Web Security Scanner v3.0

## 📝 Descripción

Web Security Scanner es una herramienta avanzada de línea de comandos para pruebas integrales de seguridad en sitios web. Permite identificar vulnerabilidades comunes, detectar tecnologías, subdirectorios y subdominios, y exportar resultados en múltiples formatos.

**⚠️ AVISO IMPORTANTE**: Esta herramienta es solo para fines educativos y pruebas de seguridad autorizadas. El uso en sitios sin permiso explícito puede ser ilegal. Los autores no se hacen responsables del uso indebido.

## ✨ Características Principales

### 🔍 Detección de Vulnerabilidades
- **Inyección SQL**: Detección avanzada en formularios y parámetros GET/POST.
- **Cross-Site Scripting (XSS)**: Identificación de vectores reflejados y variantes.
- **Inyección NoSQL**: Payloads robustos y detección de variantes complejas.
- **Redirección Abierta**: Detección de redirecciones no validadas.

### 🛠️ Detección de Tecnologías
- **Servidores web**: Apache, Nginx, IIS, LiteSpeed, Tomcat, etc.
- **Lenguajes de programación**: PHP, Python, Java, .NET, Ruby, Go, Node.js, etc.
- **CMS**: WordPress, Joomla, Drupal, Magento, PrestaShop, y más de 40 CMS soportados.
- **Frameworks JavaScript**: React, Angular, Vue.js, Svelte, Next.js, Nuxt.js, y decenas más.
- **Herramientas de análisis**: Google Analytics, Facebook Pixel, Hotjar, Matomo, etc.
- **Otras tecnologías**: CDNs, librerías, frameworks backend, servicios cloud, bases de datos.

### 🚀 Funcionalidades Avanzadas
- **Exploración automática** del sitio web objetivo (crawling).
- **Fuerza bruta de subdirectorios** usando wordlists personalizables.
- **Fuerza bruta de subdominios** con wordlists y resolución DNS.
- **Detección inteligente de formularios y parámetros**.
- **Análisis de cabeceras HTTP** y fingerprinting de tecnologías.
- **Análisis de contenido HTML** para identificación de tecnologías y frameworks.
- **Interfaz en consola con colores** para mejor legibilidad.
- **Exportación de resultados** en JSON, HTML, Word y PDF (bajo demanda).
- **Modo de detección de tecnologías únicamente**.
- **Configuración personalizable** de hilos y timeouts.
- **Tres niveles de velocidad de escaneo**: bajo (`-Sb`), medio (`-Sm`), alto (`-Sa`).
- **Modo de escaneo rápido** (`--quick`): usa menos payloads para pruebas rápidas.
- **Banner mejorado** con versión y créditos.
- **Soporte para wordlists personalizadas** en la carpeta `PAYLOAD`.

## 🛠️ Requisitos del Sistema

### Versión de Python
- Python 3.X o superior

### Dependencias Requeridas
- `requests` - Peticiones HTTP
- `beautifulsoup4` - Análisis de HTML
- `colorama` - Colores en terminal
- `urllib3` - Manejo avanzado de URLs
- `pdfkit` y `wkhtmltopdf` (solo para exportar PDF)
- `python-docx` (solo para exportar Word)
- `flask` (solo si usas la interfaz web para descargas bajo demanda)

### Módulos Incluidos en Python Estándar
- `re`, `argparse`, `sys`, `urllib.parse`, `json`, `concurrent.futures`, `socket`, `os`, `datetime`

## 📋 Instalación

### 1. Clonar o Descargar el Repositorio

1. Clona este repositorio o descarga el archivo `web_security_scanner.py` y la carpeta `PAYLOAD`.

### 2. Instalar Dependencias
```bash
pip install requests beautifulsoup4 urllib3 colorama pdfkit python-docx flask
```
> Para exportar PDF, instala también [wkhtmltopdf](https://wkhtmltopdf.org/downloads.html) y asegúrate de que esté en tu PATH.

### 3. Archivos de Configuración Requeridos
Asegúrate de tener estos archivos en el mismo directorio que el script principal:
- Carpeta `PAYLOAD` con:
  - `payloadsSQL.json`, `payloadsXSS.json`, `payloadsNoSQL.json`
  - `subdirectorios.json`, `subdominios.json`
- `redirect_payloads.py` - Payloads para redirección abierta
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
| `--tech-only` | Solo detección de tecnologías | Desactivado |
| `-o, --output` | Archivo para exportar resultados | - |
| `-j, --json` | Exportar resultados en formato JSON | Desactivado |
| `-H, --html` | Exportar resultados en formato HTML | Desactivado |
| `-Sb, --slow` | Escaneo bajo (más lento) | Desactivado |
| `-Sm, --medium` | Escaneo medio | Desactivado |
| `-Sa, --fast` | Escaneo alto (más rápido) | Desactivado |
| `--quick` | Escaneo rápido (menos payloads) | Desactivado |

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
python web_security_scanner.py -u https://ejemplo.com -j
```

#### Exportar Resultados a HTML
```bash
python web_security_scanner.py -u https://ejemplo.com -H
```

#### Exportar Ambos Reportes
```bash
python web_security_scanner.py -u https://ejemplo.com -j -H
```

#### Escaneo Bajo, Medio, Alto y Rápido
```bash
python web_security_scanner.py -u https://ejemplo.com -Sb
python web_security_scanner.py -u https://ejemplo.com -Sm
python web_security_scanner.py -u https://ejemplo.com -Sa
python web_security_scanner.py -u https://ejemplo.com --quick
```

#### Escaneo Detallado con Máximos Hilos
```bash
python web_security_scanner.py -u https://ejemplo.com -t 20 --timeout 30 -v -j -H -o escaneo_completo
```

#### Exportar Word o PDF bajo demanda (requiere Flask)
- Accede a `/descargar/word` o `/descargar/pdf` en la interfaz web para generar y descargar el reporte solo cuando lo necesites.

## 📊 Interpretación de Resultados

### Banner Inicial
El scanner muestra un banner mejorado con versión, créditos y descripción.

### Información del Servidor
- **Server**: Tipo de servidor web detectado
- **X-Powered-By**: Tecnología backend identificada
- **Content-Type**: Tipo de contenido principal

### Detección de Tecnologías
Categorías analizadas:
- **Servers**: Servidores web (Apache, Nginx, IIS, etc.)
- **Languages**: Lenguajes de programación (PHP, Python, Java, etc.)
- **CMS**: Más de 40 sistemas de gestión de contenido
- **Frontend**: Frameworks y librerías frontend
- **JS Frameworks**: Frameworks JavaScript modernos y legacy
- **Analytics**: Herramientas de análisis y marketing
- **Misc**: Otras tecnologías detectadas

### Subdirectorios y Subdominios
- **Subdirectorios**: Detectados por crawling y fuerza bruta usando wordlists.
- **Subdominios**: Detectados por fuerza bruta y resolución DNS usando wordlists.

### Vulnerabilidades Detectadas
Para cada tipo de vulnerabilidad se muestra:
- **URL afectada**
- **Método HTTP** utilizado (GET/POST)
- **Parámetro vulnerable**
- **Payload** que desencadenó la detección

### Exportación de Resultados
- **JSON**: Usa `-j` para exportar resultados en formato JSON estructurado.
- **HTML**: Usa `-H` para exportar resultados en formato HTML visual.
- **Word/PDF**: Descarga bajo demanda desde la interfaz web (no se generan automáticamente).
- Puedes usar `-o` para definir el nombre del archivo de salida.

Ejemplo de estructura JSON:
```json
{
  "sql_injection": [],
  "xss": [],
  "nosql_injection": [],
  "open_redirect": [],
  "server_info": {},
  "forms_found": 0,
  "parameters_found": [],
  "technologies": {},
  "subdirectories": [],
  "subdomains": []
}
```

## ⚠️ Limitaciones Importantes

### Detección de Vulnerabilidades
- **Falsos positivos**: El scanner puede reportar vulnerabilidades que no existen.
- **Falsos negativos**: Puede no detectar todas las vulnerabilidades existentes.
- **Profundidad limitada**: No realiza pruebas exhaustivas o bypass de WAF.
- **Cobertura parcial**: No incluye todas las categorías del OWASP Top 10.

### Detección de Tecnologías
- **Basada en firmas**: Solo detecta tecnologías con patrones conocidos.
- **Puede omitir versiones**: No siempre identifica versiones específicas.
- **Tecnologías ocultas**: No detecta tecnologías intencionalmente ocultadas.

### Subdirectorios y Subdominios
- **Wordlists limitadas**: La detección depende de la calidad y tamaño de las wordlists.
- **No realiza fuzzing avanzado**: No prueba variantes dinámicas o rutas generadas.

### Rendimiento
- **Dependiente de la red**: El rendimiento varía según la latencia.
- **Limitado por timeouts**: Sitios lentos pueden no ser escaneados completamente.
- **Recursos del sistema**: El número de hilos afecta el rendimiento.
- **Escaneo rápido**: El modo `--quick` usa menos payloads y es menos exhaustivo.

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
1. **Obtén autorización por escrito** antes de escanear cualquier sitio.
2. **Verifica las políticas** de bug bounty o responsible disclosure.
3. **Usa configuraciones conservadoras** para evitar impacto en el servicio.
4. **Documenta y reporta** responsablemente las vulnerabilidades encontradas.
5. **Respeta los términos de servicio** del sitio objetivo.

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
**Versión**: 3.0  
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

### v3.0 (Actual)
- Fuerza bruta de subdirectorios y subdominios con wordlists personalizables
- Exportación de reportes Word y PDF bajo demanda (no automática)
- Payloads NoSQL y SQL más robustos y avanzados
- Detección ampliada de tecnologías, CMS y frameworks JS
- Banner mejorado con versión y créditos
- Mejoras de rendimiento y crawling más profundo
- Mejoras en la estructura del reporte HTML
- Corrección de bugs y optimización general

### v2.7.4
- Exportación de resultados en JSON y HTML
- Tres niveles de velocidad de escaneo: bajo, medio, alto
- Modo de escaneo rápido (`--quick`)
- Mejoras en la interfaz de usuario y rendimiento
- Detección avanzada de tecnologías web
- Modo de detección de tecnologías únicamente

### v2.1
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

*Nota: Este README es parte de un proyecto educativo para entender conceptos de seguridad web. La herramienta no debe ser utilizada para actividades maliciosas o no autorizadas. si me he equicodado en algo en la docuemnatacion ahi me lo notifcan dadoa  que no he dormido bien por terminar la version 3 y a la hora en que edito esto son las 4 y 48 de la mañana*