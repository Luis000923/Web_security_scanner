# Documentación de Payloads para Pruebas de Seguridad Web

Este directorio contiene una colección completa de payloads para realizar pruebas de seguridad web y detectar vulnerabilidades comunes.

## Archivos de Payloads Disponibles

### 1. payloadsSQL.json
**Inyección SQL (SQL Injection)**
- Payloads para detectar vulnerabilidades de inyección SQL
- Incluye técnicas de bypass de autenticación
- UNION-based SQL injection
- Blind SQL injection (booleana y basada en tiempo)
- Error-based SQL injection
- Extracción de información de bases de datos
- Comandos específicos para MySQL, PostgreSQL, MS SQL Server, Oracle
- Técnicas de evasión y ofuscación

**Casos de uso:**
- Formularios de login
- Parámetros de URL
- Campos de búsqueda
- APIs que interactúan con bases de datos

### 2. payloadsXSS.json
**Cross-Site Scripting (XSS)**
- XSS reflejado (Reflected XSS)
- XSS almacenado (Stored XSS)
- XSS basado en DOM
- Bypass de filtros XSS
- Técnicas de ofuscación
- Payloads para robo de cookies
- Exfiltración de datos
- Ataques de redirección

**Casos de uso:**
- Campos de entrada de usuario
- Comentarios y foros
- Mensajes y chats
- Perfiles de usuario
- Parámetros de URL

### 3. payloadsNoSQL.json
**Inyección NoSQL (NoSQL Injection)**
- Payloads para MongoDB
- Operadores de consulta NoSQL
- Bypass de autenticación
- Extracción de datos
- Blind NoSQL injection
- JavaScript injection en MongoDB
- Operadores como $ne, $gt, $regex, $where

**Casos de uso:**
- APIs REST con MongoDB
- Autenticación de usuarios
- Búsquedas y filtros
- Aplicaciones Node.js con MongoDB

### 4. payloadsLDAP.json
**Inyección LDAP (LDAP Injection)**
- Bypass de autenticación LDAP
- Filtros LDAP maliciosos
- Extracción de información de directorios
- Técnicas de enumeración

**Casos de uso:**
- Sistemas de autenticación corporativa
- Directorios Active Directory
- Servicios de directorio LDAP

### 5. payloadsCommandInjection.json
**Inyección de Comandos (Command Injection)**
- Ejecución de comandos del sistema
- Comandos para Linux/Unix
- Comandos para Windows
- Técnicas de concatenación (;, |, &, &&, ||)
- Command substitution ($(), ``)
- Reverse shells
- Exfiltración de archivos sensibles

**Casos de uso:**
- Funciones de ping/traceroute
- Conversión de archivos
- Procesamiento de imágenes
- Cualquier función que ejecute comandos del sistema

### 6. payloadsPathTraversal.json
**Path Traversal / Directory Traversal**
- Navegación de directorios
- Acceso a archivos sensibles
- Técnicas de encoding
- Bypass de filtros de path
- Wrappers de PHP
- Acceso a /etc/passwd, win.ini, etc.

**Casos de uso:**
- Descarga de archivos
- Visualización de documentos
- Carga de plantillas
- Inclusión de archivos

### 7. payloadsXXE.json
**XML External Entity (XXE)**
- Lectura de archivos locales
- SSRF mediante XXE
- Exfiltración de datos
- Denial of Service (Billion Laughs Attack)
- XXE Out-of-Band
- XXE Blind

**Casos de uso:**
- APIs que aceptan XML
- Importación de archivos XML
- Parsers SOAP
- Configuraciones XML

### 8. payloadsSSRF.json
**Server-Side Request Forgery (SSRF)**
- Acceso a servicios internos
- Metadata de cloud (AWS, GCP, Azure)
- Bypass de firewalls
- Port scanning interno
- Protocolos file://, dict://, gopher://
- Técnicas de bypass de validación

**Casos de uso:**
- Importación de URLs
- Webhooks
- Descarga de recursos externos
- APIs de preview/thumbnail

### 9. payloadsSSTI.json
**Server-Side Template Injection (SSTI)**
- Jinja2 (Python/Flask)
- Twig (PHP/Symfony)
- Freemarker (Java)
- Velocity (Java)
- Smarty (PHP)
- ERB (Ruby)
- Ejecución remota de código
- Lectura de archivos

**Casos de uso:**
- Sistemas de plantillas
- Generación dinámica de contenido
- Emails automáticos
- Reportes PDF

### 10. payloadsCRLF.json
**CRLF Injection**
- HTTP Response Splitting
- Inyección de headers HTTP
- Modificación de cookies
- Bypass de seguridad
- Inyección de contenido

**Casos de uso:**
- Redirects personalizados
- Headers personalizados
- Logging de información
- Sistemas de redirección

### 11. payloadsOpenRedirect.json
**Open Redirect**
- Redirecciones no validadas
- Bypass de validación de URLs
- Técnicas de ofuscación de URLs
- Phishing mediante redirección
- Bypass de whitelists

**Casos de uso:**
- Funciones de logout
- Redirects después de login
- Parámetros "next" o "return"
- URLs de callback

### 12. payloadsAuthBypass.json
**Bypass de Autenticación**
- Credenciales por defecto
- Contraseñas comunes
- Usuarios administrativos
- Combinaciones username/password

**Casos de uso:**
- Brute force testing
- Pruebas de credenciales débiles
- Enumeración de usuarios
- Fuzzing de autenticación

### 13. payloadsFuzzing.json
**Fuzzing General**
- Payloads mixtos
- Detección de múltiples vulnerabilidades
- Inputs maliciosos variados
- Caracteres especiales
- Secuencias de escape

**Casos de uso:**
- Testing automatizado
- Escaneo de vulnerabilidades
- Pruebas de regresión
- Descubrimiento de vulnerabilidades

### 14. payloadsLog4Shell.json
**Log4Shell (CVE-2021-44228)**
- Explotación de Log4j
- JNDI Injection
- Técnicas de bypass de WAF
- Variaciones de payload
- Exfiltración mediante DNS

**Casos de uso:**
- Aplicaciones Java
- Servicios que usan Log4j
- Headers HTTP
- Campos de logging

### 15. subdominios.json y subdirectorios.json
**Enumeración y Descubrimiento**
- Subdominios comunes
- Directorios comunes
- Archivos sensibles
- Endpoints de administración

**Casos de uso:**
- Reconocimiento de infraestructura
- Descubrimiento de activos
- Enumeración de servicios
- Mapeo de aplicaciones web

## Uso Responsable

⚠️ **ADVERTENCIA**: Estos payloads están diseñados únicamente para:
- Pruebas de seguridad autorizadas
- Programas de Bug Bounty legítimos
- Auditorías de seguridad con permiso explícito
- Entornos de prueba propios

**NO utilizar estos payloads para:**
- Ataques no autorizados
- Acceso no autorizado a sistemas
- Daños a infraestructuras
- Actividades ilegales

## Mejores Prácticas

1. **Obtén autorización por escrito** antes de realizar cualquier prueba
2. **Documenta todos los hallazgos** de manera profesional
3. **Reporta vulnerabilidades de forma responsable**
4. **No causes daños** a los sistemas bajo prueba
5. **Respeta los alcances** definidos en el contrato de pruebas
6. **Mantén la confidencialidad** de los datos sensibles encontrados

## Actualización y Mantenimiento

Estos payloads deben actualizarse regularmente para incluir:
- Nuevas técnicas de ataque
- Bypass de protecciones modernas
- Vulnerabilidades emergentes
- Mejoras en las técnicas existentes

## Integración con Herramientas

Estos archivos JSON pueden integrarse con:
- Burp Suite (Intruder)
- OWASP ZAP
- SQLMap
- XSStrike
- Nuclei
- Scripts personalizados
- Frameworks de seguridad

## Estructura de Archivos

Todos los archivos siguen el formato JSON:
```json
[
    "payload1",
    "payload2",
    "payload3"
]
```

Esto facilita su importación y uso programático.

## Contribuciones

Para contribuir con nuevos payloads:
1. Verifica que sean efectivos y relevantes
2. Documenta su propósito y caso de uso
3. Evita duplicados
4. Mantén el formato JSON consistente

## Referencias

- OWASP Top 10
- OWASP Testing Guide
- PortSwigger Web Security Academy
- HackerOne Disclosed Reports
- CVE Database
- MITRE ATT&CK Framework

## Contacto y Soporte

Para dudas sobre el uso de estos payloads o reportar problemas:
- Revisa la documentación de tu empresa
- Consulta con el equipo de seguridad
- Sigue las políticas de seguridad establecidas

---

**Última actualización:** Noviembre 2025

**Versión:** 2.0

**Autor:** Equipo de Seguridad
