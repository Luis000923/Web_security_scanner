# Mejoras de la version 5.0.0

Este documento describe las mejoras tecnicas incorporadas en
`web-security-scanner` 5.0.0 respecto a la linea 4.x. La version 5 es una
reescritura del motor: se elimino la GUI de escritorio, el nucleo sincrono, el
instalador interactivo y el resto de artefactos de la 4.x, y se consolido todo
el producto en una unica interfaz de linea de comandos sobre un motor
asincrono.

Para la vision historica completa, vease
[COMPARATIVA_VERSIONES.md](COMPARATIVA_VERSIONES.md).

---

## 1. Arquitectura asincrona

- Motor construido sobre `asyncio` y `aiohttp` con un unico bucle de eventos.
- `AsyncScannerCore` mantiene un pool de conexiones reutilizable, cache de
  respuestas y un limitador de peticiones global.
- El orquestador ejecuta los testers a traves de un pool de workers acotado
  (`MAX_TESTER_CONCURRENCY`), de modo que una cancelacion o un timeout cancela y
  espera todas las tareas en vuelo antes de cerrar la sesion HTTP; no quedan
  tareas huerfanas ni sockets sin cerrar.
- Limite global opcional de duracion (`--max-duration`) que corta la fase de
  testers y entrega resultados parciales.
- Salida por Ctrl+C limpia: se cancela y espera el trabajo pendiente, se cierra
  la sesion y se termina con codigo 130, sin trazas de `asyncio`.
- La deteccion de tecnologias y la generacion de informes, que son intensivas
  en CPU o en E/S de disco, se ejecutan fuera del bucle de eventos mediante
  `asyncio.to_thread`.

## 2. Blindaje anti-SSRF

El guarda anti-SSRF opera sobre el seguimiento de redirecciones y combina
varias comprobaciones:

1. **Seguimiento manual de redirecciones.** El cliente no delega el
   seguimiento en `aiohttp`; procesa cada salto de forma explicita hasta
   `max_redirects`.
2. **Resolucion DNS previa por salto.** Antes de seguir un salto, el host
   destino se resuelve por DNS y el resultado se cachea por host para no
   re-resolver en cada comprobacion.
3. **Filtrado de rangos no publicos.** Se rechaza cualquier destino cuya IP
   (literal o resuelta) sea privada, loopback, link-local, reservada,
   multicast o no especificada segun el modulo `ipaddress` de la biblioteca
   estandar. El espacio compartido de proveedores (CGNAT, `100.64.0.0/10`)
   entra en la clasificacion de direccion no global. Esto bloquea, entre
   otros, el servicio de metadatos de nube en `169.254.169.254`.
4. **Fallo cerrado.** Un host que no resuelve tambien aborta la peticion con
   `SSRFRedirectError`.

El comportamiento se puede desactivar de forma explicita con
`--allow-private-redirects` para auditar objetivos internos autorizados.

## 3. Resistencia a objetivos hostiles

- Techo de 5 MiB de cuerpo descomprimido por respuesta; el flujo se lee por
  fragmentos y se abandona al superarlo (proteccion frente a streams infinitos
  y bombas de compresion).
- Timeouts de socket independientes: `sock_connect` para el establecimiento de
  la conexion y `sock_read` para el intervalo entre fragmentos, ademas del
  deadline global por peticion.
- Las respuestas truncadas se marcan como tales en el resultado.
- El rastreador aplica limites de profundidad y de numero de URLs, con corte
  preventivo ante trampas de arana (`page.php?id=1,2,3,...`) por firma
  estructural de URL.

## 4. Modulos de prueba de vulnerabilidades

La version 5 expone once testers, todos derivados de `VulnerabilityTester` y
descubiertos automaticamente por `TesterRegistry`:

| Tester | Tecnica principal |
|--------|-------------------|
| SQL Injection | Basado en error y basado en tiempo, con linea base de latencia y ronda de confirmacion. |
| XSS | Analisis sensible al contexto; la confianza depende del `Content-Type`. |
| Command Injection | Deteccion por salida de comando. |
| Path Traversal / inclusion de archivos | Deteccion por contenido de archivos de sistema, distinguiendo respuestas 403. |
| Open Redirect | Marcador unico en el destino de la redireccion. |
| SSRF | Fuga de metadatos y acceso a servicios internos. |
| NoSQL Injection | Mensajes de error de motores NoSQL. |
| IDOR | Comparacion diferencial de objetos entre identificadores. |
| XXE | Entidades externas XML. |
| CSRF | Ausencia de proteccion anti-CSRF en formularios que cambian estado. |
| Header Security | Cabeceras de seguridad ausentes o con valores debiles, tolerante a mayusculas y a directivas modernas. |

Mejoras transversales de los testers:

- Base compartida con inyeccion de parametros consciente de URL-encoding,
  captura de linea base y comparacion diferencial.
- Nivel de confianza por hallazgo: `LOW`, `MEDIUM`, `HIGH`, `CONFIRMED`.
- Compuerta para payloads destructivos (`--allow-destructive`), desactivada por
  defecto, y limite de payloads por parametro (`--max-payloads`).
- Reduccion de falsos positivos: el tester de cabeceras acepta valores modernos
  (`X-XSS-Protection: 0`, HSTS con `max-age` valido en cualquier orden) y
  reconoce nombres de cabecera en minusculas de HTTP/2 y proxies.

## 5. Sanitizacion de credenciales y secretos

- `mask_secrets` redacta tokens `Authorization: Bearer`, credenciales `Basic`,
  cabeceras `Cookie` / `Set-Cookie` y JWT en texto plano antes de escribir
  cualquier informe.
- Todos los campos del informe HTML se escapan con `html.escape`.
- Los campos de evidencia que pueden contener fragmentos de peticion o
  respuesta pasan por el enmascarado en cualquiera de los formatos de salida.

## 6. Sistema de tipos y calidad de codigo

- El codigo fuente de `web_security_scanner/` pasa `mypy` sin errores.
- `ruff check .` pasa limpiamente; la configuracion vive en `pyproject.toml`
  (`E`, `F`, `W`, `I`, `UP`, `B`).
- Anotaciones de tipo modernas (`X | None`, `list[...]`, `dict[...]`) en todo
  el arbol.

## 7. Gestion de dependencias y ejecucion

- `pyproject.toml` como unica fuente de metadatos y dependencias; `uv.lock`
  fija el arbol resuelto.
- Flujo de trabajo con `uv`: `uv sync`, `uv run pytest`, `uv run ruff check .`,
  `uv run mypy`.
- Punto de entrada unico `webscanner` (`web_security_scanner.cli:main`).

## 8. Internacionalizacion

- Textos de salida en ingles (`en`) y espanol (`es`), seleccionables con
  `--lang`.
- Las cadenas viven en `web_security_scanner/languages.yaml` y se cargan a
  traves de `utils/i18n.py`.

## 9. Informes

- Formatos JSON y HTML, generados de forma asincrona.
- El JSON incluye objetivo, perfil, vulnerabilidades ordenadas por severidad y
  confianza, tecnologias detectadas y estadisticas.
- Cuando el rastreo esta activo se genera ademas un mapa web en HTML como
  archivo independiente.
