# Ampliación de cobertura de vulnerabilidades — 2026-09-30

> Insumo para quien actualice el paper (`paper/submission/sections/`, fuera
> del árbol de este documento). No se tocó ningún `.tex` ni `_datos.tex`
> desde aquí — solo código en `web_security_scanner/`.

## Qué cambió

El análisis de cobertura (ver `AGENTS.md` §0 de este repo para el mapa de
testers) identificó 7 huecos reales, verificados por `grep` contra el código
y no solo por ausencia de nombre de archivo. De esos 7, se implementaron 4
testers nuevos; 3 quedaron fuera de alcance deliberadamente (ver abajo).

**Testers totales: 25 → 28.** Confirmado por autodiscovery
(`TesterRegistry().discover_testers()`), sin tocar `modules/registry.py` — el
registro es automático vía `pkgutil.iter_modules` sobre
`modules/vulnerability_testers/`.

Si el paper cita "25 testers de vulnerabilidad" (ver `AGENTS.md` §0 de este
repo), esa cifra debe subir a **28** en cualquier sección de metodología que
la reutilice.

## Tabla: gap → tester → evidencia

| Gap identificado | Archivo nuevo | Clase | Tipo de señal / evidencia | Relevante para Track B |
|---|---|---|---|---|
| CORS no se probaba activamente (solo headers pasivos en `header_security_async.py`) | `cors_misconfig_async.py` | `CorsMisconfigTester` | Reflexión de `Origin` arbitrario en `Access-Control-Allow-Origin` + `Allow-Credentials: true` — evidencia **causal directa** (el propio header de respuesta confirma la aceptación del origin inyectado) | Sí — candidato natural a `evidence_kind="header_reflection"` si se integra con `param_semantics.py` |
| JWT solo se usaba para autenticar, nunca como superficie de ataque | `jwt_tester_async.py` | `JwtAttackTester` | Forja `alg:none` / firma en blanco / `exp` expirado (sin librería externa, solo `base64`/`json` stdlib); comparación estructural contra la respuesta con el token válido | Sí — el oráculo es "¿la respuesta forjada es indistinguible de la autenticada?", exactamente el patrón de evidencia dura que Track B busca generalizar |
| Sin verificación de enumeración de cuentas (contigua a IDOR/access-control) | `account_enum_async.py` | `AccountEnumerationTester` | Diferencia de status / similitud estructural del cuerpo (`core/differential_analyzer.calculate_structural_similarity`) / timing entre un username plausible y uno aleatorio, ambos con password incorrecta | Sí — reutiliza el motor diferencial ya existente, útil como caso de estudio de "evidencia diferencial vs. evidencia causal" |
| Prototype pollution (Node.js) sin cobertura | `prototype_pollution_async.py` | `PrototypePollutionTester` | Gadget `__proto__.toString` corrompido; firma de crash (`TypeError: … is not a function`) o 5xx nuevo, solo en la variante "polluted" y no en baseline/control, confirmado por una segunda repetición | Parcial — el control harmless-key es justamente para descartar falsos positivos por endpoints frágiles, tema central de Track B |

Cada tester nuevo trae su propio archivo de tests (`tests/test_cors_misconfig.py`,
`tests/test_account_enum.py`, `tests/test_jwt_tester.py`,
`tests/test_prototype_pollution.py`), 26 tests en total. Conteo de suite
completa antes/después: **1596 → 1615 tests, todos en verde** (el número base
de 1596 ya reflejaba crecimiento respecto al "1294" citado en `AGENTS.md`
§5 — esa cifra del `AGENTS.md` está desactualizada y debería refrescarse
aparte, no es resultado de este trabajo).

`ruff check` y `mypy` limpios sobre los 4 archivos nuevos.

## Qué quedó deliberadamente fuera (para citar como Future Work, no omitir)

1. **HTTP Request Smuggling (CL.TE / TE.CL).** Requiere control fino de
   framing HTTP a nivel de socket crudo; `core/http_client.py` está
   construido sobre `aiohttp`, que normaliza `Content-Length` /
   `Transfer-Encoding` y no permite enviar una petición deliberadamente mal
   formada. Implementarlo bien exige un cliente aparte solo para este
   tester, con las salvaguardas de seguridad correspondientes — un desync
   mal calibrado contra un proxy compartido puede afectar peticiones de
   *otros* usuarios, no solo al objetivo. Se descartó por alcance/riesgo en
   esta pasada, no por falta de valor.
2. **GraphQL** (introspection expuesto, abuso de batching, campos sin
   autorización) y **WebSocket** (ausencia de origin-check en el
   handshake). Fuera del modelo de "inyección en un punto HTTP" que
   comparten los 28 testers actuales; encajarían mejor como un módulo propio
   con su propio ciclo de vida de conexión.
3. **TLS/cipher suites.** Fuera de alcance de un DAST de capa de aplicación;
   se resuelve mejor con una herramienta dedicada (`testssl.sh`, `sslyze`)
   corrida en paralelo, no dentro de este escáner.

## Para quien actualice el paper

- Actualizar cualquier tabla de "N testers / N categorías de vulnerabilidad"
  de 25 a 28.
- Si se cita el conteo total de tests (`1294` en `AGENTS.md` §5), verificar
  primero contra `.venv/bin/python -m pytest -q` en el momento de escribir —
  ya iba desactualizado antes de este trabajo (1596 antes de estos 4
  testers).
- Los 3 testers descartados (§"Qué quedó deliberadamente fuera") son texto
  ya redactado y listo para pegar en una sección de Future Work / Threats to
  Validity — no hace falta re-analizarlos desde cero.
- Ninguno de estos 4 testers nuevos activa `evidence_kind` todavía (siguen
  el patrón `confidence` HIGH/MEDIUM/LOW de los testers "viejos", no el gate
  de `param_semantics.py`). Si Track B extiende la taxonomía HARD/SOFT a más
  testers, estos 4 son candidatos obvios por el tipo de evidencia que ya
  producen (ver columna "Tipo de señal" arriba).
