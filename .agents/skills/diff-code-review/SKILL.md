---
name: diff-code-review
description: Checklist de revisión de código acotada al diff (asyncio, tipado mypy, edge cases, seguridad, falsos positivos del scanner). Úsala al revisar un PR, una rama, un commit o cambios locales, sin releer módulos ajenos al cambio.
---

# Revisión acotada al diff

## Entrada (y nada más)
1. Bundle: `python3 tools/context_packer.py --mode budget [--range A..B | --staged] --out -`
   (diff, firmas tipadas, callers con slice, callees, tests afectados).
2. Resumen de `ruff check`, `mypy` y `pytest -q` sobre los archivos tocados.
No abras archivos fuera del bundle. Si un hallazgo depende de código ausente,
márcalo PLAUSIBLE y nombra el símbolo que faltaría ver.

## Checklist (sólo sobre líneas `+`/`-` y sus callers)
**asyncio**
- `await` olvidado (corutina sin esperar, `asyncio.gather` con no-corutinas).
- I/O bloqueante en `async def` (`open`, `requests`, `time.sleep`, `subprocess.run`).
- `create_task` sin referencia, `CancelledError` tragada, locks sin liberar.
- `aiohttp` sin `async with`; semáforo/token bucket saltado en ruta nueva.

**Tipado**
- Firma cambiada → ¿todos los callers del bundle siguen compatibles?
- `Optional` sin comprobar, `Any` que se escapa, retorno de tupla cambiado
  (p. ej. `probe()` devuelve 3 elementos).

**Edge cases**
- Vacío, `None`, unicode, cuerpo truncado (5 MB), timeouts, redirecciones,
  división por cero en métricas.

**Seguridad**
- `shell=True`, `yaml.load`, `pickle`, rutas sin normalizar, secretos en logs
  o informes (deben pasar por `mask_secrets()` / `html.escape`).
- Peticiones a hosts no autorizados (guardia SSRF de redirecciones).

**Falsos positivos (dominio del scanner)**
- Detección por diferencia de longitud/estado sin control causal.
- Reflejo de payload confundido con ejecución; confianza (`confidence`)
  subida sin evidencia dura.

## Formato de salida
Una línea por hallazgo, de más a menos grave:
`ruta:línea — [CRITICAL|HIGH|MEDIUM|LOW] problema concreto → arreglo mínimo`
Sin elogios, sin resumen del diff, sin estilo que `ruff` ya cubre. Sin
hallazgos: `Sin hallazgos accionables.` y las herramientas corridas.
