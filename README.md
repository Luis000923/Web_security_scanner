#  Web Security Scanner v5.0.0 (Async)

Escáner de seguridad web totalmente asíncrono (`asyncio` + `aiohttp`) con
sistema de plugins para testers de vulnerabilidades. Solo para pruebas de
seguridad autorizadas y fines educativos.

##  Arquitectura v5.0

- **Core Asíncrono** (`core/scanner_core_async.py`): connection pooling, rate
  limiting global y caché de respuestas sobre un único event loop.
- **Orquestador** (`web_security_scanner_async.py`): descubre y ejecuta los
  testers, aplica perfiles y genera el mapa web.
- **Sistema de Eventos** (`events/`): desacopla la lógica de escaneo de la
  salida (la CLI se suscribe a los eventos).
- **Plugins** (`modules/vulnerability_testers/`): 12 testers async derivados de
  `base_tester_async.py`, auto-registrados vía `modules/registry.py`.
- **i18n** (`utils/i18n.py`): soporte de idiomas (`en`, `es`).

> La GUI síncrona, el core síncrono, `launcher_async.py` y el resto de
> artefactos de la v4.0 se eliminaron en esta versión.

##  Instalación

```bash
pip install -e .
```

##  Uso

El único entry point es la CLI (`webscanner`, o `python -m web_security_scanner.cli`):

```bash
webscanner scan https://example.com --profile balanced
webscanner scan https://example.com -p intense --threads 50 -f json,html
webscanner scan --help
```

Perfiles disponibles: `quick`, `balanced`, `intense`, `mapping`.

##  Tests

```bash
pytest tests/test_testers.py
```

## 📚 Documentación

Ver [Documentacion/](Documentacion/) para guías de uso y arquitectura.

---
**Nota**: Este proyecto es para fines educativos y pruebas de seguridad autorizadas.
