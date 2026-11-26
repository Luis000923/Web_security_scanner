"""Casos trampa de falsos positivos para los testers de lógica / configuración.

Cada bloque cubre un tester: primero las trampas (respuestas que antes
producían un hallazgo falso y ahora no deben producir nada, o deben bajar de
confianza) y después un positivo que demuestra que la detección real sigue
funcionando. Al final se verifica que todo hallazgo emite un ``evidence_kind``
conocido por ``core.param_semantics`` (HARD o SOFT).
"""

import json
import re
from http.cookies import Morsel
from typing import Any

import pytest
from conftest import MockScanner, param_value

from web_security_scanner.core.param_semantics import (
    HARD_EVIDENCE_KINDS,
    SOFT_EVIDENCE_KINDS,
)
from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.access_control_tester_async import (
    AccessControlTester,
)
from web_security_scanner.modules.vulnerability_testers.account_enum_async import (
    AccountEnumerationTester,
)
from web_security_scanner.modules.vulnerability_testers.brute_force_detector_async import (
    BruteForceDetector,
)
from web_security_scanner.modules.vulnerability_testers.cookie_analyzer_async import (
    CookieAnalyzer,
)
from web_security_scanner.modules.vulnerability_testers.cors_misconfig_async import (
    CorsMisconfigTester,
)
from web_security_scanner.modules.vulnerability_testers.credential_exposure_tester_async import (
    CredentialExposureTester,
)
from web_security_scanner.modules.vulnerability_testers.csrf_tester_async import CSRFTester
from web_security_scanner.modules.vulnerability_testers.file_upload_tester_async import (
    FileUploadTester,
)
from web_security_scanner.modules.vulnerability_testers.header_security_async import (
    HeaderSecurityTester,
)
from web_security_scanner.modules.vulnerability_testers.idor_tester_async import IDORTester
from web_security_scanner.modules.vulnerability_testers.jwt_tester_async import JwtAttackTester
from web_security_scanner.modules.vulnerability_testers.prototype_pollution_async import (
    PrototypePollutionTester,
)

KNOWN_KINDS = HARD_EVIDENCE_KINDS | SOFT_EVIDENCE_KINDS
ALL_FINDINGS: list[dict] = []


# ---- infraestructura común ---------------------------------------------------

def _morsel(key: str, value: str, *, samesite: str | None = None,
            secure: bool = False, domain: str = "") -> Morsel:
    m: Morsel = Morsel()
    m.set(key, value, value)
    if samesite is not None:
        m["samesite"] = samesite
    m["secure"] = secure
    if domain:
        m["domain"] = domain
    return m


class _FakeJar:
    def __init__(self, morsels):
        self._morsels = list(morsels)

    def __iter__(self):
        return iter(self._morsels)


class _FakeSession:
    def __init__(self, morsels):
        self.cookie_jar = _FakeJar(morsels)


async def _run(tester_cls, responder, target: str, *, cookies=None,
               scanner_attrs: dict[str, Any] | None = None,
               config: dict[str, Any] | None = None, targets=None,
               **run_kwargs) -> tuple[list[dict], list[str]]:
    em = ScanEventEmitter()
    found: list[dict] = []
    logs: list[str] = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k.get("vulnerability")))
    em.on(ScanEventType.LOG_MESSAGE, lambda **k: logs.append(str(k.get("message"))))
    scanner = MockScanner(responder)
    if cookies is not None:
        scanner.session = _FakeSession(cookies)  # type: ignore[attr-defined]
    for name, value in (scanner_attrs or {}).items():
        setattr(scanner, name, value)
    cfg: dict[str, Any] = {"payload_delay": 0, "max_payloads": 8}
    cfg.update(config or {})
    tester = tester_cls(scanner, em, cfg)
    for url in (targets or [target]):
        await tester.run_test(url, **run_kwargs)
    ALL_FINDINGS.extend(found)
    return found, logs


# ---- CORS --------------------------------------------------------------------

async def test_cors_comodin_con_credenciales_no_se_reporta():
    """``ACAO: *`` + credenciales: el navegador lo rechaza, no es explotable."""
    def r(m, u, kw):
        return {"headers": {"Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Credentials": "true"}}
    found, _ = await _run(CorsMisconfigTester, r, "http://target/api")
    assert found == []


async def test_cors_canario_aleatorio_por_ejecucion():
    """Cada ejecución usa un origen distinto: una lista blanca estática no
    puede coincidir por casualidad, y el reflejo es evidencia ``canary``."""
    seen: list[str] = []

    def r(m, u, kw):
        origin = kw.get("headers", {}).get("Origin", "")
        seen.append(origin)
        return {"headers": {"Access-Control-Allow-Origin": origin,
                            "Access-Control-Allow-Credentials": "true"}}
    found, _ = await _run(CorsMisconfigTester, r, "http://target/api",
                          targets=["http://target/a", "http://target/b"])
    canaries = {o for o in seen if o != "null"}
    assert len(canaries) == 2
    kinds = {f["payload"].split(": ", 1)[1]: f["evidence_kind"] for f in found}
    assert kinds["null"] == "reflection"
    assert all(kind == "canary" for origin, kind in kinds.items() if origin != "null")


# ---- Enumeración de cuentas ------------------------------------------------------

LOGIN_FORM = {"action": "http://target/login", "fields": {"username": "", "password": ""}}


async def test_enum_limite_de_tasa_a_mitad_no_es_canal_lateral():
    """El bloqueo (429) a partir de la 4.ª petición no debe leerse como
    diferencia de estado entre usuarios."""
    calls = {"n": 0}

    def r(m, u, kw):
        calls["n"] += 1
        if calls["n"] > 3:
            return {"status_code": 429, "text": "slow down"}
        return {"status_code": 200, "text": "Invalid credentials"}
    found, _ = await _run(AccountEnumerationTester, r, "http://target/login", form=LOGIN_FORM)
    assert found == []


async def test_enum_eco_del_usuario_no_es_canal_lateral():
    """El servidor solo repite el nombre enviado: misma plantilla para todos."""
    def r(m, u, kw):
        user = kw.get("data", {}).get("username", "")
        return {"status_code": 200, "text": f"Login failed for {user}. Try again."}
    found, _ = await _run(AccountEnumerationTester, r, "http://target/login", form=LOGIN_FORM)
    assert found == []


async def test_enum_nonce_dinamico_no_es_canal_lateral():
    """Un nonce por petición baja la similitud de *todas* las parejas: el
    suelo de ruido medido lo absorbe."""
    calls = {"n": 0}

    def r(m, u, kw):
        calls["n"] += 1
        nonce = f"{calls['n'] * 7919:08x}" * 3
        return {"status_code": 200, "text": f"Invalid credentials <input value='{nonce}'>"}
    found, _ = await _run(AccountEnumerationTester, r, "http://target/login", form=LOGIN_FORM)
    assert found == []


async def test_enum_mensaje_distinto_con_ruido_sigue_detectandose():
    calls = {"n": 0}

    def r(m, u, kw):
        calls["n"] += 1
        user = kw.get("data", {}).get("username", "")
        msg = ("The password you entered for this account is incorrect."
               if user == "admin" else "We could not find any account with that username, sorry!")
        return {"status_code": 200, "text": f"<p>{msg}</p><i>{calls['n']:04d}</i>"}
    found, _ = await _run(AccountEnumerationTester, r, "http://target/login", form=LOGIN_FORM)
    assert len(found) == 1
    assert found[0]["confidence"] == "MEDIUM"
    assert found[0]["evidence_kind"] == "differential"


# ---- JWT ---------------------------------------------------------------------

def _jwt() -> str:
    import base64

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'HS256'})}.{seg({'sub': '1', 'exp': 9999999999})}.sig"


async def test_jwt_endpoint_que_ignora_el_token_no_se_reporta():
    """Endpoint público (o autenticado por cookie): acepta hasta un bearer
    que no es JWT, así que aceptar el token forjado no prueba nada."""
    def r(m, u, kw):
        return {"status_code": 200, "text": '{"public": true}'}
    found, logs = await _run(JwtAttackTester, r, "http://target/api/me",
                             scanner_attrs={"_auth_headers": {}}, token=_jwt())
    assert found == []
    assert any("does not validate the token" in m for m in logs)


async def test_jwt_baseline_rechazado_no_se_prueba():
    def r(m, u, kw):
        return {"status_code": 401, "text": "expired"}
    found, _ = await _run(JwtAttackTester, r, "http://target/api/me",
                          scanner_attrs={"_auth_headers": {}}, token=_jwt())
    assert found == []


# ---- Prototype pollution --------------------------------------------------------

async def test_pp_parser_que_rechaza_la_clave_proto_no_se_reporta():
    """``secure-json-parse`` y similares devuelven 500 ante cualquier clave
    ``__proto__``: es una defensa, no una contaminación."""
    def r(m, u, kw):
        if "__proto__" in u:
            return {"status_code": 500, "text": "Object contains forbidden prototype property"}
        return {"status_code": 200, "text": "ok"}
    found, logs = await _run(PrototypePollutionTester, r, "http://target/api",
                             accepts_json_body=False)
    assert found == []
    assert any("key name itself is rejected" in m for m in logs)


async def test_pp_contaminacion_persistente_es_confirmada():
    """Tras contaminar toString, incluso la petición limpia falla: estado
    global corrompido -> CONFIRMED con evidencia dura."""
    state = {"polluted": False}

    def r(m, u, kw):
        if "__proto__[toString]" in u:
            state["polluted"] = True
        if state["polluted"]:
            return {"status_code": 500, "text": "TypeError: x.toString is not a function"}
        return {"status_code": 200, "text": "ok"}
    found, _ = await _run(PrototypePollutionTester, r, "http://target/api",
                          accepts_json_body=False)
    assert len(found) == 1
    assert found[0]["confidence"] == "CONFIRMED"
    assert found[0]["evidence_kind"] == "interpreter_error"


async def test_pp_solo_500_sin_firma_es_evidencia_blanda():
    def r(m, u, kw):
        if "__proto__[toString]" in u:
            return {"status_code": 500, "text": "Internal Server Error"}
        return {"status_code": 200, "text": "ok"}
    found, _ = await _run(PrototypePollutionTester, r, "http://target/api",
                          accepts_json_body=False)
    assert len(found) == 1
    assert found[0]["confidence"] == "MEDIUM"
    assert found[0]["evidence_kind"] == "status_change"


# ---- IDOR --------------------------------------------------------------------------

async def test_idor_id_corto_como_subcadena_no_eleva_confianza():
    """El id "1" aparece en fechas y precios: antes promovía a CONFIRMED."""
    def r(m, u, kw):
        idv = param_value(u, "id")
        if idv == "benign_baseline_123":
            return {"status_code": 200, "text": "profile baseline"}
        return {"status_code": 200,
                "text": "email someone@corp.com updated 2021-11-12 price 19.99 " + "x" * 80}
    found, _ = await _run(IDORTester, r, "http://target/page?id=7")
    assert len(found) == 1
    assert found[0]["confidence"] == "MEDIUM"


async def test_idor_solo_palabras_de_menu_es_low():
    """'account'/'profile' en la navegación no son datos de un objeto."""
    def r(m, u, kw):
        idv = param_value(u, "id")
        if idv == "benign_baseline_123":
            return {"status_code": 200, "text": "nothing"}
        return {"status_code": 200,
                "text": "<nav>My account | Edit profile</nav> product " + idv + " " + "z" * 80}
    found, _ = await _run(IDORTester, r, "http://target/page?id=7")
    assert len(found) == 1
    assert found[0]["confidence"] == "LOW"


async def test_idor_pagina_de_contacto_con_buzones_genericos_no_es_feed():
    def r(m, u, kw):
        return {"status_code": 200,
                "text": "support@corp.com sales@corp.com info@corp.com logo@2x.png"}
    found, _ = await _run(IDORTester, r, "http://target/contact")
    assert found == []


async def test_idor_feed_json_con_dos_usuarios_es_medium():
    def r(m, u, kw):
        return {"status_code": 200, "headers": {"Content-Type": "application/json"},
                "text": '[{"email": "ana@corp.com"}, {"email": "luis@corp.com"}]'}
    found, _ = await _run(IDORTester, r, "http://target/api/users")
    assert len(found) == 1
    assert found[0]["confidence"] == "MEDIUM"
    assert found[0]["evidence_kind"] == "reflection"


async def test_idor_feed_texto_con_dos_usuarios_es_low():
    def r(m, u, kw):
        return {"status_code": 200, "text": "Autores: ana@corp.com, luis@corp.com"}
    found, _ = await _run(IDORTester, r, "http://target/blog")
    assert len(found) == 1
    assert found[0]["confidence"] == "LOW"


# ---- Control de acceso -------------------------------------------------------------

async def test_acceso_sin_cookie_se_omite_en_escaneo_autenticado():
    """aiohttp añade las cookies del jar aunque se pase ``Cookie: ""``: en un
    escaneo autenticado la sonda "sin cookie" va autenticada."""
    def r(m, u, kw):
        if u == "http://target/profile":
            return {"status_code": 200, "text": '{"email": "a@corp.com"}'}
        return {"status_code": 404, "text": "not found"}
    found, _ = await _run(AccessControlTester, r, "http://target/profile",
                          scanner_attrs={"_session_manager": object()})
    assert not any(f["parameter"] == "<no-cookie>" for f in found)


async def test_verb_tampering_pagina_de_denegacion_con_200_no_es_bypass():
    denial = "Forbidden: you do not have permission to view this resource here."

    def r(m, u, kw):
        if m == "GET" and not kw.get("headers"):
            return {"status_code": 403, "text": denial}
        return {"status_code": 200, "text": denial + " "}
    found, _ = await _run(AccessControlTester, r, "http://target/private")
    assert not any("verb-tamper" in f["payload"] for f in found)


async def test_forced_browsing_firma_de_fichero_es_high():
    def r(m, u, kw):
        if u.endswith("/.git/config"):
            return {"status_code": 200,
                    "text": "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"}
        return {"status_code": 404, "text": "not found"}
    found, _ = await _run(AccessControlTester, r, "http://target/page")
    hits = [f for f in found if f["url"].endswith("/.git/config")]
    assert len(hits) == 1
    assert hits[0]["confidence"] == "HIGH"


# ---- CSRF ----------------------------------------------------------------------------

async def test_csrf_formulario_get_de_filtro_no_se_reporta():
    """Formulario GET idempotente (filtro de catálogo) con campos que no son
    de la lista de solo-lectura: antes se marcaba como CSRF."""
    def r(m, u, kw):
        return {"text": '<form method="GET" action="/catalog">'
                        '<input name="category"><input name="year"></form>'}
    found, _ = await _run(CSRFTester, r, "http://target/page")
    assert found == []


async def test_csrf_formulario_get_con_textarea_si_se_reporta():
    def r(m, u, kw):
        return {"text": '<form method="GET" action="/guestbook">'
                        '<textarea name="entry"></textarea></form>'}
    found, _ = await _run(CSRFTester, r, "http://target/page")
    assert len(found) == 1


async def test_csrf_cookie_samesite_lax_mitiga():
    def r(m, u, kw):
        return {"text": '<form method="POST" action="/transfer"><input name="amount"></form>'}
    found, _ = await _run(CSRFTester, r, "http://target/page",
                          cookies=[_morsel("sessionid", "x", samesite="Lax", secure=True)])
    assert len(found) == 1
    assert (found[0]["severity"], found[0]["confidence"]) == ("Low", "LOW")


async def test_csrf_token_en_meta_baja_confianza():
    def r(m, u, kw):
        return {"text": '<meta name="csrf-token" content="abc">'
                        '<form method="POST" action="/transfer"><input name="amount"></form>'}
    found, _ = await _run(CSRFTester, r, "http://target/page")
    assert found[0]["confidence"] == "LOW"


async def test_csrf_formulario_login_es_login_csrf_low():
    def r(m, u, kw):
        return {"text": '<form method="POST" action="/login"><input name="user">'
                        '<input name="pw" type="password"></form>'}
    found, _ = await _run(CSRFTester, r, "http://target/page")
    assert found[0]["severity"] == "Low"


async def test_csrf_enlace_externo_de_baja_no_se_reporta():
    def r(m, u, kw):
        return {"text": '<a href="https://mailer.example.net/unsubscribe?u=1">Unsubscribe</a>'}
    found, _ = await _run(CSRFTester, r, "http://target/page")
    assert found == []


async def test_csrf_samesite_ausente_se_reporta_una_vez_por_escaneo():
    def r(m, u, kw):
        return {"text": "<p>no forms</p>"}
    found, _ = await _run(CSRFTester, r, "http://target/a",
                          cookies=[_morsel("sessionid", "x")],
                          targets=["http://target/a", "http://target/b", "http://target/c"])
    assert len([f for f in found if "SameSite" in f["evidence"]]) == 1


# ---- Subida de ficheros ---------------------------------------------------------------

UPLOAD_FORM = {"action": "http://target/upload", "file_field": "avatar"}


def _marker_from(kw) -> str:
    for _opts, _hdrs, value in getattr(kw.get("data"), "_fields", []):
        if isinstance(value, bytes):
            match = re.search(rb"WSS_UPLOAD_[0-9a-f]+", value)
            if match:
                return match.group(0).decode()
    return ""


async def test_upload_enlace_a_otra_pagina_no_es_el_fichero_subido():
    """La respuesta enlaza ``index.html`` (HTML cualquiera): antes se tomaba
    como fichero subido y ``text/html`` bastaba para HIGH."""
    def r(m, u, kw):
        if m == "POST":
            return {"status_code": 200, "text": '<a href="/index.html">home</a>'}
        return {"status_code": 200, "text": "<html>home</html>",
                "headers": {"Content-Type": "text/html"}}
    found, _ = await _run(FileUploadTester, r, "http://target/upload", form=UPLOAD_FORM)
    assert all(f["confidence"] == "LOW" for f in found)
    accepted = [f for f in found if "reachability not confirmed" in f["evidence"]]
    assert len(accepted) == 1  # agregado: un hallazgo, no uno por variante


async def test_upload_servido_como_texto_inerte_es_low():
    store = {"marker": ""}

    def r(m, u, kw):
        if m == "POST":
            store["marker"] = _marker_from(kw) or store["marker"]
            return {"status_code": 200, "text": '<a href="/uploads/shell.php">ok</a>'}
        return {"status_code": 200, "text": f"<?php echo '{store['marker']}'; ?>",
                "headers": {"Content-Type": "text/plain"}}
    found, _ = await _run(FileUploadTester, r, "http://target/upload", form=UPLOAD_FORM)
    served = [f for f in found if "served back" in f["evidence"]]
    assert served and all(f["confidence"] == "LOW" for f in served)


@pytest.mark.parametrize("attrs", [{}, {"_session_manager": object(),
                                        "_auth_headers": {"Authorization": "Bearer t"}}])
async def test_upload_sin_auth_no_medible_se_omite(attrs):
    """Escaneo anónimo (sin línea base autenticada) o sesión por cookie (no
    se puede quitar del jar): la sonda sin auth no significa nada."""
    def r(m, u, kw):
        return {"status_code": 200, "text": "upload ok"}
    found, _ = await _run(FileUploadTester, r, "http://target/upload",
                          scanner_attrs=attrs, form=UPLOAD_FORM)
    assert not any("no session/auth" in f["evidence"] for f in found)


# ---- Cabeceras de seguridad ------------------------------------------------------------

async def test_cabeceras_de_documento_no_aplican_a_css():
    def r(m, u, kw):
        return {"status_code": 200, "headers": {"Content-Type": "text/css"}, "text": "a{}"}
    found, _ = await _run(HeaderSecurityTester, r, "https://target/site.css")
    assert {f["payload"] for f in found} == {"X-Content-Type-Options"}


async def test_cabeceras_peticion_fallida_no_reporta_nada():
    def r(m, u, kw):
        return {"status_code": 0, "error": "timeout", "headers": {}}
    found, _ = await _run(HeaderSecurityTester, r, "https://target/")
    assert found == []


async def test_cabeceras_server_sin_version_no_es_divulgacion():
    base = {"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=63072000"}

    def r_plain(m, u, kw):
        return {"status_code": 200, "headers": {**base, "Server": "cloudflare"}}

    def r_version(m, u, kw):
        return {"status_code": 200, "headers": {**base, "Server": "nginx/1.18.0"}}
    assert (await _run(HeaderSecurityTester, r_plain, "https://target/"))[0] == []
    found, _ = await _run(HeaderSecurityTester, r_version, "https://target/")
    assert [f["payload"] for f in found] == ["Server"]


async def test_hsts_ausente_en_http_plano_es_low():
    def r(m, u, kw):
        return {"status_code": 200, "headers": {"Content-Type": "text/html"}}
    found, _ = await _run(HeaderSecurityTester, r, "http://target/")
    hsts = [f for f in found if f["payload"] == "Strict-Transport-Security"]
    assert hsts and hsts[0]["confidence"] == "LOW"


# ---- Análisis de cookies -----------------------------------------------------------------

@pytest.mark.parametrize("morsel", [
    _morsel("connect.sid", "s:admin.Xk2pQ9vL0rT4mN8bW1yZ7cD3fG6hJ5aS"),  # firmada
    _morsel("last_page", "/admin/users"),                                 # ruta
    _morsel("_ga", "GA1.2.admin.1700000000"),                             # analítica
    _morsel("role", "admin", domain="other.example"),                     # otro host
])
async def test_cookie_trampas_no_se_reportan(morsel):
    def r(m, u, kw):
        return {"text": "ok"}
    found, _ = await _run(CookieAnalyzer, r, "http://target/page", cookies=[morsel])
    assert found == []


async def test_cookie_dos_indicios_es_medium_uno_es_low():
    def r(m, u, kw):
        return {"text": "ok"}
    found, _ = await _run(CookieAnalyzer, r, "http://target/page",
                          cookies=[_morsel("GRUYERE", "51292534|pepe||author")])
    assert found[0]["confidence"] == "MEDIUM"
    found, _ = await _run(CookieAnalyzer, r, "http://other/page",
                          cookies=[_morsel("sess", "x|42|y")])
    assert found[0]["confidence"] == "LOW"


# ---- Exposición de credenciales -------------------------------------------------------------

@pytest.mark.parametrize("body", [
    "password: 'Password'",                               # etiqueta de UI
    "password = \"changeme\"",                            # marcador
    "api_key: 'YOUR_API_KEY_HERE_0000'",                  # plantilla
    "aws_key = AKIAIOSFODNN7EXAMPLE",                     # clave de la documentación AWS
    "const PEM = '-----BEGIN RSA PRIVATE KEY-----';",     # cabecera sin cuerpo
    "mongodb://user:pass@localhost/db",                   # cadena de ejemplo
])
async def test_credenciales_trampas_no_se_reportan(body):
    def r(m, u, kw):
        return {"status_code": 200, "text": body}
    found, _ = await _run(CredentialExposureTester, r, "http://target/app.js")
    assert found == []


async def test_credenciales_clave_privada_con_cuerpo_es_high():
    key = ("-----BEGIN RSA PRIVATE KEY-----\n"
           "MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9Oi7Z0qDZJb5rY9xW1Ji4y8eQ4pUq0F\n"
           "x2Yk7LmQ9cVb3nR1tZ8wK5pH6sD4fG2jA0==\n-----END RSA PRIVATE KEY-----")

    def r(m, u, kw):
        return {"status_code": 200, "text": key}
    found, _ = await _run(CredentialExposureTester, r, "http://target/app.js")
    assert len(found) == 1
    assert found[0]["confidence"] == "HIGH"
    assert "MIIE" not in found[0]["evidence"]  # nunca se copia el secreto


async def test_credenciales_asignacion_generica_es_medium_y_enmascarada():
    def r(m, u, kw):
        return {"status_code": 200, "text": "db_password = 'q7#Vt9!zLm2@'"}
    found, _ = await _run(CredentialExposureTester, r, "http://target/app.js")
    assert len(found) == 1
    assert (found[0]["confidence"], found[0]["severity"]) == ("MEDIUM", "High")
    assert "q7#Vt9!zLm2@" not in found[0]["evidence"]


async def test_formulario_get_con_campo_passenger_no_es_login():
    def r(m, u, kw):
        return {"status_code": 200,
                "text": '<form method="GET" action="/flights"><input name="passenger"></form>'}
    found, _ = await _run(CredentialExposureTester, r, "http://target/flights")
    assert found == []


# ---- Fuerza bruta ---------------------------------------------------------------------------

async def test_fuerza_bruta_csrf_caducado_no_concluye():
    """Todas las peticiones rebotan con 403 (token CSRF caducado): la lógica
    de login nunca se ejecutó, la ausencia de bloqueo no prueba nada."""
    def r(m, u, kw):
        return {"status_code": 403, "text": "CSRF token mismatch"}
    found, logs = await _run(BruteForceDetector, r, "http://target/login",
                             form={"action": "http://target/login",
                                   "fields": {"username": "a", "password": "x"}})
    assert found == []
    assert any("inconclusive" in m for m in logs)


async def test_fuerza_bruta_pocos_intentos_es_low():
    def r(m, u, kw):
        return {"status_code": 200, "text": "invalid credentials"}
    found, _ = await _run(BruteForceDetector, r, "http://target/login",
                          config={"brute_force_attempts": 4},
                          form={"action": "http://target/login",
                                "fields": {"username": "a", "password": "x"}})
    assert len(found) == 1
    assert found[0]["confidence"] == "LOW"
    assert found[0]["evidence_kind"] == "differential"


# ---- Taxonomía de evidencia (debe ejecutarse al final del módulo) --------------------------

def test_todo_hallazgo_emite_un_evidence_kind_conocido():
    assert ALL_FINDINGS, "los tests anteriores deberían haber emitido hallazgos"
    unknown = [(f.get("type"), f.get("evidence_kind")) for f in ALL_FINDINGS
               if f.get("evidence_kind") not in KNOWN_KINDS]
    assert unknown == []
