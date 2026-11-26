"""Etiquetado ``evidence_kind`` (HARD / SOFT) en los testers de inyección.

Cada tester declara *por qué* disparó para que la política de parámetros de
flow-control (``core.param_semantics``) pueda distinguir evidencia causal
(HARD: ejecución observada, canario renderizado, error de intérprete, timing
confirmado) de mera divergencia o eco (SOFT: reflejo, timing no reproducido).

Por tester se cubre al menos:

* un positivo HARD con la etiqueta correcta;
* un caso SOFT (confianza/severidad rebajadas) o un negativo;
* y, donde aporta, la interacción con el gate sobre un parámetro de
  flow-control (``next`` / ``url`` / ``redirect_uri`` ...): SOFT se descarta,
  HARD se conserva con la severidad capada salvo CONFIRMED de grado ejecución.
"""

from conftest import MockScanner, collect_vulns, param_value

from web_security_scanner.core.param_semantics import (
    HARD_EVIDENCE_KINDS,
    SOFT_EVIDENCE_KINDS,
)
from web_security_scanner.core.payload_loader import WSS_CANARY
from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.command_injection_async import (
    CommandInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.crlf_async import CRLFTester
from web_security_scanner.modules.vulnerability_testers.deserialization_async import (
    DeserializationTester,
)
from web_security_scanner.modules.vulnerability_testers.log4shell_async import (
    Log4ShellTester,
)
from web_security_scanner.modules.vulnerability_testers.open_redirect_async import (
    OpenRedirectTester,
)
from web_security_scanner.modules.vulnerability_testers.path_traversal_async import (
    PathTraversalTester,
)
from web_security_scanner.modules.vulnerability_testers.protocol_injection_tester_async import (
    ProtocolInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.ssrf_tester_async import SSRFTester
from web_security_scanner.modules.vulnerability_testers.ssti_async import PRODUCT, SSTITester
from web_security_scanner.modules.vulnerability_testers.stored_xss_tester_async import (
    StoredXSSTester,
)
from web_security_scanner.modules.vulnerability_testers.xss_tester_async import XSSTester
from web_security_scanner.modules.vulnerability_testers.xssi_tester_async import XSSITester
from web_security_scanner.modules.vulnerability_testers.xxe_tester_async import XXETester

PASSWD = "root:x:0:0:root:/root:/bin/bash"


async def _run(tester_cls, responder, target, *, payloads=None, form=None, config=None):
    """Ejecuta un tester contra MockScanner, opcionalmente con payloads fijos.

    Fijar ``payloads`` aísla el test del corpus curado (cuyo orden y tamaño
    pueden cambiar) cuando lo que se prueba es la clasificación de una ruta.
    """
    em = ScanEventEmitter()
    found = []
    em.on(ScanEventType.VULNERABILITY_FOUND,
          lambda **k: found.append(k.get("vulnerability")))
    cfg = {"payload_delay": 0, "max_payloads": 8}
    if config:
        cfg.update(config)
    tester = tester_cls(MockScanner(responder), em, cfg)
    if payloads is not None:
        tester.payloads = list(payloads)
    if form is not None:
        await tester.run_test(target, form=form)
    else:
        await tester.run_test(target)
    return found


def test_las_etiquetas_usadas_existen_en_param_semantics():
    """Ningún tester puede inventar un kind: todos deben estar ya definidos."""
    usados_hard = {"canary", "code_execution", "interpreter_error",
                   "time_confirmed", "error_signature"}
    usados_soft = {"reflection", "time_unconfirmed"}
    assert usados_hard <= HARD_EVIDENCE_KINDS
    assert usados_soft <= SOFT_EVIDENCE_KINDS


# ---- XSS reflejado ---------------------------------------------------------

def _xss_reflector(content_type, param="q"):
    def r(m, u, kw):
        return {"text": f"<html><body>{param_value(u, param)}</body></html>",
                "headers": {"Content-Type": content_type}}
    return r


async def test_xss_reflejo_ejecutable_en_html_es_canary_hard():
    found = await _run(XSSTester, _xss_reflector("text/html"),
                       "http://target/s?q=1", payloads=["<script>alert(1)</script>"])
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "canary"
    assert found[0]["confidence"] == "HIGH"
    assert found[0]["severity"] == "High"


async def test_xss_reflejo_en_json_es_reflection_soft():
    found = await _run(XSSTester, _xss_reflector("application/json"),
                       "http://target/s?q=1", payloads=["<script>alert(1)</script>"])
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "reflection"
    assert found[0]["confidence"] == "LOW"
    assert found[0]["severity"] == "Low"


async def test_xss_reflejo_soft_en_next_se_descarta():
    found = await _run(XSSTester, _xss_reflector("application/json", "next"),
                       "http://target/login?next=/home",
                       payloads=["<script>alert(1)</script>"])
    assert found == []


async def test_xss_canary_en_next_se_conserva_capado():
    found = await _run(XSSTester, _xss_reflector("text/html", "next"),
                       "http://target/login?next=/home",
                       payloads=["<script>alert(1)</script>"])
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "canary"
    assert found[0]["severity"] == "Medium"


async def test_xss_reflejo_escapado_no_se_reporta():
    def r(m, u, kw):
        return {"text": "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>",
                "headers": {"Content-Type": "text/html"}}
    assert await _run(XSSTester, r, "http://target/s?q=1",
                      payloads=["<script>alert(1)</script>"]) == []


# ---- XSS almacenado --------------------------------------------------------

def _stored_app(template):
    store = {"comment": ""}

    def r(m, u, kw):
        if m == "POST":
            store["comment"] = (kw.get("data") or {}).get("comment", "")
            return {"text": "saved"}
        return {"text": template.format(store["comment"])}
    return r


_FORM = {"action": "http://target/post", "fields": {"comment": "hi"}}
_STORED_PAYLOAD = "<script>alert('wssStoredXSS')</script>"


async def test_stored_xss_en_cuerpo_html_es_canary_hard():
    found = await _run(StoredXSSTester, _stored_app("<html>c: {}</html>"),
                       "http://target/post", payloads=[_STORED_PAYLOAD], form=_FORM)
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "canary"
    assert found[0]["confidence"] == "HIGH"


async def test_stored_xss_dentro_de_textarea_es_reflection_soft():
    """Persistido en crudo pero en contexto RCDATA inerte: no se ejecuta."""
    found = await _run(StoredXSSTester,
                       _stored_app("<html><textarea>{}</textarea></html>"),
                       "http://target/post", payloads=[_STORED_PAYLOAD], form=_FORM)
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "reflection"
    assert found[0]["confidence"] == "LOW"
    assert found[0]["severity"] == "Low"


# ---- SSTI ------------------------------------------------------------------

async def test_ssti_expresion_evaluada_es_code_execution():
    def r(m, u, kw):
        q = param_value(u, "q")
        if "1338*1337" in q:
            return {"text": f"<h1>Hola {PRODUCT}</h1>"}
        return {"text": f"<h1>Hola {q}</h1>"}

    found = await collect_vulns(SSTITester, r, target="http://target/p?q=1")
    assert found
    assert found[0]["evidence_kind"] == "code_execution"
    assert found[0]["confidence"] == "CONFIRMED"


async def test_ssti_confirmado_en_redirect_param_no_se_capa():
    """code_execution CONFIRMED es de grado ejecución: el cap se renuncia."""
    def r(m, u, kw):
        v = param_value(u, "next")
        if "1338*1337" in v:
            return {"text": f"ir a {PRODUCT}"}
        return {"text": f"ir a {v}"}

    found = await collect_vulns(SSTITester, r, target="http://target/l?next=/home")
    assert found
    assert found[0]["severity"] == "High"


async def test_ssti_eco_literal_no_se_reporta():
    def r(m, u, kw):
        return {"text": f"echo: {param_value(u, 'q')}"}
    assert await collect_vulns(SSTITester, r, target="http://target/p?q=1") == []


# ---- Command injection -----------------------------------------------------

class _CmdTesterLatenciaSimulada(CommandInjectionTester):
    """El tester usa la latencia de reloj de ``_timed_request``; aquí se toma
    la latencia simulada del ``elapsed`` de la respuesta del mock."""

    async def _timed_request(self, method, url, **kwargs):
        resp, _ = await super()._timed_request(method, url, **kwargs)
        return resp, float(resp.get("elapsed", 0) or 0)


async def test_cmdi_salida_de_comando_es_code_execution():
    def r(m, u, kw):
        if "passwd" in param_value(u, "q"):
            return {"text": PASSWD}
        return {"text": "ok"}

    found = await _run(CommandInjectionTester, r, "http://target/p?q=1",
                       payloads=["; cat /etc/passwd"])
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "code_execution"
    assert found[0]["severity"] == "Critical"


async def test_cmdi_error_de_shell_es_interpreter_error():
    def r(m, u, kw):
        if "wsscmd" in param_value(u, "q"):
            return {"text": "/bin/sh: 1: wsscmd: not found"}
        return {"text": "ok"}

    found = await _run(CommandInjectionTester, r, "http://target/p?q=1",
                       payloads=["; wsscmd"])
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "interpreter_error"


async def test_cmdi_timing_no_reproducido_es_soft_y_low():
    """Un pico de latencia que no se reproduce: time_unconfirmed, severidad Low."""
    state = {"slow_left": 1}

    def r(m, u, kw):
        if "sleep" in param_value(u, "q") and state["slow_left"] > 0:
            state["slow_left"] -= 1
            return {"text": "ok", "elapsed": 9.0}
        return {"text": "ok", "elapsed": 0.05}

    found = await _run(_CmdTesterLatenciaSimulada, r, "http://target/p?q=1",
                       payloads=["; sleep 5"])
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "time_unconfirmed"
    assert found[0]["severity"] == "Low"


async def test_cmdi_timing_no_reproducido_en_next_se_descarta():
    state = {"slow_left": 1}

    def r(m, u, kw):
        if "sleep" in param_value(u, "next") and state["slow_left"] > 0:
            state["slow_left"] -= 1
            return {"text": "ok", "elapsed": 9.0}
        return {"text": "ok", "elapsed": 0.05}

    assert await _run(_CmdTesterLatenciaSimulada, r, "http://target/l?next=/home",
                      payloads=["; sleep 5"]) == []


# ---- Path traversal --------------------------------------------------------

async def test_path_traversal_fichero_filtrado_es_canary():
    def r(m, u, kw):
        if "passwd" in param_value(u, "file"):
            return {"text": PASSWD}
        return {"text": "documento"}

    # /etc/passwd es destructivo ante un sink de escritura: solo con opt-in.
    found = await _run(PathTraversalTester, r, "http://target/d?file=a.pdf",
                       payloads=["../../../../etc/passwd"],
                       config={"allow_destructive": True})
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "canary"
    assert found[0]["confidence"] == "CONFIRMED"


async def test_path_traversal_confirmado_en_param_path_conserva_high():
    """``path`` es un nombre de flow-control; un canary CONFIRMED no se capa."""
    def r(m, u, kw):
        if "passwd" in param_value(u, "path"):
            return {"text": PASSWD}
        return {"text": "documento"}

    found = await _run(PathTraversalTester, r, "http://target/d?path=/docs/a",
                       payloads=["../../../../etc/passwd"],
                       config={"allow_destructive": True})
    assert len(found) == 1
    assert found[0]["severity"] == "High"


async def test_path_traversal_403_no_se_reporta():
    def r(m, u, kw):
        return {"status_code": 403, "text": "Forbidden: /etc/passwd"}
    assert await _run(PathTraversalTester, r, "http://target/d?file=a",
                      payloads=["../../../../etc/passwd"]) == []


# ---- XXE -------------------------------------------------------------------

async def test_xxe_entidad_resuelta_es_canary():
    def r(m, u, kw):
        body = kw.get("data") or b""
        if m == "POST" and b"file:///etc/passwd" in body:
            return {"text": f"<foo>{PASSWD}</foo>"}
        return {"text": "<ok/>"}

    found = await collect_vulns(XXETester, r, target="http://target/xml")
    assert found
    assert found[0]["evidence_kind"] == "canary"


async def test_xxe_sin_fuga_no_se_reporta():
    def r(m, u, kw):
        return {"text": "<error>DOCTYPE is not allowed</error>"}
    assert await collect_vulns(XXETester, r, target="http://target/xml") == []


# ---- SSRF ------------------------------------------------------------------

async def test_ssrf_confirmado_en_param_url_conserva_critical():
    def r(m, u, kw):
        if "169.254.169.254" in param_value(u, "url"):
            return {"text": "ami-id\ninstance-id\n"}
        return {"text": "preview"}

    found = await _run(SSRFTester, r, "http://target/fetch?url=https://a.example/",
                       payloads=["http://169.254.169.254/latest/meta-data/"])
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "canary"
    assert found[0]["confidence"] == "CONFIRMED"
    assert found[0]["severity"] == "Critical"


async def test_ssrf_contenido_ambiental_en_url_baja_a_medium_confianza():
    """La página ya contiene el indicador sin payload: el doble oráculo lo marca
    como ambiental (MEDIUM). SSRF está exento del gate por diseño (vive en
    parámetros de destino), así que la severidad no se toca: la señal de
    "no causal" va en la confianza."""
    def r(m, u, kw):
        return {"text": "docs: instance-id is shown in the console"}

    found = await _run(SSRFTester, r, "http://target/fetch?url=https://a.example/",
                       payloads=["http://169.254.169.254/latest/meta-data/"])
    assert len(found) == 1
    assert found[0]["confidence"] == "MEDIUM"
    assert found[0]["evidence_kind"] == "canary"


# ---- Open redirect ---------------------------------------------------------

async def test_open_redirect_location_controlado_es_canary_en_next():
    def r(m, u, kw):
        return {"status_code": 302, "headers": {"Location": param_value(u, "next")}}

    found = await collect_vulns(OpenRedirectTester, r,
                                target="http://target/login?next=/home")
    assert found
    assert found[0]["evidence_kind"] == "canary"
    assert found[0]["confidence"] == "CONFIRMED"


async def test_open_redirect_host_fijo_no_se_reporta():
    def r(m, u, kw):
        return {"status_code": 302, "headers": {"Location": "https://app.example/"}}
    assert await collect_vulns(OpenRedirectTester, r,
                               target="http://target/login?next=/home") == []


# ---- CRLF ------------------------------------------------------------------

async def test_crlf_cabecera_inyectada_es_canary():
    def r(m, u, kw):
        raw = param_value(u, "q")
        # Sink realista: el valor se escribe en una cabecera (Location).
        headers = {"Content-Type": "text/html",
                   "Location": raw.split("\r")[0].split("\n")[0]}
        if "\n" in raw:
            _, _, rest = raw.partition("\n")
            name, _, value = rest.partition(":")
            if name.strip():
                headers[name.strip()] = value.strip()
        return {"text": "ok", "headers": headers}

    found = await collect_vulns(CRLFTester, r, target="http://target/p?q=1")
    assert found
    assert found[0]["evidence_kind"] == "canary"
    assert WSS_CANARY in found[0]["evidence"]


async def test_crlf_eco_en_cuerpo_no_se_reporta():
    def r(m, u, kw):
        return {"text": f"dijiste {param_value(u, 'q')}"}
    assert await collect_vulns(CRLFTester, r, target="http://target/p?q=1") == []


# ---- Log4Shell -------------------------------------------------------------

async def test_log4shell_entrega_sin_evidence_kind():
    """Solo entrega OOB sin callback observado: no debe fingir ``oob``."""
    def r(m, u, kw):
        return {"text": "ok"}

    found = await collect_vulns(Log4ShellTester, r, target="http://target/p?q=1",
                                config={"oob_domain": "c.example-oob.invalid"})
    assert len(found) == 1
    assert "evidence_kind" not in found[0]
    assert found[0]["severity"] == "Info"


# ---- Deserialización -------------------------------------------------------

async def test_deserialization_firma_de_error_es_error_signature():
    def r(m, u, kw):
        return {"text": "java.io.InvalidClassException: local class incompatible"}

    found = await collect_vulns(DeserializationTester, r, target="http://target/p?q=1")
    assert found
    assert found[0]["evidence_kind"] == "error_signature"


async def test_deserialization_en_redirect_uri_se_capa_siempre():
    """error_signature nunca obtiene el bypass CONFIRMED del cap."""
    def r(m, u, kw):
        if param_value(u, "redirect_uri").startswith("benign"):
            return {"text": "ok"}
        return {"text": "java.io.StreamCorruptedException: invalid stream header"}

    found = await collect_vulns(DeserializationTester, r,
                                target="http://target/cb?redirect_uri=/home")
    assert found
    assert found[0]["evidence_kind"] == "error_signature"
    assert found[0]["severity"] == "Medium"


# ---- Protocol injection ----------------------------------------------------

def _profile_app():
    store = {"website": ""}

    def r(m, u, kw):
        if m == "POST":
            store["website"] = (kw.get("data") or {}).get("website", "")
            return {"text": "saved"}
        return {"text": f'<html><a href="{store["website"]}">web</a></html>'}
    return r


_PROFILE_FORM = {"action": "http://target/profile",
                 "fields": {"website": "https://example.com"}}


async def test_protocol_javascript_en_href_es_canary_hard():
    found = await _run(ProtocolInjectionTester, _profile_app(), "http://target/profile",
                       payloads=["javascript:alert(1)"], form=_PROFILE_FORM)
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "canary"
    assert found[0]["confidence"] == "HIGH"


async def test_protocol_file_en_href_es_reflection_soft():
    """Un ``file://`` en un enlace no ejecuta nada ni prueba un fetch del servidor."""
    found = await _run(ProtocolInjectionTester, _profile_app(), "http://target/profile",
                       payloads=["file:///etc/passwd"], form=_PROFILE_FORM)
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "reflection"
    assert found[0]["confidence"] == "LOW"
    assert found[0]["severity"] == "Low"


# ---- XSSI ------------------------------------------------------------------

_JS = {"Content-Type": "application/javascript"}


async def test_xssi_callback_como_wrapper_es_canary():
    def r(m, u, kw):
        cb = param_value(u, "cb")
        if cb:
            return {"text": f"/**/ {cb}({{}})", "headers": _JS}
        return {"text": "default({})", "headers": _JS}

    found = await collect_vulns(XSSITester, r, target="http://target/feed?uid=1")
    hits = [f for f in found if f.get("parameter") == "cb"]
    assert len(hits) == 1
    assert hits[0]["evidence_kind"] == "canary"
    assert hits[0]["confidence"] == "HIGH"


async def test_xssi_eco_fuera_del_wrapper_es_reflection_soft():
    def r(m, u, kw):
        cb = param_value(u, "cb")
        if cb:
            return {"text": f"default({{}}); // rejected callback {cb}(", "headers": _JS}
        return {"text": "default({})", "headers": _JS}

    found = await collect_vulns(XSSITester, r, target="http://target/feed?uid=1")
    hits = [f for f in found if f.get("parameter") == "cb"]
    assert len(hits) == 1
    assert hits[0]["evidence_kind"] == "reflection"
    assert hits[0]["confidence"] == "LOW"
    assert hits[0]["severity"] == "Low"


async def test_xssi_eco_soft_en_param_callback_se_mantiene_low():
    """``callback`` a secas es el nombre de función JSONP, no un destino de
    redirección: el gate de flow-control no aplica y el eco SOFT queda en LOW."""
    def r(m, u, kw):
        cb = param_value(u, "callback")
        if cb:
            return {"text": f"default({{}}); // rejected {cb}(", "headers": _JS}
        return {"text": "default({})", "headers": _JS}

    found = await collect_vulns(XSSITester, r, target="http://target/feed?uid=1")
    hits = [f for f in found if f.get("parameter") == "callback"]
    assert len(hits) == 1
    assert hits[0]["evidence_kind"] == "reflection"
    assert hits[0]["confidence"] == "LOW"
    assert "param_semantics_verdict" not in hits[0]


async def test_xssi_hallazgos_pasivos_no_llevan_evidence_kind():
    def r(m, u, kw):
        return {"text": '[{"email": "a@corp.com"}]',
                "headers": {"Content-Type": "application/json"}}

    found = await collect_vulns(XSSITester, r, target="http://target/api/users")
    assert len(found) == 1
    assert "evidence_kind" not in found[0]


async def test_path_traversal_contenido_codificado_en_html_se_detecta():
    """OWASP Benchmark devuelve el fichero pasado por ESAPI ``encodeForHTML``:
    ``root:x:0:0:`` llega como ``root&#x3a;x&#x3a;0&#x3a;0&#x3a;``."""
    encoded = PASSWD.replace(":", "&#x3a;").replace("/", "&#x2f;")

    def r(m, u, kw):
        if "passwd" in param_value(u, "file"):
            return {"text": f"The beginning of file is:\n\n{encoded}"}
        return {"text": "documento"}

    found = await _run(PathTraversalTester, r, "http://target/d?file=a.pdf",
                       payloads=["../../../../../../../../etc/passwd"],
                       config={"allow_destructive": True})
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "canary"
    assert found[0]["confidence"] == "CONFIRMED"
