"""Compuerta de alcanzabilidad del sink (CRLF / open redirect).

Un CRLF solo puede partir cabeceras si el valor del parametro acaba en una
cabecera de respuesta; un open redirect solo si llega a un destino de
redireccion. Si un canario benigno no llega, el resto de payloads no puede
producir la senal del detector y se saltan.
"""

from conftest import collect_vulns, param_value

from web_security_scanner.modules.vulnerability_testers.crlf_async import (
    MARKER_HEADER,
    CRLFTester,
)
from web_security_scanner.modules.vulnerability_testers.open_redirect_async import (
    MARKER,
    OpenRedirectTester,
)

URL = "http://target/page?q=1"


def _counting(responder):
    calls = {"n": 0}

    def r(m, u, kw):
        calls["n"] += 1
        return responder(m, u, kw)
    return r, calls


async def test_crlf_punto_sin_reflejo_en_cabeceras_se_salta():
    r, calls = _counting(lambda m, u, kw: {"status_code": 200, "text": "ok", "headers": {}})
    assert await collect_vulns(CRLFTester, r, target=URL) == []
    assert calls["n"] <= 2  # solo la sonda canario (y como mucho una baseline)


async def test_crlf_punto_que_refleja_en_cabecera_se_sigue_probando():
    def r(m, u, kw):
        v = param_value(u, "q")
        headers = {"X-Echo": v.split("\r")[0].split("\n")[0]}
        if f"{MARKER_HEADER}:" in v:
            headers[MARKER_HEADER] = v.split(f"{MARKER_HEADER}:")[1].strip()
        return {"status_code": 200, "text": "ok", "headers": headers}
    found = await collect_vulns(CRLFTester, r, target=URL)
    assert found


async def test_crlf_ablation_restaura_el_barrido_completo():
    r, calls = _counting(lambda m, u, kw: {"status_code": 200, "text": "ok", "headers": {}})
    await collect_vulns(CRLFTester, r, target=URL, config={"sink_gate": False})
    assert calls["n"] > 2


async def test_redirect_punto_que_no_redirige_se_salta():
    r, calls = _counting(lambda m, u, kw: {"status_code": 200, "text": "hola", "headers": {}})
    assert await collect_vulns(OpenRedirectTester, r, target=URL) == []
    assert calls["n"] <= 2


async def test_redirect_punto_que_redirige_se_sigue_probando():
    def r(m, u, kw):
        return {"status_code": 302, "text": "", "headers": {"Location": param_value(u, "q")}}
    found = await collect_vulns(OpenRedirectTester, r, target=URL)
    assert found and MARKER in found[0]["payload"]


async def test_redirect_fallo_de_transporte_no_cierra_la_compuerta():
    r, calls = _counting(lambda m, u, kw: {"status_code": 0, "text": "", "headers": {}})
    await collect_vulns(OpenRedirectTester, r, target=URL)
    assert calls["n"] > 2
