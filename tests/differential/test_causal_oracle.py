"""Tests for the control-payload causality oracle.

Two invariants carry the whole mechanism and get the most attention here:

1. **A twin is always the same length as its payload.** A control of a
   different size moves the response length, which is the very quantity the
   false positives turn on, and the oracle would then "confirm" the effect it
   exists to explain away.
2. **Only an actively contradicting twin withholds a finding.** No twin, or an
   unreachable twin, keeps the pre-existing behaviour -- a control can
   falsify, it cannot fail to disprove and still delete a real detection.

Findings in this file are in Spanish by repo convention (``tests/``).
"""

from __future__ import annotations

import html
from urllib.parse import quote

import pytest

from web_security_scanner.core.causal_oracle import (
    _NOSQL_EQUALITY_OPPOSITES,
    CAUSAL_EVIDENCE_KIND,
    LDAP,
    NOSQL,
    SQLI,
    UNATTRIBUTED_EVIDENCE_KIND,
    CausalOracleMixin,
    _echo_forms,
    _numeric_entity_form,
    attribute_divergence,
    responses_equivalent,
    semantic_twin,
    twin_is_available,
)

# Payloads que deben tener control, con su gemelo esperado. Si una de estas
# lineas falla, la longitud o la familia del control han cambiado.
CONTROLLED: list[tuple[str, str, str]] = [
    # --- NoSQL: operador -> operador opuesto, misma longitud ---------------
    ("{'$gt':''}", NOSQL, "{'$lt':''}"),
    ("{'$ne':''}", NOSQL, "{'$eq':''}"),
    ("{'$eq':''}", NOSQL, "{'$ne':''}"),
    ("{'$lt':''}", NOSQL, "{'$gt':''}"),
    ('{"$gte":1}', NOSQL, '{"$lte":1}'),
    ("{'$exists':true}", NOSQL, "{'$exists':null}"),
    ("{'$regex':'.*'}", NOSQL, "{'$regex':'^$'}"),
    ("{'$where':'1==1'}", NOSQL, "{'$where':'1==0'}"),
    # --- NoSQL: forma de cadena -------------------------------------------
    ("' || '1'=='1", NOSQL, "' || '1'=='2"),
    ("admin' || '1'=='1", NOSQL, "admin' || '1'=='2"),
    # --- SQL: tautologia -> contradiccion, misma longitud ------------------
    ("' AND 1=1-- -", SQLI, "' AND 1=2-- -"),
    ("' OR 1=1-- -", SQLI, "' OR 1=2-- -"),
    ("' and 1=1#", SQLI, "' and 1=2#"),
    ("' AND 10=10-- ", SQLI, "' AND 10=11-- "),
    ("' OR '1'='1", SQLI, "' OR '1'='2"),
    ("' AND 'a'='a", SQLI, "' AND 'a'='b"),
    # --- LDAP: wildcard -> literal que no casa -----------------------------
    ("*)(uid=*", LDAP, "*)(uid=_"),
    ("*)(objectClass=*", LDAP, "*)(objectClass=_"),
    ("*))%00", LDAP, "_))%00"),
]

# Payloads SIN control. Todos son casos donde una inversion que conserve la
# longitud y la familia del payload no existe; ninguno puede perder un hallazgo
# por ello, porque la ausencia de control mantiene el comportamiento previo.
UNCONTROLLED: list[tuple[str, str]] = [
    ("' AND 1=2-- -", SQLI),      # ya es una contradiccion: ampliarla cambia el tamano
    ("' UNION SELECT 1,2-- -", SQLI),   # UNION no tiene inversion de igual longitud
    ("admin' AND SLEEP(5)#", SQLI),    # rama de tiempo, con su propio oraculo
    ("{'$in':[]}", NOSQL),        # $nin es un byte mas ancho: tabla asimetrica
    ("admin)(&))", LDAP),         # ningun wildcard token que invertir
    ("' OR 1=1 -- -", "UNKNOWN"),  # clase sin regla registrada
    ("", SQLI),
]


# --------------------------------------------------------------------------- #
# semantic_twin
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(("payload", "vuln_class", "expected"), CONTROLLED)
def test_twin_exacto(payload: str, vuln_class: str, expected: str) -> None:
    assert semantic_twin(payload, vuln_class) == expected


@pytest.mark.parametrize(("payload", "vuln_class", "expected"), CONTROLLED)
def test_twin_conserva_la_longitud(payload: str, vuln_class: str, expected: str) -> None:
    """La invariante que hace que el control sea un control y no una causa extra."""
    assert len(expected) == len(payload)


@pytest.mark.parametrize(("payload", "vuln_class", "expected"), CONTROLLED)
def test_twin_es_distinto_del_payload(payload: str, vuln_class: str, expected: str) -> None:
    assert expected != payload


@pytest.mark.parametrize(("payload", "vuln_class"), UNCONTROLLED)
def test_payload_sin_control_devuelve_none(payload: str, vuln_class: str) -> None:
    assert semantic_twin(payload, vuln_class) is None


def test_twin_preserva_el_prefijo_y_el_sufijo() -> None:
    """Solo cambia el operando: el resto del payload se conserva byte a byte."""
    payload = "' AND 1=1 AND 2=2-- -"
    twin = semantic_twin(payload, SQLI)
    assert twin is not None
    assert twin.startswith("' AND ")
    assert twin.endswith("-- -")
    # El primer operando de la izquierda no se toca; el derecho, si.
    assert twin[0:7] == payload[0:7]


def test_twin_de_ldap_toca_el_ultimo_wildcard() -> None:
    """``*)(uid=*`` invierte el cuantificador que introdujo el fragmento inyectado.

    Invertir el ``*`` inicial dejaria el valor original del parametro como
    ``uid=*`` y solo negaria el prefijo, que es la parte que la aplicacion
    controla. El ultimo es el que el fragmento inyectado anadio.
    """
    twin = semantic_twin("*)(uid=*", LDAP)
    assert twin == "*)(uid=_"
    assert twin[0] == "*"


def test_twin_no_toca_el_wildcard_dentro_de_un_identificador() -> None:
    """``a*b`` no es un wildcard de LDAP: no debe invertirse."""
    assert semantic_twin("a*b", LDAP) is None


def test_twin_de_no_sql_no_toca_una_clave_que_solo_contiene_operador() -> None:
    """Un ``$where`` dentro de un valor, no como operador, no habilita la regla."""
    assert semantic_twin("precio$where", NOSQL) is None


def test_clase_desconocida_no_invoca_ninguna_regla() -> None:
    assert semantic_twin("' AND 1=1-- -", "") is None
    assert semantic_twin("' AND 1=1-- -", "xss") is None


def test_clase_es_case_insensitive() -> None:
    assert semantic_twin("*)(uid=*", "LDAP") == "*)(uid=_"
    assert semantic_twin("' AND 1=1-- -", "SQLi") == "' AND 1=2-- -"


# --------------------------------------------------------------------------- #
# responses_equivalent
# --------------------------------------------------------------------------- #

def _resp(status: int, body: str) -> dict:
    return {"status_code": status, "text": body}


def test_mismo_cuerpo_es_equivalente() -> None:
    assert responses_equivalent(_resp(200, "error de filtro"), _resp(200, "error de filtro"))


def test_whitespace_no_cuenta_como_diferencia() -> None:
    """Dos veces la misma pagina formateada distinto son la misma respuesta."""
    pretty = "<html>\n  <body>  not found  </body>\n</html>"
    flat = "<html> <body> not found </body> </html>"
    assert responses_equivalent(_resp(404, pretty), _resp(404, flat))


def test_status_distinto_no_es_equivalente() -> None:
    assert not responses_equivalent(_resp(200, "a" * 500), _resp(404, "a" * 500))


def test_misma_longitud_distinto_contenido_es_distinto() -> None:
    """Mismo numero de bytes, dos respuestas: eso ya es una respuesta distinta.

    Una API JSON que contesta ``{"match": true}`` a un operador y
    ``{"match": false}`` a su gemelo ha contestado dos veces. Si una tolerancia
    solo basada en longitud llamara "equivalentes" a eso, el resultado del
    control -- que es justo lo que este oraculo existe para leer -- se borraria.
    """
    true_body = '{"ok":1}'
    false_body = '{"ok":0}'
    assert len(true_body) == len(false_body)
    assert not responses_equivalent(_resp(200, true_body), _resp(200, false_body))


def test_una_fila_de_mas_son_una_respuesta_distinta() -> None:
    """El caso genuino: un motor NoSQL devuelve un documento mas con el otro operador."""
    short = "<table>" + "".join(f"<tr><td>user{i}</td></tr>" for i in range(6)) + "</table>"
    longer = short + "<tr><td>bob</td></tr>"
    assert not responses_equivalent(_resp(200, short), _resp(200, longer))


def test_ruido_de_sesion_dentro_del_suelo_no_es_diferencia() -> None:
    """Ids de peticion y marcas de tiempo cambian entre dos sondas del mismo punto.

    Leerlos como diferencia conductual atribuiria causalidad a la huella del
    propio scanner.
    """
    base = "<html>" + "x" * 2000 + "</html>"
    noisy = "<html>" + "x" * 2000 + " req=8813 t=17:04:22" + "</html>"
    assert responses_equivalent(_resp(200, base), _resp(200, noisy))


def test_deriva_minima_dentro_de_la_tolerancia_no_es_equivalente() -> None:
    """>2 % de deriva ya es una diferencia conductual, no ruido de formato."""
    base = "x" * 2000
    assert not responses_equivalent(_resp(200, base), _resp(200, base + "y" * 60))


def test_una_pagina_de_error_sustituye_a_una_tabla() -> None:
    assert not responses_equivalent(
        _resp(200, "<table>" + "x" * 900 + "</table>"),
        _resp(200, "404 not found"),
    )


def test_respuestas_ausentes_nunca_inventan_una_diferencia() -> None:
    """Sin control no se puede afirmar una diferencia: se conserva el hallazgo."""
    assert responses_equivalent(None, _resp(200, "cuerpo"))
    assert responses_equivalent(_resp(200, "cuerpo"), None)
    assert responses_equivalent({}, {})


# --------------------------------------------------------------------------- #
# twin_is_available
# --------------------------------------------------------------------------- #

def test_status_cero_es_un_fallo_de_transporte_no_una_respuesta() -> None:
    """``_request_with_resilience`` devuelve status 0 para cualquier Exception."""
    assert not twin_is_available({"status_code": 0, "text": ""})


def test_sin_clave_text_no_hay_observacion() -> None:
    assert not twin_is_available({"status_code": 200})


@pytest.mark.parametrize("bad", [None, {}, {"status_code": "200", "text": "x"}])
def test_respuestas_malformadas_no_son_controles(bad) -> None:
    assert not twin_is_available(bad)


def test_respuesta_real_si_es_control() -> None:
    assert twin_is_available(_resp(200, "cuerpo"))


# --------------------------------------------------------------------------- #
# attribute_divergence
# --------------------------------------------------------------------------- #

def test_sin_control_se_atribuye() -> None:
    """Un payload sin gemelo conserva el comportamiento previo."""
    verdict = attribute_divergence(_resp(200, "corto"), _resp(200, "corto"), None)
    assert verdict.attributed
    assert verdict.reason == "no-control"
    assert verdict.evidence_kind == ""  # no se afirma causalidad que no se probo


def test_control_inalcanzable_se_atribuye() -> None:
    """La ausencia de un control no es una refutacion.

    Si el scanner se queda sin presupuesto a media comprobacion, el hallazgo
    previo sigue en pie: un control puede refutar, no puede fallar al no
    disprobar y aun asi borrar una deteccion real.
    """
    verdict = attribute_divergence(
        _resp(200, "corto"), {"status_code": 0, "text": ""}, "*)(uid=_")
    assert verdict.attributed
    assert verdict.reason == "twin-unavailable"


def test_control_que_coincide_reprime_el_hallazgo() -> None:
    """La falsificacion: el objetivo respondio igual a los dos payloads."""
    verdict = attribute_divergence(
        _resp(404, "no such file"), _resp(404, "no such file"), "*)(uid=_")
    assert not verdict.attributed
    assert verdict.reason == "twin-matches-payload"
    assert verdict.evidence_kind == UNATTRIBUTED_EVIDENCE_KIND


def test_control_que_diverge_atribuye_la_causa() -> None:
    verdict = attribute_divergence(
        _resp(200, "<table>" + "<tr><td>alice</td></tr>" * 8 + "</table>"),
        _resp(200, "<table>" + "<tr><td>alice</td></tr>" * 8
              + "<tr><td>bob</td></tr></table>"),
        "*)(uid=_")
    assert verdict.attributed
    assert verdict.reason == "twin-diverges"
    assert verdict.evidence_kind == CAUSAL_EVIDENCE_KIND
    assert verdict.twin == "*)(uid=_"
    assert verdict.twin_status == 200


def test_el_veredicto_guarda_el_status_del_control() -> None:
    verdict = attribute_divergence(
        _resp(200, "a" * 400), _resp(500, "a" * 400), "*)(uid=_")
    assert verdict.attributed
    assert verdict.twin_status == 500


# --------------------------------------------------------------------------- #
# CausalOracleMixin
# --------------------------------------------------------------------------- #

class _FakeTester(CausalOracleMixin):
    """Tester minimo: el mixin solo necesita ``config`` y ``probe``."""

    def __init__(self, config: dict, responses: dict[str, dict]) -> None:
        self.config = config
        self._responses = responses
        self.probed: list[str] = []

    async def probe(self, point, payload: str, *, base_url: str = "",
                    use_cache: bool | None = None):
        self.probed.append(payload)
        return self._responses.get(payload, {"status_code": 0, "text": ""}), 0.0, ""


class _LDAPTester(_FakeTester):
    causal_class = LDAP


class _NoClassTester(_FakeTester):
    causal_class = ""


async def test_el_mixin_pide_el_control_una_sola_vez() -> None:
    tester = _LDAPTester({}, {"*)(uid=_": _resp(200, "<ul>" + "x" * 400 + " sin coincidencias")})
    verdict = await tester.confirm_cause(
        "pt", "*)(uid=*", test_response=_resp(200, "<ul>" + "x" * 400 + " uid=alice uid=bob"))
    assert tester.probed == ["*)(uid=_"]
    assert verdict.attributed


async def test_el_mixin_no_pide_control_si_no_hay_gemelo() -> None:
    tester = _LDAPTester({}, {})
    verdict = await tester.confirm_cause(
        "pt", "admin)(&))", test_response=_resp(200, "corto"))
    assert tester.probed == []
    assert verdict.reason == "no-control"


async def test_el_ablation_desactiva_la_peticion() -> None:
    """``--no-causal-oracle`` restaura el comportamiento previo sin tocar el informe."""
    tester = _LDAPTester({"causal_oracle": False}, {})
    verdict = await tester.confirm_cause(
        "pt", "*)(uid=*", test_response=_resp(200, "corto"))
    assert tester.probed == []
    assert verdict.reason == "disabled"
    assert verdict.attributed


async def test_un_tester_sin_clase_registrada_no_hace_nada() -> None:
    tester = _NoClassTester({}, {})
    verdict = await tester.confirm_cause(
        "pt", "*)(uid=*", test_response=_resp(200, "corto"))
    assert tester.probed == []
    assert verdict.reason == "disabled"
    assert not tester.causal_oracle_enabled()


def test_el_ablation_por_defecto_esta_encendido() -> None:
    assert _LDAPTester({}, {}).causal_oracle_enabled()


# --------------------------------------------------------------------------- #
# Regression: the two defects that made the first live run a no-op
#
# Both were found by instrumenting every verdict on the instances that actually
# produced the cross-class claims, not by reading the code. They are recorded
# here as tests because each one silently disabled the oracle for a whole
# payload family.
# --------------------------------------------------------------------------- #

class TestJSWhereFamilyHasAControl:
    """``$where`` bodies are JavaScript quoted with double quotes.

    This is the single most frequent source of a mislabelled NoSQL finding
    against OWASP Benchmark. Every rule in the NoSQL inversion table looks for a
    single-quoted literal or a ``{"$op": ...}`` pair, so it read the whole
    function as opaque, declined, and the finding kept its pre-control behaviour
    unchanged -- 28 of the ``pathtraver -> nosqli`` claims and 13 of the
    ``cmdi -> nosqli`` ones came from this one shape.
    """

    WHERE = (
        '{"$where": "function() { return this.username == \'admin\' && '
        "this.password.match(/.*/)//; return true; }\"}"
    )

    def test_tiene_control(self):
        assert semantic_twin(self.WHERE, NOSQL) is not None

    def test_control_conserva_longitud(self):
        twin = semantic_twin(self.WHERE, NOSQL)
        assert twin is not None
        assert len(twin) == len(self.WHERE)

    def test_control_es_distinto(self):
        twin = semantic_twin(self.WHERE, NOSQL)
        assert twin is not None and twin != self.WHERE

    def test_regex_catchall_se_convierte_en_no_match(self):
        """``/.*/`` -> ``/^$/``: same width, opposite meaning."""
        twin = semantic_twin(self.WHERE, NOSQL)
        assert twin is not None
        assert "/^$/" in twin and "/.*/" not in twin

    def test_igualdad_js_se_invierte(self):
        """A ``$where`` with no regex literal still gets a control."""
        payload = (
            '{"$where": "function() { return this.username == \'admin\' && '
            "this.password == \'admin\'; }\"}"
        )
        twin = semantic_twin(payload, NOSQL)
        assert twin is not None
        assert "!= 'admin'" in twin
        assert len(twin) == len(payload)

    def test_igualdad_estrecha_se_invierte(self):
        payload = '{"$where": "return a === 1"}'
        twin = semantic_twin(payload, NOSQL)
        assert twin is not None and "!==" in twin
        assert len(twin) == len(payload)

    def test_operador_js_desconocido_preserva_tabla(self):
        """A gate this module does not know must not raise."""
        for operator in _NOSQL_EQUALITY_OPPOSITES:
            assert _NOSQL_EQUALITY_OPPOSITES[operator] in ("==", "!=", "===", "!==")

    def test_la_forma_de_cadena_gana_al_fallback_js(self):
        """The quoted rule stays ahead of the JavaScript fallback.

        ``' || '1'='1`` contains ``==``, and the JavaScript rule would happily
        turn it into ``' || '1'!='1``. Both invert the payload, but the quoted
        rule is the more specific one and produces the control the corpus is
        designed around, so it keeps priority.
        """
        assert semantic_twin("' || '1'='1", NOSQL) == "' || '1'='2"


class TestEchoOfTheTwinIsNotBehaviour:
    """A target that echoes its input makes every divergence look causal.

    The payload's body and the twin's body then differ *only* in the echoed bytes,
    so without stripping, the comparison reads the scanner's own footprint as the
    target's behaviour and attributes causality to a payload that changed
    nothing. Reflection is not interpretation.
    """

    PAYLOAD = '{"username": {"$ne": null}, "password": {"$ne": null}}'
    TWIN = '{"username": {"$eq": null}, "password": {"$ne": null}}'

    def test_eco_simple_no_atribuye(self):
        verdict = attribute_divergence(
            _resp(200, f"error: {self.PAYLOAD}"),
            _resp(200, f"error: {self.TWIN}"),
            self.TWIN,
            payload=self.PAYLOAD,
        )
        assert not verdict.attributed
        assert verdict.reason == "twin-matches-payload"

    def test_eco_con_escapes_numericos_de_benchmark(self):
        """OWASP Benchmark entity-escapes every non-alphanumeric character."""
        def escape(text: str) -> str:
            return "".join(c if c.isalnum() else f"&#x{ord(c):x};" for c in text)

        verdict = attribute_divergence(
            _resp(200, f"error: {escape(self.PAYLOAD)}"),
            _resp(200, f"error: {escape(self.TWIN)}"),
            self.TWIN,
            payload=self.PAYLOAD,
        )
        assert not verdict.attributed

    def test_sin_payload_sigue_viendo_el_eco_del_gemelo(self):
        """Omitting the payload still catches the twin's own echo.

        The twin is on both sides of the comparison, so its echo is visible
        without ever being told what the payload was. What the parameter buys is
        seeing an echo of the *payload* when the two bodies carry different
        spellings -- that is the case the next test covers.
        """
        verdict = attribute_divergence(
            _resp(200, f"error: {self.PAYLOAD}"),
            _resp(200, f"error: {self.TWIN}"),
            self.TWIN,
        )
        assert not verdict.attributed

    def test_con_payload_no_se_atribuye(self):
        """Con el payload, el eco se ve y la atribucion cae.

        Documenta que el parametro es portador de carga, no decorativo: el mismo
        par de cuerpos se atribuye sin el y se retiene con el.
        """
        verdict = attribute_divergence(
            _resp(200, f"error: {self.PAYLOAD}"),
            _resp(200, f"error: {self.TWIN}"),
            self.TWIN,
            payload=self.PAYLOAD,
        )
        assert not verdict.attributed

    def test_eco_no_borra_una_diferencia_estructural(self):
        """Una diferencia estructural sigue siendo atribuible.

        Las dos respuestas son identicas byte a byte salvo el eco: el resto del
        cuerpo no cambio. Cuando el resto *si* cambia, el objetivo esta
        haciendo algo distinto y el veredicto vuelve a ser ``twin-diverges`` --
        pero solo si no se observa eco, porque un objetivo que refleja no puede
        dar una atribucion creible (ver la clase siguiente).
        """
        verdict = attribute_divergence(
            _resp(200, "2 rows returned: alice, bob"),
            _resp(200, "HTTP Status 500 - Internal Server Error"),
            self.TWIN,
        )
        assert verdict.attributed
        assert verdict.reason == "twin-diverges"

    def test_eco_corto_no_se_toca(self):
        """A one- or two-character payload has no marker to strip.

        Stripping it would delete unrelated parts of the page, which is a much
        worse error than missing an echo.
        """
        assert _echo_forms("1") == ()
        assert _echo_forms("*)") == ()

    def test_formas_de_eco_cubren_las_cuatro_codificaciones(self):
        forms = _echo_forms(self.PAYLOAD)
        assert self.PAYLOAD in forms
        assert html.escape(self.PAYLOAD, quote=True) in forms
        assert quote(self.PAYLOAD, safe="") in forms
        assert _numeric_entity_form(self.PAYLOAD) in forms


class TestReglasDerivadasDeLosPayloadsReales:
    """Controles anadidos tras instrumentar la corrida que resulto ser un no-op.

    Cada regla de esta clase existe porque una familia concreta de claims
    cruzados llego al reporte con ``evidence_kind`` vacio -- es decir, el
    oraculo no pudo construir control y dejo pasar el hallazgo sin cambios.
    """

    # --- NoSQL: literal booleano -------------------------------------------
    def test_where_true_se_convierte_en_null(self):
        payload = '{"$or":[{"$where":"return true"}]}'
        twin = semantic_twin(payload, NOSQL)
        assert twin == '{"$or":[{"$where":"return null"}]}'

    def test_true_no_se_dentra_dentro_de_un_identificador(self):
        assert semantic_twin('{"a":"truely"}', NOSQL) is None
        assert semantic_twin('{"a":"untrue"}', NOSQL) is None

    # --- LDAP: valor de un filtro de igualdad ------------------------------
    def test_valor_de_filtro_se_invierte_en_su_lugar(self):
        payload = "admin)(|(homeDirectory=/root))"
        twin = semantic_twin(payload, LDAP)
        assert twin is not None
        assert twin == "admin)(|(homeDirectory=/roou))"
        assert len(twin) == len(payload)

    def test_valor_no_come_parentesis_de_cierre(self):
        """Un ``\\S+`` glotón invertiria el parentesis final y romperia la estructura.

        La afirmacion del payload es el valor (``admin``), no el cierre del
        filtro. Invertir el cierre produce algo que ya no es un filtro, y por
        tanto no es una afirmacion opuesta sino una carga distinta.
        """
        payload = "admin)(|(cn=admin))"
        twin = semantic_twin(payload, LDAP)
        assert twin is not None
        assert twin.endswith("))")
        assert "(cn=admi" in twin

    def test_comodin_tiene_prioridad_sobre_el_valor(self):
        assert semantic_twin("*)(uid=*)", LDAP) == "*)(uid=_)"
        assert semantic_twin("admin)(objectClass=*)", LDAP) == "admin)(objectClass=_)"

    def test_payload_sin_proposicion_no_tiene_control(self):
        """``admin)(&))`` no afirma nada: es un delimitador de comentario LDAP.

        Sin una proposicion que invertir no hay control construible, y el
        comportamiento pre-existente se conserva. Documentado aqui para que un
        refactor futuro sepa que esto es una decision y no un olvido.
        """
        assert semantic_twin("admin)(&))", LDAP) is None

    # --- SQL: comparacion entre subconsulta -------------------------------
    def test_subconsulta_comparada_con_escalar(self):
        payload = "' AND (SELECT 1 FROM users WHERE password LIKE '%a%')=1--"
        twin = semantic_twin(payload, SQLI)
        assert twin is not None
        assert twin.endswith("=2--")
        assert len(twin) == len(payload)

    def test_operando_numerico_comparado_como_numero(self):
        """``01=1`` es la misma tautologia que ``1=1``.

        Un escape ``%a0`` delante de la comparacion deja un ``0`` pegado al
        operando izquierdo; compararlos como cadenas lo lee como
        contradiccion y renuncia a construir el control.
        """
        twin = semantic_twin("'%a0OR%a01=1-- -", SQLI)
        assert twin == "'%a0OR%a01=2-- -"

    def test_escape_de_espaciado_no_oculta_la_comparacion(self):
        """La familia de evasion de WAF con espaciado escapado.

        ``%0b`` (vertical tab) y ``%a0`` (nbsp) son los dos que aparecen en el
        reporte. El escape mete un digito justo delante de la comparacion, que
        es justo lo que un limite ``(?<!\\d)`` rechazaria.
        """
        for spelling in ("%0b", "%a0", "%20", "%09"):
            payload = f"'{spelling}OR{spelling}1=1-- -"
            twin = semantic_twin(payload, SQLI)
            assert twin == f"'{spelling}OR{spelling}1=2-- -", spelling

    def test_operando_se_lee_del_escape_hacia_dentro(self):
        """``%201=1``: el escape y la comparacion comparten la misma tirada.

        Leida como ``201=1`` es una contradiccion y el control se rechaza; leida
        como ``%20`` + ``1=1`` es la tautologia que el payload queria. La
        lectura mas corta resuelve la ambiguedad y deja los digitos del escape
        con el escape.
        """
        assert semantic_twin("'%20OR%201=1-- -", SQLI) == "'%20OR%201=2-- -"

    def test_tirada_larga_sigue_funcionando(self):
        """La lectura corta no rompe los casos sin escape."""
        assert semantic_twin("' AND 10=10-- -", SQLI) == "' AND 10=11-- -"
        assert semantic_twin("1=1", SQLI) == "1=2"

    def test_time_based_no_tiene_control(self):
        """``SLEEP`` no se puede refutar con una respuesta.

        Su senal es la latencia, no el cuerpo, asi que un gemelo de igual
        longitud seguiria durmiendo. Emitir uno y comparar cuerpos borraria una
        deteccion real: por eso ``no-control`` es la respuesta correcta.
        """
        assert semantic_twin("' AND SLEEP(5)#", SQLI) is None
        assert semantic_twin("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", SQLI) is None

    def test_union_select_no_tiene_control(self):
        """``UNION SELECT`` no afirma una proposicion de verdad/falso.

        Un gemelo posible (cambiar las columnas) seguiria intentando la misma
        union: no refuta nada y compararla no dice nada sobre la causa.
        """
        assert semantic_twin("-1'/*!50000UNION*//*!50000SELECT*/1,2,3-- -", SQLI) is None

    def test_ya_contradictorio_no_tiene_control(self):
        assert semantic_twin("' AND 1=2-- -", SQLI) is None


class TestUnObjetivoQueReflejaNoPuedeAtribuir:
    """El eco normalizado hace que borrar el token no baste.

    OWASP Benchmark normaliza la entrada antes de reflejarla: un payload que
    lleva ``LIKE '%<314 digitos>%'`` vuelve como ``LIKE '%'``. Los dos cuerpos
    difieren en la posicion donde el payload y el gemelo difieren, pero ninguna
    busqueda literal encuentra el token que borrar. Sin la regla de abajo, ese
    caso se atribuiria -- se afirmaria causalidad sobre un hallazgo que es puro
    reflejo, y el hallazgo sobreviviria al reporte con una etiqueta de evidencia
    causal que nadie verifico.
    """

    PAYLOAD = "' AND (SELECT 1 FROM users WHERE password LIKE '%1234567890%')=1--"
    TWIN = "' AND (SELECT 1 FROM users WHERE password LIKE '%1234567890%')=2--"

    def test_eco_normalizado_no_atribuye(self):
        def echo(digit: str) -> str:
            return "' AND (SELECT 1 FROM users WHERE password LIKE '%')=" + digit + "--"

        verdict = attribute_divergence(
            _resp(200, echo("1")), _resp(200, echo("2")),
            self.TWIN, payload=self.PAYLOAD,
        )
        assert not verdict.attributed
        # Lo refuta la regla de diferencia-igual-a-la-peticion, que corre antes
        # que la del eco visible; ambas son refutaciones por reflejo.
        assert verdict.reason in ("twin-diverges-echo", "twin-diverges-reflection")

    def test_un_objetivo_que_no_refleja_sigue_atribuyendo(self):
        """La regla solo se activa si el eco es observable.

        Una pagina de error que contiene un *fragmento* del payload no es un eco:
        alli la diferencia entre los cuerpos si es comportamiento.
        """
        verdict = attribute_divergence(
            _resp(500, "<html>UnknownFormatConversionException</html>"),
            _resp(500, "<html>Nothing found for this identifier</html>"),
            self.TWIN, payload=self.PAYLOAD,
        )
        assert verdict.attributed
        assert verdict.reason == "twin-diverges"

    def test_el_eco_normalizado_se_detecta_sin_el_payload(self):
        """La deteccion no depende del parametro ``payload``.

        Lo que se busca es un tramo largo del token, y el token mas largo de los
        dos es el gemelo, que siempre se conoce. Por eso este caso se retiene
        tambien sin pasarle el payload: el parametro es una comodidad, no la
        fuente de la informacion.
        """
        def echo(digit: str) -> str:
            return "' AND (SELECT 1 FROM users WHERE password LIKE '%')=" + digit + "--"

        verdict = attribute_divergence(
            _resp(200, echo("1")), _resp(200, echo("2")), self.TWIN,
        )
        assert not verdict.attributed
        # Lo refuta la regla de diferencia-igual-a-la-peticion, que corre antes
        # que la del eco visible; ambas son refutaciones por reflejo.
        assert verdict.reason in ("twin-diverges-echo", "twin-diverges-reflection")
