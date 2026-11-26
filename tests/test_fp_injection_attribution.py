"""Atribucion especifica de clase en los testers NoSQL, LDAP y SQLi.

Origen: auditoria del report completo de OWASP Benchmark (presupuesto 20,
brazo baseline). 308/313 FP eran MEDIUM sin evidencia dura y el patron
dominante era "tipo de vuln incorrecto sobre un endpoint realmente vulnerable":
una divergencia causada por *cualquier* caracter especial se atribuia a
NoSQL/LDAP/SQL.

Casos trampa (deben callar o degradarse) y positivos (deben seguir detectando).
Los hallazgos de este fichero estan en espanol por convencion de ``tests/``.
"""

from __future__ import annotations

import pytest
from conftest import collect_log_messages, collect_vulns, param_value

from web_security_scanner.core.causal_oracle import CAUSAL_EVIDENCE_KIND
from web_security_scanner.core.param_semantics import evidence_strength
from web_security_scanner.modules.vulnerability_testers._injection_attribution import (
    GENERIC_CONTROLS,
    canonical_boolean_pair,
)
from web_security_scanner.modules.vulnerability_testers.ldap_injection_async import (
    LDAPInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.nosql_injection_async import (
    NoSQLInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.sql_injection_async import (
    SQLInjectionTester,
)

URL = "http://target/page?id=1"
BENIGN = "benign_baseline_123"
ERROR_PAGE = "Error processing request. " * 30


def _rigid_endpoint(method, url, kwargs):
    """Endpoint que diverge con cualquier caracter especial (', ", ), $, ...).

    Es el endpoint SQLi / path traversal / cmdi del Benchmark visto desde un
    tester de otra clase: reacciona a que el valor "se rompe", no a lo que dice.
    """
    value = param_value(url, "id")
    if value == BENIGN or value.isdigit():
        return {"status_code": 200, "text": "ok"}
    return {"status_code": 200, "text": ERROR_PAGE}


def _operator_only_endpoint(method, url, kwargs):
    """Diverge con cualquier payload que lleve sintaxis de operador ($, {, *),
    pero los caracteres genericos sueltos responden como la linea base.

    El control generico no lo refuta; lo refuta el gemelo semantico, que
    obtiene exactamente la misma pagina de error que el payload.
    """
    value = param_value(url, "id")
    if any(tok in value for tok in ("$", "{", "*", "||", ")(")):
        return {"status_code": 200, "text": ERROR_PAGE}
    return {"status_code": 200, "text": "ok"}


# --------------------------------------------------------------------------- #
# NoSQL
# --------------------------------------------------------------------------- #

async def test_nosql_trampa_cualquier_caracter_especial_no_es_nosql():
    assert await collect_vulns(NoSQLInjectionTester, _rigid_endpoint, target=URL) == []


async def test_nosql_trampa_el_retiro_queda_registrado_en_el_log():
    logs = await collect_log_messages(NoSQLInjectionTester, _rigid_endpoint, target=URL)
    assert any("Withheld a NoSQL differential" in m and "generic-control" in m
               for m in logs)


async def test_nosql_trampa_gemelo_identico_refuta_la_divergencia():
    assert await collect_vulns(
        NoSQLInjectionTester, _operator_only_endpoint, target=URL) == []


async def test_nosql_sin_gemelo_y_sin_refutacion_queda_low_soft():
    from conftest import MockScanner

    from web_security_scanner.events.event_emitter import ScanEventEmitter

    tester = NoSQLInjectionTester(MockScanner(lambda m, u, kw: {"text": "ok"}),
                                  ScanEventEmitter(), {"payload_delay": 0})
    verdict = await tester.attribute_class_divergence(
        "id", '{"$where": "sleep(5000)"}',
        response={"status_code": 200, "text": "x" * 300},
        baseline={"status_code": 200, "length": 2, "text": "ok"},
        base_url=URL)
    assert verdict.report
    assert (verdict.confidence, verdict.evidence_kind) == ("LOW", "differential")


async def test_nosql_positivo_error_de_mongo():
    def responder(method, url, kwargs):
        value = param_value(url, "id")
        if "$" in value:
            return {"status_code": 500, "text": "MongoServerError: unknown operator: $foo"}
        return {"status_code": 200, "text": "ok"}

    found = await collect_vulns(NoSQLInjectionTester, responder, target=URL)
    assert found
    assert found[0]["evidence_kind"] == "error_signature"
    assert found[0]["confidence"] == "CONFIRMED"


async def test_nosql_positivo_par_booleano_ne_coherente():
    def responder(method, url, kwargs):
        value = param_value(url, "id")
        truthy = ("$ne" in value or "$gt" in value) and not (
            "$eq" in value or "$lt" in value)
        if truthy:
            return {"status_code": 200, "text": "alice bob carol " * 40}
        return {"status_code": 200, "text": "no users"}

    found = await collect_vulns(NoSQLInjectionTester, responder, target=URL)
    assert len(found) == 1
    assert found[0]["evidence_kind"] == CAUSAL_EVIDENCE_KIND
    assert evidence_strength(found[0]["evidence_kind"]) == "hard"
    assert found[0]["confidence"] == "MEDIUM"
    assert found[0]["severity"] == "Critical"
    assert "true/false/true" in found[0]["evidence"]


async def test_nosql_replay_inestable_baja_a_low_soft():
    calls = {"n": 0}

    def responder(method, url, kwargs):
        value = param_value(url, "id")
        if "$eq" in value or "$lt" in value:
            return {"status_code": 200, "text": "no users"}
        if "$ne" in value or "$gt" in value:
            calls["n"] += 1
            # La primera respuesta y su replay no coinciden: ruido, no logica.
            return {"status_code": 200, "text": ("alice " if calls["n"] % 2 else "zed ") * 60}
        return {"status_code": 200, "text": "no users"}

    found = await collect_vulns(NoSQLInjectionTester, responder, target=URL)
    assert found
    assert found[0]["confidence"] == "LOW"
    assert found[0]["evidence_kind"] == "differential"
    assert evidence_strength(found[0]["evidence_kind"]) == "soft"
    assert found[0]["severity"] == "Low"


async def test_nosql_ablation_restaura_el_veredicto_previo():
    found = await collect_vulns(NoSQLInjectionTester, _rigid_endpoint, target=URL,
                                config={"causal_oracle": False})
    assert found
    assert found[0]["evidence_kind"] == "differential"
    assert found[0]["confidence"] == "MEDIUM"
    assert found[0]["severity"] == "Critical"


@pytest.mark.parametrize("texto", [
    "Gibson guitars catalogue",            # 'bson' como subcadena
    "SyntaxError: Unexpected end of JSON input",  # JSON.parse generico
    "We run MongoDB in production",
])
def test_nosql_firmas_genericas_ya_no_cuentan_como_error_de_motor(texto):
    assert not NoSQLInjectionTester._has_nosql_error(texto)


@pytest.mark.parametrize("texto", [
    "E11000 duplicate key error collection",
    "com.mongodb.MongoQueryException: Query failed",
    "pymongo.errors.OperationFailure: unknown operator: $foo",
    "Cast to ObjectId failed for value",
])
def test_nosql_firmas_especificas_de_mongo(texto):
    assert NoSQLInjectionTester._has_nosql_error(texto)


# --------------------------------------------------------------------------- #
# LDAP
# --------------------------------------------------------------------------- #

async def test_ldap_trampa_cualquier_caracter_especial_no_es_ldap():
    assert await collect_vulns(LDAPInjectionTester, _rigid_endpoint, target=URL) == []


async def test_ldap_trampa_gemelo_identico_refuta_la_divergencia():
    assert await collect_vulns(
        LDAPInjectionTester, _operator_only_endpoint, target=URL) == []


async def test_ldap_positivo_error_de_filtro():
    def responder(method, url, kwargs):
        value = param_value(url, "id")
        if "(" in value or ")" in value:
            return {"status_code": 500,
                    "text": "javax.naming.directory.InvalidSearchFilterException: Bad search filter"}
        return {"status_code": 200, "text": "ok"}

    found = await collect_vulns(LDAPInjectionTester, responder, target=URL)
    assert found
    assert found[0]["evidence_kind"] == "error_signature"


async def test_ldap_positivo_par_comodin_verdadero_falso():
    def responder(method, url, kwargs):
        value = param_value(url, "id")
        if "=*" in value:
            return {"status_code": 200, "text": "LDAP results: uid=alice uid=bob " * 20}
        return {"status_code": 200, "text": "LDAP results: none"}

    found = await collect_vulns(LDAPInjectionTester, responder, target=URL)
    assert len(found) == 1
    assert found[0]["evidence_kind"] == CAUSAL_EVIDENCE_KIND
    assert found[0]["confidence"] == "MEDIUM"
    assert found[0]["severity"] == "High"


def test_ldap_protocol_error_generico_no_es_firma():
    assert not LDAPInjectionTester._has_ldap_error("HTTP/2 stream protocol error")
    assert LDAPInjectionTester._has_ldap_error("[LDAP: error code 87 - Bad search filter]")


# --------------------------------------------------------------------------- #
# SQL injection
# --------------------------------------------------------------------------- #

def _sqli_endpoint(method, url, kwargs):
    """HSQLDB vulnerable: ``... PASSWORD='<valor>'``.

    ``' OR 'a'='a`` devuelve filas, ``' OR 'a'='b`` ninguna, y cualquier otra
    comilla rota da la pagina de error generica (sin firma de motor), que es lo
    que produce la divergencia "Boolean-based" del Benchmark.
    """
    value = param_value(url, "id")
    if value == BENIGN or value.isdigit():
        return {"status_code": 200, "text": "No results"}
    if value == "' OR 'a'='a":
        return {"status_code": 200, "text": "alice:secret bob:hunter2 " * 20}
    if value == "' OR 'a'='b":
        return {"status_code": 200, "text": "No results"}
    return {"status_code": 200, "text": ERROR_PAGE}


async def test_sqli_positivo_par_booleano_coherente_es_medium_causal():
    found = await collect_vulns(SQLInjectionTester, _sqli_endpoint, target=URL)
    assert len(found) == 1
    assert found[0]["evidence_kind"] == CAUSAL_EVIDENCE_KIND
    assert found[0]["confidence"] == "MEDIUM"
    assert found[0]["severity"] == "High"


async def test_sqli_trampa_divergencia_unidireccional_baja_a_low_sin_perderse():
    # Todo valor no benigno da la misma pagina: el par verdadero/falso no se
    # distingue. No se descarta (protege el recall), se degrada a LOW/SOFT.
    found = await collect_vulns(SQLInjectionTester, _rigid_endpoint, target=URL)
    assert len(found) == 1
    assert found[0]["confidence"] == "LOW"
    assert found[0]["evidence_kind"] == "differential"
    assert found[0]["severity"] == "Low"
    assert "unattributed" in found[0]["evidence"]


async def test_sqli_replay_inestable_baja_a_low():
    calls = {"n": 0}

    def responder(method, url, kwargs):
        value = param_value(url, "id")
        if value == "' OR 'a'='a":
            calls["n"] += 1
            return {"status_code": 200, "text": f"row{calls['n']} " * 40}
        return _sqli_endpoint(method, url, kwargs)

    found = await collect_vulns(SQLInjectionTester, responder, target=URL)
    assert found
    assert found[0]["confidence"] == "LOW"
    assert "replay-unstable" in found[0]["evidence"]


async def test_sqli_error_de_motor_sigue_siendo_high():
    def responder(method, url, kwargs):
        value = param_value(url, "id")
        if "'" in value:
            return {"status_code": 500, "text": "java.sql.SQLException: unexpected token"}
        return {"status_code": 200, "text": "ok"}

    found = await collect_vulns(SQLInjectionTester, responder, target=URL)
    assert found
    assert found[0]["evidence_kind"] == "error_signature"
    assert found[0]["confidence"] == "HIGH"


async def test_sqli_ablation_restaura_el_veredicto_previo():
    found = await collect_vulns(SQLInjectionTester, _rigid_endpoint, target=URL,
                                config={"causal_oracle": False})
    assert found
    assert found[0]["confidence"] == "MEDIUM"
    assert found[0]["evidence_kind"] == "differential"
    assert found[0]["severity"] == "High"


@pytest.mark.parametrize("payload, esperado", [
    ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", ("' OR 'a'='a", "' OR 'a'='b")),
    ('" AND 1=1', ('" OR "a"="a', '" OR "a"="b')),
    ("1) AND SLEEP(5)", ("1 OR 1=1", "1 OR 1=2")),
])
def test_par_canonico_segun_contexto_de_comillas(payload, esperado):
    verdadero, falso = canonical_boolean_pair(payload)
    assert (verdadero, falso) == esperado
    assert len(verdadero) == len(falso)


def test_controles_genericos_son_caracteres_sueltos():
    assert set(GENERIC_CONTROLS) == {"'", '"', ")"}


def _esapi_echo_endpoint(method, url, kwargs):
    """Sink de path traversal del Benchmark: repite la entrada codificada con
    ESAPI ``encodeForHTML`` (los espacios quedan sin codificar) y no la
    interpreta como SQL. El par verdadero/falso solo difiere en su propio eco.
    """
    from web_security_scanner.core.causal_oracle import _esapi_entity_form
    value = param_value(url, "id")
    return {"status_code": 200,
            "text": "Now ready to write to file: /testfiles/" + _esapi_entity_form(value)}


def test_echo_forms_incluye_la_forma_esapi_con_espacios_literales():
    from web_security_scanner.core.causal_oracle import _echo_forms
    assert "&#x27; OR &#x27;a&#x27;&#x3d;&#x27;a" in _echo_forms("' OR 'a'='a")


async def test_sqli_trampa_eco_esapi_no_es_causal():
    # Antes: el eco codificado de 'a' frente a 'b' contaba como diferencia de
    # comportamiento y el hallazgo salia MEDIUM/differential_causal.
    found = await collect_vulns(SQLInjectionTester, _esapi_echo_endpoint, target=URL)
    assert found, "SQLi nunca retira: debe quedar reportado, pero en LOW"
    assert all(f["evidence_kind"] != CAUSAL_EVIDENCE_KIND for f in found)
    assert all(f["confidence"] == "LOW" for f in found)


_HSQL_500 = (
    "HTTP Status 500 Type Exception Report Message "
    "org.springframework.jdbc.BadSqlGrammarException: StatementCallback; bad SQL "
    "grammar [SELECT * from USERS]; nested exception is java.sql.BatchUpdateException: "
    "user lacks privilege or object not found: RECEIVE_MESSAGE"
)


@pytest.mark.parametrize("fragment", [
    "BadSqlGrammarException", "bad SQL grammar [SELECT", "java.sql.BatchUpdateException",
    "java.sql.SQLSyntaxErrorException", "user lacks privilege or object not found: X",
    "org.hsqldb.HsqlException",
])
def test_sqli_firmas_hsqldb_spring_jdbc(fragment):
    tester = SQLInjectionTester.__new__(SQLInjectionTester)
    assert tester._check_error(fragment)


def test_sqli_firmas_no_saltan_con_texto_generico():
    tester = SQLInjectionTester.__new__(SQLInjectionTester)
    for txt in ("java.sql is a package", "bad grammar in your essay", "object not found"):
        assert not tester._check_error(txt)


def _echo_and_interpret_endpoint(method, url, kwargs):
    """Endpoint SQLi del Benchmark que repite la consulta (codificada con ESAPI)
    y ademas la interpreta: la rama verdadera devuelve filas."""
    from web_security_scanner.core.causal_oracle import _esapi_entity_form
    value = param_value(url, "id")
    if value in ("1", BENIGN) or value.isdigit():
        return {"status_code": 200, "text": "No results returned for query: PASSWORD='1'"}
    if value == "' OR 'a'='a":
        return {"status_code": 200, "text": "Your results are: {USERID=0}"}
    return {"status_code": 200,
            "text": "No results returned for query: PASSWORD='" + _esapi_entity_form(value) + "'"}


async def test_sqli_eco_mas_interpretacion_sigue_siendo_causal():
    # Quitar el eco no debe borrar la diferencia real fuera del eco.
    found = await collect_vulns(SQLInjectionTester, _echo_and_interpret_endpoint, target=URL)
    assert any(f["evidence_kind"] == CAUSAL_EVIDENCE_KIND and f["confidence"] == "MEDIUM"
               for f in found)


def _static_error_trap(method, url, kwargs):
    """Trampa SQLi del Benchmark: la consulta esta rota con independencia de la
    entrada, asi que la linea base benigna ya devuelve el error del driver."""
    return {"status_code": 500,
            "text": "java.sql.SQLSyntaxErrorException: user lacks privilege or "
                    "object not found: A_VALUE in statement [ CALL a_Value ]"}


async def test_sqli_trampa_error_presente_en_baseline_no_es_error_based():
    found = await collect_vulns(SQLInjectionTester, _static_error_trap, target=URL)
    assert all(f.get("evidence_kind") != "error_signature" for f in found)
    assert all(f["confidence"] != "HIGH" for f in found)


def _error_only_with_payload(method, url, kwargs):
    value = param_value(url, "id")
    if value in ("1", BENIGN) or value.isdigit():
        return {"status_code": 200, "text": "Your results are: "}
    return {"status_code": 500, "text": _HSQL_500}


async def test_sqli_error_solo_con_payload_sigue_siendo_high():
    found = await collect_vulns(SQLInjectionTester, _error_only_with_payload, target=URL)
    assert any(f["evidence_kind"] == "error_signature" and f["confidence"] == "HIGH"
               for f in found)


def _call_procedure_endpoint(method, url, kwargs):
    """``CALL <valor>``: el valor benigno ya falla (procedimiento inexistente),
    pero el payload provoca un error distinto (cadena mal formada)."""
    value = param_value(url, "id")
    if "'" in value:
        return {"status_code": 500, "text": "java.sql.SQLSyntaxErrorException: "
                "malformed string: ' in statement [ CALL ' AND SLEEP(5)-- -}]"}
    return {"status_code": 500, "text": "java.sql.SQLSyntaxErrorException: user lacks "
            f"privilege or object not found: {value.upper()} in statement [ CALL {value} ]"}


async def test_sqli_error_distinto_al_de_la_baseline_si_cuenta():
    found = await collect_vulns(SQLInjectionTester, _call_procedure_endpoint, target=URL)
    assert any(f["evidence_kind"] == "error_signature" and f["confidence"] == "HIGH"
               for f in found)


def _truncating_echo_endpoint(method, url, kwargs):
    """XSS del Benchmark: repite la entrada sin su ultimo caracter y anade 'Z'.
    Ninguna forma literal del payload aparece en el cuerpo."""
    value = param_value(url, "id")
    return {"status_code": 200, "text": value[:-1] + "Z"}


def _shell_word_echo_endpoint(method, url, kwargs):
    """CMDi del Benchmark: ``ls`` sobre cada palabra, comillas eliminadas."""
    value = param_value(url, "id")
    words = value.replace("'", "").replace('"', "").split()
    err = "".join(f"ls: cannot access '{w}': No such file or directory<br>" for w in words)
    return {"status_code": 200, "text": "Here is the std err of the command:<br>" + err}


@pytest.mark.parametrize("responder", [_truncating_echo_endpoint, _shell_word_echo_endpoint])
@pytest.mark.parametrize("tester_cls", [NoSQLInjectionTester, LDAPInjectionTester,
                                        SQLInjectionTester])
async def test_eco_transformado_no_es_causal(tester_cls, responder):
    # El cuerpo del payload y el del gemelo solo difieren donde difieren las
    # propias peticiones: es reflejo, no comportamiento.
    found = await collect_vulns(tester_cls, responder, target=URL)
    assert all(f.get("evidence_kind") != CAUSAL_EVIDENCE_KIND for f in found)
    assert all(f["confidence"] not in ("MEDIUM", "HIGH", "CONFIRMED") for f in found)


def test_gemelo_nosql_no_introduce_espacios():
    # Un espacio de relleno es un separador de palabras para un shell: el gemelo
    # cambiaria la respuesta de un endpoint CMDi por motivos ajenos a NoSQL.
    from web_security_scanner.core.causal_oracle import NOSQL, semantic_twin
    twin = semantic_twin("username[$nin][]=guest&password[$ne]=", NOSQL)
    assert twin == "username[$nin][]=guest&password[$eq]="
    assert semantic_twin('{"$nin": ["a"]}', NOSQL) is None
