"""Tests del gate de semántica de parámetros (Track B).

Cubre el gate ``VulnerabilityTester._apply_param_semantics`` y el contrato de
``core.param_semantics``:

* parámetro de redirección + evidencia HARD -> se mantiene (con tope de
  severidad salvo oráculo de ejecución CONFIRMED);
* + evidencia SOFT -> suprimido, pero auditable (registro
  ``param_semantics_verdict`` + copia en ``param_semantics_suppressed`` +
  LOG_MESSAGE estructurado);
* + sin ``evidence_kind`` -> se mantiene con severidad capada;
* parámetro que no es de flow-control -> sin cambios y sin campo de auditoría;
* ``--no-param-semantics`` -> sin cambios en absoluto, y el flag llega a la
  config del tester y al manifest;
* nombres neutros (``target``, ``page``…) con valor URL -> el gate aplica.
"""

import pytest

from web_security_scanner.cli import _build_config, _build_parser
from web_security_scanner.core.manifest_async import build_manifest
from web_security_scanner.core.param_semantics import (
    ACTION_CAPPED,
    ACTION_EXEMPT,
    ACTION_KEPT,
    ACTION_PASS,
    ACTION_SUPPRESSED,
    HARD_EVIDENCE_KINDS,
    SOFT_EVIDENCE_KINDS,
    apply_redirect_param_policy,
    evidence_strength,
    is_flow_control_point,
)
from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.base_tester_async import (
    VulnerabilityTester,
)


class _GateTester(VulnerabilityTester):
    """Tester mínimo: solo sirve para ejercitar report_vulnerability."""

    @property
    def name(self) -> str:
        return "GateTester"

    @property
    def description(self) -> str:
        return "tester de prueba del gate"

    async def run_test(self, target_url, **kwargs):  # pragma: no cover
        return None


class OpenRedirectTester(_GateTester):
    """Mismo nombre de clase que el tester real: debe quedar exento."""


class _Harness:
    def __init__(self, tester_cls=_GateTester, **config):
        self.emitter = ScanEventEmitter()
        self.found: list[dict] = []
        self.logs: list[dict] = []
        self.emitter.on(ScanEventType.VULNERABILITY_FOUND,
                        lambda **k: self.found.append(k["vulnerability"]))
        self.emitter.on(ScanEventType.LOG_MESSAGE, lambda **k: self.logs.append(k))
        cfg = {"payload_delay": 0, "ai_enabled": False}
        cfg.update(config)
        self.tester = tester_cls(None, self.emitter, cfg)

    async def report(self, *, param_value=None, **vuln):
        base = {"type": "SQL Injection", "url": "http://t/login",
                "severity": "Critical", "confidence": "HIGH"}
        base.update(vuln)
        return await self.tester.report_vulnerability(base, param_value=param_value)


# ---- contrato estable de los registros de evidencia -------------------

def test_registros_hard_y_soft_conservan_su_contrato():
    # Otros agentes dependen de estos nombres y de estos miembros.
    for kind in ("error_signature", "interpreter_error", "time_confirmed",
                 "oob", "code_execution", "canary"):
        assert kind in HARD_EVIDENCE_KINDS
    for kind in ("differential", "status_change", "reflection", "time_unconfirmed"):
        assert kind in SOFT_EVIDENCE_KINDS
    assert not HARD_EVIDENCE_KINDS & SOFT_EVIDENCE_KINDS


def test_differential_causal_registrado_como_hard_como_documenta_causal_oracle():
    from web_security_scanner.core.causal_oracle import CAUSAL_EVIDENCE_KIND
    assert CAUSAL_EVIDENCE_KIND in HARD_EVIDENCE_KINDS
    # Pero no es de grado ejecución: sigue capado aun en CONFIRMED.
    v = apply_redirect_param_policy(parameter="next", evidence_kind=CAUSAL_EVIDENCE_KIND,
                                    severity="High", confidence="CONFIRMED")
    assert (v.keep, v.severity, v.action) == (True, "Medium", ACTION_CAPPED)


@pytest.mark.parametrize("kind,esperado", [
    ("error_signature", "hard"), ("DIFFERENTIAL", "soft"), (None, "unlabelled"),
    ("", "unlabelled"), ("header_reflection", "unknown"),
])
def test_clasificacion_de_fuerza_de_evidencia(kind, esperado):
    assert evidence_strength(kind) == esperado


# ---- política pura -----------------------------------------------------

def test_politica_por_defecto_sigue_descartando_sin_etiqueta():
    # Compatibilidad: sin cap_unlabelled el comportamiento previo no cambia.
    v = apply_redirect_param_policy(parameter="next", evidence_kind=None,
                                    severity="High", confidence="HIGH")
    assert v.keep is False and v.action == ACTION_SUPPRESSED


def test_politica_cap_unlabelled_mantiene_y_capa():
    v = apply_redirect_param_policy(parameter="next", evidence_kind=None,
                                    severity="High", confidence="HIGH",
                                    cap_unlabelled=True)
    assert (v.keep, v.severity, v.action) == (True, "Medium", ACTION_CAPPED)
    audit = v.to_audit(parameter="next")
    assert audit["original_severity"] == "High"
    assert audit["final_severity"] == "Medium"
    assert audit["evidence_strength"] == "unlabelled"


def test_etiqueta_desconocida_se_trata_como_soft():
    v = apply_redirect_param_policy(parameter="redirect_uri",
                                    evidence_kind="header_reflection",
                                    severity="High", confidence="HIGH")
    assert v.keep is False and v.evidence_strength == "unknown"


def test_parametro_ordinario_da_accion_pass():
    v = apply_redirect_param_policy(parameter="id", evidence_kind="differential",
                                    severity="Critical", confidence="MEDIUM")
    assert (v.keep, v.action, v.flow_control) == (True, ACTION_PASS, False)


# ---- gate en el tester base -------------------------------------------

async def test_redirect_con_evidencia_hard_se_mantiene_capada_y_auditada():
    h = _Harness()
    out = await h.report(parameter="next", evidence_kind="error_signature")
    assert out is not None and h.found == [out]
    assert out["severity"] == "Medium"
    assert "fp_filter" in out  # campo legado que siguen leyendo los consumidores
    verdict = out["param_semantics_verdict"]
    assert verdict["action"] == ACTION_CAPPED
    assert verdict["evidence_strength"] == "hard"
    assert verdict["original_severity"] == "Critical"
    assert verdict["final_severity"] == "Medium"
    assert verdict["parameter"] == "next"
    assert verdict["tester"] == "GateTester"


async def test_redirect_con_oraculo_de_ejecucion_confirmado_conserva_severidad():
    h = _Harness()
    out = await h.report(parameter="next", evidence_kind="time_confirmed",
                         confidence="CONFIRMED")
    assert out["severity"] == "Critical"
    assert "fp_filter" not in out
    assert out["param_semantics_verdict"]["action"] == ACTION_KEPT


async def test_redirect_con_evidencia_soft_se_suprime_pero_no_en_silencio():
    h = _Harness()
    out = await h.report(parameter="redirect_uri", evidence_kind="differential")
    assert out is None and h.found == []
    # La supresión queda registrada en el tester ...
    [suprimido] = h.tester.param_semantics_suppressed
    assert suprimido["parameter"] == "redirect_uri"
    verdict = suprimido["param_semantics_verdict"]
    assert verdict["action"] == ACTION_SUPPRESSED
    assert verdict["evidence_strength"] == "soft"
    assert verdict["final_severity"] is None
    assert "redirect_uri" in verdict["reason"]
    # ... y en un LOG_MESSAGE con el registro estructurado.
    logs = [k for k in h.logs if "param_semantics_verdict" in k]
    assert len(logs) == 1
    assert logs[0]["param_semantics_verdict"] == verdict
    assert "Suppressed" in logs[0]["message"]


async def test_redirect_sin_evidence_kind_se_mantiene_capada():
    h = _Harness()
    out = await h.report(parameter="return_to")  # sin evidence_kind
    assert out is not None
    assert out["severity"] == "Medium"
    verdict = out["param_semantics_verdict"]
    assert verdict["action"] == ACTION_CAPPED
    assert verdict["evidence_strength"] == "unlabelled"
    assert verdict["evidence_kind"] is None


async def test_sin_evidence_kind_y_severidad_baja_no_se_toca():
    h = _Harness()
    out = await h.report(parameter="next", severity="Low")
    assert out["severity"] == "Low"
    assert "fp_filter" not in out
    assert out["param_semantics_verdict"]["action"] == ACTION_KEPT


@pytest.mark.parametrize("kind", ["differential", "error_signature", None])
async def test_parametro_no_flow_control_sin_cambios(kind):
    h = _Harness()
    vuln = {"parameter": "id"}
    if kind:
        vuln["evidence_kind"] = kind
    out = await h.report(**vuln)
    assert out["severity"] == "Critical"
    assert "param_semantics_verdict" not in out
    assert "fp_filter" not in out
    assert getattr(h.tester, "param_semantics_suppressed", []) == []


@pytest.mark.parametrize("kind", ["differential", "error_signature", None])
async def test_flag_desactivado_sin_cambios(kind):
    h = _Harness(param_semantics=False)
    vuln = {"parameter": "next"}
    if kind:
        vuln["evidence_kind"] = kind
    out = await h.report(**vuln)
    assert out is not None and h.found == [out]
    assert out["severity"] == "Critical"
    assert "param_semantics_verdict" not in out
    assert "fp_filter" not in out


@pytest.mark.parametrize("name,value", [
    ("target", "/dashboard/"), ("page", "https://app.example/home"),
    ("u", "%2Fadmin%2F"), ("ref", "//evil.example/"),
])
async def test_nombre_neutro_con_valor_url_activa_el_gate(name, value):
    assert is_flow_control_point(name, value) is True
    h = _Harness()
    out = await h.report(parameter=name, evidence_kind="differential",
                         param_value=value)
    assert out is None
    assert h.tester.param_semantics_suppressed[0]["param_semantics_verdict"][
        "parameter"] == name


@pytest.mark.parametrize("name,value", [("target", "42"), ("page", "3"), ("u", "alice")])
async def test_nombre_neutro_con_valor_no_url_sin_cambios(name, value):
    h = _Harness()
    out = await h.report(parameter=name, evidence_kind="differential",
                         param_value=value)
    assert out is not None and out["severity"] == "Critical"
    assert "param_semantics_verdict" not in out


async def test_tester_nativo_de_flow_control_queda_exento():
    h = _Harness(tester_cls=OpenRedirectTester)
    out = await h.report(type="Open Redirect", parameter="next",
                         evidence_kind="reflection", severity="High")
    assert out is not None and out["severity"] == "High"
    assert out["param_semantics_verdict"]["action"] == ACTION_EXEMPT
    assert "fp_filter" not in out


async def test_atributo_flow_control_native_tambien_exime():
    class _Nativo(_GateTester):
        flow_control_native = True

    h = _Harness(tester_cls=_Nativo)
    out = await h.report(parameter="url", evidence_kind="differential")
    assert out is not None
    assert out["param_semantics_verdict"]["action"] == ACTION_EXEMPT


# ---- flag de CLI -> config del tester -> manifest ---------------------

def _config(*argv):
    args = _build_parser().parse_args(["scan", "http://t", *argv])
    return _build_config(args)


def test_flag_por_defecto_activa_el_gate():
    assert _config()["testers"]["param_semantics"] is True


def test_flag_no_param_semantics_llega_a_testers_y_manifest():
    cfg = _config("--no-param-semantics")
    assert cfg["testers"]["param_semantics"] is False
    manifest = build_manifest(run_id="r", config=cfg, global_seed=None,
                              corpus_dir="/nonexistent")
    assert manifest["config"]["testers"]["param_semantics"] is False


def test_flag_no_causal_oracle_llega_a_testers_y_manifest():
    assert _config()["testers"]["causal_oracle"] is True
    cfg = _config("--no-causal-oracle")
    assert cfg["testers"]["causal_oracle"] is False
    manifest = build_manifest(run_id="r", config=cfg, global_seed=None,
                              corpus_dir="/nonexistent")
    assert manifest["config"]["testers"]["causal_oracle"] is False
