"""False-positive suppression on redirect / flow-control parameters.

A Django-style ``?next=/dashboard/`` (or ``redirect_uri``, ``return_to``,
``url`` …) is validated by the application and then redirected to. Injecting a
SQL / NoSQL / LDAP payload into it routinely changes the response — a 302, a
"not a valid redirect URL" form error, a different hidden-field length — with
nothing ever reaching a database or directory server. Those differential-only
findings used to be reported as Critical/High and then poisoned the triage-LLM
dataset with confidently-wrong labels.

The rules under test:

* differential-only evidence on a redirect parameter -> finding dropped;
* the same evidence on an ordinary parameter (``id``) -> still reported;
* hard evidence (DB / LDAP parser error) on a redirect parameter -> kept, but
  never at High/Critical severity unless the confidence is CONFIRMED;
* the open-redirect tester, whose whole job is those parameters, is untouched.
"""

import pytest
from conftest import collect_vulns, param_value

from web_security_scanner.core.param_semantics import (
    apply_redirect_param_policy,
    cap_severity,
    is_flow_control_point,
    is_redirect_param,
)
from web_security_scanner.modules.vulnerability_testers.ldap_injection_async import (
    LDAPInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.nosql_injection_async import (
    NoSQLInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.open_redirect_async import (
    OpenRedirectTester,
)
from web_security_scanner.modules.vulnerability_testers.sql_injection_async import (
    SQLInjectionTester,
)

LOGIN_URL = "http://target/accounts/login/?next=/dashboard/"
ID_URL = "http://target/item?id=1"


# ---- param_semantics unit level ---------------------------------------

@pytest.mark.parametrize("name", [
    "next", "NEXT", "next_url", "redirect", "redirect_to", "redirect_uri",
    "return_to", "returnUrl", "back", "goto", "continue", "destination",
    "callback_url", "url", "uri", "image_url", "success_url",
])
def test_known_redirect_parameter_names_are_recognised(name):
    assert is_redirect_param(name) is True


@pytest.mark.parametrize("name", [
    "id", "q", "search", "username", "user_id", "email", "order", "feedback",
    "comment", "filename", "sort", "category",
])
def test_ordinary_parameter_names_are_not_redirect_params(name):
    assert is_redirect_param(name) is False


def test_ambiguous_name_needs_a_url_like_value():
    # `target=42` is an identifier; `target=/dashboard/` is a destination.
    assert is_flow_control_point("target", "42") is False
    assert is_flow_control_point("target", "/dashboard/") is True
    assert is_flow_control_point("target", "https://app.example/home") is True


def test_policy_drops_differential_evidence_on_redirect_param():
    verdict = apply_redirect_param_policy(
        parameter="next", evidence_kind="differential",
        severity="Critical", confidence="MEDIUM",
    )
    assert verdict.keep is False
    assert "next" in verdict.reason


def test_policy_keeps_hard_evidence_but_caps_severity():
    verdict = apply_redirect_param_policy(
        parameter="redirect_uri", evidence_kind="error_signature",
        severity="High", confidence="HIGH",
    )
    assert verdict.keep is True
    assert verdict.severity == "Medium"
    assert verdict.confidence == "HIGH"


def test_policy_keeps_full_severity_when_confirmed():
    verdict = apply_redirect_param_policy(
        parameter="next", evidence_kind="time_confirmed",
        severity="High", confidence="CONFIRMED",
    )
    assert verdict.keep is True
    assert verdict.severity == "High"


def test_policy_leaves_ordinary_parameters_untouched():
    verdict = apply_redirect_param_policy(
        parameter="id", evidence_kind="differential",
        severity="Critical", confidence="MEDIUM",
    )
    assert (verdict.keep, verdict.severity, verdict.confidence) == (
        True, "Critical", "MEDIUM")


def test_cap_severity_never_raises_a_low_finding():
    assert cap_severity("Low") == "Low"
    assert cap_severity("Info") == "Info"
    assert cap_severity("Critical") == "Medium"


# ---- SQL injection ----------------------------------------------------

def _redirecting_app(method, url, kwargs):
    """A login page that validates ``next`` and 302s when it is a safe path.

    Any other value gets a differently-sized error page — the exact divergence
    the boolean-based oracle used to report as SQLi.
    """
    value = param_value(url, "next")
    if value.startswith("/"):
        return {"status_code": 302, "text": "", "headers": {"Location": value}}
    return {"status_code": 200, "text": "<html>" + "Unsafe redirect URL. " * 40 + "</html>"}


async def test_sqli_not_reported_on_next_parameter_differential():
    assert await collect_vulns(SQLInjectionTester, _redirecting_app,
                               target=LOGIN_URL) == []


async def test_sqli_still_reported_on_ordinary_parameter_differential():
    def responder(method, url, kwargs):
        value = param_value(url, "id")
        if value.isdigit() or value.startswith("benign"):
            return {"status_code": 200, "text": "<html>item 1</html>"}
        return {"status_code": 200, "text": "<html>" + "row " * 200 + "</html>"}

    found = await collect_vulns(SQLInjectionTester, responder, target=ID_URL)
    assert found, "a differential on a plain parameter must still be reported"
    assert found[0]["parameter"] == "id"


async def test_sqli_database_error_on_next_is_kept_but_capped():
    def responder(method, url, kwargs):
        value = param_value(url, "next")
        if value.startswith("/") or value.startswith("benign"):
            return {"status_code": 302, "text": ""}
        return {"status_code": 500,
                "text": "You have an error in your SQL syntax near '--'"}

    found = await collect_vulns(SQLInjectionTester, responder, target=LOGIN_URL)
    assert found, "a real DBMS error must survive the redirect-param filter"
    vuln = found[0]
    assert vuln["parameter"] == "next"
    assert vuln["severity"] == "Medium"      # capped down from High
    assert vuln["confidence"] == "HIGH"
    assert "fp_filter" in vuln



# ---- NoSQL injection --------------------------------------------------

async def test_nosql_not_reported_on_redirect_parameter():
    def responder(method, url, kwargs):
        value = param_value(url, "redirect_uri")
        if value.startswith("/") or value.startswith("benign"):
            return {"status_code": 302, "text": ""}
        return {"status_code": 400, "text": "invalid redirect target " * 30}

    assert await collect_vulns(
        NoSQLInjectionTester, responder,
        target="http://target/login?redirect_uri=/home/") == []


async def test_nosql_driver_error_on_redirect_parameter_is_kept():
    def responder(method, url, kwargs):
        value = param_value(url, "redirect_uri")
        if value.startswith("/") or value.startswith("benign"):
            return {"status_code": 302, "text": ""}
        return {"status_code": 500, "text": "MongoError: E11000 duplicate key"}

    found = await collect_vulns(
        NoSQLInjectionTester, responder,
        target="http://target/login?redirect_uri=/home/")
    assert found
    assert found[0]["severity"] == "Medium"   # capped down from Critical


async def test_nosql_still_reported_on_ordinary_parameter():
    def responder(method, url, kwargs):
        value = param_value(url, "id")
        if value.startswith("benign") or value.isdigit():
            return {"status_code": 200, "text": "user 1"}
        return {"status_code": 200, "text": "all users " * 100}

    found = await collect_vulns(NoSQLInjectionTester, responder, target=ID_URL)
    assert found
    assert found[0]["severity"] == "Critical"


# ---- LDAP injection ---------------------------------------------------

async def test_ldap_not_reported_on_return_to_parameter():
    def responder(method, url, kwargs):
        value = param_value(url, "return_to")
        if value.startswith("/") or value.startswith("benign"):
            return {"status_code": 302, "text": ""}
        return {"status_code": 200, "text": "please supply a valid URL " * 40}

    assert await collect_vulns(
        LDAPInjectionTester, responder,
        target="http://target/sso?return_to=/portal/") == []


async def test_ldap_filter_error_on_return_to_is_kept_but_capped():
    def responder(method, url, kwargs):
        value = param_value(url, "return_to")
        if value.startswith("/") or value.startswith("benign"):
            return {"status_code": 302, "text": ""}
        return {"status_code": 500, "text": "javax.naming.NamingException: bad search filter"}

    found = await collect_vulns(
        LDAPInjectionTester, responder,
        target="http://target/sso?return_to=/portal/")
    assert found
    assert found[0]["severity"] == "Medium"    # capped down from High
    assert found[0]["confidence"] == "HIGH"


# ---- the open-redirect tester must keep working -----------------------

async def test_open_redirect_still_reports_on_next_parameter():
    """The policy targets *injection* findings, not open-redirect ones."""
    def responder(method, url, kwargs):
        value = param_value(url, "next")
        return {"status_code": 302, "text": "", "headers": {"Location": value}}

    found = await collect_vulns(OpenRedirectTester, responder, target=LOGIN_URL)
    assert found, "open redirect on `next` is a real finding and must survive"
