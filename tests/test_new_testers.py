"""Integration tests for the v5.1 testers (SSTI, CRLF, LDAP, deserialization, Log4Shell).

Each runs the real tester against a MockScanner responder simulating a
vulnerable endpoint, mirroring test_testers.py / test_payload_loader.py.
"""

from conftest import collect_vulns, param_value

from web_security_scanner.core.payload_loader import WSS_CANARY
from web_security_scanner.modules.vulnerability_testers.crlf_async import CRLFTester
from web_security_scanner.modules.vulnerability_testers.deserialization_async import (
    DeserializationTester,
)
from web_security_scanner.modules.vulnerability_testers.ldap_injection_async import (
    LDAPInjectionTester,
)
from web_security_scanner.modules.vulnerability_testers.log4shell_async import Log4ShellTester
from web_security_scanner.modules.vulnerability_testers.ssti_async import PRODUCT, SSTITester

# ---- SSTI --------------------------------------------------------------

async def test_ssti_detected_when_expression_is_evaluated():
    def responder(method, url, kwargs):
        q = param_value(url, "q")
        # A vulnerable engine evaluates the arithmetic; echo only the result.
        if "1338*1337" in q:
            return {"text": f"<h1>Hello {PRODUCT}</h1>"}
        return {"text": f"<h1>Hello {q}</h1>"}

    found = await collect_vulns(SSTITester, responder)
    assert found
    assert any(v["confidence"] == "HIGH" and PRODUCT not in v["payload"] for v in found)


async def test_ssti_not_flagged_when_expression_is_reflected_literally():
    def responder(method, url, kwargs):
        return {"text": f"echo: {param_value(url, 'q')}"}

    assert await collect_vulns(SSTITester, responder) == []


async def test_ssti_not_flagged_when_product_already_on_page():
    def responder(method, url, kwargs):
        return {"text": f"Order #{PRODUCT} — {param_value(url, 'q')}"}

    assert await collect_vulns(SSTITester, responder) == []


# ---- CRLF -------------------------------------------------------------

async def test_crlf_detected_when_header_reflected():
    def responder(method, url, kwargs):
        raw = param_value(url, "q")  # parse_qs already decoded %0d%0a -> \r\n
        headers = {"Content-Type": "text/html"}
        if "\r\n" in raw or "\n" in raw:
            first, _, rest = raw.partition("\n")
            name, _, value = rest.partition(":")
            if name.strip():
                headers[name.strip()] = value.strip()
        return {"text": "ok", "headers": headers}

    found = await collect_vulns(CRLFTester, responder)
    assert found
    assert any(WSS_CANARY in v["evidence"] for v in found)


async def test_crlf_not_flagged_when_input_only_in_body():
    def responder(method, url, kwargs):
        return {"text": f"you said {param_value(url, 'q')}", "headers": {}}

    assert await collect_vulns(CRLFTester, responder) == []


# ---- LDAP -----------------------------------------------------------

async def test_ldap_injection_detected_via_error_signature():
    def responder(method, url, kwargs):
        q = param_value(url, "q")
        if "*)(" in q or ")(&" in q:
            return {"text": "javax.naming.NamingException: [LDAP: error code 4]"}
        return {"text": "no results"}

    found = await collect_vulns(LDAPInjectionTester, responder)
    assert found
    assert any(v["confidence"] == "HIGH" for v in found)


async def test_ldap_injection_quiet_on_clean_target():
    def responder(method, url, kwargs):
        return {"text": "results for " + param_value(url, "q")}

    assert await collect_vulns(LDAPInjectionTester, responder) == []


# ---- Deserialization ------------------------------------------------

async def test_deserialization_detected_via_error_signature():
    def responder(method, url, kwargs):
        return {"text": "java.io.InvalidClassException: local class incompatible"}

    found = await collect_vulns(DeserializationTester, responder)
    assert found
    assert found[0]["type"]


async def test_deserialization_quiet_when_no_sink():
    def responder(method, url, kwargs):
        return {"text": "welcome"}

    assert await collect_vulns(DeserializationTester, responder) == []


# ---- Log4Shell ----------------------------------------------------

async def test_log4shell_inert_without_oob_domain():
    def responder(method, url, kwargs):
        return {"text": "ok"}

    assert await collect_vulns(Log4ShellTester, responder) == []


async def test_log4shell_delivers_and_reports_when_oob_configured():
    seen = []

    def responder(method, url, kwargs):
        seen.append((url, kwargs.get("headers")))
        return {"text": "ok"}

    found = await collect_vulns(
        Log4ShellTester, responder, config={"oob_domain": "c.example-oob.invalid"}
    )
    assert found
    assert found[0]["severity"] == "Info" and found[0]["confidence"] == "LOW"
    assert any("jndi" in (h or {}).get("User-Agent", "") for _, h in seen)
