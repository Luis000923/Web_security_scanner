import urllib.parse
from pathlib import Path

import pytest

from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType

# Ensure i18n is loaded once for all tests.
from web_security_scanner.utils.i18n import i18n

_LANG = Path(__file__).parent.parent / "web_security_scanner" / "languages.yaml"
i18n.load_languages(str(_LANG))
i18n.set_language("en")


class MockScanner:
    """
    Minimal stand-in for AsyncScannerCore.

    `responder(method, url, kwargs) -> response_dict` lets each test decide how
    the "target" replies. Response dicts mirror the real core's shape:
    {status_code, text, headers, url, elapsed}.
    """

    def __init__(self, responder):
        self.responder = responder

    async def request(self, method, url, **kwargs):
        resp = self.responder(method, url, kwargs)
        resp.setdefault("status_code", 200)
        resp.setdefault("text", "")
        resp.setdefault("headers", {})
        resp.setdefault("elapsed", 0.0)
        resp.setdefault("url", url)
        return resp


def param_value(url, name):
    """Helper: read a query param value from a URL."""
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    return q.get(name, [""])[0]


async def collect_vulns(tester_cls, responder, target="http://target/page?q=1&id=1", config=None):
    """Instantiate a tester against a MockScanner and return found vulns."""
    em = ScanEventEmitter()
    found = []
    em.on(ScanEventType.VULNERABILITY_FOUND, lambda **k: found.append(k.get("vulnerability")))
    cfg = {"payload_delay": 0, "max_payloads": 8}
    if config:
        cfg.update(config)
    tester = tester_cls(MockScanner(responder), em, cfg)
    await tester.run_test(target)
    return found


async def collect_log_messages(tester_cls, responder, target="http://target/page?q=1&id=1", config=None):
    """Run a tester and return every LOG_MESSAGE payload it emitted.

    Guards the enum-vs-string emit bug: testers must emit the ScanEventType
    enum, not the string "LOG_MESSAGE" (which the emitter silently drops).
    """
    em = ScanEventEmitter()
    logs = []
    em.on(ScanEventType.LOG_MESSAGE, lambda **k: logs.append(k.get("message")))
    cfg = {"payload_delay": 0, "max_payloads": 8}
    if config:
        cfg.update(config)
    tester = tester_cls(MockScanner(responder), em, cfg)
    await tester.run_test(target)
    return logs


@pytest.fixture
def collect():
    return collect_vulns
