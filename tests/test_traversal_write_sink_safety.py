"""Seguridad ante sinks de escritura en el tester de path traversal.

Incidente verificado: en el OWASP Benchmark los sinks ``FileOutputStream``
abren ``TESTFILES_DIR + payload`` en modo escritura como root, así que el
payload de *lectura* ``../../../../../../../../etc/passwd`` truncó
``/etc/passwd`` a 0 bytes. Estos tests fijan la mitigación: sin
``allow_destructive`` solo salen traversals a objetivos que sobreviven a un
``open(O_WRONLY|O_CREAT|O_TRUNC)`` como root (procfs sin handler de escritura,
DLLs de sistema mapeadas en Windows) y la detección sigue funcionando sobre
esos objetivos.
"""
import json
from pathlib import Path

import pytest
from conftest import MockScanner, param_value

from web_security_scanner.core.payload_loader import Payload
from web_security_scanner.events.event_emitter import ScanEventEmitter, ScanEventType
from web_security_scanner.modules.vulnerability_testers.path_traversal_async import (
    DEFAULT_PAYLOADS,
    PATH_SEGMENT_PAYLOADS,
    PathTraversalTester,
    is_write_unsafe_file_target,
)

CORPUS = (Path(__file__).resolve().parents[1]
          / "web_security_scanner" / "PAYLOAD" / "data" / "path_traversal.json")

PROC_STATUS_BODY = (
    "Name:\tjava\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t1\nNgid:\t0\n"
    "Pid:\t1\nPPid:\t0\nTracerPid:\t0\nUid:\t0\t0\t0\t0\n"
)
PROC_VERSION_BODY = (
    "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-075) "
    "(x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0) #45-Ubuntu SMP"
)
PE_BODY = "MZ\x90\x00\x03\x00\x00\x00!This program cannot be run in DOS mode.\r\r\n$"

DESTRUCTIVOS = [
    "../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "/etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..%c0%af..%c0%afetc/passwd",
    "../../../../etc/passwd%00.png",
    "../../../../etc/shadow",
    "..\\..\\..\\..\\windows\\win.ini",
    "c:\\windows\\win.ini",
    "file:///etc/passwd",
    "file://localhost/c:/windows/win.ini",
    "php://filter/convert.base64-encode/resource=../../../etc/passwd",
    "../../.env",
    "../../wp-config.php",
    "~/.ssh/id_rsa",
    # procfs que NO es seguro: fd/N es un symlink a un fichero real abierto.
    "/proc/self/fd/1",
    "../../../../proc/self/fd/3",
    "/proc/self/exe",
    # Salir de /proc vuelve a un fichero real.
    "/proc/self/status/../../../etc/passwd",
]

SEGUROS = [
    "../../../../../../../../proc/self/status",
    "/proc/self/status",
    "....//....//....//proc/self/status",
    "%2e%2e%2f%2e%2e%2fproc%2fself%2fstatus",
    "/proc/self/status%00.png",
    "../../../../proc/version",
    "/proc/self/cmdline",
    "/proc/mounts",
    "..\\..\\..\\..\\windows\\system32\\kernel32.dll",
    "..%5c..%5cwindows%5csystem32%5cntdll.dll",
    # Traversal a directorio: abrir un directorio en escritura falla (EISDIR).
    "../../",
    "..%2F..%2F",
    "/proc/self/cwd/",
    # Wrappers sin fichero detrás.
    "data://text/plain;base64,V1NTYzRuNHJ5Nzc4OA==",
    "php://input",
]


def _tester(config=None):
    cfg = {"payload_delay": 0}
    if config:
        cfg.update(config)
    return PathTraversalTester(MockScanner(lambda m, u, k: {"text": ""}),
                               ScanEventEmitter(), cfg)


async def _run(responder, target, *, payloads=None, config=None):
    em = ScanEventEmitter()
    found = []
    em.on(ScanEventType.VULNERABILITY_FOUND,
          lambda **k: found.append(k.get("vulnerability")))
    cfg = {"payload_delay": 0, "max_payloads": 0}
    if config:
        cfg.update(config)
    urls = []

    def recording(method, url, kwargs):
        urls.append(url)
        return responder(method, url, kwargs)

    tester = PathTraversalTester(MockScanner(recording), em, cfg)
    if payloads is not None:
        tester.payloads = list(payloads)
    await tester.run_test(target)
    return found, urls


# ---- Clasificador -----------------------------------------------------------

@pytest.mark.parametrize("payload", DESTRUCTIVOS)
def test_objetivo_de_sistema_es_destructivo(payload):
    assert is_write_unsafe_file_target(payload)
    assert _tester().is_destructive_payload(payload)


@pytest.mark.parametrize("payload", SEGUROS)
def test_objetivo_seguro_no_es_destructivo(payload):
    assert not is_write_unsafe_file_target(payload)
    assert not _tester().is_destructive_payload(payload)


def test_heuristica_base_se_conserva():
    """El override suma al gate base, no lo sustituye."""
    assert _tester().is_destructive_payload("../../x; rm -rf /")


# ---- filter_payloads / filter_payload_objs ------------------------------------

def test_filter_payloads_quita_etc_passwd_sin_allow_destructive():
    kept = _tester().filter_payloads(DESTRUCTIVOS + SEGUROS)
    assert kept == SEGUROS
    assert not any("passwd" in p or "win.ini" in p for p in kept)


def test_filter_payloads_permite_etc_passwd_con_allow_destructive():
    payloads = DESTRUCTIVOS + SEGUROS
    assert _tester({"allow_destructive": True}).filter_payloads(payloads) == payloads


def test_filter_payload_objs_mismo_comportamiento():
    objs = [Payload(vector=v, category="path_traversal") for v in DESTRUCTIVOS + SEGUROS]
    kept = _tester().filter_payload_objs(objs)
    assert [p.vector for p in kept] == SEGUROS
    allowed = _tester({"allow_destructive": True}).filter_payload_objs(objs)
    assert [p.vector for p in allowed] == DESTRUCTIVOS + SEGUROS


def test_defaults_tienen_objetivos_seguros_primero():
    for lista in (DEFAULT_PAYLOADS, PATH_SEGMENT_PAYLOADS):
        safe = _tester().filter_payloads(lista)
        assert safe, "sin allow_destructive debe quedar algún payload"
        assert lista[:len(safe)] == safe


# ---- Corpus -----------------------------------------------------------------

def test_corpus_marca_destructive_coherente_con_el_clasificador():
    """El flag del corpus también protege a ExploitEngine (include_destructive=False)."""
    payloads = json.loads(CORPUS.read_text(encoding="utf-8"))["payloads"]
    incoherentes = [
        p["id"] for p in payloads
        if is_write_unsafe_file_target(p["vector"]) and not p.get("destructive")
    ]
    assert incoherentes == []
    seguros = [p for p in payloads if "write_safe" in p.get("tags", [])]
    assert seguros and all(not p.get("destructive") for p in seguros)


# ---- Comportamiento extremo a extremo ----------------------------------------

async def test_run_test_no_envia_ficheros_de_sistema_por_defecto():
    found, urls = await _run(lambda m, u, k: {"text": "documento"},
                             "http://target/d?file=a.pdf",
                             payloads=DESTRUCTIVOS + SEGUROS)
    assert found == []
    enviados = [param_value(u, "file") for u in urls]
    assert enviados and not any(is_write_unsafe_file_target(v) for v in enviados)


async def test_run_test_envia_etc_passwd_con_allow_destructive():
    _, urls = await _run(lambda m, u, k: {"text": "documento"},
                         "http://target/d?file=a.pdf",
                         payloads=["../../../../etc/passwd"],
                         config={"allow_destructive": True})
    assert any("passwd" in param_value(u, "file") for u in urls)


@pytest.mark.parametrize("cuerpo,marca", [
    (PROC_STATUS_BODY, "proc/self/status"),
    (PROC_VERSION_BODY, "proc/version"),
    (PE_BODY, "kernel32.dll"),
])
async def test_objetivo_seguro_sigue_detectando(cuerpo, marca):
    def r(m, u, kw):
        if marca in param_value(u, "file").replace("\\", "/"):
            return {"text": cuerpo}
        return {"text": "documento"}

    found, _ = await _run(r, "http://target/d?file=a.pdf",
                          payloads=[p for p in SEGUROS + DEFAULT_PAYLOADS
                                    if marca in p.replace("\\", "/")])
    assert len(found) == 1
    assert found[0]["evidence_kind"] == "canary"
    assert found[0]["confidence"] == "CONFIRMED"


async def test_proc_status_codificado_en_html_detecta():
    """ESAPI encodeForHTML (Benchmark) codifica ':' y tabuladores."""
    encoded = PROC_STATUS_BODY.replace(":", "&#x3a;").replace("\t", "&#x9;")

    def r(m, u, kw):
        if "proc/self/status" in param_value(u, "file"):
            return {"text": encoded}
        return {"text": "documento"}

    found, _ = await _run(r, "http://target/d?file=a.pdf",
                          payloads=["/proc/self/status"])
    assert len(found) == 1


async def test_ruta_sin_parametros_filtra_tambien_segmentos():
    found, urls = await _run(lambda m, u, k: {"text": "nada"},
                             "http://target/static/report.pdf")
    assert found == []
    assert urls
    for url in urls:
        tail = url.rsplit("/static/", 1)[-1]
        assert not is_write_unsafe_file_target(tail), tail


def test_firma_proc_version_no_dispara_con_texto_suelto():
    t = _tester()
    assert not t._leaked_file("We run Linux version 6.8 on our servers.")
    assert t._leaked_file(PROC_VERSION_BODY)
