"""Helpers extracted by the low-risk dedup refactor keep the old semantics."""

from __future__ import annotations

from web_security_scanner.core.external_tools import (
    GospiderAdapter,
    InteractshAdapter,
    KatanaAdapter,
    KiterunnerAdapter,
    NaabuAdapter,
    NucleiAdapter,
)
from web_security_scanner.core.external_tools.base import iter_json_lines
from web_security_scanner.utils.http_headers import content_type_of

NOISY = '[INF] banner\n\n  {"a": 1}  \nnot json\n{"b": 2}\n[1, 2]\n'


def test_iter_json_lines_salta_banners_vacias_e_invalidas() -> None:
    assert list(iter_json_lines(NOISY)) == [{"a": 1}, {"b": 2}, [1, 2]]


def test_iter_json_lines_con_prefijo_solo_objetos() -> None:
    assert list(iter_json_lines(NOISY, prefix="{")) == [{"a": 1}, {"b": 2}]


def test_iter_json_lines_vacio() -> None:
    assert list(iter_json_lines("")) == []


def test_adaptadores_jsonl_ignoran_ruido() -> None:
    out = '[WRN] x\n{"url": "http://t/a", "status": 200}\n{broken\n'
    assert GospiderAdapter().parse(out)[0]["status_code"] == 200
    assert KiterunnerAdapter().parse(out)[0]["url"] == "http://t/a"
    assert KatanaAdapter().parse(out)[0]["url"] == "http://t/a"
    assert NaabuAdapter().parse('{"ip": "10.0.0.1", "port": 80}\nnoise')[0]["host"] == "10.0.0.1"
    assert (
        NucleiAdapter().parse('{"template-id": "t1", "info": {"severity": "high"}}')[0]["severity"]
        == "high"
    )
    assert InteractshAdapter().parse('[1]\n{"protocol": "dns"}')[0]["protocol"] == "dns"
    assert len(InteractshAdapter().parse('[1]\n{"protocol": "dns"}')) == 1


def test_content_type_of_case_insensitive_y_lower() -> None:
    assert (
        content_type_of({"Content-Type": "Text/HTML; charset=UTF-8"}) == "text/html; charset=utf-8"
    )
    assert content_type_of({"content-TYPE": "application/json"}) == "application/json"


def test_content_type_of_ausente_o_none() -> None:
    assert content_type_of({}) == ""
    assert content_type_of(None) == ""
    assert content_type_of({"X-Other": "a"}) == ""


class _FakeContent:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def iter_chunked(self, _size: int):  # type: ignore[no-untyped-def]
        for chunk in self._chunks:
            yield chunk


class _FakeResponse:
    def __init__(self, chunks: list[bytes], encoding: str | None = "utf-8") -> None:
        self.content = _FakeContent(chunks)
        self._encoding = encoding
        self.closed = False

    def get_encoding(self) -> str:
        if self._encoding is None:
            raise RuntimeError("no encoding")
        return self._encoding

    def close(self) -> None:
        self.closed = True


async def test_read_body_capped_bajo_el_limite() -> None:
    from web_security_scanner.core.http_client import read_body_capped

    resp = _FakeResponse([b"hola ", b"mundo"])
    assert await read_body_capped(resp, 100) == ("hola mundo", False, 10)  # type: ignore[arg-type]
    assert not resp.closed


async def test_read_body_capped_trunca_y_cierra_el_socket() -> None:
    from web_security_scanner.core.http_client import read_body_capped

    resp = _FakeResponse([b"aaaa", b"bbbb", b"cccc"])
    assert await read_body_capped(resp, 6) == ("aaaabb", True, 6)  # type: ignore[arg-type]
    assert resp.closed


async def test_read_body_capped_encoding_desconocido_cae_a_utf8() -> None:
    from web_security_scanner.core.http_client import read_body_capped

    resp = _FakeResponse(["ñ".encode()], encoding=None)
    assert await read_body_capped(resp, 100) == ("ñ", False, 2)  # type: ignore[arg-type]


# --- report helpers ----------------------------------------------------------


def test_pdf_kv_table_layout_y_spacer() -> None:
    from reportlab.lib.units import cm
    from reportlab.platypus import Spacer, Table

    from web_security_scanner.report_generator import _pdf_kv_table, _pdf_styles

    block = _pdf_kv_table([["Vector", "a&amp;b"], ["Payload", "x"]], _pdf_styles())
    table, spacer = block
    assert isinstance(table, Table) and isinstance(spacer, Spacer)
    assert table._colWidths == [3.5 * cm, 11.5 * cm]
    assert [c[0].text for c in table._cellvalues] == ["<b>Vector</b>", "<b>Payload</b>"]
    assert [c[1].text for c in table._cellvalues] == ["a&amp;b", "x"]
    (grid,) = table._linecmds
    assert grid[0] == "GRID" and grid[3] == 0.5 and grid[4].hexval() == "0xdddddd"
    cell = table._cellStyles[0][0]
    assert (cell.valign, cell.leftPadding, cell.topPadding, cell.bottomPadding) == (
        "TOP",
        6,
        5,
        5,
    )
    assert spacer.height == 0.5 * cm


def test_pdf_findings_usa_una_tabla_por_hallazgo() -> None:
    from reportlab.platypus import Table

    from web_security_scanner.report_generator import _pdf_findings, _pdf_styles

    vuln = {
        "type": "XSS",
        "risk_level": "High",
        "confidence": "HIGH",
        "confirmation_status": "confirmed",
        "vector": "q",
        "evidence": "<script>",
    }
    story = _pdf_findings({"vulnerabilities": [vuln, dict(vuln)]}, _pdf_styles())
    tables = [f for f in story if isinstance(f, Table)]
    assert len(tables) == 2
    labels = [row[0].text for row in tables[0]._cellvalues]
    assert labels[-1].endswith("</b>") and len(labels) == len(set(labels))
    assert len(labels) == len([r for r in tables[1]._cellvalues])  # same layout per finding
    no_evidence = dict(vuln, evidence=None)
    (short,) = [
        f
        for f in _pdf_findings({"vulnerabilities": [no_evidence]}, _pdf_styles())
        if isinstance(f, Table)
    ]
    assert len(short._cellvalues) == len(labels) - 1  # Evidence row is optional


def test_write_json_report_crea_directorio_y_respeta_formato(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import json as _json

    from web_security_scanner.report_generator import write_json_report

    out = tmp_path / "a" / "b"
    path = write_json_report({"ñ": [1, 2]}, str(out), ".sarif.json")
    assert path.startswith(str(out / "scan_")) and path.endswith(".sarif.json")
    text = (out / path.rsplit("/", 1)[-1]).read_text(encoding="utf-8")
    assert text == _json.dumps({"ñ": [1, 2]}, indent=2, ensure_ascii=False)


def test_generadores_json_delegan_en_write_json_report(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from web_security_scanner import report_engine, report_generator

    data = {"target": "http://t", "vulnerabilities": []}
    for fn, suffix in [
        (report_generator.generate_json_report, ".json"),
        (report_engine.generate_sarif_report, ".sarif.json"),
        (report_engine.generate_enriched_json_report, ".enriched.json"),
    ]:
        assert fn(data, str(tmp_path)).endswith(suffix)


# --- HTTP session construction ---------------------------------------------


async def test_new_client_session_user_agent_y_cookie_jar() -> None:
    import aiohttp

    from web_security_scanner.core.http_client import new_client_session

    session = new_client_session(
        aiohttp.TCPConnector(), {"X-A": "1"}, "UA/1", cookie_jar_unsafe=True
    )
    try:
        assert session.headers["User-Agent"] == "UA/1"
        assert session.headers["X-A"] == "1"
        assert session.cookie_jar._unsafe is True  # type: ignore[attr-defined]
    finally:
        await session.close()
    explicit = new_client_session(
        aiohttp.TCPConnector(), {"User-Agent": "mine"}, "UA/1", cookie_jar_unsafe=False
    )
    try:
        assert explicit.headers["User-Agent"] == "mine"
    finally:
        await explicit.close()


async def test_start_idempotente_en_ambos_clientes() -> None:
    from web_security_scanner.core.http_client import AsyncHTTPClient, HTTPClientConfig
    from web_security_scanner.core.scanner_core_async import AsyncScannerCore, ScanConfig

    client = AsyncHTTPClient(HTTPClientConfig())
    await client.start()
    first = client.session
    await client.start()
    assert client.session is first
    await first.close()  # closed behind its back: AsyncHTTPClient rebuilds
    await client.start()
    assert client.session is not first and not client.session.closed
    await client.close()

    core = AsyncScannerCore(ScanConfig())
    await core.start()
    session = core.session
    await core.start()
    assert core.session is session
    await core.close()
    assert core.session is None
    await core.start()
    assert core.session is not None and core.session is not session
    await core.close()
