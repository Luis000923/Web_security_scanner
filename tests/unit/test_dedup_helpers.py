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
