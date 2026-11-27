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
