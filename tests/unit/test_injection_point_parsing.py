"""Unit tests for InjectionPoint request materialisation.

Covers the four request-body shapes the scanner has to get right for a probe to
mean anything: GET query string, nested JSON, form-urlencoded, and multipart
(with its field / filename / content / content_type positions).

The property that matters throughout is **syntactic integrity**: after a payload
is injected, the request must still parse as the shape it claims to be, the
payload must land *exactly* where intended (byte-for-byte, after the normal
transport encoding round-trip), and every sibling structure the caller supplied
must survive untouched. A probe whose body got corrupted does not test the
vulnerability -- it tests nothing, and silently reads as a negative result.

Docstrings and comments are English (house rule). Research findings
(i.e. statements about the tool's behaviour, not mechanics) are Spanish.
"""

import json
import urllib.parse

import aiohttp
import pytest

from web_security_scanner.core.injection_point import (
    InjectionPoint,
    inject_query_param,
)

# Payloads chosen to break naive concatenation: reserved delimiters for each
# transport, quoting, newlines, unicode, and a SQL/command metacharacter set.
NASTY_PAYLOADS = [
    "' OR 1=1--",
    "a&b=c",
    "x=y&z",
    "<script>alert(1)</script>",
    'quo"te',
    "semi;colon",
    "back\\slash",
    "100%",
    "hash#fragment",
    "space here",
    "acentuación-ñ",
    "null\x00byte",
    "$IFS${IFS}",
    "../../etc/passwd",
]


# ---- helpers ---------------------------------------------------------------


def _form_fields(form: aiohttp.FormData) -> list[tuple]:
    """Flatten a FormData into (name, filename, content_type, value) tuples.

    Reads aiohttp's internal ``_fields`` triple (type_options, headers, value).
    ``filename`` lives in the options MultiDict while ``content_type`` is
    normalised into a real ``Content-Type`` header, so both have to be read.
    """
    out = []
    for opts, headers, value in form._fields:
        out.append((
            opts.get("name"),
            opts.get("filename"),
            (headers or {}).get("Content-Type"),
            value,
        ))
    return out


def _field_by_name(form: aiohttp.FormData, name: str):
    for entry in _form_fields(form):
        if entry[0] == name:
            return entry
    raise AssertionError(f"multipart field {name!r} not found in {form!r}")


# ---- GET query string ------------------------------------------------------


@pytest.mark.parametrize("payload", NASTY_PAYLOADS)
def test_get_param_payload_survives_query_encoding(payload):
    """The payload must arrive at the origin byte-for-byte.

    urllib's query encoding is the only transformation allowed between the
    payload string and what the server parses out of the query.
    """
    point = InjectionPoint(base_url="http://target/api/search", param="q", vector="getparam")
    method, url, kwargs = point.apply_payload(payload)

    assert method == "GET"
    assert kwargs == {}, "a GET probe must not carry a request body"
    parsed = urllib.parse.urlparse(url)
    assert urllib.parse.parse_qs(parsed.query)[ "q"] == [payload]


def test_get_param_replaces_only_the_target_param():
    point = InjectionPoint(
        base_url="http://target/api?cat=books&q=original&page=2", param="q"
    )
    _, url, _ = point.apply_payload("INJECTED")

    got = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert got["q"] == ["INJECTED"], "target param must be overwritten, not appended"
    assert got["cat"] == ["books"], "sibling query params must survive"
    assert got["page"] == ["2"]


def test_get_param_keeps_repeated_values_of_other_params():
    """doseq round-trip: a multi-valued sibling must not collapse to one value."""
    point = InjectionPoint(
        base_url="http://target/api?tag=a&tag=b", param="q"
    )
    _, url, _ = point.apply_payload("X")

    got = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert sorted(got["tag"]) == ["a", "b"]
    assert got["q"] == ["X"]


def test_get_param_preserves_the_non_query_components():
    point = InjectionPoint(
        base_url="https://user:pw@target:8443/api?a=1", param="q"
    )
    _, url, _ = point.apply_payload("X")
    parsed = urllib.parse.urlparse(url)

    assert parsed.scheme == "https"
    assert parsed.netloc == "user:pw@target:8443"
    assert parsed.path == "/api"
    assert parsed.params == ""


def test_get_param_adds_the_param_when_absent():
    _, url, _ = InjectionPoint(base_url="http://target/api", param="q").apply_payload("X")
    assert urllib.parse.parse_qs(urllib.parse.urlparse(url).query) == {"q": ["X"]}


def test_get_param_survives_an_empty_payload():
    """An empty payload must still be encoded as a present parameter, not
    dropped by ``parse_qs``' default behaviour."""
    _, url, _ = InjectionPoint(base_url="http://target/api", param="q").apply_payload("")

    assert "q=" in url
    assert urllib.parse.parse_qs(
        urllib.parse.urlparse(url).query, keep_blank_values=True
    ) == {"q": [""]}


def test_inject_query_param_does_not_mutate_its_input():
    base = "http://target/api?a=1"
    returned = inject_query_param(base, "q", "X")

    assert base == "http://target/api?a=1", "the input string is immutable"
    assert returned != base, "and the function returns a new URL, not the input"


# ---- form-urlencoded -------------------------------------------------------


def test_form_param_forces_post_and_carries_a_urlencoded_body():
    point = InjectionPoint(
        base_url="http://target/login", param="user", vector="formparam",
        template={"user": "alice", "pass": "s3cret"},
    )
    method, url, kwargs = point.apply_payload("admin' OR '1'='1")

    assert method == "POST", "body vectors must force POST regardless of .method"
    assert kwargs.get("data") == {"user": "admin' OR '1'='1", "pass": "s3cret"}


@pytest.mark.parametrize("payload", NASTY_PAYLOADS)
def test_form_param_body_round_trips_through_urlencoding(payload):
    point = InjectionPoint(
        base_url="http://target/login", param="user", vector="formparam",
        template={"user": "alice", "other": "keep"},
    )
    _, _, kwargs = point.apply_payload(payload)

    encoded = urllib.parse.urlencode(kwargs["data"])
    decoded = urllib.parse.parse_qs(encoded)
    assert decoded["user"] == [payload]
    assert decoded["other"] == ["keep"], "sibling fields must survive the encoding"


def test_form_param_does_not_mutate_the_caller_template():
    template = {"user": "alice", "other": "keep"}
    point = InjectionPoint(
        base_url="http://target/login", param="user", vector="formparam", template=template
    )
    point.apply_payload("INJECTED")

    assert template == {"user": "alice", "other": "keep"}, \
        "apply_payload must not write back into the caller's template"


# ---- nested JSON -----------------------------------------------------------


def test_json_param_injects_at_a_deep_dotted_path():
    template = {"user": {"profile": {"id": "7", "name": "alice"}}, "session": "abc"}
    point = InjectionPoint(
        base_url="http://target/api", param="user.profile.id",
        vector="jsonparam", template=template,
    )
    method, _, kwargs = point.apply_payload("7 OR 1=1")

    assert method == "POST"
    body = kwargs["json"]
    assert body["user"]["profile"]["id"] == "7 OR 1=1"
    # Siblings at every level of the tree must be byte-identical.
    assert body["user"]["profile"]["name"] == "alice"
    assert body["session"] == "abc"


def test_json_param_addresses_list_elements_by_index():
    template = {"roles": ["admin", "user", "guest"], "tenant": "eu"}
    point = InjectionPoint(
        base_url="http://target/api", param="roles.1",
        vector="jsonparam", template=template,
    )
    _, _, kwargs = point.apply_payload("superuser")

    body = kwargs["json"]
    assert body["roles"] == ["admin", "superuser", "guest"]
    assert body["tenant"] == "eu"


def test_json_param_pads_a_short_list_with_none():
    """Over-indexing a list must not shift or drop existing elements."""
    template = {"roles": ["admin"]}
    point = InjectionPoint(
        base_url="http://target/api", param="roles.3",
        vector="jsonparam", template=template,
    )
    _, _, kwargs = point.apply_payload("X")

    roles = kwargs["json"]["roles"]
    assert roles[0] == "admin", "existing element must stay at its index"
    assert roles[3] == "X"
    assert roles[1:3] == [None, None]


def test_json_param_creates_missing_intermediate_containers():
    point = InjectionPoint(
        base_url="http://target/api", param="a.b.c",
        vector="jsonparam", template={},
    )
    _, _, kwargs = point.apply_payload("X")

    assert kwargs["json"] == {"a": {"b": {"c": "X"}}}


def test_json_param_infers_a_list_when_the_next_segment_is_an_index():
    """`items.0.name` must build a list, not a dict keyed by the string "0"."""
    point = InjectionPoint(
        base_url="http://target/api", param="items.0.name",
        vector="jsonparam", template={},
    )
    _, _, kwargs = point.apply_payload("X")

    items = kwargs["json"]["items"]
    assert isinstance(items, list), "numeric segment must address a list"
    assert items[0]["name"] == "X"


def test_json_param_does_not_mutate_the_caller_template():
    template = {"user": {"profile": {"id": "7"}}}
    point = InjectionPoint(
        base_url="http://target/api", param="user.profile.id",
        vector="jsonparam", template=template,
    )
    point.apply_payload("INJECTED")

    assert template == {"user": {"profile": {"id": "7"}}}


@pytest.mark.parametrize("payload", NASTY_PAYLOADS)
def test_json_param_body_stays_valid_json(payload):
    point = InjectionPoint(
        base_url="http://target/api", param="q", vector="jsonparam",
        template={"q": "", "meta": {"lang": "en"}},
    )
    _, _, kwargs = point.apply_payload(payload)

    body = kwargs["json"]
    assert body["q"] == payload
    assert body["meta"] == {"lang": "en"}

    reloaded = json.loads(json.dumps(body))
    assert reloaded["q"] == payload, "the payload must survive JSON serialisation"


def test_json_param_injects_a_string_into_a_numeric_slot():
    """FINDING: the injected value is always a str, never coerced to int.

    A payload aimed at an integer-typed field therefore sends a type-invalid
    value. That is intentional for SQLi/commandi (the payload must reach the
    query layer verbatim), but it means a "no vulnerability found" verdict on a
    strictly-typed numeric field is not evidence of absence. Relevant to the
    Track B false-positive discussion: the probe is testing the parser, not the
    vulnerability, when the target rejects the type.
    """
    point = InjectionPoint(
        base_url="http://target/api", param="id", vector="jsonparam",
        template={"id": 42},
    )
    _, _, kwargs = point.apply_payload("42 OR 1=1")

    assert kwargs["json"]["id"] == "42 OR 1=1"
    assert not isinstance(kwargs["json"]["id"], int)


# ---- multipart -------------------------------------------------------------

_MULTIPART_TEMPLATE = {
    "fields": {"comment": "hello", "submit": "Send"},
    "files": {"attachment": {
        "filename": "report.pdf", "content": b"%PDF-1.4 fake",
        "content_type": "application/pdf",
    }},
}


def test_multipart_field_injection_targets_a_plain_field():
    point = InjectionPoint(
        base_url="http://target/upload", param="comment",
        vector="multipart_field", template=_MULTIPART_TEMPLATE,
    )
    method, _, kwargs = point.apply_payload("a&b=c")

    assert method == "POST"
    name, _fn, _ct, value = _field_by_name(kwargs["data"], "comment")
    assert value == "a&b=c", "& and = in a field value must stay literal"


def test_multipart_keeps_the_file_part_intact_when_a_field_is_targeted():
    point = InjectionPoint(
        base_url="http://target/upload", param="comment",
        vector="multipart_field", template=_MULTIPART_TEMPLATE,
    )
    _, _, kwargs = point.apply_payload("X")

    name, filename, _ct, value = _field_by_name(kwargs["data"], "attachment")
    assert filename == "report.pdf"
    assert value == b"%PDF-1.4 fake"
    assert _field_by_name(kwargs["data"], "submit")[3] == "Send"


def test_multipart_filename_injection_replaces_the_filename():
    point = InjectionPoint(
        base_url="http://target/upload", param="attachment",
        vector="multipart_file", template=_MULTIPART_TEMPLATE,
    )
    _, _, kwargs = point.apply_payload('evil"; --BOUNDARY')

    _name, filename, _ct, value = _field_by_name(kwargs["data"], "attachment")
    assert filename == 'evil"; --BOUNDARY'
    assert value == b"%PDF-1.4 fake", "the file content must not be replaced too"


def test_multipart_content_type_injection_lands_in_the_header():
    point = InjectionPoint(
        base_url="http://target/upload", param="attachment",
        vector="multipart", part_type="content_type", template=_MULTIPART_TEMPLATE,
    )
    _, _, kwargs = point.apply_payload("application/x-shockwave")

    _name, filename, content_type, _value = _field_by_name(kwargs["data"], "attachment")
    assert content_type == "application/x-shockwave"
    assert filename == "report.pdf", "the filename must not move with the payload"


def test_multipart_content_injection_allows_control_bytes():
    """The file *body* is the one multipart position that legitimately takes
    CRLF and other control bytes, since it is not a header."""
    point = InjectionPoint(
        base_url="http://target/upload", param="attachment",
        vector="multipart", part_type="content", template=_MULTIPART_TEMPLATE,
    )
    _, _, kwargs = point.apply_payload("HEAD\r\n\r\n<body>\x00")

    _name, filename, _ct, value = _field_by_name(kwargs["data"], "attachment")
    assert value == b"HEAD\r\n\r\n<body>\x00"
    assert filename == "report.pdf"


def test_multipart_content_is_always_utf8_encoded():
    """FINDING: the content position cannot carry raw non-UTF-8 bytes.

    `apply_payload` is typed `payload: str` and `_build_multipart` does
    `payload.encode("utf-8")` with no bytes path, so a str containing U+00FF is
    sent as the two bytes C3 BF rather than the single byte FF. Any probe
    targeting a GBK/Shift-JIS/Latin-1 legacy-encoded SQL column is therefore
    silently mangled before it reaches the wire -- and a negative result on such
    a target is a false negative, not evidence of absence.
    """
    point = InjectionPoint(
        base_url="http://target/upload", param="attachment",
        vector="multipart", part_type="content", template=_MULTIPART_TEMPLATE,
    )
    _, _, kwargs = point.apply_payload("\xff")

    value = _field_by_name(kwargs["data"], "attachment")[3]
    assert value == b"\xc3\xbf", "U+00FF must expand to its 2-byte UTF-8 form"


@pytest.mark.parametrize("bad", [
    "a\nb", "a\rb", "a\r\nb", "a\x00b", "a\x1bb", "a\x7fb", "a\x0bb",
])
def test_multipart_header_positions_reject_control_characters(bad):
    """FINDING: aiohttp >=3.14 hard-rejects most control bytes in a multipart
    filename or content-type instead of encoding them (TAB is the one control
    byte it permits, which is correct per RFC 9110).

    Consequence for Track A: `multipart_file` and `part_type="content_type"`
    probes physically cannot carry a raw CRLF payload -- aiohttp refuses to put
    it in a header value at all. So a mutation chain that introduces a newline
    cannot be measured through these vectors as a *pass*; the wire form is not
    the payload.

    What the probe does now: `_build_multipart` catches the rejection,
    percent-encodes the control bytes, retries, and marks the request
    `_wss_probe_aborted`. The probe is therefore never lost, and the response
    is explicitly NOT treated as evidence about the original payload. See
    `tests/differential/test_probe_abort.py` for the full contract.

    This test pins the *upstream* constraint that makes the fallback necessary:
    if aiohttp ever starts accepting these bytes, the sanitising path stops
    firing and this assertion fails, which is the signal to drop it.
    """
    for vector, part_type in (
        ("multipart_file", "field"),
        ("multipart", "content_type"),
    ):
        point = InjectionPoint(
            base_url="http://target/upload", param="attachment",
            vector=vector, part_type=part_type, template=_MULTIPART_TEMPLATE,
        )
        method, url, kwargs = point.apply_payload(bad)

        # The probe is constructed rather than aborted outright...
        assert method == "POST"
        assert kwargs["data"] is not None
        # ...but it is flagged, because the bytes that go out are not the bytes
        # the caller asked to send.
        assert kwargs.get("_wss_probe_aborted"), (
            "control-character payload must be marked aborted, not sent silently"
        )


def test_multipart_header_position_still_permits_tab():
    """Boundary of the previous test: TAB is legal in a header value and must
    keep working, otherwise an evasion chain that inserts tab-obfuscation loses
    the whole multipart vector for no reason."""
    point = InjectionPoint(
        base_url="http://target/upload", param="attachment",
        vector="multipart_file", template=_MULTIPART_TEMPLATE,
    )
    _, _, kwargs = point.apply_payload("a\tb")

    assert _field_by_name(kwargs["data"], "attachment")[1] == "a\tb"


def test_multipart_accepts_a_flat_template_without_the_fields_wrapper():
    point = InjectionPoint(
        base_url="http://target/upload", param="a",
        vector="multipart_field", template={"a": "1", "b": "2"},
    )
    _, _, kwargs = point.apply_payload("X")

    assert _field_by_name(kwargs["data"], "a")[3] == "X"
    assert _field_by_name(kwargs["data"], "b")[3] == "2"


def test_multipart_handles_a_file_entry_given_as_a_bare_value():
    point = InjectionPoint(
        base_url="http://target/upload", param="a",
        vector="multipart_field",
        template={"fields": {"a": "1"}, "files": {"f": "bare-string"}},
    )
    _, _, kwargs = point.apply_payload("X")

    assert _field_by_name(kwargs["data"], "f")[3] == "bare-string"


# ---- vector metadata -------------------------------------------------------


@pytest.mark.parametrize("vector", [
    "formparam", "jsonparam", "multipart", "multipart_field",
    "multipart_file", "multipart_header",
])
def test_every_body_vector_forces_post(vector):
    """FINDING: an InjectionPoint can be constructed with .method="GET" and a
    body vector, and the two are silently reconciled by `http_method`. Nothing
    warns about the contradiction, so a caller that only reads `.method` builds
    the wrong request."""
    point = InjectionPoint(base_url="http://t/a", param="p", vector=vector, method="GET")
    assert point.method == "GET", "the declared field is not rewritten"
    assert point.http_method == "POST"
    assert point.apply_payload("X")[0] == "POST"


def test_unknown_vector_is_rejected_at_construction():
    with pytest.raises(ValueError, match="unknown injection vector"):
        InjectionPoint(base_url="http://t/a", param="p", vector="telepathy")


def test_describe_is_the_vector_param_label():
    point = InjectionPoint(base_url="http://t/a", param="user.id", vector="jsonparam")
    assert point.describe() == "jsonparam:user.id"
