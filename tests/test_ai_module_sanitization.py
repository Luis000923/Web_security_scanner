"""Curation + sanitisation guarantees of ``ai_module``.

These are the properties the fine-tuning corpus depends on for its validity. If
any of them silently regresses, the model still trains — it just learns a
shortcut instead of the task, and nothing downstream would notice:

* **anonymisation** — the OWASP Benchmark encodes the vulnerability class (and
  effectively the verdict) in the URL path and parameter name. Any of that
  surviving into the model input is a label leak, not a feature.
* **noise rejection** — transport failures and empty/truncated bodies must be
  dropped rather than labelled, and *absence* of a field must never be treated
  as a failure signal (native telemetry rows legitimately omit ``status_code``).
* **body normalisation** — bodies are trimmed to reflection windows, so the
  evidence the label was derived from has to survive the trim.
* **de-duplication** — rows the model cannot tell apart must collapse to one, or
  near-identical samples leak across the train/val split.

``ai_module.dataset_generator`` is stdlib-only, so this suite needs no ML deps.
"""

import pytest

from ai_module.dataset_generator import (
    Sample,
    _payload_from_url,
    classify_noise,
    clean_rows,
    dedup,
    generic_param,
    is_junk_payload,
    normalize_body,
    payload_family,
    sanitize_endpoint,
)
from ai_module.structured_inference import (
    REFUSAL_SENTINEL,
    Verdict,
    parse_payloads,
    parse_triage,
)

# --------------------------------------------------------------------------- #
# Anonymisation — no shortcut from the URL/param to the label
# --------------------------------------------------------------------------- #

BENCH_URLS = [
    "https://localhost:8443/benchmark/sqli-00/BenchmarkTest00008?BenchmarkTest00008=x",
    "https://127.0.0.1:8443/benchmark/xss-03/BenchmarkTest01234",
    "http://t/benchmark/pathtraver-01/BenchmarkTest02000?foo=../../etc/passwd",
]


@pytest.mark.parametrize("url", BENCH_URLS)
def test_sanitize_endpoint_strips_every_class_and_verdict_hint(url):
    out = sanitize_endpoint(url)
    lowered = out.lower()
    for leak in ("sqli", "xss", "pathtraver", "cmdi", "benchmarktest", "8443",
                 "localhost", "127.0.0.1"):
        assert leak not in lowered, f"{leak!r} leaked through sanitize_endpoint"
    assert out.startswith("/") and "?" not in out


def test_sanitize_endpoint_is_constant_across_classes():
    """Two different vuln classes must be indistinguishable after anonymisation."""
    assert len({sanitize_endpoint(u) for u in BENCH_URLS}) == 1


@pytest.mark.parametrize("param", [
    "BenchmarkTest00008", "benchmarktest01234", "param", "param1", "p", "p3",
    "q", "input", "foo", "bar", "arg", "arg2",
])
def test_generic_param_neutralises_oracle_correlated_names(param):
    assert generic_param(param) == "p"


@pytest.mark.parametrize("param", ["username", "redirect_uri", "search_term"])
def test_generic_param_keeps_genuinely_informative_names(param):
    assert generic_param(param) == param


def test_generic_param_handles_empty_and_whitespace():
    assert generic_param("") == "p"
    assert generic_param("   ") == "p"
    assert generic_param(None) == "p"


# --------------------------------------------------------------------------- #
# Payload recovery + junk filtering
# --------------------------------------------------------------------------- #

def test_payload_from_url_prefers_the_named_parameter():
    url = "http://t/x?other=benign&id=%27+OR+1%3D1--"
    assert _payload_from_url(url, "id") == "' OR 1=1--"


def test_payload_from_url_falls_back_to_the_last_value():
    assert _payload_from_url("http://t/x?only=%3Cscript%3E", "missing") == "<script>"


def test_payload_from_url_survives_a_query_less_url():
    assert _payload_from_url("http://t/x", "id") == ""


@pytest.mark.parametrize("payload", [
    "", "   ", "abc", "12345", "hello",              # too short, no semantics
    "a" * 200,                                        # long structureless blob
])
def test_is_junk_payload_rejects_unlearnable_strings(payload):
    assert is_junk_payload(payload) is True


@pytest.mark.parametrize("payload", [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "; sleep 5",
    "' UNION SELECT NULL,version()--",
    "${jndi:ldap://x/a}",
])
def test_is_junk_payload_keeps_real_injection_vectors(payload):
    assert is_junk_payload(payload) is False


def test_short_payload_with_a_marker_is_not_junk():
    """The length rule must not override the presence of injection semantics."""
    assert is_junk_payload("'--") is False


@pytest.mark.parametrize("payload,family", [
    ("' AND SLEEP(5)--", "sqli-time"),
    ("' UNION SELECT NULL--", "sqli-error-union"),
    ("<svg/onload=alert(1)>", "xss"),
    ("../../../../etc/passwd", "path-traversal"),
])
def test_payload_family_buckets_by_technique(payload, family):
    assert payload_family(payload) == family


# --------------------------------------------------------------------------- #
# Noise classification — reject on evidence, never on absence
# --------------------------------------------------------------------------- #

def test_classify_noise_accepts_a_native_telemetry_row():
    """Telemetry rows carry no status_code/body; that is not a failure signal."""
    row = {"url": "http://t/x?id=1", "param": "id", "elapsed_time": 0.12,
           "decision": False, "confidence_final": "LOW"}
    assert classify_noise(row) is None


@pytest.mark.parametrize("row,reason", [
    ({}, "missing_url"),
    ({"url": "http://t/x", "error": "Cannot connect to host t:80"}, "network_error"),
    ({"url": "http://t/x", "error": "malformed payload"}, "request_error"),
    ({"url": "http://t/x", "timed_out": True}, "timeout"),
    ({"url": "http://t/x", "status_code": 0}, "no_response"),
    ({"url": "http://t/x", "elapsed_time": 9999.0}, "implausible_latency"),
])
def test_classify_noise_rejects_explicit_failure_signals(row, reason):
    assert classify_noise(row) == reason


def test_classify_noise_keeps_a_500_that_carries_evidence():
    """A 5xx *is* the signal for some injections — only drop the empty ones."""
    with_body = {"url": "http://t/x", "status_code": 500,
                 "body": "java.sql.SQLException: unterminated string"}
    assert classify_noise(with_body) is None
    assert classify_noise({"url": "http://t/x", "status_code": 500}) == "server_error"


def test_clean_rows_counts_every_rejection_reason():
    rows = [
        {"url": "http://t/a?id=1", "param": "id", "payload_id": "x",
         "elapsed_time": 0.1, "decision": False, "request_index": 1},
        {"url": "http://t/b", "status_code": 0, "param": "id",
         "payload_id": "y", "elapsed_time": 0.1, "decision": False,
         "request_index": 2},
        {"not": "a probe row"},
    ]
    kept, stats = clean_rows(rows)
    assert stats["kept"] == len(kept)
    assert stats["noise:no_response"] == 1
    assert sum(v for k, v in stats.items() if k.startswith("skipped:")) == 1


def test_clean_rows_can_keep_noise_for_inspection():
    rows = [{"url": "http://t/b", "status_code": 0, "param": "id",
             "payload_id": "y", "elapsed_time": 0.1, "decision": False,
             "request_index": 1}]
    kept, stats = clean_rows(rows, drop_noise=False)
    assert len(kept) == 1 and stats["noise:no_response"] == 1


# --------------------------------------------------------------------------- #
# Body normalisation — the evidence must survive the trim
# --------------------------------------------------------------------------- #

def test_normalize_body_returns_short_bodies_verbatim():
    assert normalize_body("<p>hello</p>", "' OR 1=1--") == "<p>hello</p>"


def test_normalize_body_keeps_the_reflection_window_of_a_long_body():
    payload = "<xss-marker-42>"
    body = ("filler " * 2000) + payload + (" trailing" * 2000)
    out = normalize_body(body, payload, max_bytes=512, window=40)
    assert payload in out, "the reflected payload must survive truncation"
    assert len(out) < len(body)


def test_normalize_body_truncates_when_the_payload_is_absent():
    body = "x" * 10_000
    out = normalize_body(body, "not-present-anywhere", max_bytes=256)
    assert out.endswith("…[truncated]") and len(out) < 1000


def test_normalize_body_drops_binary_content():
    out = normalize_body("\x00\x01\x02\x03\x04\x05\x06\x07" * 100, "p")
    assert "binary" in out.lower()


def test_normalize_body_collapses_whitespace_runs():
    assert normalize_body("a" + " " * 40 + "b", "") == "a  b"


# --------------------------------------------------------------------------- #
# De-duplication — near-identical samples must not cross the split
# --------------------------------------------------------------------------- #

def _sample(user, assistant="TRUE_POSITIVE", dedup_key=None):
    meta = {"_dedup": dedup_key} if dedup_key else {}
    return Sample(system="sys", user=user, assistant=assistant, meta=meta)


def test_dedup_collapses_identical_rendered_samples():
    out, removed = dedup([_sample("same"), _sample("same"), _sample("other")])
    assert [s.user for s in out] == ["same", "other"]
    assert removed == 1


def test_dedup_honours_the_explicit_observable_key():
    """Two rows differing only in jitter share a key and must collapse to one."""
    out, removed = dedup([
        _sample("probe latency=0.101s", dedup_key="k1"),
        _sample("probe latency=0.104s", dedup_key="k1"),
    ])
    assert len(out) == 1 and removed == 1


def test_dedup_keeps_samples_with_distinct_keys():
    out, removed = dedup([_sample("a", dedup_key="k1"), _sample("b", dedup_key="k2")])
    assert len(out) == 2 and removed == 0


def test_sample_public_meta_hides_private_traceability_fields():
    s = Sample(system="s", user="u", assistant="a",
               meta={"_real_url": "https://localhost:8443/benchmark/sqli-00/X",
                     "family": "sqli-time"})
    for rendered in (s.to_chatml(), s.to_alpaca()):
        assert rendered["meta"] == {"family": "sqli-time"}
        assert "_real_url" not in rendered["meta"]


# --------------------------------------------------------------------------- #
# Structured decoding — malformed output must fold to the safe verdict
# --------------------------------------------------------------------------- #

def test_parse_triage_recovers_a_json_object_from_surrounding_prose():
    out = parse_triage('sure! {"verdict":"TRUE_POSITIVE","confidence":0.9,'
                       '"reasoning":"stacked error","next_step":"confirm"} done')
    assert out.verdict is Verdict.TRUE_POSITIVE and out.confidence == 0.9


def test_parse_triage_folds_garbage_to_uncertain():
    assert parse_triage("total nonsense").verdict is Verdict.UNCERTAIN
    assert parse_triage("").verdict is Verdict.UNCERTAIN


def test_parse_triage_maps_the_refusal_sentinel_to_restricted():
    assert parse_triage(REFUSAL_SENTINEL).verdict is Verdict.RESTRICTED


def test_parse_triage_salvages_a_verdict_from_an_otherwise_invalid_object():
    """An out-of-range confidence must not discard a usable verdict."""
    out = parse_triage('{"verdict":"FALSE_POSITIVE","confidence":42,"reasoning":""}')
    assert out.verdict is Verdict.FALSE_POSITIVE
    assert 0.0 <= out.confidence <= 1.0


def test_parse_payloads_marks_unparseable_output_with_the_sentinel():
    out = parse_payloads("no json here")
    assert [p.payload for p in out.payloads] == ["<none>"]
    assert out.payloads[0].rationale == "parse failure"


def test_parse_payloads_keeps_the_valid_items_of_a_partly_broken_list():
    out = parse_payloads('{"payloads":[{"payload":"\' OR 1=1--","score":0.8},'
                         '{"rationale":"missing payload field"}]}')
    assert [p.payload for p in out.payloads] == ["' OR 1=1--"]
