"""Probes that were never sent must not be scored as negatives.

Two defects, one file, because they are the same defect seen from two ends:

1. ``InjectionPoint._build_multipart`` raised ``ValueError`` from aiohttp for a
   payload containing a control character, and that exception unwound through
   ``probe()`` into the caller's payload loop -- killing the whole sweep, not
   just the offending payload. Every payload queued behind it was silently lost.
2. ``compute_metrics`` had no bucket for "the scan could not measure this
   point", so a perimeter block / soft 404 / aborted probe read as a false
   negative and dragged recall toward a number that describes the perimeter
   rather than the scanner.

Docstrings and comments are English (house rule). Research findings
(statements about the tool's behaviour, not mechanics) are Spanish.
"""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import aiohttp
import pytest

from web_security_scanner.core.benchmark_ground_truth import load_findings_from_report
from web_security_scanner.core.hybrid_score import ProbeStatus
from web_security_scanner.core.ieee_metrics import (
    Finding,
    GroundTruth,
    compute_metrics,
    render_console_summary,
    render_latex,
    render_markdown,
)
from web_security_scanner.core.injection_point import (
    InjectionPoint,
    ProbeAbortedError,
    encode_header_value,
)
from web_security_scanner.core.scanner_core_async import AsyncScannerCore

# ---- fixtures ---------------------------------------------------------------

_FILE_TPL = {
    "fields": {},
    "files": {
        "f": {
            "filename": "a.bin",
            "content": b"x",
            "content_type": "application/octet-stream",
        }
    },
}


def _file_point(vector: str, part_type: str) -> InjectionPoint:
    return InjectionPoint(
        base_url="http://target.local/upload",
        param="f" if part_type == "field" else f"f.{part_type}",
        vector=vector,
        method="POST",
        part_type=part_type,
        template=_FILE_TPL,
    )


# ---- 1. the multipart abort path --------------------------------------------


def test_control_char_in_filename_does_not_raise():
    """A CRLF payload must not abort probe construction.

    This is the CRLF header-injection payload class, which the
    ``multipart_file`` vector exists to send. Raising here meant the probe was
    never issued at all.
    """
    point = _file_point("multipart_file", "filename")
    _method, _url, kwargs = point.apply_payload("evil\r\nX-Injected: 1")
    assert kwargs["data"] is not None


def test_sanitised_fallback_is_flagged_as_aborted():
    """The retry sends a *different* payload, so it must be marked untested.

    Percent-encoding the control characters means no raw CRLF reaches the
    wire. Reporting the resulting response as evidence about the original
    payload would be a fabricated measurement.
    """
    point = _file_point("multipart_file", "filename")
    _method, _url, kwargs = point.apply_payload("evil\r\nX-Injected: 1")
    reason = kwargs.get("_wss_probe_aborted", "")
    assert reason, "sanitised fallback must be reported as aborted"
    assert "differ" in reason or "not evidence" in reason


def test_clean_payload_is_not_flagged():
    """The marker must not fire on a payload that needs no sanitising."""
    point = _file_point("multipart_file", "filename")
    _method, _url, kwargs = point.apply_payload("shell.php")
    assert "_wss_probe_aborted" not in kwargs


def test_content_type_control_char_is_handled():
    """Same class of failure on the ``multipart_header`` vector."""
    point = _file_point("multipart_header", "content_type")
    _method, _url, kwargs = point.apply_payload("text/plain\r\nX-Evil: 1")
    assert kwargs.get("_wss_probe_aborted")


def test_control_char_in_template_is_handled_on_retry():
    """A recon-discovered template can carry a control char into a *sibling* part.

    Scanner-supplied rather than attacker-controlled, but it reaches the same
    header serialiser as the target part, so it takes the same fallback. The
    target's own filename is replaced by the payload, so only the untouched
    sibling exercises this path.
    """
    tpl = {"fields": {}, "files": {
        "f": {"filename": "a.bin", "content": b"x",
              "content_type": "application/octet-stream"},
        "sibling": {"filename": "b\r\nc.bin", "content": b"y",
                    "content_type": "application/octet-stream"},
    }}
    point = InjectionPoint(
        base_url="http://target.local/upload", param="f.filename",
        vector="multipart_file", method="POST", part_type="filename", template=tpl,
    )
    _method, _url, kwargs = point.apply_payload("shell.php")
    assert kwargs.get("_wss_probe_aborted"), "sibling part must not abort the probe"


def test_unserialisable_payload_raises_typed_error_not_bare_valueerror():
    """A genuinely unserialisable part raises the typed error.

    ``ProbeAbortedError`` subclasses ``ValueError`` so a caller can catch
    either, but it carries the point identity for telemetry. This is the path
    the sanitising retry cannot rescue, which is why the two are distinct.
    """
    point = _file_point("multipart_file", "filename")
    # A list cannot be rendered into a filename at all -- not a control-character
    # problem, so the retry does not apply.
    with pytest.raises(ProbeAbortedError) as excinfo:
        point.apply_payload(["unserialisable"])  # type: ignore[arg-type]
    assert excinfo.value.vector == "multipart_file"
    assert excinfo.value.param == "f.filename"


def test_probe_aborted_error_is_a_valueerror():
    """Callers with a pre-existing ``except ValueError`` keep working."""
    assert issubclass(ProbeAbortedError, ValueError)


def test_encode_header_value_escapes_only_control_chars():
    """Quotes, backslashes and non-ASCII pass through untouched.

    aiohttp already RFC 2231-encodes those. Escaping them again would change
    the payload beyond what the rejection required.
    """
    assert encode_header_value('a"b\\c\xffd') == 'a"b\\c\xffd'
    assert encode_header_value("a\r\n\x00b") == "a%0D%0A%00b"
    # Tab is legal in a header value and is not an injection vector.
    assert encode_header_value("a\tb") == "a\tb"


# ---- 1b. the send-time transport failure ------------------------------------
#
# `_build_multipart` handles the *build* side of a multipart probe, and it is
# the only place that can: constructing an `aiohttp.FormData` touches no
# socket, so no transport error can originate there. Catching one there would be
# dead code that implies otherwise.
#
# The transport side is ``AsyncScannerCore._request_with_resilience``, which
# catches every ``Exception`` -- and aiohttp's ``ClientError`` family, the
# mid-body failures a multipart upload can produce, all derive from it -- and
# converts it to a ``status_code: 0`` response carrying the error text. The tests
# below pin that at the layer that owns it.


def _core_raising(exc: Exception) -> AsyncScannerCore:
    """A real ``AsyncScannerCore`` whose request path raises ``exc``.

    Built with ``__new__`` so no session or event loop is needed; only the
    attributes ``_request_with_resilience`` actually reads are populated, which
    is also a check that the method's surface is as small as it looks.
    """
    core = AsyncScannerCore.__new__(AsyncScannerCore)
    core.config = SimpleNamespace(
        max_retries=0, adaptive_throttle=False, verify_ssl=True,
    )
    core._semaphore = asyncio.Semaphore(1)
    core._host_backoff = MagicMock()
    core._logger = logging.getLogger("test.transport")
    core._concurrency_controller = None
    core.telemetry_engine = MagicMock()
    core._ssl_notice_emitted = False

    async def _raising(*_args, **_kwargs):
        raise exc

    core._request_following = _raising
    return core


@pytest.mark.parametrize(
    "exc",
    [
        # The mid-body transport failures a multipart upload can produce.
        # ``asyncio.StreamError`` would be the literal name, but it was removed
        # in Python 3.11 and CI runs 3.10-3.12; these are its live stand-ins and
        # every one of them derives from ``Exception``, which is exactly what
        # the blanket handler in ``_request_with_resilience`` claims.
        aiohttp.ClientPayloadError("chunked body truncated"),
        aiohttp.ServerDisconnectedError("server disconnected"),
        aiohttp.ClientConnectionError("connection reset"),
    ],
    ids=["client-payload-error", "server-disconnected", "client-connection-error"],
)
@pytest.mark.asyncio
async def test_transport_failure_becomes_a_status_zero_response(exc):
    """Un fallo de transporte se convierte en respuesta; no sube.

    This is the invariant that keeps a payload loop alive. If it breaks, the
    exception reaches the caller's ``for payload in payloads`` loop and every
    payload queued behind it is lost -- not as a crash, but as silence, which is
    how the original ``_build_multipart`` defect presented.
    """
    core = _core_raising(exc)

    result = await core._request_with_resilience(
        "POST", "http://target.local/upload", False, {}, {"data": object()},
        "target.local",
    )

    assert result["status_code"] == 0
    assert result["text"] == ""
    assert str(exc) in result["error"]


@pytest.mark.asyncio
async def test_the_transport_failure_response_is_complete():
    """A caller never has to handle a half-built response.

    Every tester reads ``status_code``, ``text`` and ``headers`` off whatever
    ``probe()`` hands back without checking which branch produced it. A missing
    key here is an ``AttributeError`` several testers deep, on the one response
    that was never supposed to carry a verdict.
    """
    core = _core_raising(aiohttp.ClientPayloadError("truncated"))

    result = await core._request_with_resilience(
        "POST", "http://target.local/upload", False, {}, {}, "target.local",
    )

    assert {"status_code", "text", "headers", "url", "elapsed", "error"} <= set(result)
    # And it is distinguishable from a real, empty 200: the error text is the
    # only thing telling a caller the measurement never happened.
    assert result["error"]
    assert result["status_code"] == 0


# ---- 2. the metrics boundary ------------------------------------------------


def _gt() -> GroundTruth:
    return GroundTruth(
        instances=(
            (("/vuln/1", "id"), True, "sqli"),
            (("/vuln/2", "id"), True, "sqli"),
            (("/vuln/3", "id"), True, "xss"),
            (("/safe/1", "id"), False, "sqli"),
            (("/safe/2", "id"), False, "xss"),
        ),
        name="unit-gt",
    )


def test_untested_point_is_not_counted_as_false_negative():
    """The core contract: an unmeasured point is neither TP nor FN."""
    findings = [
        Finding(url="/vuln/1", parameter="id", vulnerability_type="sqli"),
        Finding(url="/vuln/2", parameter="id", vulnerability_type="sqli"),
        Finding(url="/vuln/3", parameter="id", vulnerability_type="blocked_untested",
                untested=True),
    ]
    result = compute_metrics(findings, _gt())
    assert result.fn == 0
    assert result.tp == 2
    assert result.untested_points == [("/vuln/3", "id")]


def test_untested_point_does_not_inflate_precision():
    """An untested record is not a claim, so it cannot become a true positive."""
    findings = [
        Finding(url="/vuln/1", parameter="id", vulnerability_type="sqli"),
        Finding(url="/vuln/3", parameter="id", vulnerability_type="probe_aborted",
                untested=True),
    ]
    result = compute_metrics(findings, _gt())
    # Only the real finding is a claim; the untested marker must not be scored TP.
    assert result.tp == 1
    assert result.precision == 1.0


def test_recall_lower_bound_charges_untested_vulnerable_as_fn():
    """The pessimistic companion to the conditional recall.

    This is the number that stops a perimeter-blocked scan from being read as
    a high-recall scanner. Both vulnerable instances not marked untested are
    still genuine misses, so the two figures differ by exactly the skipped one.
    """
    findings = [
        Finding(url="/vuln/1", parameter="id", vulnerability_type="sqli"),
        Finding(url="/vuln/3", parameter="id", vulnerability_type="blocked_untested",
                untested=True),
    ]
    result = compute_metrics(findings, _gt())
    assert result.tp == 1
    assert result.fn == 1          # /vuln/2 was never mentioned and was measured
    assert result.untested_vulnerable == 1
    assert result.recall == 0.5                    # 1 TP / (1 + 1)
    assert result.recall_lower_bound == pytest.approx(1 / 3)


def test_benign_untested_point_does_not_count_against_recall():
    """A soft 404 on a non-vulnerable point is not the scanner's problem."""
    findings = [
        Finding(url="/vuln/1", parameter="id", vulnerability_type="sqli"),
        Finding(url="/safe/2", parameter="id", vulnerability_type="soft404_untested",
                untested=True),
    ]
    result = compute_metrics(findings, _gt())
    assert result.untested_vulnerable == 0
    assert result.recall_lower_bound == result.recall


def test_coverage_reflects_untested_points():
    """Coverage is what makes the conditional recall interpretable."""
    findings = [
        Finding(url="/vuln/3", parameter="id", vulnerability_type="blocked_untested",
                untested=True),
    ]
    result = compute_metrics(findings, _gt())
    assert result.coverage == pytest.approx(4 / 5)


def test_real_finding_wins_over_untested_marker_at_same_key():
    """A genuine detection must not be shadowed by an untested record.

    Both are keyed identically, so whichever the ingest order puts first used to
    take the slot. Losing a real detection this way would turn a true positive
    into an "untested" point -- the opposite error.
    """
    for findings in (
        [Finding(url="/vuln/1", parameter="id", vulnerability_type="sqli"),
         Finding(url="/vuln/1", parameter="id", vulnerability_type="blocked_untested",
                 untested=True)],
        [Finding(url="/vuln/1", parameter="id", vulnerability_type="blocked_untested",
                 untested=True),
         Finding(url="/vuln/1", parameter="id", vulnerability_type="sqli")],
    ):
        result = compute_metrics(findings, _gt())
        assert result.tp == 1, "real finding must survive dedupe"
        assert result.untested_points == []


def test_untested_at_unlabelled_point_is_ignored():
    """Excluding an unlabelled point would hide scanner silence."""
    findings = [Finding(url="/not/labelled", parameter="q",
                        vulnerability_type="blocked_untested", untested=True)]
    result = compute_metrics(findings, _gt())
    assert result.untested_points == []
    assert result.fp_outside_gt == 0


def test_untested_key_matching_survives_a_custom_resolver():
    """The marker must still match when a resolver rewrites the key.

    A benchmark-style resolver expects a test-case id; the marker carries the
    probed URL. Without the raw-key fallback the exclusion is silently lost.
    """
    gt = _gt()
    findings = [Finding(url="/vuln/3", parameter="id",
                        vulnerability_type="blocked_untested", untested=True)]
    result = compute_metrics(findings, gt, key_resolver=lambda f: [("nope", "nope")])
    assert result.untested_points == [("/vuln/3", "id")]
    assert result.fn == 2   # the other two vulnerable instances


def test_untested_marker_survives_report_ingestion():
    """A ``probe_status`` in the report becomes an untested record, not a finding."""
    report = {
        "vulnerabilities": [
            {"url": "/vuln/1", "parameter": "id", "type": "SQL Injection"},
            {"url": "/vuln/3", "parameter": "id",
             "probe_status": ProbeStatus.BLOCKED_UNTESTED.value},
        ]
    }
    findings, warnings = load_findings_from_report(report)
    assert not warnings
    assert [f.untested for f in findings] == [False, True]
    assert findings[1].vulnerability_type == "blocked_untested"


def test_status_bearing_finding_without_the_flag_is_a_claim():
    """Ingestion keys off the explicit flag, not a type string.

    A vulnerability class is free-form text; only ``untested`` decides the
    bucket. Keying off the string would silently swallow a real finding whose
    type happened to read like a status.
    """
    report = {"vulnerabilities": [
        {"url": "/vuln/1", "parameter": "id", "type": "probe_aborted"},
    ]}
    findings, _ = load_findings_from_report(report)
    assert findings[0].untested is False


# ---- 3. the figures are not publishable without their qualifiers -------------


def test_reports_state_coverage_when_anything_was_untested():
    findings = [Finding(url="/vuln/3", parameter="id",
                        vulnerability_type="blocked_untested", untested=True)]
    result = compute_metrics(findings, _gt())

    for rendered in (render_console_summary(result),
                     render_markdown(result),
                     render_latex(result)):
        assert "coverage" in rendered.lower() or "Coverage" in rendered
        assert "ower bound" in rendered or "lower_bound" in rendered


def test_reports_are_unchanged_when_nothing_was_untested():
    """No untested points means no coverage section -- nothing to qualify."""
    findings = [Finding(url="/vuln/1", parameter="id", vulnerability_type="sqli")]
    result = compute_metrics(findings, _gt())
    assert "Coverage" not in render_markdown(result)
    assert "Untested" not in render_console_summary(result)


def test_untested_points_are_exported_for_audit():
    findings = [Finding(url="/vuln/3", parameter="id",
                        vulnerability_type="blocked_untested", untested=True)]
    result = compute_metrics(findings, _gt())
    exported = result.to_dict()
    assert exported["untested_points"] == [["/vuln/3", "id"]]
    rates = result.rates()
    for key in ("coverage", "recall_lower_bound", "untested_points", "untested_vulnerable"):
        assert key in rates


def test_benign_untested_point_keeps_tn_semantics():
    """An unmeasured benign point is excluded, not counted as a true negative."""
    findings = [
        Finding(url="/vuln/1", parameter="id", vulnerability_type="sqli"),
        Finding(url="/safe/1", parameter="id", vulnerability_type="soft404_untested",
                untested=True),
    ]
    result = compute_metrics(findings, _gt())
    assert result.tn == 1        # /safe/2 only
    assert result.specificity == 1.0
