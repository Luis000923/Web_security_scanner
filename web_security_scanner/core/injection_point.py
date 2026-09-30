"""Unified InjectionPoint abstraction for HTTP request mutation.

Supports injection across:
- GET: Query-string parameters.
- POST (url-encoded): Form parameters in application/x-www-form-urlencoded body.
- POST (JSON): Leaf value nodes in arbitrary nested JSON objects and arrays
  preserving valid JSON structure.
- POST (multipart): Form fields and file upload headers/filenames in
  multipart/form-data.
- HTTP Headers: Request headers (User-Agent, Referer, X-Forwarded-For, etc.).
- Cookies: HTTP Cookie parameters.
"""

from __future__ import annotations

import copy
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import aiohttp

# Canonical vector names supported by the scanner.
VALID_VECTORS = (
    "getparam",
    "formparam",
    "jsonparam",
    "multipart",
    "multipart_field",
    "multipart_file",
    "multipart_header",
    "header",
    "cookie",
)

# Vectors whose payload lives in the HTTP body -> forces method POST.
_BODY_VECTORS = frozenset({
    "formparam",
    "jsonparam",
    "multipart",
    "multipart_field",
    "multipart_file",
    "multipart_header",
})

# Benign marker reused for baselines across every vector.
BENIGN_MARKER = "benign_baseline_123"

# Headers fuzzed by default when header injection is enabled without an explicit list.
DEFAULT_INJECTABLE_HEADERS = (
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
)


def _seg_is_index(seg: str) -> bool:
    """True when a dotted-path segment addresses a list index (e.g. '0', '12')."""
    return seg.isdigit() or (seg.startswith("-") and seg[1:].isdigit())


def _set_dotted(obj: Any, path: str, value: Any) -> None:
    """Assign ``value`` at a dotted ``path`` inside a nested dict/list in place.

    E.g. ``user.profile.id`` -> ``obj['user']['profile']['id'] = value``.
    Numeric segments address list elements (e.g. ``roles.0`` -> ``obj['roles'][0]``).
    Lists are padded with None if index exceeds current length.
    """
    parts = path.split(".")
    cursor = obj
    for i, key in enumerate(parts[:-1]):
        want_list = _seg_is_index(parts[i + 1])
        cursor = _descend(cursor, key, make_list=want_list)
    _assign(cursor, parts[-1], value)


def _descend(cursor: Any, key: str, *, make_list: bool) -> Any:
    """Return (creating if needed) the child container at ``key`` under ``cursor``."""
    if isinstance(cursor, list) and _seg_is_index(key):
        idx = int(key)
        while idx >= len(cursor):
            cursor.append(None)
        if not isinstance(cursor[idx], (dict, list)):
            cursor[idx] = [] if make_list else {}
        return cursor[idx]
    if not isinstance(cursor, dict):
        return {}
    nxt = cursor.get(key)
    if not isinstance(nxt, (dict, list)):
        nxt = [] if make_list else {}
        cursor[key] = nxt
    return nxt


def _assign(cursor: Any, key: str, value: Any) -> None:
    """Assign a leaf value into a dict or list cursor."""
    if isinstance(cursor, list) and _seg_is_index(key):
        idx = int(key)
        while idx >= len(cursor):
            cursor.append(None)
        cursor[idx] = value
    elif isinstance(cursor, dict):
        cursor[key] = value


def _iter_leaf_paths(obj: Any, prefix: str = "") -> list[str]:
    """Return dotted paths to every scalar leaf of a nested dict/list structure.

    E.g. ``{'a': 1, 'b': {'c': 2}, 'd': [10, 20]}`` ->
    ``['a', 'b.c', 'd.0', 'd.1']``.
    """
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = f"{prefix}.{k}" if prefix else str(k)
            out.extend(_iter_leaf_paths(v, child))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_iter_leaf_paths(v, f"{prefix}.{i}" if prefix else str(i)))
    elif prefix:
        out.append(prefix)
    return out


def _expand_header_names(spec: Any) -> list[str]:
    """Normalise an ``inject_headers`` spec to a concrete list of header names."""
    if spec in (True, "default", "__default__"):
        return list(DEFAULT_INJECTABLE_HEADERS)
    if isinstance(spec, dict):
        return [str(k) for k in spec]
    if isinstance(spec, str):
        return [s.strip() for s in spec.split(",") if s.strip()]
    if spec:
        return [str(s) for s in spec]
    return []


def inject_query_param(target_url: str, param_name: str, payload: str) -> str:
    """Return a copy of ``target_url`` with ``param_name`` set to ``payload`` using urlencode."""
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [payload]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


class ProbeAbortedError(ValueError):
    """A probe could not be constructed or sent; the point was never tested.

    Distinct from a transport failure: nothing left the process, so there is no
    response to score. Callers should record the probe as
    :attr:`~web_security_scanner.core.hybrid_score.ProbeStatus.PROBE_ABORTED`
    and move to the next payload -- never as a false negative.

    Subclasses :class:`ValueError` because the underlying cause is a rejected
    header value, so pre-existing ``except ValueError`` handlers keep working.
    """

    def __init__(self, message: str, *, param: str = "", vector: str = "") -> None:
        super().__init__(message)
        self.param = param
        self.vector = vector


#: Characters aiohttp refuses to serialise into a header value. Matched by the
#: C0 range plus DEL; ``\t`` is excluded because aiohttp permits it (and a tab
#: is not a header-injection vector). Encoded as ``%XX`` on the fallback path,
#: which is what RFC 7578 / RFC 2231 part filenames do anyway -- so the escaped
#: form is still a *valid* payload for most parsers, just not a CRLF one.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def encode_header_value(value: str) -> str:
    """Percent-encode the control characters aiohttp rejects in a header value.

    The *only* encoding applied is to the control characters themselves -- quotes,
    backslashes and non-ASCII are already handled by aiohttp's RFC 2231 encoder
    and are deliberately left untouched so the payload's meaning is preserved.
    """
    return _CONTROL_CHARS_RE.sub(
        lambda m: f"%{ord(m.group()):02X}", value
    )


@dataclass(frozen=True)
class InjectionPoint:
    """Unified abstraction for a testable injection point across HTTP request locations.

    Attributes:
        base_url: The target endpoint URL.
        param: The parameter name or dotted path (for JSON / multipart).
        vector: Transport vector ('getparam', 'formparam', 'jsonparam',
                'multipart', 'multipart_field', 'multipart_file',
                'multipart_header', 'header', 'cookie').
        method: HTTP verb ('GET', 'POST', etc.). Body vectors automatically force POST.
        template: Surrounding benign structure (dict/list of form fields, json tree,
                  file upload descriptors, headers, or cookies).
        part_type: For multipart points, specifies whether the target is 'field',
                   'filename', 'content_type', or 'header'.
        extra: Additional metadata associated with the injection point.
    """

    base_url: str
    param: str
    vector: str = "getparam"
    method: str = "GET"
    template: dict[str, Any] = field(default_factory=dict)
    part_type: str = "field"
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.vector not in VALID_VECTORS:
            raise ValueError(
                f"unknown injection vector {self.vector!r}; "
                f"expected one of {VALID_VECTORS}"
            )

    @property
    def http_method(self) -> str:
        """Effective HTTP verb: body vectors force POST, others use ``method``."""
        return "POST" if self.vector in _BODY_VECTORS else self.method

    def describe(self) -> str:
        """Short ``vector:param`` label for logs and telemetry."""
        return f"{self.vector}:{self.param}"

    def apply_payload(
        self, payload: str, base_url: str = ""
    ) -> tuple[str, str, dict[str, Any]]:
        """Materialise an HTTP request probe placing ``payload`` at this injection point.

        Returns:
            (method, url, request_kwargs) suitable for passing directly to an HTTP client.
        """
        method = self.http_method
        target_url = self.base_url or base_url
        kwargs: dict[str, Any] = {}

        if self.vector == "getparam":
            target_url = inject_query_param(target_url, self.param, payload)

        elif self.vector == "formparam":
            body = dict(self.template or {})
            body[self.param] = payload
            kwargs["data"] = body

        elif self.vector == "jsonparam":
            template = self.template if self.template is not None else {}
            body = copy.deepcopy(
                template if isinstance(template, (dict, list)) else dict(template)
            )
            _set_dotted(body, self.param, payload)
            kwargs["json"] = body

        elif self.vector in ("multipart", "multipart_field", "multipart_file", "multipart_header"):
            form_data = self._build_multipart(payload)
            kwargs["data"] = form_data
            # A sanitised fallback still needs to reach the caller, otherwise the
            # probe silently becomes an ordinary result for a payload that never
            # went out on the wire. Carried in the request kwargs rather than on
            # ``self``: the dataclass is frozen, and a per-probe condition has no
            # business mutating the point itself.
            reason = getattr(form_data, "_wss_aborted_reason", "")
            if reason:
                kwargs["_wss_probe_aborted"] = reason

        elif self.vector == "header":
            headers = dict(self.template or {})
            headers[self.param] = payload
            kwargs["headers"] = headers

        elif self.vector == "cookie":
            cookies = dict(self.template or {})
            cookies[self.param] = payload
            kwargs["cookies"] = cookies

        return method, target_url, kwargs

    def _build_multipart(self, payload: str) -> aiohttp.FormData:
        """Construct an aiohttp.FormData object reflecting the mutated multipart template.

        Never lets a payload byte the HTTP client refuses abort the caller. Two
        distinct failure shapes are handled, because they need different answers:

        * **Control characters in a header-bound part** (``filename``,
          ``content_type``) -- ``aiohttp`` raises ``ValueError`` from
          ``add_field`` ("Forbidden control character detected in headers").
          This is the CRLF header-injection payload class, and it is *inherent*
          to what the multipart_file / multipart_header vectors are testing, so
          treating it as an error to be raised loses a probe the scanner was
          specifically built to send.

          Fallback: percent-encode the offending characters
          (:func:`encode_header_value`) and retry, so the probe still goes out
          against the point. It is a *different* payload -- no raw CRLF reaches
          the wire, so a finding from it is evidence about a benign
          RFC 2231-encoded filename, not about CRLF handling. It is therefore
          recorded as ``aborted`` so the caller can mark the point untested
          rather than treat a non-answer as a negative result.

        * **Any other rejection** -- a genuinely unserialisable value. Raises
          :class:`ProbeAbortedError` so the caller can register a single
          ``PROBE_ABORTED`` probe and continue, instead of the exception
          unwinding through the whole payload loop and silently discarding
          every payload after the offending one.
        """
        try:
            return self._build_multipart_unsafe(payload)
        except ProbeAbortedError:
            raise
        except (ValueError, TypeError, UnicodeError) as exc:
            # The control-character case: retry once with the header values
            # sanitised, and mark the result aborted so the caller knows the
            # response it gets back is not evidence about this payload.
            try:
                form = self._build_multipart_unsafe(payload, sanitize=True)
            except (ValueError, TypeError, UnicodeError) as exc2:
                raise ProbeAbortedError(
                    f"multipart part could not be serialised: {exc2}",
                    param=self.param, vector=self.vector,
                ) from exc2
            form._wss_aborted_reason = (  # noqa: SLF001  (telemetry carrier)
                f"payload sanitised before send ({type(exc).__name__}: {exc}); "
                "the wire form differs from the payload, so the response is not "
                "evidence about this payload"
            )
            return form

    def _build_multipart_unsafe(
        self, payload: str, *, sanitize: bool = False,
    ) -> aiohttp.FormData:
        """Build the multipart body, optionally sanitising header-bound parts.

        Split out of :meth:`_build_multipart` so the retry path is the *same*
        code with one flag flipped, rather than a second copy that could drift.
        """
        form = aiohttp.FormData()
        tpl = self.template or {}

        # The template can be a structured multipart dict:
        # {"fields": {name: val}, "files": {name: {"filename": ..., "content": ..., "content_type": ...}}}
        # Or a flat dict of field key-values.
        fields = tpl.get("fields") if isinstance(tpl, dict) and "fields" in tpl else tpl
        files = tpl.get("files") if isinstance(tpl, dict) and "files" in tpl else {}

        if not isinstance(fields, dict):
            fields = {}
        if not isinstance(files, dict):
            files = {}

        # 1. Regular fields
        for name, val in fields.items():
            if self.vector in ("multipart", "multipart_field") and name == self.param:
                form.add_field(name, str(payload))
            else:
                form.add_field(name, str(val))

        # 2. Files
        for field_name, file_info in files.items():
            if isinstance(file_info, dict):
                fname = file_info.get("filename", "upload.bin")
                content = file_info.get("content", b"")
                ctype = file_info.get("content_type", "application/octet-stream")
                # The template is scanner-supplied, not attacker-controlled, but
                # a recon-discovered form can carry a control character into it
                # and the same rejection would apply. Sanitised on the retry
                # path for the same reason the payload is.
                if sanitize:
                    fname = encode_header_value(str(fname))
                    ctype = encode_header_value(str(ctype))

                # Check if this file is the target of injection
                is_target = (self.param == field_name) or (self.param.startswith(f"{field_name}."))

                if is_target:
                    if self.part_type == "filename" or self.vector == "multipart_file":
                        fname = encode_header_value(payload) if sanitize else payload
                    elif self.part_type == "content_type" or self.vector == "multipart_header":
                        ctype = encode_header_value(payload) if sanitize else payload
                    elif self.part_type == "content":
                        content = payload.encode("utf-8") if isinstance(payload, str) else payload
                    else:
                        fname = encode_header_value(payload) if sanitize else payload

                form.add_field(field_name, content, filename=fname, content_type=ctype)
            else:
                form.add_field(field_name, file_info)

        return form
