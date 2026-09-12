"""
Input validation helpers for the async scanner.

Historically the v4.0 code only did ad-hoc ``urlparse`` checks scattered across
the synchronous scanner. Those files are gone; this module is the single place
target-URL validation lives now.
"""

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

# Scheme + host must be present; only HTTP(S) targets are supported.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class InvalidTargetError(ValueError):
    """Raised when a target URL is malformed or uses an unsupported scheme."""


# --- Secret masking -------------------------------------------------------
#
# Scanners routinely capture request/response snippets as "evidence". Those
# snippets can contain the operator's own credentials (a Bearer token, a
# session cookie, a raw JWT). We must never persist those verbatim into a
# JSON/HTML report that gets shared around. ``mask_secrets`` runs a handful of
# cheap regex substitutions over any text just before it is written out.
_SECRET_PATTERNS = (
    # Authorization: Bearer <token>
    (re.compile(r"(Authorization\s*:\s*Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
     r"\1***"),
    # Authorization: Basic <base64>  (and any other single-token scheme)
    (re.compile(r"(Authorization\s*:\s*)(?!Bearer\b)\S+.*", re.IGNORECASE),
     r"\1***"),
    # Cookie: / Set-Cookie: everything to end of line
    (re.compile(r"(Set-Cookie\s*:\s*).*", re.IGNORECASE), r"\1***"),
    (re.compile(r"(Cookie\s*:\s*).*", re.IGNORECASE), r"\1***"),
    # Bare JWT anywhere in the text (header.payload.signature)
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
     "***JWT***"),
)


def mask_secrets(text: Any) -> Any:
    """Redact common secrets (Bearer tokens, cookies, JWTs) from ``text``.

    Accepts any value; non-strings are returned untouched (callers that want a
    string should coerce first). The masking is intentionally conservative and
    line oriented so the surrounding evidence stays readable.
    """
    if not isinstance(text, str) or not text:
        return text
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def validate_target_url(raw: str) -> str:
    """
    Validate and normalise a target URL.

    Returns the cleaned URL. Raises :class:`InvalidTargetError` if the value is
    not a well-formed absolute ``http(s)`` URL.
    """
    if not raw or not raw.strip():
        raise InvalidTargetError("Target URL is empty.")

    url = raw.strip()
    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise InvalidTargetError(
            f"Unsupported scheme '{parsed.scheme}'. Use http:// or https://."
        )
    if not parsed.hostname:
        raise InvalidTargetError("Target URL has no host component.")

    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME_RE.match(host):
            raise InvalidTargetError(f"Invalid host: {host!r}") from None

    return url
