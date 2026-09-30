"""Response inspection and filtering engine: Soft 404 and fictitious HTTP 200 error detection.

Detects when a target web server returns HTTP 200 OK for requests that are actually:
- Soft 404 (custom 'Page Not Found' template masquerading as a successful response).
- Generic server error pages (unhandled exceptions, system errors).
- WAF or security perimeter blocks disguised as 200 OK pages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Regex patterns for Soft 404 indicators in HTML title and headings
_SOFT_404_TITLE_RE = re.compile(
    r"<title[^>]*>.*?(?:404|not\s+found|page\s+not\s+found|p[áa]gina\s+no\s+encontrada|"
    r"no\s+encontrad[ao]|does\s+not\s+exist|no\s+existe).*?</title>",
    re.IGNORECASE | re.DOTALL,
)

_SOFT_404_HEADING_RE = re.compile(
    r"<h[1-2][^>]*>.*?(?:404|not\s+found|page\s+not\s+found|p[áa]gina\s+no\s+encontrada|"
    r"file\s+or\s+directory\s+not\s+found).*?</h[1-2]>",
    re.IGNORECASE | re.DOTALL,
)

_SOFT_404_BODY_PHRASES = (
    "the requested url was not found",
    "page you are looking for does not exist",
    "the page you requested could not be found",
    "the page cannot be found",
    "página no encontrada",
    "pagina no encontrada",
    "el recurso solicitado no existe",
    "404 - file or directory not found",
    "404 not found",
    "documento no encontrado",
    "sorry, we couldn't find that page",
    "this page is not available",
)

_GENERIC_ERROR_PHRASES = (
    "an unexpected error has occurred",
    "an unexpected error occurred",
    "internal server error",
    "unhandled exception",
    "ha ocurrido un error inesperado",
    "error en el servidor",
    "something went wrong on our end",
    "server error in '/' application",
    "fatal error:",
)

_BLOCKED_PHRASES = (
    "access denied",
    "acceso denegado",
    "request blocked",
    "solicitud bloqueada",
    "blocked by security policy",
    "attention required! | cloudflare",
    "security incident has been detected",
    "web application firewall",
    "your request was flagged",
)


@dataclass(frozen=True)
class ResponseClassification:
    """Outcome of response content inspection."""

    status_code: int
    is_soft_404: bool
    is_generic_error: bool
    is_blocked: bool
    is_fictitious_200: bool
    category: str  # "ok", "soft_404", "server_error", "blocked", "http_error"
    reason: str


class ResponseFilter:
    """Detects Soft 404s, fake 200 OK errors, and perimeter blocks in HTTP responses."""

    @classmethod
    def classify(cls, response: dict[str, Any]) -> ResponseClassification:
        status = response.get("status_code", 0)
        text = response.get("text", "") or ""
        lower_text = text.lower()

        # Hard HTTP errors
        if status == 404:
            return ResponseClassification(
                status_code=status,
                is_soft_404=False,
                is_generic_error=False,
                is_blocked=False,
                is_fictitious_200=False,
                category="http_error",
                reason="HTTP 404 Not Found status code.",
            )

        if status in (403, 406):
            return ResponseClassification(
                status_code=status,
                is_soft_404=False,
                is_generic_error=False,
                is_blocked=True,
                is_fictitious_200=False,
                category="blocked",
                reason=f"HTTP {status} perimeter block.",
            )

        if status >= 500:
            return ResponseClassification(
                status_code=status,
                is_soft_404=False,
                is_generic_error=True,
                is_blocked=False,
                is_fictitious_200=False,
                category="server_error",
                reason=f"HTTP {status} server error status code.",
            )

        # Inspection for fictitious 200 OK responses
        if status == 200:
            # 1. Soft 404 Check
            if _SOFT_404_TITLE_RE.search(text):
                return ResponseClassification(
                    status_code=200,
                    is_soft_404=True,
                    is_generic_error=False,
                    is_blocked=False,
                    is_fictitious_200=True,
                    category="soft_404",
                    reason="Soft 404: HTML title indicates not found.",
                )

            if _SOFT_404_HEADING_RE.search(text):
                return ResponseClassification(
                    status_code=200,
                    is_soft_404=True,
                    is_generic_error=False,
                    is_blocked=False,
                    is_fictitious_200=True,
                    category="soft_404",
                    reason="Soft 404: HTML heading indicates not found.",
                )

            if any(phrase in lower_text for phrase in _SOFT_404_BODY_PHRASES):
                return ResponseClassification(
                    status_code=200,
                    is_soft_404=True,
                    is_generic_error=False,
                    is_blocked=False,
                    is_fictitious_200=True,
                    category="soft_404",
                    reason="Soft 404: Body text contains generic not-found message.",
                )

            # 2. Block / Access Denied Check
            if any(phrase in lower_text for phrase in _BLOCKED_PHRASES):
                return ResponseClassification(
                    status_code=200,
                    is_soft_404=False,
                    is_generic_error=False,
                    is_blocked=True,
                    is_fictitious_200=True,
                    category="blocked",
                    reason="Disguised 200 OK: Body text indicates security block or access denied.",
                )

            # 3. Generic Server Error Check
            if any(phrase in lower_text for phrase in _GENERIC_ERROR_PHRASES):
                return ResponseClassification(
                    status_code=200,
                    is_soft_404=False,
                    is_generic_error=True,
                    is_blocked=False,
                    is_fictitious_200=True,
                    category="server_error",
                    reason="Disguised 200 OK: Body text indicates unhandled server error.",
                )

        return ResponseClassification(
            status_code=status,
            is_soft_404=False,
            is_generic_error=False,
            is_blocked=False,
            is_fictitious_200=False,
            category="ok",
            reason="Response is legitimate content.",
        )

    @classmethod
    def is_soft_404(cls, response: dict[str, Any]) -> bool:
        return cls.classify(response).is_soft_404

    @classmethod
    def is_fictitious_200(cls, response: dict[str, Any]) -> bool:
        return cls.classify(response).is_fictitious_200
