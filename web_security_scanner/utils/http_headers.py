"""Small, dependency-free helpers for HTTP header dictionaries."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def content_type_of(headers: Mapping[str, Any] | None) -> str:
    """Return the lower-cased ``Content-Type`` value, or ``""`` when absent.

    Header names are matched case-insensitively and the first match wins;
    ``None`` is treated as an empty mapping.
    """
    for key, value in (headers or {}).items():
        if key.lower() == "content-type":
            return str(value).lower()
    return ""
