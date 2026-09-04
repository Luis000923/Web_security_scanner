"""Lexical mining of endpoints embedded in JavaScript bundles.

Ported from ``route-mapper`` (``parser.py``). The analysis is purely lexical
(regex): the JavaScript is never executed nor interpreted. It returns a set of
root-relative paths (``/api/v1/users``) that the caller must resolve against the
resource URL and validate against the scope engine before use.
"""

from __future__ import annotations

import re

# Absolute paths ("/something/...") wrapped in single, double or backtick
# quotes. Deliberately conservative: the path must start with a single slash
# followed by an alphanumeric character, which rejects protocol-relative URLs
# ("//cdn") and stray division operators.
_JS_ENDPOINT_RE = re.compile(r"""['"`](/[A-Za-z0-9][A-Za-z0-9_./~-]*)['"`]""")

# Static-asset extensions that are noise as an API endpoint.
_JS_NOISE_SUFFIXES = (
    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ttf", ".ico", ".webp",
)


def extract_js_endpoints(content: str) -> set[str]:
    """Extract absolute paths embedded as string literals in JavaScript code.

    Purely lexical: the JavaScript is never executed. Returns a set of
    root-relative paths that the caller resolves against the resource URL and
    validates against the scope engine.
    """
    endpoints: set[str] = set()
    for match in _JS_ENDPOINT_RE.finditer(content):
        path = match.group(1)
        if path.lower().endswith(_JS_NOISE_SUFFIXES):
            continue
        endpoints.add(path)
    return endpoints
