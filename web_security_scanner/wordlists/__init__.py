"""Brute-force wordlists (subdomains, directories).

These are enumeration inputs for the crawler / mapper, not injection
signatures — they live here rather than in ``PAYLOAD/`` (which is reserved for
``payloads_v5.json`` and its schema).

    from web_security_scanner.wordlists import load_wordlist
    subs = load_wordlist("subdomains")          # list[str], deduped, order kept
"""

from __future__ import annotations

import json
from pathlib import Path

WORDLIST_DIR = Path(__file__).resolve().parent

_KNOWN = {
    "subdomains": WORDLIST_DIR / "subdomains.json",
    "directories": WORDLIST_DIR / "directories.json",
}


def load_wordlist(name: str, *, limit: int | None = None) -> list[str]:
    """Return the named wordlist as a de-duplicated list of strings.

    Unknown names and unreadable/malformed files return ``[]`` so callers can
    fall back to a built-in list without special-casing.
    """
    path = _KNOWN.get(name)
    if path is None or not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for item in data:
        if isinstance(item, str) and item and item not in seen:
            seen.add(item)
            out.append(item)
        if limit is not None and len(out) >= limit:
            break
    return out
