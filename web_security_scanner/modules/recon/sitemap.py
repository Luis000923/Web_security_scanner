"""XXE / XML-bomb hardened ``sitemap.xml`` parser.

Ported from ``route-mapper`` (``parser.py``). A legitimate sitemap
(sitemaps.org protocol) never carries a DTD or entity declarations; their
presence is treated as an XXE / "billion laughs" attempt and the document is
rejected (an empty list is returned). Malformed XML also yields ``[]`` instead
of propagating.
"""

from __future__ import annotations

import re
from xml.etree.ElementTree import ParseError
from xml.etree.ElementTree import fromstring as _xml_fromstring

_XML_DTD_RE = re.compile(r"<!DOCTYPE|<!ENTITY", re.IGNORECASE)


def parse_sitemap(xml_content: str) -> list[str]:
    """Return the URLs declared in a sitemap XML document (``<loc>`` elements).

    Supports both ``<urlset>`` and ``<sitemapindex>`` and is namespace
    agnostic. Any DTD or entity declaration, or malformed XML, results in an
    empty list. ElementTree itself does not resolve external entities.
    """
    if _XML_DTD_RE.search(xml_content):
        return []
    try:
        root = _xml_fromstring(xml_content)  # noqa: S314 - DTD/entities already rejected
    except (ParseError, ValueError):
        return []

    locs: list[str] = []
    seen: set[str] = set()
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]  # drop "{namespace}"
        if tag != "loc" or not element.text:
            continue
        url = element.text.strip()
        if url and url not in seen:
            seen.add(url)
            locs.append(url)
    return locs
