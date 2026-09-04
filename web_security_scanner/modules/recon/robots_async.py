"""Async ``robots.txt`` compliance with ``Crawl-delay`` support.

Ported behaviourally from ``route-mapper`` (``robots.py``) but the fetch is
routed through the scanner core, so the existing SSRF-safe redirect guard,
timeouts and body-size cap all apply. Fails open (allow) when ``robots.txt``
cannot be retrieved, as the standard recommends.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib import robotparser
from urllib.parse import urljoin, urlparse

_MAX_ROBOTS_BYTES = 512 * 1024


class AsyncRobotsPolicy:
    """Per-origin cached ``robots.txt`` policy."""

    def __init__(
        self,
        scanner_core: Any,
        *,
        user_agent: str = "*",
        enabled: bool = True,
        logger: logging.Logger | None = None,
    ) -> None:
        self._scanner = scanner_core
        self._user_agent = user_agent
        self._enabled = enabled
        self._log = logger or logging.getLogger(__name__)
        self._parsers: dict[str, robotparser.RobotFileParser | None] = {}

    async def _parser_for(self, url: str) -> robotparser.RobotFileParser | None:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in self._parsers:
            return self._parsers[origin]

        parser = robotparser.RobotFileParser()
        result: robotparser.RobotFileParser | None = parser
        robots_url = urljoin(origin + "/", "robots.txt")
        try:
            resp = await self._scanner.request("GET", robots_url)
            status = resp.get("status_code", 0)
            if status == 0:
                result = None
            elif status >= 400:
                # No usable robots.txt; an empty parser is already fail-open.
                parser.parse([])
            else:
                body = (resp.get("text") or "")[:_MAX_ROBOTS_BYTES]
                parser.parse(body.splitlines())
        except Exception as exc:  # noqa: BLE001 - fail open on any fetch error
            self._log.debug("robots.txt for %s unavailable: %s", origin, exc)
            result = None

        self._parsers[origin] = result
        return result

    async def can_fetch(self, url: str) -> bool:
        if not self._enabled:
            return True
        parser = await self._parser_for(url)
        if parser is None:
            return True
        try:
            return parser.can_fetch(self._user_agent, url)
        except Exception:  # noqa: BLE001
            return True

    async def crawl_delay(self, url: str) -> float | None:
        if not self._enabled:
            return None
        parser = await self._parser_for(url)
        if parser is None:
            return None
        try:
            value = parser.crawl_delay(self._user_agent)
        except Exception:  # noqa: BLE001
            return None
        return float(value) if value is not None else None
