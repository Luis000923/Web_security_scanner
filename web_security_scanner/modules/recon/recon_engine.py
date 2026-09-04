"""Phase 1 recon orchestrator.

Wraps :class:`~web_security_scanner.modules.web_mapper_async.WebMapperAsync`
with the ``route-mapper`` recon knobs (sitemap seeding, JS endpoint mining,
``robots.txt`` ``Crawl-delay``, jitter) and exposes a single ``run`` coroutine
that returns the crawl map together with the list of URLs and parameters to
feed into the Phase 2 vulnerability testers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReconConfig:
    """Tunable recon settings (all backwards-compatible defaults)."""

    max_urls: int = 1000
    max_depth: int = 3
    crawl_delay: float = 0.1
    jitter: float = 0.0
    parse_js: bool = True
    use_sitemap: bool = False
    respect_robots: bool = True
    include_subdomains: bool = True
    max_links_per_page: int = 1000
    # Hard cap on how many discovered URLs are handed to the testers.
    max_scan_targets: int = 60


@dataclass
class ReconResult:
    """Outcome of a recon pass."""

    map_data: dict[str, Any]
    targets: list[str]
    js_endpoints: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    params_by_url: dict[str, list[str]] = field(default_factory=dict)


class ReconEngine:
    """Runs the enriched recon crawl and collects tester targets."""

    def __init__(
        self,
        mapper: Any,
        config: ReconConfig | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._mapper = mapper
        self._config = config or ReconConfig()
        self._log = logger or logging.getLogger(__name__)
        self._apply_config()

    def _apply_config(self) -> None:
        cfg = self._config
        m = self._mapper
        m.max_urls = cfg.max_urls
        m.max_depth = cfg.max_depth
        m.crawl_delay = cfg.crawl_delay
        m.jitter = max(0.0, cfg.jitter)
        m.parse_js = cfg.parse_js
        m.use_sitemap = cfg.use_sitemap
        m.respect_robots = cfg.respect_robots
        m.include_subdomains = cfg.include_subdomains
        m.max_links_per_page = max(1, cfg.max_links_per_page)

    async def run(self, base_url: str) -> ReconResult:
        """Execute the recon crawl and return the map plus tester targets."""
        map_data = await self._mapper.map_website(
            base_url, max_depth=self._config.max_depth, max_urls=self._config.max_urls
        )
        targets = self._mapper.get_scan_targets(
            base_url, max_targets=self._config.max_scan_targets
        )
        self._log.info(
            "Recon complete: %d URLs crawled, %d JS endpoints, %d sitemap URLs, "
            "%d tester target(s)",
            len(self._mapper.visited_urls),
            len(self._mapper.js_endpoints),
            len(self._mapper.sitemap_urls),
            len(targets),
        )
        return ReconResult(
            map_data=map_data,
            targets=targets,
            js_endpoints=sorted(self._mapper.js_endpoints),
            sitemap_urls=sorted(self._mapper.sitemap_urls),
            params_by_url=dict(self._mapper.discovered_params),
        )
