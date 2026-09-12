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
from urllib.parse import urlparse

from .browser_engine import BrowserRecon, DomXssFinding
from .sensitive_files_detector import SensitiveFileDetector, SensitiveFileFinding
from .server_fingerprinter import ServerFingerprinter, ServerFingerprintResult
from .surface_correlator import PrioritizedTarget, SurfaceCorrelator


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
    # ---- Phase 4: headless-browser recon (SPA + DOM-XSS) -------------
    # Opt-in. When True and Playwright is importable, a headless Chromium pass
    # runs after the HTTP crawl to execute client JS, intercept XHR/fetch and
    # trace DOM-XSS source->sink flows. A missing Playwright install degrades
    # to a logged no-op (see BrowserRecon.available).
    use_browser: bool = False
    browser_nav_timeout: float = 15.0
    browser_settle_time: float = 2.0
    browser_max_pages: int = 6
    # Max Chromium tabs alive at once during the browser pass (each one is a
    # renderer process); clamped to browser_max_pages by BrowserRecon.
    browser_max_concurrent_pages: int = 3
    # ---- Sensitive-file exposure detection ----------------------------
    # Opt-in (fires additional non-destructive GET probes per discovered base
    # path). Degrades to an empty result on any failure - see
    # ReconEngine._run_sensitive_files.
    detect_sensitive_files: bool = False
    sensitive_files_max_base_paths: int = 6
    sensitive_files_max_concurrent: int = 8
    # ---- Server / infrastructure fingerprinting -----------------------
    # Opt-in. When True, parses Server/X-Powered-By/Via headers and verifies
    # matching advisories; fingerprint_active_probes gates the non-destructive
    # Safe PoC Probe step (e.g. MS15-034) required before anything that needs
    # active confirmation is ever reported.
    fingerprint_server: bool = False
    fingerprint_active_probes: bool = True


@dataclass
class ReconResult:
    """Outcome of a recon pass."""

    map_data: dict[str, Any]
    # Phase 2 attack queue. Risk/Value-ranked (see ``prioritized_targets``
    # below) with the seed URL always leading; capped at
    # ``ReconConfig.max_scan_targets``.
    targets: list[str]
    js_endpoints: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    params_by_url: dict[str, list[str]] = field(default_factory=dict)
    # Phase 4: URLs/endpoints discovered by the headless browser (client-side
    # routing + intercepted XHR/fetch) and DOM-XSS source->sink findings.
    browser_endpoints: list[str] = field(default_factory=list)
    dom_xss_findings: list[DomXssFinding] = field(default_factory=list)
    # Phase 5 (final): the *full* discovered attack surface (a superset of
    # ``targets`` - includes parameterless pages too), classified by category
    # and ranked by Risk/Value score, descending. ``targets`` is built from
    # this ranking (seed first, then by score) but capped at
    # ``max_scan_targets``; this list is uncapped, e.g. for the recon report.
    prioritized_targets: list[PrioritizedTarget] = field(default_factory=list)
    # Sensitive-asset exposures (config/backup/VCS files), opt-in via
    # ReconConfig.detect_sensitive_files.
    sensitive_files: list[SensitiveFileFinding] = field(default_factory=list)
    # Server/framework fingerprint + verified version advisories, opt-in via
    # ReconConfig.fingerprint_server.
    server_fingerprint: ServerFingerprintResult | None = None


class ReconEngine:
    """Runs the enriched recon crawl and collects tester targets."""

    def __init__(
        self,
        mapper: Any,
        config: ReconConfig | None = None,
        logger: logging.Logger | None = None,
        browser: BrowserRecon | None = None,
    ) -> None:
        self._mapper = mapper
        self._config = config or ReconConfig()
        self._log = logger or logging.getLogger(__name__)
        self._browser = browser
        self._apply_config()

    def _make_browser(self) -> BrowserRecon:
        return BrowserRecon(
            nav_timeout=self._config.browser_nav_timeout,
            settle_time=self._config.browser_settle_time,
            max_pages=self._config.browser_max_pages,
            max_concurrent_pages=self._config.browser_max_concurrent_pages,
            logger=self._log,
            scope=getattr(self._mapper, "_scope", None),
        )

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
        browser_endpoints: list[str] = []
        dom_xss: list[DomXssFinding] = []
        if self._config.use_browser:
            browser_endpoints, dom_xss = await self._run_browser(base_url)

        sensitive_files: list[SensitiveFileFinding] = []
        if self._config.detect_sensitive_files:
            sensitive_files = await self._run_sensitive_files(base_url)

        server_fingerprint: ServerFingerprintResult | None = None
        if self._config.fingerprint_server:
            server_fingerprint = await self._run_server_fingerprint(base_url)

        # --- Surface correlation: classify + Risk/Value-rank every *discovered*
        # URL (not just the query/JS/sitemap-filtered ``targets`` above - a
        # parameterless admin panel or upload form is scored too), then
        # rebuild the Phase 2 attack queue from that ranking so the
        # highest-scoring endpoints (admin panels, upload/API endpoints,
        # fingerprint-confirmed vulnerable components, ...) are dispatched to
        # the testers first.
        candidate_pool = self._mapper.get_all_candidate_urls(base_url)
        for url in browser_endpoints:
            if url not in candidate_pool:
                candidate_pool.append(url)
        for finding in sensitive_files:
            if finding.url not in candidate_pool:
                candidate_pool.append(finding.url)
        prioritized_targets = self._correlate_surface(
            base_url, candidate_pool, map_data, set(browser_endpoints)
        )
        targets = self._build_priority_queue(base_url, prioritized_targets)
        priority_summary = SurfaceCorrelator.summarize(prioritized_targets)
        map_data["priority_targets"] = [
            {
                "url": pt.url,
                "categories": list(pt.categories),
                "score": pt.score,
                "priority": pt.priority,
                "evidence": list(pt.evidence),
            }
            for pt in prioritized_targets
        ]
        map_data.setdefault("statistics", {})["surface_priority"] = priority_summary
        if sensitive_files:
            map_data["sensitive_files"] = [
                {
                    "url": f.url, "path": f.path, "risk": f.risk, "category": f.category,
                    "status_code": f.status_code, "confidence": f.confidence, "evidence": f.evidence,
                }
                for f in sensitive_files
            ]
        if server_fingerprint is not None and (server_fingerprint.fingerprints or server_fingerprint.findings):
            map_data["server_fingerprint"] = {
                "fingerprints": [
                    {"header": fp.header, "product": fp.product, "version": fp.version}
                    for fp in server_fingerprint.fingerprints
                ],
                "findings": [
                    {
                        "cve_id": pf.cve_id, "name": pf.name, "severity": pf.severity,
                        "confidence": pf.confidence, "poc_method": pf.poc_method,
                    }
                    for pf in server_fingerprint.findings
                ],
            }

        self._log.info(
            "Recon complete: %d URLs crawled, %d JS endpoints, %d sitemap URLs, "
            "%d browser endpoint(s), %d DOM-XSS finding(s), %d sensitive file(s), "
            "%d tester target(s) (%d critical, %d high priority)",
            len(self._mapper.visited_urls),
            len(self._mapper.js_endpoints),
            len(self._mapper.sitemap_urls),
            len(browser_endpoints),
            len(dom_xss),
            len(sensitive_files),
            len(targets),
            priority_summary.get("CRITICAL", 0),
            priority_summary.get("HIGH", 0),
        )
        return ReconResult(
            map_data=map_data,
            targets=targets,
            js_endpoints=sorted(self._mapper.js_endpoints),
            sitemap_urls=sorted(self._mapper.sitemap_urls),
            params_by_url=dict(self._mapper.discovered_params),
            browser_endpoints=browser_endpoints,
            dom_xss_findings=dom_xss,
            prioritized_targets=prioritized_targets,
            sensitive_files=sensitive_files,
            server_fingerprint=server_fingerprint,
        )

    def _build_priority_queue(
        self, base_url: str, prioritized_targets: list[PrioritizedTarget]
    ) -> list[str]:
        """Rebuild the Phase 2 attack queue from the Risk/Value ranking.

        The seed always leads the queue (matches the historical
        ``get_scan_targets`` contract of every earlier phase); everything
        else follows in descending score order, capped at
        ``max_scan_targets``.
        """
        cap = max(1, self._config.max_scan_targets)
        # ``get_all_candidate_urls``/``get_scan_targets`` both seed their own
        # list with the raw ``base_url`` (no normalization) - match that so
        # the containment check below actually dedupes against it.
        queue = [base_url]
        for pt in prioritized_targets:
            if len(queue) >= cap:
                break
            if pt.url in queue:
                continue
            queue.append(pt.url)
        return queue[:cap]

    def _discovered_base_paths(self, base_url: str) -> list[str]:
        """Directory-like paths the crawler has already seen for ``base_url``'s host.

        Feeds :class:`SensitiveFileDetector` so it probes real discovered
        sub-paths (an admin panel, an API mount, ...) in addition to the site
        root, instead of only ever checking the root directory.
        """
        domain = urlparse(base_url).netloc
        domain_data = self._mapper.site_structure.get("domains", {}).get(domain, {})
        paths = list(dict.fromkeys(domain_data.get("paths", [])))
        paths.sort(key=len)
        return paths

    async def _run_sensitive_files(self, base_url: str) -> list[SensitiveFileFinding]:
        """Sensitive-asset exposure sweep. Never raises into the caller."""
        try:
            detector = SensitiveFileDetector(
                self._mapper.scanner,
                max_base_paths=self._config.sensitive_files_max_base_paths,
                max_concurrent=self._config.sensitive_files_max_concurrent,
                logger=self._log,
            )
            result = await detector.detect(
                base_url, base_paths=self._discovered_base_paths(base_url)
            )
        except Exception as exc:  # noqa: BLE001 - defensive, must not abort recon
            self._log.warning("Sensitive-file detection failed: %s", exc)
            return []
        if result.findings:
            self._log.info(
                "Sensitive-file detection: %d exposed asset(s) found (of %d probed).",
                len(result.findings), result.probed,
            )
        return result.findings

    async def _run_server_fingerprint(self, base_url: str) -> ServerFingerprintResult | None:
        """Server/framework fingerprinting pass. Never raises into the caller."""
        try:
            fingerprinter = ServerFingerprinter(
                self._mapper.scanner,
                enable_active_probes=self._config.fingerprint_active_probes,
                logger=self._log,
            )
            result = await fingerprinter.fingerprint(base_url)
        except Exception as exc:  # noqa: BLE001 - defensive, must not abort recon
            self._log.warning("Server fingerprinting failed: %s", exc)
            return None
        if result.findings:
            self._log.info(
                "Server fingerprinting: %d verified advisory(ies) confirmed.",
                len(result.findings),
            )
        return result

    def _correlate_surface(
        self,
        base_url: str,
        targets: list[str],
        map_data: dict[str, Any],
        browser_endpoints: set[str],
    ) -> list[PrioritizedTarget]:
        """Run :class:`SurfaceCorrelator` over the discovered attack surface.

        Never raises into the caller: a correlation failure degrades to the
        original discovery-order queue (every target at INFO priority)
        instead of aborting recon.
        """
        try:
            correlator = SurfaceCorrelator(logger=self._log)
            return correlator.correlate(
                targets,
                forms=self._mapper.site_structure.get("forms", []),
                params_by_url=self._mapper.discovered_params,
                technologies=map_data.get("technologies", {}),
                hidden_urls=set(self._mapper.js_endpoints) | browser_endpoints,
            )
        except Exception as exc:  # noqa: BLE001 - defensive, must not abort recon
            self._log.warning("Surface correlation failed: %s", exc)
            return [
                PrioritizedTarget(url=u, categories=("generic",), score=0.0,
                                   priority="INFO")
                for u in targets
            ]

    async def _run_browser(
        self, base_url: str
    ) -> tuple[list[str], list[DomXssFinding]]:
        """Headless-browser recon pass. Never raises into the caller."""
        browser = self._browser or self._make_browser()
        if not browser.available():
            self._log.info(
                "Browser recon requested (use_browser=True) but Playwright is not "
                "installed; continuing with HTTP-only recon."
            )
            return [], []
        try:
            outcome = await browser.explore(
                base_url, seed_params=dict(self._mapper.discovered_params)
            )
        except Exception as exc:  # noqa: BLE001 - defensive, must not abort recon
            self._log.warning("Browser recon pass errored: %s", exc)
            return [], []
        endpoints = sorted(outcome.discovered_urls)
        return endpoints, list(outcome.dom_xss)
