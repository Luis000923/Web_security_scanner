import asyncio
import logging
from typing import Any

from .core.scanner_core_async import AsyncScannerCore, ScanConfig, SSRFRedirectError
from .events.event_emitter import ScanEventEmitter, ScanEventType
from .modules.registry import TesterRegistry
from .modules.technology_detector import TechnologyDetector
from .modules.vulnerability_testers.base_tester_async import VulnerabilityTester
from .modules.web_mapper_async import WebMapperAsync
from .utils.i18n import i18n


class WebSecurityScanner:
    """
    Main Scanner Class (Async).
    Orchestrates the scanning process, manages dependencies, and handles events.
    """
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.event_emitter = ScanEventEmitter()

        # Initialize Core
        core_config = ScanConfig(**self.config.get('core', {}))
        self.core = AsyncScannerCore(core_config)

        self.testers: list[VulnerabilityTester] = []
        self.mapper = WebMapperAsync(self.core)
        # Let the crawler emit URL_SCANNED progress events through the same bus.
        self.mapper.event_emitter = self.event_emitter
        self._logger = logging.getLogger(__name__)
        # Accumulated findings for the current scan
        self.vulnerabilities: list[dict[str, Any]] = []

        # Subscribe mapper to vulnerabilities
        self.event_emitter.on(ScanEventType.VULNERABILITY_FOUND, self._on_vulnerability_found)

    def _on_vulnerability_found(self, **kwargs):
        """Collect vulnerabilities for the report."""
        vuln = kwargs.get('vulnerability')
        if vuln:
            self.vulnerabilities.append(vuln)
            self.mapper.vulnerabilities.append(vuln)

    async def initialize(self):
        """
        Initialize the scanner: discover testers and instantiate them.
        """
        # Discover testers
        TesterRegistry.discover_testers()
        tester_classes = TesterRegistry.get_testers()

        self.testers = []
        for cls in tester_classes:
            try:
                tester = cls(self.core, self.event_emitter, self.config.get('testers', {}))
                self.testers.append(tester)
                self._logger.info(f"Initialized tester: {tester.name}")
            except Exception as e:
                self._logger.error(f"Failed to initialize tester {cls.__name__}: {e}")

    async def run_scan(self, target_url: str, profile: str = "balanced",
                       generate_map: bool = True, max_duration: float | None = None,
                       max_depth: int | None = None, max_urls: int | None = None) -> dict[str, Any]:
        """
        Run the full scan against the target URL.

        Returns a results dict: {target, profile, vulnerabilities, statistics,
        map_report}. Honors an optional global ``max_duration`` (seconds) that
        caps total tester time even if individual testers wait on slow payloads.
        """
        if not self.testers:
            await self.initialize()

        self._apply_profile(profile)
        # Reset per-scan state so repeated scans don't accumulate findings
        self.vulnerabilities = []
        self.mapper.vulnerabilities = []

        await self.event_emitter.emit(ScanEventType.SCAN_START, url=target_url)
        await self.core.start()

        map_report = None
        map_data = {}
        technologies = {}
        try:
            self._logger.info(f"Starting scan on {target_url} with profile: {profile}")

            runnable = [t for t in self.testers if self._should_run_tester(t, profile)]
            if runnable:
                self._logger.debug(f"Scheduling {len(runnable)} tester(s)")
                await self._run_testers(runnable, target_url, max_duration)
            else:
                self._logger.warning("No testers scheduled for this profile.")

            # Technology fingerprinting on the target's landing page. The GET is
            # cached, so the mapper (and any tester) reuses it for free.
            technologies = await self._detect_technologies(target_url)

            if generate_map:
                self._logger.info("Generating web architecture map...")
                await self.event_emitter.emit(ScanEventType.PROGRESS_UPDATE, message="Mapping web architecture...")
                map_data = await self.mapper.map_website(
                    target_url, max_depth=max_depth, max_urls=max_urls
                )
                if self.mapper.limit_reached:
                    msg = (f"Crawler abortado preventivamente por límite max_urls "
                           f"({self.mapper.max_urls}) / spider-trap; mapa parcial.")
                    self._logger.warning(msg)
                    await self.event_emitter.emit(ScanEventType.LOG_MESSAGE, message=msg)
                map_report = await self.mapper.generate_map_async(map_data)
                self._logger.info(f"Map generated at: {map_report}")
                await self.event_emitter.emit(ScanEventType.LOG_MESSAGE, message=f"Report generated: {map_report}")

        except asyncio.CancelledError:
            # KeyboardInterrupt / external cancellation. Testers were already
            # cancelled + awaited by the worker pool; just clean up below and
            # surface a single info-level line (no stack trace).
            self._logger.info(i18n.get("scanner.scan_cancelled"))
            raise
        except Exception as e:
            self._logger.error(f"Scan failed: {e}")
            await self.event_emitter.emit(ScanEventType.ERROR, error=str(e))
        finally:
            try:
                await self.core.close()
            except Exception as e:
                self._logger.debug(f"Error closing scanner core: {e}")
            try:
                await self.event_emitter.emit(ScanEventType.SCAN_COMPLETE)
            except Exception:
                pass
            self._logger.info("Scan complete")

        return {
            "target": target_url,
            "profile": profile,
            "vulnerabilities": self.vulnerabilities,
            "technologies": technologies,
            "statistics": {
                # Mapper stats first; scanner-owned counters override so the
                # mapper's empty total_technologies can't clobber the real count.
                **(map_data.get("statistics", {}) if map_data else {}),
                "total_vulnerabilities": len(self.vulnerabilities),
                "total_technologies": sum(len(v) for v in technologies.values()),
            },
            "map_report": map_report,
        }

    async def _detect_technologies(self, target_url: str) -> dict[str, list]:
        """
        Fingerprint the target's landing page (server, CMS, JS frameworks,
        analytics, WAF/CDN). Detection is CPU-bound (regex + HTML parsing) so it
        runs off the event loop via ``asyncio.to_thread``.
        """
        try:
            await self.event_emitter.emit(
                ScanEventType.PROGRESS_UPDATE, message="Detecting technologies..."
            )
            resp = await self.core.request("GET", target_url)
            if resp.get("status_code", 0) == 0:
                return {}
            detector = TechnologyDetector(self._logger)
            tech = await asyncio.to_thread(
                detector.detect_all, resp.get("headers", {}), resp.get("text", "")
            )
            if tech:
                await self.event_emitter.emit(
                    ScanEventType.LOG_MESSAGE,
                    message=f"Detected {sum(len(v) for v in tech.values())} technologies.",
                )
            return tech
        except Exception as e:
            self._logger.error(f"Technology detection failed: {e}")
            return {}

    # Concurrency/timeout defaults per profile
    PROFILE_DEFAULTS = {
        'mapping': {'max_concurrency': 5, 'timeout': 5},
        'quick': {'max_concurrency': 20, 'timeout': 5},
        'balanced': {'max_concurrency': 10, 'timeout': 10},
        'intense': {'max_concurrency': 50, 'timeout': 15},
    }

    def _apply_profile(self, profile: str):
        """
        Apply profile concurrency/timeout defaults, but only for values the
        caller did NOT explicitly set (explicit CLI --threads/--timeout win).
        """
        defaults = self.PROFILE_DEFAULTS.get(profile, self.PROFILE_DEFAULTS['balanced'])
        explicit = self.config.get('core', {})
        if 'max_concurrency' not in explicit:
            self.core.config.max_concurrency = defaults['max_concurrency']
        if 'timeout' not in explicit:
            self.core.config.timeout = defaults['timeout']
        # Rebuild the semaphore to match the effective concurrency
        self.core._semaphore = asyncio.Semaphore(self.core.config.max_concurrency)

    def _should_run_tester(self, tester: VulnerabilityTester, profile: str) -> bool:
        """Determine if a tester should run based on the profile."""
        cls_name = tester.__class__.__name__

        if profile == 'mapping':
            # Only passive or very light checks
            return cls_name in ['HeaderSecurityTester']
        elif profile == 'quick':
            # Fast, high-impact checks
            return cls_name in ['HeaderSecurityTester', 'XSSTester', 'SQLInjectionTester']

        # Balanced and Intense run everything
        return True

    # How many testers may run concurrently. Each tester issues its own
    # requests sequentially, so this only bounds tester-level fan-out; per
    # request concurrency is enforced by the core semaphore. Routing through
    # the core worker pool also means cancellation/timeout cancels AND awaits
    # every tester before the session is closed (no orphan tasks / socket
    # leaks).
    MAX_TESTER_CONCURRENCY = 8

    async def _run_testers(self, testers: list[VulnerabilityTester],
                           target_url: str, max_duration: float | None):
        """Run testers through a bounded worker pool, honoring max_duration."""
        async def _worker(tester: VulnerabilityTester):
            await self._run_tester_safe(tester, target_url)

        concurrency = min(len(testers), self.MAX_TESTER_CONCURRENCY)
        run = self.core.run_worker_pool(testers, _worker, concurrency=concurrency)

        if max_duration:
            try:
                await asyncio.wait_for(run, timeout=max_duration)
            except asyncio.TimeoutError:
                self._logger.warning(
                    f"Scan hit max-duration ({max_duration}s); stopping testers."
                )
                await self.event_emitter.emit(
                    ScanEventType.LOG_MESSAGE,
                    message=f"Max duration {max_duration}s reached; partial results.",
                )
        else:
            await run

    async def _run_tester_safe(self, tester: VulnerabilityTester, target_url: str):
        """Run a single tester with error handling."""
        try:
            await self.event_emitter.emit(ScanEventType.PROGRESS_UPDATE, message=f"Running {tester.name}...")
            await tester.run_test(target_url)
        except asyncio.CancelledError:
            raise
        except SSRFRedirectError as e:
            self._logger.warning(f"{tester.name}: redirect blocked (SSRF guard): {e}")
            await self.event_emitter.emit(
                ScanEventType.LOG_MESSAGE,
                message=f"{tester.name}: redirect blocked by SSRF guard.",
            )
        except Exception as e:
            self._logger.error(f"Error in tester {tester.name}: {e}")
            await self.event_emitter.emit(ScanEventType.ERROR, error=f"{tester.name} failed: {str(e)}")

    def get_event_emitter(self) -> ScanEventEmitter:
        return self.event_emitter
