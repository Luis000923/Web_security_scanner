import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from .core.manifest_async import write_manifest
from .core.scanner_core_async import AsyncScannerCore, ScanConfig, SSRFRedirectError
from .core.telemetry_async import TelemetryWorker
from .events.event_emitter import ScanEventEmitter, ScanEventType
from .modules.recon import ReconConfig, ReconEngine
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
        # Phase 1 recon: route-mapper-derived crawling, JS endpoint mining,
        # sitemap seeding, robots Crawl-delay, jitter and the 3-layer anti-SSRF
        # ScopeEngine. Settings come from config['recon'].
        self.recon_config = ReconConfig(**self.config.get('recon', {}))
        self.mapper = WebMapperAsync(
            self.core,
            max_urls=self.recon_config.max_urls,
            max_depth=self.recon_config.max_depth,
            crawl_delay=self.recon_config.crawl_delay,
            jitter=self.recon_config.jitter,
            parse_js=self.recon_config.parse_js,
            use_sitemap=self.recon_config.use_sitemap,
            respect_robots=self.recon_config.respect_robots,
            include_subdomains=self.recon_config.include_subdomains,
            max_links_per_page=self.recon_config.max_links_per_page,
        )
        # Let the crawler emit URL_SCANNED progress events through the same bus.
        self.mapper.event_emitter = self.event_emitter
        self.recon = ReconEngine(self.mapper, self.recon_config)
        self._logger = logging.getLogger(__name__)
        # Accumulated findings for the current scan
        self.vulnerabilities: list[dict[str, Any]] = []
        # Phase 1 telemetry sink; created per-scan in ``run_scan`` when
        # ``config['telemetry']['enabled']`` is set.
        self.telemetry: TelemetryWorker | None = None

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
                       max_depth: int | None = None, max_urls: int | None = None,
                       target_list: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """
        Run the full scan against the target URL.

        Returns a results dict: {target, profile, vulnerabilities, statistics,
        map_report}. Honors an optional global ``max_duration`` (seconds) that
        caps total tester time even if individual testers wait on slow payloads.

        ``target_list`` (Phase 2): when provided, a list of ``{url, param,
        method}`` dicts is used to populate the Phase 2 target queue directly and
        the reconnaissance/crawler phase is skipped entirely (see
        ``_targets_from_list``).
        """
        if not self.testers:
            await self.initialize()

        self._apply_profile(profile)
        # Reset per-scan state so repeated scans don't accumulate findings
        self.vulnerabilities = []
        self.mapper.vulnerabilities = []

        await self.event_emitter.emit(ScanEventType.SCAN_START, url=target_url)
        await self.core.start()

        # Phase 1: spin up the telemetry worker (needs the running loop) and
        # hand it to every tester before any payload is fired.
        await self._start_telemetry()

        # ai-agent: attach the optional LLM triage / payload-synthesis client
        # to every tester (no-op unless --ai-verify / --ai-synthesize is set).
        self._start_ai_agent()

        # Phase 3: snapshot the reproducibility manifest (corpus hash, RNG
        # seed, full config, git commit) before Phase 1/2 probing starts.
        await self._write_manifest()

        map_report = None
        map_data = {}
        technologies = {}
        try:
            self._logger.info(f"Starting scan on {target_url} with profile: {profile}")

            scan_targets: list[str] = [target_url]

            # --- Phase 2 bridge: static target list bypasses recon entirely -
            if target_list:
                scan_targets = self._targets_from_list(target_list) or [target_url]
                msg = (f"Phase 1 recon skipped (--target-list): "
                       f"{len(scan_targets)} static target(s) queued.")
                self._logger.info(msg)
                await self.event_emitter.emit(ScanEventType.LOG_MESSAGE, message=msg)
                await self.event_emitter.emit(
                    ScanEventType.PROGRESS_UPDATE, message=msg
                )

            # --- Phase 1: Recon (route-mapper core) -------------------------
            elif generate_map:
                self._logger.info("Phase 1: reconnaissance (crawl / JS mining / sitemap)...")
                await self.event_emitter.emit(
                    ScanEventType.PROGRESS_UPDATE, message="Phase 1: reconnaissance..."
                )
                if max_depth is not None:
                    self.recon_config.max_depth = max_depth
                    self.mapper.max_depth = max_depth
                if max_urls is not None:
                    self.recon_config.max_urls = max_urls
                    self.mapper.max_urls = max_urls
                recon_result = await self.recon.run(target_url)
                map_data = recon_result.map_data
                scan_targets = recon_result.targets or [target_url]
                await self._handle_dom_xss(recon_result)
                if self.mapper.limit_reached:
                    msg = (f"Crawler abortado preventivamente por límite max_urls "
                           f"({self.mapper.max_urls}) / spider-trap; mapa parcial.")
                    self._logger.warning(msg)
                    await self.event_emitter.emit(ScanEventType.LOG_MESSAGE, message=msg)
                map_report = await self.mapper.generate_map_async(map_data)
                self._logger.info(f"Map generated at: {map_report}")
                await self.event_emitter.emit(
                    ScanEventType.LOG_MESSAGE, message=f"Report generated: {map_report}"
                )
                await self.event_emitter.emit(
                    ScanEventType.LOG_MESSAGE,
                    message=(f"Phase 2: {len(scan_targets)} target(s) queued for the "
                             f"vulnerability testers."),
                )

            # --- Phase 2: Vulnerability testing over discovered targets ----
            runnable = [t for t in self.testers if self._should_run_tester(t, profile)]
            if runnable:
                self._logger.debug(
                    f"Scheduling {len(runnable)} tester(s) over {len(scan_targets)} target(s)"
                )
                await self._dispatch_testers(runnable, scan_targets, max_duration)
            else:
                self._logger.warning("No testers scheduled for this profile.")

            # Technology fingerprinting on the target's landing page. The GET is
            # cached, so the mapper (and any tester) reuses it for free.
            technologies = await self._detect_technologies(target_url)

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
            # Flush + await the telemetry writer BEFORE the session/loop go away
            # so no queued rows are lost.
            if self.telemetry is not None:
                try:
                    await self.telemetry.stop()
                    self._logger.info(
                        "Telemetry: %d row(s) written to %s (%d dropped)",
                        self.telemetry.written, self.telemetry.path,
                        self.telemetry.dropped,
                    )
                except Exception as e:  # pragma: no cover - defensive
                    self._logger.warning(f"Error stopping telemetry worker: {e}")
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
            "telemetry": self.telemetry.summary() if self.telemetry is not None else None,
        }

    @staticmethod
    def _targets_from_list(entries: list[dict[str, Any]]) -> list[str]:
        """Turn ``[{url, param, method}, ...]`` into a deduped list of scan URLs.

        The vulnerability testers discover injectable parameters from the query
        string (``get_query_params``), so an entry that names a ``param`` is
        folded into the URL as ``?param=<probe>`` here. Entries with no ``param``
        pass through untouched. ``method`` is currently advisory (the testers
        issue GETs); a non-GET method is kept in the log for traceability.
        """
        seen: set[str] = set()
        out: list[str] = []
        for entry in entries or []:
            url = (entry or {}).get("url")
            if not url:
                continue
            param = entry.get("param")
            if param:
                url = VulnerabilityTester.inject_param(url, str(param), "1")
            if url not in seen:
                seen.add(url)
                out.append(url)
        return out

    def _start_ai_agent(self) -> None:
        """Build the AI ``AgentClient`` and attach it to every tester.

        Driven by ``config['testers']``:
            ai_verify / ai_synthesize -> at least one must be truthy or this
                is a no-op (client stays ``None``, testers use heuristics only)
            ai_backend / ai_base_url / ai_model -> forwarded to ``AgentClient``

        Every failure mode here (``ai_module`` not installed, bad config,
        constructor raising) is caught and logged — the scan continues on its
        traditional heuristics. The client itself degrades per-call if the
        local inference server is unreachable.
        """
        tcfg = self.config.get("testers", {}) or {}
        if not (tcfg.get("ai_verify") or tcfg.get("ai_synthesize")):
            return
        try:
            from ai_module.agent_inference import AgentClient
        except Exception as exc:  # noqa: BLE001
            self._logger.warning(
                "ai_module unavailable (%s); --ai-verify/--ai-synthesize ignored", exc
            )
            return
        kwargs: dict[str, Any] = {}
        for src, dst in (("ai_backend", "backend"), ("ai_base_url", "base_url"),
                         ("ai_model", "model")):
            if tcfg.get(src):
                kwargs[dst] = tcfg[src]
        try:
            client = AgentClient(**kwargs)
        except Exception as exc:  # noqa: BLE001
            self._logger.warning(
                "Could not build AI AgentClient (%s); continuing without it", exc
            )
            return
        for tester in self.testers:
            tester.ai_client = client
        self._logger.info(
            "AI agent attached (backend=%s verify=%s synthesize=%s)",
            client.backend, bool(tcfg.get("ai_verify")), bool(tcfg.get("ai_synthesize")),
        )

    async def _start_telemetry(self) -> None:
        """Create + start the JSONL telemetry worker and attach it to testers.

        Controlled by ``config['telemetry']``:
            enabled  -> bool (default False; no-op when unset)
            path     -> explicit .jsonl file (default: <dir>/telemetry_<ts>_<run>.jsonl)
            dir      -> directory for the default filename (default: 'reports/telemetry')
            run_id   -> pin the run id (else a fresh uuid4 hex)
        """
        conf = self.config.get("telemetry", {}) or {}
        if not conf.get("enabled"):
            return
        run_id = conf.get("run_id")
        path = conf.get("path")
        if not path:
            out_dir = Path(conf.get("dir", "reports/telemetry"))
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            short = (run_id or "")[:8] or "run"
            path = out_dir / f"telemetry_{stamp}_{short}.jsonl"
        worker = TelemetryWorker(path, run_id=run_id)
        await worker.start()
        self.telemetry = worker
        for tester in self.testers:
            tester.telemetry = worker
        self._logger.info(
            "Telemetry enabled: run_id=%s -> %s", worker.run_id, worker.path
        )
        await self.event_emitter.emit(
            ScanEventType.LOG_MESSAGE,
            message=f"Telemetry: recording probes to {worker.path} (run_id={worker.run_id})",
        )

    async def _handle_dom_xss(self, recon_result: Any) -> None:
        """Turn Phase 4 browser DOM-XSS findings into vulns + telemetry rows.

        Each source->sink flow observed by the headless-browser instrumentation
        is reported through the same ``VULNERABILITY_FOUND`` bus as every other
        tester and, when telemetry is enabled, appended to the JSONL run log in
        the canonical probe-row schema (``vector='domsink'``, ``decision=True``).
        """
        findings = list(getattr(recon_result, "dom_xss_findings", []) or [])
        if not findings:
            return
        msg = f"Phase 4: {len(findings)} DOM-XSS source->sink flow(s) observed in-browser."
        self._logger.info(msg)
        await self.event_emitter.emit(ScanEventType.LOG_MESSAGE, message=msg)
        for finding in findings:
            vuln = finding.to_vulnerability()
            await self.event_emitter.emit(
                ScanEventType.VULNERABILITY_FOUND,
                vulnerability=vuln,
                tester="BrowserDomXss",
            )
            if self.telemetry is not None:
                self.telemetry.record({
                    "tester_id": "BrowserDomXss",
                    "payload_id": f"domxss:{finding.sink}",
                    "context": "dom_xss",
                    "confidence_apriori": "HIGH",
                    "url": finding.url,
                    "method": "GET",
                    "param": finding.param or finding.source,
                    "vector": "domsink",
                    "elapsed_time": 0.0,
                    "decision": True,
                    "confidence_final": "HIGH",
                })

    async def _write_manifest(self) -> None:
        """Persist the Phase 3 reproducibility manifest, if telemetry is on.

        The manifest (corpus SHA-256, ``--global-seed``, full run config, git
        commit) is only meaningful alongside a telemetry run, so it is written
        into the same directory as the JSONL log and shares its ``run_id``.
        A hashing/git/disk failure is logged and swallowed — it must never
        abort or delay the scan itself.
        """
        if self.telemetry is None:
            return
        try:
            path = await write_manifest(
                self.telemetry.path.parent,
                run_id=self.telemetry.run_id,
                config=self.config,
                global_seed=self.config.get("global_seed"),
            )
        except Exception as exc:  # pragma: no cover - defensive, disk errors
            self._logger.warning("Failed to write reproducibility manifest: %s", exc)
            return
        self._logger.info("Reproducibility manifest written: %s", path)
        await self.event_emitter.emit(
            ScanEventType.LOG_MESSAGE, message=f"Manifest: {path}"
        )

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

        # Noisy / out-of-band testers: only in the 'intense' profile.
        if cls_name in ('Log4ShellTester', 'DeserializationTester'):
            return profile == 'intense'

        # Balanced and Intense run everything else
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
        """Run every tester against a single URL (kept for callers/tests)."""
        await self._dispatch_testers(testers, [target_url], max_duration)

    async def _dispatch_testers(self, testers: list[VulnerabilityTester],
                                targets: list[str], max_duration: float | None):
        """Run each tester against each discovered target through a bounded pool.

        Work items are ``(tester, url)`` pairs, so the Phase 1 recon output
        (URLs + parameters mined from HTML, JavaScript and the sitemap) is
        ingested automatically by all 16 vulnerability testers. The pool bounds
        fan-out and guarantees cancel+await of every task on timeout / Ctrl+C.
        """
        pairs = [(tester, url) for url in targets for tester in testers]
        if not pairs:
            return

        async def _worker(item: tuple[VulnerabilityTester, str]):
            tester, url = item
            await self._run_tester_safe(tester, url)

        concurrency = min(len(pairs), self.MAX_TESTER_CONCURRENCY)
        run = self.core.run_worker_pool(pairs, _worker, concurrency=concurrency)

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
