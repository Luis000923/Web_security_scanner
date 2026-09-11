import asyncio
import json
import logging
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from .core.manifest_async import write_manifest
from .core.scanner_core_async import AsyncScannerCore, ScanConfig, SSRFRedirectError
from .core.session_async import IdentityPool, SessionConfig, SessionManager
from .core.telemetry_async import TelemetryWorker
from .events.event_emitter import ScanEventEmitter, ScanEventType
from .modules.exploit_engine import DEFAULT_MAX_TARGETS, ExploitEngine
from .modules.recon import ReconConfig, ReconEngine
from .modules.recon.surface_correlator import PrioritizedTarget
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
        # LLM triage agent (opt-in). ``ai_client`` is built in ``_start_ai_agent``
        # only when ``--enable-ai-triaging`` was passed and the backend is
        # healthy; ``ai_triage_decisions`` is the per-scan audit trail of every
        # keep / drop verdict, surfaced in the results dict for the oracle.
        self.ai_client: Any = None
        self.ai_triage_decisions: list[dict[str, Any]] = []
        # Adaptive exploitation engine (opt-in, ``--enable-exploit-engine``).
        # ``exploit_attempts`` is the per-scan Proof-of-Impact audit trail,
        # threaded into the results dict as ``proof_of_impact`` for the report.
        self.exploit_attempts: list[dict[str, Any]] = []

        # Authenticated-scan session manager (form login / static cookies /
        # bearer token). Built only when ``config['session']`` is present, so
        # public scans are entirely unaffected.
        self.session_manager: SessionManager | None = None
        # Secondary (Role B, C, ...) authenticated identities for cross-session
        # analysis (IDOR authenticated-A-vs-B). Built in ``_authenticate`` from
        # ``session_manager.cfg.identities``; ``None`` when that dict is empty,
        # so a scan without multi-identity config never constructs one.
        self.identity_pool: IdentityPool | None = None
        sess_cfg = self.config.get("session")
        if sess_cfg:
            try:
                self.session_manager = SessionManager(
                    SessionConfig.from_dict(sess_cfg),
                    on_event=self._emit_session_event,
                )
            except (TypeError, ValueError) as exc:
                self._logger.error("Invalid session configuration: %s", exc)

        # Testers read tuning knobs (and, when configured, the identity pool)
        # from this dict by reference (see VulnerabilityTester.__init__). It
        # must exist and be the *same* object before ``initialize()`` builds
        # the testers, so a later ``self.config['testers']['identity_pool'] =
        # ...`` assignment in ``_authenticate`` (which runs after
        # ``initialize()``) is visible to every already-constructed tester.
        self.config.setdefault('testers', {})

        # Subscribe mapper to vulnerabilities
        self.event_emitter.on(ScanEventType.VULNERABILITY_FOUND, self._on_vulnerability_found)
        self.event_emitter.on(ScanEventType.AI_TRIAGE_DECISION, self._on_ai_triage_decision)
        self.event_emitter.on(ScanEventType.EXPLOIT_ATTEMPT, self._on_exploit_attempt)

    def _on_vulnerability_found(self, **kwargs):
        """Collect vulnerabilities for the report."""
        vuln = kwargs.get('vulnerability')
        if vuln:
            self.vulnerabilities.append(vuln)
            self.mapper.vulnerabilities.append(vuln)

    def _on_ai_triage_decision(self, **kwargs):
        """Collect the LLM triage audit trail for the report / oracle."""
        decision = kwargs.get('decision')
        if decision:
            self.ai_triage_decisions.append(decision)

    def _on_exploit_attempt(self, **kwargs):
        """Collect the adaptive exploitation engine's Proof-of-Impact trail."""
        attempt = kwargs.get('attempt')
        if attempt:
            self.exploit_attempts.append(attempt)

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
        recon}. Honors an optional global ``max_duration`` (seconds) that
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
        self.ai_triage_decisions = []
        self.exploit_attempts = []

        await self.event_emitter.emit(ScanEventType.SCAN_START, url=target_url)
        await self.core.start()

        # Establish the authenticated session (static cookies / form login /
        # bearer token) before recon so protected zones are crawled too. A
        # no-op when no --auth-* / --session-* option was given.
        auth_ok = await self._authenticate(target_url)

        # Phase 1: spin up the telemetry worker (needs the running loop) and
        # hand it to every tester before any payload is fired.
        await self._start_telemetry()

        # LLM triage agent (opt-in): build the AgentClient and attach it to
        # every tester when --enable-ai-triaging is set and the backend is
        # healthy. Transparent degradation otherwise.
        await self._start_ai_agent()

        # Phase 3: snapshot the reproducibility manifest (corpus hash, RNG
        # seed, full config, git commit) before Phase 1/2 probing starts.
        await self._write_manifest()

        map_data = {}
        technologies = {}
        prioritized_targets: list[PrioritizedTarget] = []
        aborted: str | None = None
        try:
            if not auth_ok:
                aborted = "authentication"
                raise RuntimeError(
                    "authentication is required (--auth-required) but the login "
                    "did not establish a session; aborting."
                )
            self._logger.info(f"Starting scan on {target_url} with profile: {profile}")

            # Each entry is {"url": str, "kwargs": dict}; ``kwargs`` is splatted
            # into ``tester.run_test`` so a target can carry a body/header/cookie
            # injection descriptor. The recon path yields empty-kwargs entries.
            scan_targets: list[dict[str, Any]] = [{"url": target_url, "kwargs": {}}]

            # --- Phase 2 bridge: static target list bypasses recon entirely -
            if target_list:
                scan_targets = (self._targets_from_list(target_list)
                                or [{"url": target_url, "kwargs": {}}])
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
                prioritized_targets = recon_result.prioritized_targets
                scan_targets = [{"url": u, "kwargs": {}}
                                for u in (recon_result.targets or [target_url])]
                await self._handle_dom_xss(recon_result)
                await self._handle_sensitive_files(recon_result)
                await self._handle_server_fingerprint(recon_result)
                if self.mapper.limit_reached:
                    msg = (f"Crawler abortado preventivamente por límite max_urls "
                           f"({self.mapper.max_urls}) / spider-trap; mapa parcial.")
                    self._logger.warning(msg)
                    await self.event_emitter.emit(ScanEventType.LOG_MESSAGE, message=msg)
                await self.event_emitter.emit(
                    ScanEventType.LOG_MESSAGE,
                    message=(f"Phase 2: {len(scan_targets)} target(s) queued for the "
                             f"vulnerability testers."),
                )

            # --- Phase 2: Vulnerability testing over discovered targets ----
            runnable = [t for t in self.testers if self._should_run_tester(t, profile)]
            if runnable:
                # Explicit warm-up phase (JVM-latency-bias mitigation): fire
                # discard requests at every endpoint before any baseline /
                # telemetry capture. Opt-in via --warmup; no-op at 0.
                await self._warmup_targets(scan_targets)
                self._logger.debug(
                    f"Scheduling {len(runnable)} tester(s) over {len(scan_targets)} target(s)"
                )
                await self._dispatch_testers(runnable, scan_targets, max_duration)
            else:
                self._logger.warning("No testers scheduled for this profile.")

            # Technology fingerprinting on the target's landing page. The GET is
            # cached, so the mapper (and any tester) reuses it for free.
            technologies = await self._detect_technologies(target_url)

            # --- Exploit engine: adaptive, non-destructive Proof-of-Impact --
            # validation of the CRITICAL/HIGH surface targets (opt-in via
            # --enable-exploit-engine). No-op without prioritized targets
            # (e.g. --target-list bypasses recon entirely).
            if prioritized_targets:
                await self._run_exploit_engine(technologies, prioritized_targets)

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
            # Settle any in-flight triage batch before the loop goes away, so no
            # caller is left parked on an unresolved future.
            await self._stop_ai_agent()
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
            if self.identity_pool is not None:
                # Secondary identities (session_async.IdentityPool) each own an
                # independent AsyncScannerCore/aiohttp.ClientSession that the
                # primary self.core.close() above never touches.
                try:
                    await self.identity_pool.close()
                except Exception as e:  # pragma: no cover - defensive
                    self._logger.debug(f"Error closing secondary identities: {e}")
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
            "recon": self._recon_summary(map_data),
            "telemetry": self.telemetry.summary() if self.telemetry is not None else None,
            "ai_triage": self._ai_triage_summary(),
            "proof_of_impact": self.exploit_attempts,
            "aborted": aborted,
        }

    @staticmethod
    def _recon_summary(map_data: dict[str, Any]) -> dict[str, Any]:
        """Trim ``map_data`` down to the Phase 1 artifacts the report engine
        needs (priority tree, sensitive files, server fingerprint, ...),
        dropping fields already surfaced elsewhere in the results dict
        (``structure``, ``technologies``, ``vulnerabilities``) so the final
        report never serializes the same findings twice.
        """
        if not map_data:
            return {}
        return {
            "base_domain": map_data.get("base_domain"),
            "scan_timestamp": map_data.get("scan_timestamp"),
            "subdomains": map_data.get("subdomains", []),
            "js_endpoints": map_data.get("js_endpoints", []),
            "sitemap_urls": map_data.get("sitemap_urls", []),
            "priority_targets": map_data.get("priority_targets", []),
            "sensitive_files": map_data.get("sensitive_files", []),
            "server_fingerprint": map_data.get("server_fingerprint"),
            "surface_priority": map_data.get("statistics", {}).get("surface_priority", {}),
        }

    def _ai_triage_summary(self) -> dict[str, Any] | None:
        """Audit trail of the LLM triage agent for this scan, or ``None`` when
        the agent was not active. Consumed by ``tools/eval_oracle.py`` to score
        the real false-positive suppression rate and any false negatives the
        model introduced against the OWASP Benchmark ground truth.
        """
        tcfg = self.config.get("testers", {}) or {}
        if not tcfg.get("ai_enabled", False):
            return None
        decisions = list(self.ai_triage_decisions)
        dropped = [d for d in decisions if d.get("dropped")]
        return {
            "enabled": True,
            "active": self.ai_client is not None,
            "backend": getattr(self.ai_client, "backend", None),
            "fp_threshold": tcfg.get("ai_fp_threshold", 0.75),
            "total_candidates_triaged": len(decisions),
            "suppressed": len(dropped),
            "kept": len(decisions) - len(dropped),
            "decisions": decisions,
        }

    @staticmethod
    def _targets_from_list(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Turn ``[{url, param, vector, method, body, json, headers, cookies}, ...]``
        into a deduped list of ``{"url": str, "kwargs": dict}`` scan targets.

        ``kwargs`` is splatted into ``tester.run_test`` so a single target-list
        entry can drive any injection vector:

        - plain ``{url, param}`` (or ``vector: getparam``) -> the param is folded
          into the query string as ``?param=1`` (legacy behaviour, empty kwargs);
        - ``json`` (nested object) or ``vector: jsonparam`` -> a JSON POST body
          form descriptor (``kwargs['form']`` with ``enctype='json'``); every
          leaf of the structure becomes a ``jsonparam`` point;
        - ``body`` (flat object) or ``vector: formparam`` -> an
          ``application/x-www-form-urlencoded`` POST body form descriptor;
        - ``headers`` (object) or ``vector: header`` -> ``kwargs['inject_headers']``
          (a bare ``vector: header`` with a ``param`` injects just that header;
          with neither, the builtin default header set);
        - ``cookies`` (object) or ``vector: cookie`` -> ``kwargs['inject_cookies']``.
        """
        seen: set[tuple] = set()
        out: list[dict[str, Any]] = []
        for entry in entries or []:
            url = (entry or {}).get("url")
            if not url:
                continue
            vector = str(entry.get("vector") or "").lower()
            param = entry.get("param")
            body = entry.get("body")
            json_body = entry.get("json")
            headers = entry.get("headers")
            cookies = entry.get("cookies")
            kwargs: dict[str, Any] = {}

            if json_body is not None or vector == "jsonparam":
                fields = json_body if json_body is not None else {str(param or "q"): "1"}
                kwargs["form"] = {"action": url, "enctype": "json", "fields": fields}
            elif body is not None or vector == "formparam":
                fields = body if body is not None else {str(param or "q"): "1"}
                kwargs["form"] = {"action": url, "enctype": "form", "fields": fields}

            if headers is not None or vector == "header":
                kwargs["inject_headers"] = (
                    headers if headers is not None
                    else ([str(param)] if param else "__default__")
                )
            if cookies is not None or vector == "cookie":
                kwargs["inject_cookies"] = (
                    cookies if cookies is not None
                    else ({str(param): "1"} if param else {})
                )

            if not kwargs and param:
                url = VulnerabilityTester.inject_param(url, str(param), "1")

            key = (url, json.dumps(kwargs, sort_keys=True, default=str))
            if key in seen:
                continue
            seen.add(key)
            out.append({"url": url, "kwargs": kwargs})
        return out

    async def _start_ai_agent(self) -> None:
        """Build the LLM triage ``AgentClient`` and attach it to every tester.

        Opt-in: does nothing unless ``config['testers']['ai_enabled']`` is set
        (CLI ``--enable-ai-triaging``). Transparent degradation — any of the
        following logs one line and lets the scan continue on the deterministic
        heuristics, never raising:

            * ``ai_module`` / its deps not installed
            * ``AgentClient`` constructor fails
            * the inference backend fails its ``healthcheck()`` (server down)

        Per-call failures after attach are absorbed inside the testers
        (``_ai_triage`` / ``ai_supplemental_payloads``), so a mid-scan backend
        outage also falls back cleanly.
        """
        tcfg = self.config.get("testers", {}) or {}
        if not tcfg.get("ai_enabled", False):
            return
        if not (tcfg.get("ai_verify", True) or tcfg.get("ai_synthesize", False)):
            self._logger.info(
                "AI triage requested but both halves are disabled; running the "
                "deterministic heuristic engine."
            )
            return
        try:
            from ai_module.agent_inference import AgentClient, BatchingTriageClient
        except Exception as exc:  # noqa: BLE001
            await self.event_emitter.emit(
                ScanEventType.LOG_MESSAGE,
                message=(f"AI triage unavailable ({exc}); falling back to "
                         f"deterministic heuristics. Install with "
                         f"`pip install -e \".[ai]\"`."),
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
            await self.event_emitter.emit(
                ScanEventType.LOG_MESSAGE,
                message=(f"Could not build the AI AgentClient ({exc}); falling "
                         f"back to deterministic heuristics."),
            )
            return

        try:
            healthy = await client.healthcheck()
        except Exception as exc:  # noqa: BLE001 - defensive
            healthy = False
            self._logger.debug("AI healthcheck raised: %s", exc)
        if not healthy:
            await self.event_emitter.emit(
                ScanEventType.LOG_MESSAGE,
                message=(f"AI inference backend not reachable "
                         f"(backend={client.backend} "
                         f"url={getattr(client, 'base_url', 'n/a')}); falling "
                         f"back to deterministic heuristics."),
            )
            return

        # Findings arrive one at a time from whichever tester found them, but
        # several testers run concurrently: wrap the client so those inline
        # calls coalesce into batched requests over one reusable session
        # instead of a serialised round trip (and connection) per finding.
        batched = BatchingTriageClient(
            client,
            max_batch=int(tcfg.get("ai_batch_size", 8) or 8),
            linger=float(tcfg.get("ai_batch_linger", 0.05) or 0.0),
            concurrency=int(tcfg.get("ai_concurrency", 4) or 4),
        )
        self.ai_client = batched
        for tester in self.testers:
            tester.ai_client = batched
        await self.event_emitter.emit(
            ScanEventType.LOG_MESSAGE,
            message=(f"AI triage active (backend={client.backend} "
                     f"verify={bool(tcfg.get('ai_verify', True))} "
                     f"synthesize={bool(tcfg.get('ai_synthesize', False))} "
                     f"batch={batched._max_batch} "
                     f"fp_threshold={tcfg.get('ai_fp_threshold', 0.75)})"),
        )

    async def _run_exploit_engine(
        self, technologies: dict[str, list[str]],
        prioritized_targets: list[PrioritizedTarget],
    ) -> None:
        """Adaptive, non-destructive Proof-of-Impact pass (opt-in).

        Enabled via ``--enable-exploit-engine``. Transparent degradation: any
        failure here is logged and swallowed so the exploit engine can never
        abort an otherwise-successful scan.
        """
        tcfg = self.config.get("testers", {}) or {}
        if not tcfg.get("enable_exploit_engine", False):
            return
        try:
            engine = ExploitEngine(
                self.core, self.event_emitter, tcfg,
                technologies=technologies,
                max_targets=tcfg.get("exploit_max_targets", DEFAULT_MAX_TARGETS),
            )
            await self.event_emitter.emit(
                ScanEventType.PROGRESS_UPDATE,
                message="Exploit engine: adaptive Proof-of-Impact validation...",
            )
            attempts = await engine.run(prioritized_targets)
            confirmed = sum(1 for a in attempts if a.classification == "CONFIRMED_EXPLOITABLE")
            await self.event_emitter.emit(
                ScanEventType.LOG_MESSAGE,
                message=(f"Exploit engine: {len(attempts)} Proof-of-Impact attempt(s), "
                         f"{confirmed} confirmed exploitable."),
            )
        except Exception as exc:  # noqa: BLE001 - PoC pass must never abort the scan
            self._logger.warning("Exploit engine pass failed: %s", exc)

    async def _stop_ai_agent(self) -> None:
        """Drain any queued triage batch and release the agent's HTTP session.

        The client reference is kept so ``_ai_triage_summary`` can still report
        that the agent was active for this run.
        """
        close = getattr(self.ai_client, "aclose", None)
        if close is None:
            return
        try:
            await close()
        except Exception as exc:  # noqa: BLE001 - teardown must never fail a scan
            self._logger.debug("Error closing the AI triage client: %s", exc)

    async def _emit_session_event(self, message: str) -> None:
        """Bridge SessionManager progress lines onto the scan event bus."""
        await self.event_emitter.emit(ScanEventType.LOG_MESSAGE,
                                      message=f"[auth] {message}")

    async def _authenticate(self, target_url: str | None = None) -> bool:
        """Apply static session material and perform the form/token login.

        Returns ``False`` only when authentication was *required*
        (``--auth-required``) and did not establish a session — the caller
        aborts. In every other case (no auth configured, or auth configured but
        best-effort) it returns ``True`` and the scan proceeds, authenticated if
        it could be.
        """
        sm = self.session_manager
        if sm is None:
            return True

        try:
            sm.apply_static(self.core, target_url)
        except Exception as exc:  # noqa: BLE001 - never abort on a bad jar file
            self._logger.error("Failed to apply static session material: %s", exc)
            await self.event_emitter.emit(
                ScanEventType.ERROR, error=f"session setup failed: {exc}")

        ok = True
        if sm.cfg.does_form_login:
            ok = await sm.authenticate(self.core, force=True)
            if not ok:
                await self.event_emitter.emit(
                    ScanEventType.ERROR,
                    error="Authentication failed; continuing unauthenticated."
                    if not sm.cfg.required else "Authentication failed.",
                )

        # Attach for transparent mid-scan re-auth (no-op when reauth is off or
        # this is a static-only session).
        self.core.attach_session_manager(sm)

        if sm.cfg.required and not ok:
            return False

        # Multi-identity (cross-session) analysis: start every secondary role
        # declared under ``session.identities`` concurrently. Independent of
        # the primary login above (``ok``/``required``) — a secondary identity
        # a target rejects is logged by IdentityPool.start_one and simply
        # yields no context for that role, degrading IDORTester's cross-session
        # check to a no-op rather than aborting the whole scan.
        if sm.cfg.identities:
            self.identity_pool = IdentityPool(self.core, on_event=self._emit_session_event)
            await self.identity_pool.start_all(
                sm.cfg.identities, self.core.config, target_url=target_url,
            )
            self.config['testers']['identity_pool'] = self.identity_pool
            await self.event_emitter.emit(
                ScanEventType.LOG_MESSAGE,
                message=(f"[auth] {len(self.identity_pool.secondary_roles)} secondary "
                         f"identity(ies) started: {self.identity_pool.secondary_roles}"),
            )

        if sm.cfg.active and (ok or not sm.cfg.does_form_login):
            await self.event_emitter.emit(
                ScanEventType.LOG_MESSAGE,
                message="[auth] session material attached to the HTTP core.",
            )
        return True

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

    async def _handle_sensitive_files(self, recon_result: Any) -> None:
        """Turn sensitive-file exposures into vulns + telemetry rows.

        Mirrors :meth:`_handle_dom_xss`: each finding is reported through the
        same ``VULNERABILITY_FOUND`` bus as every other tester.
        """
        findings = list(getattr(recon_result, "sensitive_files", []) or [])
        if not findings:
            return
        msg = f"Sensitive-file detector: {len(findings)} exposed asset(s) found."
        self._logger.info(msg)
        await self.event_emitter.emit(ScanEventType.LOG_MESSAGE, message=msg)
        for finding in findings:
            vuln = finding.to_vulnerability()
            await self.event_emitter.emit(
                ScanEventType.VULNERABILITY_FOUND,
                vulnerability=vuln,
                tester="SensitiveFileDetector",
            )
            if self.telemetry is not None:
                self.telemetry.record({
                    "tester_id": "SensitiveFileDetector",
                    "payload_id": f"sensitive-file:{finding.path}",
                    "context": "sensitive_file",
                    "confidence_apriori": finding.confidence,
                    "url": finding.url,
                    "method": "GET",
                    "param": finding.path,
                    "vector": "recon",
                    "elapsed_time": 0.0,
                    "decision": True,
                    "confidence_final": finding.confidence,
                })

    async def _handle_server_fingerprint(self, recon_result: Any) -> None:
        """Turn verified server-fingerprint advisories into vulns + telemetry rows."""
        fp_result = getattr(recon_result, "server_fingerprint", None)
        if fp_result is None or not fp_result.findings:
            return
        msg = f"Server fingerprinting: {len(fp_result.findings)} verified advisory(ies) confirmed."
        self._logger.info(msg)
        await self.event_emitter.emit(ScanEventType.LOG_MESSAGE, message=msg)
        for vuln in fp_result.to_vulnerabilities():
            await self.event_emitter.emit(
                ScanEventType.VULNERABILITY_FOUND,
                vulnerability=vuln,
                tester="ServerFingerprinter",
            )
            if self.telemetry is not None:
                self.telemetry.record({
                    "tester_id": "ServerFingerprinter",
                    "payload_id": f"server-fingerprint:{vuln.get('cve_id')}",
                    "context": "server_fingerprint",
                    "confidence_apriori": vuln.get("confidence"),
                    "url": vuln.get("url"),
                    "method": "GET",
                    "param": vuln.get("cve_id"),
                    "vector": "recon",
                    "elapsed_time": 0.0,
                    "decision": True,
                    "confidence_final": vuln.get("confidence"),
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

    async def _warmup_targets(self, targets: "Sequence[str | dict[str, Any]]") -> int:
        """Fire N discard requests at each unique endpoint to prime the server.

        Mitigates JVM JIT warm-up bias on the OWASP Benchmark testbed: without
        it the first baseline latency samples per endpoint capture cold,
        interpreted-bytecode responses. Controlled by
        ``config['testers']['warmup_requests']`` (``--warmup``); ``0`` disables
        it. Requests route through :meth:`AsyncScannerCore.warmup`, so the token
        bucket, concurrency semaphore and SSRF guard all still apply, and
        :meth:`~AsyncScannerCore.warmup` dedups per endpoint so a per-point
        warm-up inside a tester never re-fires.
        """
        n = int((self.config.get("testers", {}) or {}).get("warmup_requests", 0) or 0)
        if n <= 0:
            return 0
        urls = []
        seen: set[str] = set()
        for t in targets:
            url = t["url"] if isinstance(t, dict) else t
            if url not in seen:
                seen.add(url)
                urls.append(url)
        issued = 0
        for url in urls:
            try:
                issued += await self.core.warmup(url, n)
            except asyncio.CancelledError:
                raise
            except SSRFRedirectError:
                self._logger.warning("warm-up skipped for %s (SSRF guard)", url)
            except Exception as exc:  # noqa: BLE001 - warm-up is best-effort
                self._logger.debug("warm-up failed for %s: %s", url, exc)
        await self.event_emitter.emit(
            ScanEventType.LOG_MESSAGE,
            message=(f"Warm-up phase: {issued} discard request(s) over "
                     f"{len(urls)} endpoint(s) (N={n})."),
        )
        return issued

    async def _dispatch_testers(self, testers: list[VulnerabilityTester],
                                targets: "Sequence[str | dict[str, Any]]",
                                max_duration: float | None):
        """Run each tester against each discovered target through a bounded pool.

        ``targets`` entries are either a bare URL string (Phase 1 recon output)
        or a ``{"url": str, "kwargs": dict}`` mapping (a --target-list entry that
        carries a body/header/cookie injection descriptor). ``kwargs`` is
        splatted into ``run_test``. The pool bounds fan-out and guarantees
        cancel+await of every task on timeout / Ctrl+C.
        """
        norm = [t if isinstance(t, dict) else {"url": t, "kwargs": {}}
                for t in targets]
        pairs = [(tester, t) for t in norm for tester in testers]
        if not pairs:
            return

        async def _worker(item: tuple[VulnerabilityTester, dict[str, Any]]):
            tester, t = item
            await self._run_tester_safe(tester, t["url"], **t.get("kwargs", {}))

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

    async def _run_tester_safe(self, tester: VulnerabilityTester, target_url: str,
                               **run_kwargs: Any):
        """Run a single tester with error handling.

        ``run_kwargs`` (e.g. ``form`` / ``inject_headers`` / ``inject_cookies``
        from a --target-list entry) is forwarded to ``run_test`` so the tester
        enumerates the extra injection vectors alongside the query string.
        """
        try:
            await self.event_emitter.emit(ScanEventType.PROGRESS_UPDATE, message=f"Running {tester.name}...")
            await tester.run_test(target_url, **run_kwargs)
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
