import asyncio
import logging
from typing import List, Dict, Any, Optional
from .events.event_emitter import ScanEventEmitter, ScanEventType
from .core.scanner_core_async import AsyncScannerCore, ScanConfig
from .modules.registry import TesterRegistry
from .modules.vulnerability_testers.base_tester_async import VulnerabilityTester
from .modules.web_mapper_async import WebMapperAsync

class WebSecurityScanner:
    """
    Main Scanner Class (Async).
    Orchestrates the scanning process, manages dependencies, and handles events.
    """
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.event_emitter = ScanEventEmitter()
        
        # Initialize Core
        core_config = ScanConfig(**self.config.get('core', {}))
        self.core = AsyncScannerCore(core_config)
        
        self.testers: List[VulnerabilityTester] = []
        self.mapper = WebMapperAsync(self.core)
        self._logger = logging.getLogger(__name__)
        
        # Subscribe mapper to vulnerabilities
        self.event_emitter.on(ScanEventType.VULNERABILITY_FOUND, self._on_vulnerability_found)

    def _on_vulnerability_found(self, **kwargs):
        """Collect vulnerabilities for the report."""
        vuln = kwargs.get('vulnerability')
        if vuln:
            # Adapt format if needed, but it seems compatible
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

    async def run_scan(self, target_url: str, profile: str = "balanced"):
        """
        Run the full scan against the target URL.
        """
        if not self.testers:
            await self.initialize()

        self._apply_profile(profile)
        
        await self.event_emitter.emit(ScanEventType.SCAN_START, url=target_url)
        await self.core.start()
        
        try:
            self._logger.info(f"Starting scan on {target_url} with profile: {profile}")
            
            # Create tasks for all testers
            tasks = []
            for tester in self.testers:
                if self._should_run_tester(tester, profile):
                    self._logger.debug(f"Scheduling {tester.name}")
                    tasks.append(self._run_tester_safe(tester, target_url))
            
            # Run all testers concurrently
            if tasks:
                await asyncio.gather(*tasks)
            else:
                self._logger.warning("No testers scheduled for this profile.")
            
            # Run Web Mapper
            self._logger.info("Generating web architecture map...")
            await self.event_emitter.emit(ScanEventType.PROGRESS_UPDATE, message="Mapping web architecture...")
            map_data = await self.mapper.map_website(target_url)
            report_path = self.mapper.generate_map(map_data)
            
            self._logger.info(f"Map generated at: {report_path}")
            await self.event_emitter.emit(ScanEventType.LOG_MESSAGE, message=f"Report generated: {report_path}")
            
        except Exception as e:
            self._logger.error(f"Scan failed: {e}")
            await self.event_emitter.emit(ScanEventType.ERROR, error=str(e))
        finally:
            await self.core.close()
            await self.event_emitter.emit(ScanEventType.SCAN_COMPLETE)
            self._logger.info("Scan complete")

    def _apply_profile(self, profile: str):
        """Apply scan profile settings."""
        # Update core config based on profile
        if profile == 'mapping':
            self.core.config.max_concurrency = 5
            self.core.config.timeout = 5
            # Update semaphore
            self.core._semaphore = asyncio.Semaphore(5)
        elif profile == 'quick':
            self.core.config.max_concurrency = 20
            self.core.config.timeout = 5
            self.core._semaphore = asyncio.Semaphore(20)
        elif profile == 'balanced':
            self.core.config.max_concurrency = 10
            self.core.config.timeout = 10
            self.core._semaphore = asyncio.Semaphore(10)
        elif profile == 'intense':
            self.core.config.max_concurrency = 50
            self.core.config.timeout = 15
            self.core._semaphore = asyncio.Semaphore(50)

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

    async def _run_tester_safe(self, tester: VulnerabilityTester, target_url: str):
        """Run a single tester with error handling."""
        try:
            await self.event_emitter.emit(ScanEventType.PROGRESS_UPDATE, message=f"Running {tester.name}...")
            await tester.run_test(target_url)
        except Exception as e:
            self._logger.error(f"Error in tester {tester.name}: {e}")
            await self.event_emitter.emit(ScanEventType.ERROR, error=f"{tester.name} failed: {str(e)}")

    def get_event_emitter(self) -> ScanEventEmitter:
        return self.event_emitter
