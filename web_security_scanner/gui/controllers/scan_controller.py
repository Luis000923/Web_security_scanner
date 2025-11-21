import asyncio
import threading
from typing import Callable, Any
from ...web_security_scanner_async import WebSecurityScanner
from ...events.event_emitter import ScanEventType

class ScanController:
    """
    Controller for the scanning process.
    Bridges the GUI and the Async Scanner.
    """
    def __init__(self, scanner: WebSecurityScanner):
        self.scanner = scanner
        self.view_callbacks = {}
        self._scan_thread = None
        self._loop = None
        
        # Subscribe to scanner events
        self.scanner.event_emitter.on(ScanEventType.SCAN_START, self._on_scan_start)
        self.scanner.event_emitter.on(ScanEventType.PROGRESS_UPDATE, self._on_progress)
        self.scanner.event_emitter.on(ScanEventType.VULNERABILITY_FOUND, self._on_vulnerability)
        self.scanner.event_emitter.on(ScanEventType.SCAN_COMPLETE, self._on_scan_complete)
        self.scanner.event_emitter.on(ScanEventType.ERROR, self._on_error)
        self.scanner.event_emitter.on(ScanEventType.LOG_MESSAGE, self._on_log)

    def set_callback(self, event_type: str, callback: Callable[..., Any]):
        """Register UI callbacks for events."""
        self.view_callbacks[event_type] = callback

    def start_scan(self, url: str, profile: str = "balanced"):
        """Start the scan in a separate thread."""
        if self._scan_thread and self._scan_thread.is_alive():
            return

        self._scan_thread = threading.Thread(target=self._run_async_scan, args=(url, profile), daemon=True)
        self._scan_thread.start()

    def _run_async_scan(self, url: str, profile: str):
        """Entry point for the scan thread."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self.scanner.run_scan(url, profile))
        self._loop.close()

    # Event Handlers (called from async loop, need to be thread-safe for UI)
    # In a real app, we might need to use queue or after() to update UI on main thread.
    # Here we assume the view handles thread safety or we use a helper.

    def _on_scan_start(self, **kwargs):
        if 'on_start' in self.view_callbacks:
            self.view_callbacks['on_start'](kwargs.get('url'))

    def _on_progress(self, **kwargs):
        if 'on_progress' in self.view_callbacks:
            self.view_callbacks['on_progress'](kwargs.get('message'))

    def _on_vulnerability(self, **kwargs):
        if 'on_vulnerability' in self.view_callbacks:
            self.view_callbacks['on_vulnerability'](kwargs.get('vulnerability'))

    def _on_scan_complete(self, **kwargs):
        if 'on_complete' in self.view_callbacks:
            self.view_callbacks['on_complete']()

    def _on_error(self, **kwargs):
        if 'on_error' in self.view_callbacks:
            self.view_callbacks['on_error'](kwargs.get('error'))

    def _on_log(self, **kwargs):
        if 'on_log' in self.view_callbacks:
            self.view_callbacks['on_log'](kwargs.get('message'))
