from typing import Callable, Dict, List, Any, Awaitable, Union
from enum import Enum, auto
import asyncio
import logging

class ScanEventType(Enum):
    SCAN_START = auto()
    PROGRESS_UPDATE = auto()
    VULNERABILITY_FOUND = auto()
    SCAN_COMPLETE = auto()
    ERROR = auto()
    LOG_MESSAGE = auto()

class ScanEventEmitter:
    """
    Event emitter for the Web Security Scanner.
    Decouples the scanning logic from the UI/CLI.
    """
    def __init__(self):
        self._listeners: Dict[ScanEventType, List[Callable[..., Any]]] = {
            event_type: [] for event_type in ScanEventType
        }
        self._logger = logging.getLogger(__name__)

    def on(self, event_type: ScanEventType, callback: Callable[..., Any]):
        """Subscribe to an event."""
        if event_type not in self._listeners:
            self._listeners[event_type] = []
        self._listeners[event_type].append(callback)

    async def emit(self, event_type: ScanEventType, **kwargs):
        """Emit an event asynchronously."""
        if event_type in self._listeners:
            for callback in self._listeners[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(**kwargs)
                    else:
                        callback(**kwargs)
                except Exception as e:
                    self._logger.error(f"Error in event listener for {event_type}: {e}")

    def emit_sync(self, event_type: ScanEventType, **kwargs):
        """Emit an event synchronously (fire and forget for async listeners)."""
        if event_type in self._listeners:
            for callback in self._listeners[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        # Schedule async callback in the running loop if possible
                        try:
                            loop = asyncio.get_running_loop()
                            loop.create_task(callback(**kwargs))
                        except RuntimeError:
                            # No running loop
                            pass 
                    else:
                        callback(**kwargs)
                except Exception as e:
                    self._logger.error(f"Error in event listener for {event_type}: {e}")
