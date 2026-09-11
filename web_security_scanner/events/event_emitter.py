import asyncio
import logging
from collections.abc import Callable
from enum import Enum, auto
from typing import Any


class ScanEventType(Enum):
    SCAN_START = auto()
    PROGRESS_UPDATE = auto()
    URL_SCANNED = auto()
    VULNERABILITY_FOUND = auto()
    SCAN_COMPLETE = auto()
    ERROR = auto()
    LOG_MESSAGE = auto()
    # Emitted once per candidate finding that reached the LLM triage agent
    # (``--enable-ai-triaging``), whether the agent kept or dropped it. Carries
    # a ``decision`` dict so the orchestrator can build an audit trail of the
    # agent's false-positive suppressions / false-negative risk for the report.
    AI_TRIAGE_DECISION = auto()
    # Emitted once per non-destructive Proof-of-Impact probe the adaptive
    # exploitation engine (``--enable-exploit-engine``,
    # ``modules.exploit_engine.ExploitEngine``) attempts, whatever its
    # classification. Carries an ``attempt`` dict (``ExploitAttempt.to_dict()``)
    # so the orchestrator can build the scan's exploitation audit trail.
    EXPLOIT_ATTEMPT = auto()

class ScanEventEmitter:
    """
    Event emitter for the Web Security Scanner.
    Decouples the scanning logic from the UI/CLI.
    """
    def __init__(self):
        self._listeners: dict[ScanEventType, list[Callable[..., Any]]] = {
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
