"""
Core module for Web Security Scanner.

Contains the async scanner core (connection pooling, token-bucket rate
limiting, response caching, User-Agent rotation, SSRF-safe redirects) and the
bounded worker-pool helper.
"""

from .scanner_core_async import (
    AsyncResponseCache,
    AsyncScannerCore,
    ScanConfig,
    SSRFRedirectError,
    TokenBucket,
    worker_pool,
)
from .telemetry_async import TelemetryWorker

__all__ = [
    'AsyncScannerCore',
    'AsyncResponseCache',
    'ScanConfig',
    'SSRFRedirectError',
    'TelemetryWorker',
    'TokenBucket',
    'worker_pool',
]
