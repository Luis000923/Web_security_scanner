"""Reconnaissance layer.

Ports the advanced recon capabilities of ``route-mapper`` into the async
scanner:

* :func:`extract_js_endpoints` - lexical mining of absolute paths embedded in
  JavaScript bundles (never executes or interprets the script).
* :func:`parse_sitemap` - XXE / XML-bomb hardened ``sitemap.xml`` parser.
* :class:`ScopeEngine` - strict host scoping plus the pre-flight DNS/IP SSRF
  filter (third layer of the anti-SSRF defence).
* :class:`AsyncRobotsPolicy` - async ``robots.txt`` compliance with
  ``Crawl-delay`` support, routed through the scanner core so the existing
  SSRF guard covers the fetch.
* :class:`ReconEngine` / :class:`ReconConfig` - Phase 1 orchestrator that feeds
  the discovered URLs and parameters to the vulnerability testers.
"""

from .browser_engine import (
    DOM_XSS_CANARY,
    MONITORED_SINKS,
    BrowserRecon,
    BrowserReconResult,
    DomXssFinding,
)
from .js_miner import extract_js_endpoints
from .recon_engine import ReconConfig, ReconEngine, ReconResult
from .robots_async import AsyncRobotsPolicy
from .scope_engine import (
    ScopeEngine,
    ScopeViolation,
    SsrfViolation,
    is_blocked_ip,
    is_valid_subdomain,
    normalize_url,
)
from .sitemap import parse_sitemap

__all__ = [
    "AsyncRobotsPolicy",
    "BrowserRecon",
    "BrowserReconResult",
    "DOM_XSS_CANARY",
    "DomXssFinding",
    "MONITORED_SINKS",
    "ReconConfig",
    "ReconEngine",
    "ReconResult",
    "ScopeEngine",
    "ScopeViolation",
    "SsrfViolation",
    "extract_js_endpoints",
    "is_blocked_ip",
    "is_valid_subdomain",
    "normalize_url",
    "parse_sitemap",
]
