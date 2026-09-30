"""Attack-surface correlation and Risk/Value prioritization.

Phase 1 recon (``WebMapperAsync`` / ``ReconEngine``) already discovers URLs,
query parameters, HTML forms and coarse technology hints (see
``WebMapperAsync._analyze_structure`` and ``TechnologyDetector``), but hands
them to the Phase 2 testers as a flat, discovery-order queue
(``get_scan_targets``): a throwaway ``/about`` page and an unauthenticated
``/wp-content/plugins/.../ajax.php`` endpoint are treated identically.

This module closes that gap. :class:`SurfaceCorrelator` re-reads the same
recon artifacts (crawled URLs, forms, discovered query parameters, detected
technologies and JS-mined "hidden" endpoints) and:

* classifies every discovered URL into one or more attack-surface categories
  - admin panel, file-upload endpoint, API/GraphQL endpoint, authentication
    endpoint, known-vulnerable-framework path, or exposed sensitive file;
* assigns a Risk/Value score (0-100) built from the category's base weight
  plus signal-strength modifiers (query-param count, presence of a POST
  form and its input surface, a fingerprint-confirmed vulnerable component,
  or an endpoint that only JavaScript mining turned up); and
* buckets the score into a human-facing priority label
  (CRITICAL/HIGH/MEDIUM/LOW/INFO).

``ReconEngine`` uses the sorted output both to reorder the Phase 2 attack
queue (highest Risk/Value first, so a bounded ``max_duration`` scan spends
its budget on the endpoints most worth attacking) and to render a
"Attack Surface Priority" section in the recon HTML report.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

# --- Categories -------------------------------------------------------------

ADMIN_PANEL = "admin_panel"
FILE_UPLOAD = "file_upload"
API_ENDPOINT = "api_endpoint"
AUTH_ENDPOINT = "auth_endpoint"
VULNERABLE_FRAMEWORK = "vulnerable_framework"
SENSITIVE_FILE = "sensitive_file"
FORM_ENDPOINT = "form_endpoint"
GENERIC = "generic"

# Declaration order doubles as the tie-break preference used when a URL's
# evidence lines are rendered (most specific / highest-risk first).
SURFACE_CATEGORIES = (
    SENSITIVE_FILE,
    VULNERABLE_FRAMEWORK,
    ADMIN_PANEL,
    FILE_UPLOAD,
    AUTH_ENDPOINT,
    API_ENDPOINT,
    FORM_ENDPOINT,
    GENERIC,
)

PRIORITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Base Risk/Value weight per category - the single highest-weighted category
# a URL matches sets its score floor before the additive modifiers below.
_CATEGORY_WEIGHT: dict[str, int] = {
    SENSITIVE_FILE: 75,
    VULNERABLE_FRAMEWORK: 55,
    ADMIN_PANEL: 50,
    FILE_UPLOAD: 45,
    AUTH_ENDPOINT: 35,
    API_ENDPOINT: 25,
    FORM_ENDPOINT: 15,
    GENERIC: 5,
}

# Path-keyword signatures. Matched case-insensitively against the URL path
# only (never the query string, to keep false positives low).
_ADMIN_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"/wp-admin", r"/wp-login", r"/administrator", r"/admin(?:/|$)",
    r"/cpanel", r"/phpmyadmin", r"/pma(?:/|$)", r"/manage(?:ment)?(?:/|$)",
    r"/dashboard", r"/console", r"/backend", r"/moderator",
))

_FILE_UPLOAD_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"/upload", r"/file[-_]?upload", r"/import(?:/|$)", r"/attachment",
    r"/avatar", r"/media/upload", r"/add[-_]?file", r"/fileman",
))

_API_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"/api/", r"/rest/", r"/graphql", r"/v\d+/", r"/swagger", r"/openapi",
    r"\.json$", r"/odata/", r"/soap/",
))

_AUTH_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"/login", r"/signin", r"/sign-in", r"/auth(?:/|$)", r"/oauth",
    r"/sso(?:/|$)", r"/register", r"/signup", r"/sign-up",
    r"/password/reset", r"/forgot[-_]?password",
))

_SENSITIVE_FILE_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"\.env$", r"/\.git/", r"\.sql$", r"\.bak$", r"\.old$", r"\.zip$",
    r"\.tar\.gz$", r"\.swp$", r"web\.config$", r"\.ds_store$", r"id_rsa$",
    r"\.pem$", r"config\.php\.bak", r"settings\.py$", r"/\.env\.",
))

# Endpoints that are inherently high-risk regardless of any fingerprinted
# technology - well-known default management interfaces / debug consoles.
_ALWAYS_VULNERABLE_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"/manager/html", r"/jmx-console", r"/actuator(?:/|$)",
    r"/jenkins/script", r"/solr/admin", r"/_profiler/", r"/debug/default/view",
    r"/console/login", r"/geoserver/web",
))

# Technology-name -> path signatures for known-vulnerable-component paths.
# Only applied when the corresponding technology was fingerprinted for the
# URL's domain (see ``technologies`` in ``correlate``), so a coincidental
# ``/wp-content/`` string on a non-WordPress site never fires this.
_TECH_VULNERABLE_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "WordPress": tuple(re.compile(p, re.IGNORECASE) for p in (
        r"/wp-content/plugins/", r"/wp-content/themes/", r"/xmlrpc\.php",
    )),
    "Joomla": tuple(re.compile(p, re.IGNORECASE) for p in (
        r"/administrator/components/", r"/components/com_",
    )),
    "Drupal": tuple(re.compile(p, re.IGNORECASE) for p in (
        r"/changelog\.txt$", r"/user/login", r"/node/\d+/edit",
    )),
    "Jenkins": tuple(re.compile(p, re.IGNORECASE) for p in (r"/jenkins/",)),
    "Apache Struts": tuple(re.compile(p, re.IGNORECASE) for p in (
        r"\.action$", r"\.do$",
    )),
    "Apache Solr": tuple(re.compile(p, re.IGNORECASE) for p in (r"/solr/",)),
}


@dataclass(frozen=True)
class PrioritizedTarget:
    """A recon-discovered URL with its attack-surface classification."""

    url: str
    categories: tuple[str, ...]
    score: float
    priority: str
    evidence: tuple[str, ...] = ()
    param_count: int = 0
    form_count: int = 0
    hidden: bool = False


def _score_to_priority(score: float) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "INFO"


def _classify_path(path: str) -> tuple[set[str], list[str]]:
    """Path-keyword classification only (no forms/params/tech signal)."""
    categories: set[str] = set()
    evidence: list[str] = []

    for label, patterns in (
        (SENSITIVE_FILE, _SENSITIVE_FILE_PATTERNS),
        (ADMIN_PANEL, _ADMIN_PATTERNS),
        (FILE_UPLOAD, _FILE_UPLOAD_PATTERNS),
        (AUTH_ENDPOINT, _AUTH_PATTERNS),
        (API_ENDPOINT, _API_PATTERNS),
    ):
        for pattern in patterns:
            if pattern.search(path):
                categories.add(label)
                evidence.append(f"path matches {label} pattern: {pattern.pattern}")
                break

    for pattern in _ALWAYS_VULNERABLE_PATTERNS:
        if pattern.search(path):
            categories.add(VULNERABLE_FRAMEWORK)
            evidence.append(f"known exposed management endpoint: {pattern.pattern}")
            break

    return categories, evidence


class SurfaceCorrelator:
    """Groups and ranks recon-discovered URLs by attack-surface Risk/Value."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._log = logger or logging.getLogger(__name__)

    def correlate(
        self,
        urls: Any,
        *,
        forms: Any = (),
        params_by_url: dict[str, list[str]] | None = None,
        technologies: dict[str, list[dict[str, Any]]] | None = None,
        hidden_urls: Any = (),
    ) -> list[PrioritizedTarget]:
        """Classify and score every URL in ``urls``.

        Args:
            urls: Discovered URLs to correlate (typically
                ``WebMapperAsync.get_scan_targets()`` output).
            forms: ``site_structure['forms']`` entries
                (``{'url', 'action', 'method', 'inputs'}``).
            params_by_url: ``WebMapperAsync.discovered_params``
                (normalized URL -> query-param names).
            technologies: ``map_data['technologies']``
                (domain -> list of ``{'name', 'type', 'confidence', ...}``).
            hidden_urls: URLs only surfaced via JavaScript mining / the
                headless-browser pass, never linked from crawled HTML - a
                signal of deliberately unadvertised (shadow) endpoints.

        Returns:
            One :class:`PrioritizedTarget` per input URL, sorted by
            descending score (ties broken alphabetically for determinism).
        """
        params_by_url = params_by_url or {}
        technologies = technologies or {}
        hidden = set(hidden_urls)

        forms_by_url: dict[str, list[dict[str, Any]]] = {}
        for form in forms or ():
            forms_by_url.setdefault(str(form.get("url", "")), []).append(form)

        results: list[PrioritizedTarget] = []
        for url in urls:
            results.append(self._classify_one(
                url, forms_by_url, params_by_url, technologies, hidden,
            ))

        results.sort(key=lambda t: (-t.score, t.url))
        return results

    def _classify_one(
        self,
        url: str,
        forms_by_url: dict[str, list[dict[str, Any]]],
        params_by_url: dict[str, list[str]],
        technologies: dict[str, list[dict[str, Any]]],
        hidden: set[str],
    ) -> PrioritizedTarget:
        parsed = urlparse(url)
        path = parsed.path or "/"
        domain = parsed.netloc

        categories, evidence = _classify_path(path)

        # Technology-confirmed vulnerable-component paths.
        tech_confirmed = False
        detected_names = {
            str(t.get("name", "")) for t in technologies.get(domain, [])
        }
        for tech_name, patterns in _TECH_VULNERABLE_PATTERNS.items():
            if tech_name not in detected_names:
                continue
            for pattern in patterns:
                if pattern.search(path):
                    categories.add(VULNERABLE_FRAMEWORK)
                    evidence.append(
                        f"path matches known {tech_name} component "
                        f"(fingerprint-confirmed): {pattern.pattern}"
                    )
                    tech_confirmed = True
                    break

        params = params_by_url.get(url, [])
        page_forms = forms_by_url.get(url, [])
        has_post_form = any(
            str(f.get("method", "GET")).upper() == "POST" for f in page_forms
        )
        total_inputs = sum(int(f.get("inputs", 0) or 0) for f in page_forms)
        is_hidden = url in hidden

        if not categories:
            if page_forms:
                categories.add(FORM_ENDPOINT)
                evidence.append(f"{len(page_forms)} HTML form(s) found on page")
            else:
                categories.add(GENERIC)
        elif page_forms:
            evidence.append(f"{len(page_forms)} HTML form(s) found on page")

        if params:
            evidence.append(f"{len(params)} query parameter(s): {', '.join(params)}")
        if is_hidden:
            evidence.append("only discovered via JS mining / browser pass (shadow endpoint)")

        base = max(_CATEGORY_WEIGHT[c] for c in categories)
        param_bonus = min(len(params) * 4, 20)
        form_bonus = 10 if has_post_form else (4 if page_forms else 0)
        input_bonus = min(total_inputs * 3, 15)
        tech_bonus = 15 if tech_confirmed else 0
        hidden_bonus = 10 if is_hidden else 0

        score = min(
            100.0,
            base + param_bonus + form_bonus + input_bonus + tech_bonus + hidden_bonus,
        )

        ordered_categories = tuple(c for c in SURFACE_CATEGORIES if c in categories)
        return PrioritizedTarget(
            url=url,
            categories=ordered_categories,
            score=score,
            priority=_score_to_priority(score),
            evidence=tuple(evidence),
            param_count=len(params),
            form_count=len(page_forms),
            hidden=is_hidden,
        )

    @staticmethod
    def summarize(targets: list[PrioritizedTarget]) -> dict[str, int]:
        """Count targets per priority level, e.g. for report statistics."""
        counts = dict.fromkeys(PRIORITY_LEVELS, 0)
        for t in targets:
            counts[t.priority] = counts.get(t.priority, 0) + 1
        return counts
