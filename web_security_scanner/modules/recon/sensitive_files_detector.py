"""Sensitive-asset discovery: active probing for exposed config/backup/VCS files.

Phase 1 recon (``WebMapperAsync``) already discovers the site's directory
structure from crawled links; this module takes those base paths (plus the
site root) and actively probes a curated catalog of high-risk filenames
(``.env``, ``.git/HEAD``, database dumps, ``web.config``, ...) under each one.

Every probe is a plain, non-destructive ``GET`` issued through the injected
``AsyncScannerCore`` (rate limiting, SSRF guarding and UA rotation are
inherited for free). To keep the false-positive rate low, a request is only
reported as a genuine exposure when it survives a **soft-404 check**: a
baseline request for a random, guaranteed-nonexistent path is fetched first,
and any candidate whose status code and response body match that baseline
(a custom "not found" page served with HTTP 200) is discarded rather than
reported.

Findings feed :class:`~.surface_correlator.SurfaceCorrelator` by having their
URLs merged into the recon candidate pool (see ``ReconEngine._run_sensitive_files``)
so they are picked up by the existing ``sensitive_file`` category, and are also
converted into the scanner's standard vulnerability-report shape via
:meth:`SensitiveFileFinding.to_vulnerability`.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from ...wordlists import load_wordlist

# --- Catalog ------------------------------------------------------------

RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"


@dataclass(frozen=True)
class SensitiveFileSpec:
    """One entry of the built-in high-confidence sensitive-file catalog."""

    path: str
    risk: str
    category: str
    description: str


# Curated, high-confidence entries. Risk is fixed per asset class rather than
# derived from a generic weight so ".env" (credentials) and a generic backup
# archive are never conflated - both land on CRITICAL/HIGH as required, never
# lower.
SENSITIVE_FILE_CATALOG: tuple[SensitiveFileSpec, ...] = (
    # --- credentials / secrets ------------------------------------------
    SensitiveFileSpec(".env", RISK_CRITICAL, "credentials",
                       "Environment variable dump (DB/API credentials)"),
    SensitiveFileSpec(".env.local", RISK_CRITICAL, "credentials",
                       "Environment variable dump (DB/API credentials)"),
    SensitiveFileSpec(".env.production", RISK_CRITICAL, "credentials",
                       "Production environment variable dump"),
    SensitiveFileSpec(".env.backup", RISK_CRITICAL, "credentials",
                       "Backed-up environment variable dump"),
    SensitiveFileSpec("id_rsa", RISK_CRITICAL, "credentials", "Private SSH key"),
    SensitiveFileSpec("id_rsa.pub", RISK_HIGH, "credentials", "SSH public key (recon value)"),
    SensitiveFileSpec("credentials.json", RISK_CRITICAL, "credentials",
                       "Serialized credentials/service-account file"),
    SensitiveFileSpec(".npmrc", RISK_HIGH, "credentials",
                       "npm config that may embed a registry auth token"),
    # --- version-control metadata ---------------------------------------
    SensitiveFileSpec(".git/HEAD", RISK_CRITICAL, "vcs",
                       "Exposed .git repository (full source disclosure risk)"),
    SensitiveFileSpec(".git/config", RISK_CRITICAL, "vcs",
                       "Exposed .git repository configuration"),
    SensitiveFileSpec(".svn/entries", RISK_HIGH, "vcs", "Exposed Subversion working-copy metadata"),
    SensitiveFileSpec(".hg/store/00manifest.i", RISK_HIGH, "vcs", "Exposed Mercurial repository metadata"),
    # --- server / application configuration ------------------------------
    SensitiveFileSpec("web.config", RISK_HIGH, "server-config",
                       "IIS configuration (may leak connection strings)"),
    SensitiveFileSpec("config.json", RISK_HIGH, "server-config", "Application configuration file"),
    SensitiveFileSpec("appsettings.json", RISK_HIGH, "server-config", ".NET application configuration"),
    SensitiveFileSpec("settings.py", RISK_HIGH, "server-config", "Django settings (SECRET_KEY exposure risk)"),
    SensitiveFileSpec("wp-config.php.bak", RISK_CRITICAL, "server-config",
                       "WordPress database credentials backup"),
    SensitiveFileSpec("docker-compose.yml", RISK_HIGH, "server-config",
                       "Docker Compose file (may embed secrets/ports)"),
    # --- database / site backups ----------------------------------------
    SensitiveFileSpec("backup.sql", RISK_CRITICAL, "backup", "Full database dump"),
    SensitiveFileSpec("dump.sql", RISK_CRITICAL, "backup", "Full database dump"),
    SensitiveFileSpec("db.sqlite3", RISK_CRITICAL, "backup", "SQLite database file"),
    SensitiveFileSpec("database.sql.gz", RISK_CRITICAL, "backup", "Compressed database dump"),
    SensitiveFileSpec("backup.zip", RISK_HIGH, "backup", "Generic site/database backup archive"),
    SensitiveFileSpec("site-backup.tar.gz", RISK_HIGH, "backup", "Generic site backup archive"),
)

# Body-content markers used to upgrade a HIGH-confidence hit to CONFIRMED once
# the response body itself corroborates the file type (defends against a
# generic soft-404 page that happened to slip past the baseline comparison).
_CONTENT_CONFIRMERS: tuple[tuple[re.Pattern[str], re.Pattern[str]], ...] = (
    (re.compile(r"\.git/HEAD$"), re.compile(r"^\s*(ref:\s*refs/|[0-9a-f]{40}\b)", re.IGNORECASE)),
    (re.compile(r"\.git/config$"), re.compile(r"\[core]", re.IGNORECASE)),
    (re.compile(r"\.env(\.|$)"), re.compile(r"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=")),
    (re.compile(r"id_rsa$|\.pem$"), re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE)),
    (re.compile(r"\.sql(\.gz)?$|dump|backup"), re.compile(r"insert into|create table", re.IGNORECASE)),
)


@dataclass(frozen=True)
class SensitiveFileFinding:
    """One confirmed (soft-404-filtered) sensitive-asset exposure."""

    url: str
    path: str
    risk: str
    category: str
    status_code: int
    content_length: int
    confidence: str
    evidence: str

    def to_vulnerability(self) -> dict[str, Any]:
        """Render into the scanner's ``VULNERABILITY_FOUND`` payload shape."""
        severity = "Critical" if self.risk == RISK_CRITICAL else "High"
        return {
            "type": "Sensitive File Exposure",
            "name": f"Exposed sensitive file: {self.path}",
            "url": self.url,
            "parameter": self.path,
            "payload": "N/A",
            "severity": severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "detector": "sensitive-files",
        }


@dataclass
class SensitiveFileDetectionResult:
    """Aggregate output of a :meth:`SensitiveFileDetector.detect` pass."""

    findings: list[SensitiveFileFinding] = field(default_factory=list)
    probed: int = 0
    baseline_established: bool = False


@dataclass
class _Baseline:
    status_code: int
    normalized_body: str


def _normalize_body(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()[:4000]


def _looks_like_baseline(resp: dict[str, Any], baseline: _Baseline | None) -> bool:
    """True when ``resp`` is indistinguishable from the soft-404 baseline."""
    if baseline is None:
        return False
    if int(resp.get("status_code", 0) or 0) != baseline.status_code:
        return False
    normalized = _normalize_body(str(resp.get("text", "") or ""))
    if normalized == baseline.normalized_body:
        return True
    base_len = len(baseline.normalized_body)
    tolerance = max(24, int(base_len * 0.05))
    return abs(len(normalized) - base_len) <= tolerance


def _confirms_content(path: str, text: str) -> bool:
    """True when the response body itself corroborates the expected file type."""
    sample = text[:4000]
    for path_pattern, body_pattern in _CONTENT_CONFIRMERS:
        if path_pattern.search(path) and body_pattern.search(sample):
            return True
    return False


def _dir_url(url: str) -> str:
    """Normalize ``url`` to a directory URL (scheme://netloc/path/)."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/" if "/" in path else "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


class SensitiveFileDetector:
    """Probes a base URL (and its discovered sub-paths) for exposed assets."""

    def __init__(
        self,
        scanner_core: Any,
        *,
        extra_names: list[str] | None = None,
        max_base_paths: int = 6,
        max_concurrent: int = 8,
        max_probes: int = 400,
        logger: logging.Logger | None = None,
    ) -> None:
        self.scanner = scanner_core
        self.max_base_paths = max(1, max_base_paths)
        self.max_concurrent = max(1, max_concurrent)
        self.max_probes = max(1, max_probes)
        self._log = logger or logging.getLogger(__name__)
        self._extra_names = (
            list(extra_names) if extra_names is not None else load_wordlist("sensitive_files")
        )

    def _build_directories(self, base_url: str, base_paths: Any) -> list[str]:
        root = _dir_url(base_url)
        directories = [root]
        seen = {root}
        for raw in base_paths or ():
            candidate = _dir_url(urljoin(root, str(raw).lstrip("/") + "/"))
            if candidate in seen:
                continue
            seen.add(candidate)
            directories.append(candidate)
            if len(directories) >= self.max_base_paths:
                break
        return directories

    def _build_candidates(self, directories: list[str]) -> list[tuple[str, SensitiveFileSpec]]:
        specs = list(SENSITIVE_FILE_CATALOG) + [
            SensitiveFileSpec(name, RISK_HIGH, "wordlist", "Wordlist-derived sensitive path")
            for name in self._extra_names
        ]
        out: list[tuple[str, SensitiveFileSpec]] = []
        seen_urls: set[str] = set()
        for directory in directories:
            for spec in specs:
                url = urljoin(directory, spec.path)
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                out.append((url, spec))
                if len(out) >= self.max_probes:
                    return out
        return out

    async def _probe_baseline(self, root_url: str) -> _Baseline | None:
        nonce = uuid.uuid4().hex[:20]
        probe_url = urljoin(root_url, f"__wss_soft404_check_{nonce}__")
        try:
            resp = await self.scanner.request("GET", probe_url, use_cache=False)
        except Exception as exc:  # noqa: BLE001 - baseline is best-effort
            self._log.debug(f"Sensitive-file soft-404 baseline probe failed: {exc}")
            return None
        return _Baseline(
            status_code=int(resp.get("status_code", 0) or 0),
            normalized_body=_normalize_body(str(resp.get("text", "") or "")),
        )

    async def _probe_one(
        self, url: str, spec: SensitiveFileSpec, baseline: _Baseline | None
    ) -> SensitiveFileFinding | None:
        try:
            resp = await self.scanner.request("GET", url, use_cache=False)
        except Exception as exc:  # noqa: BLE001 - one bad probe must not abort the sweep
            self._log.debug(f"Sensitive-file probe failed for {url}: {exc}")
            return None

        status = int(resp.get("status_code", 0) or 0)
        if status in (404, 410) or status == 0 or status >= 500:
            return None
        if status in (401, 403):
            return SensitiveFileFinding(
                url=url, path=spec.path, risk=spec.risk, category=spec.category,
                status_code=status, content_length=len(str(resp.get("text", "") or "")),
                confidence="MEDIUM",
                evidence=(f"{spec.description} - path exists but access is restricted "
                          f"(HTTP {status})."),
            )
        if not (200 <= status < 400):
            return None
        if _looks_like_baseline(resp, baseline):
            return None

        text = str(resp.get("text", "") or "")
        confirmed = _confirms_content(spec.path, text)
        return SensitiveFileFinding(
            url=url, path=spec.path, risk=spec.risk, category=spec.category,
            status_code=status, content_length=len(text),
            confidence="CONFIRMED" if confirmed else "HIGH",
            evidence=(f"{spec.description} - exposed at HTTP {status}"
                      f"{' (body content confirms file type)' if confirmed else ''}."),
        )

    async def detect(
        self, base_url: str, *, base_paths: Any = ()
    ) -> SensitiveFileDetectionResult:
        """Probe ``base_url`` and its discovered sub-directories for exposed assets."""
        directories = self._build_directories(base_url, base_paths)
        baseline = await self._probe_baseline(directories[0])
        candidates = self._build_candidates(directories)

        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def _guarded(url: str, spec: SensitiveFileSpec) -> SensitiveFileFinding | None:
            async with semaphore:
                return await self._probe_one(url, spec, baseline)

        outcomes = await asyncio.gather(
            *(_guarded(url, spec) for url, spec in candidates), return_exceptions=True
        )
        findings: list[SensitiveFileFinding] = []
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                continue
            if outcome is not None:
                findings.append(outcome)

        return SensitiveFileDetectionResult(
            findings=findings, probed=len(candidates), baseline_established=baseline is not None,
        )
