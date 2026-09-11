"""Infrastructure fingerprinting and active vulnerability-advisory verification.

Parses the ``Server`` / ``X-Powered-By`` / ``Via`` response headers into
``(product, version)`` pairs and cross-references them against a small
built-in advisory catalog.

Two very different confidence tiers come out of that cross-reference:

* **Banner-only** advisories (e.g. an outdated Apache below a known-fixed
  version) are reported at ``LOW``/``MEDIUM`` confidence - a banner string is
  operator-controlled and easy to spoof or leave stale after patching, so
  these are informational leads, not proof.
* **Actively-verified** advisories carry a non-destructive **Safe PoC Probe**
  that must independently confirm the condition before anything is reported
  at all. The flagship example is CVE-2015-1635 / MS15-034: the IIS/HTTP.sys
  banner version alone cannot prove (or disprove) whether the OS-level hotfix
  is installed, since the patch does not change the IIS version string. A
  crafted ``Range: bytes=0-18446744073709551615`` request against any
  resource on the site is the standard, single-request, non-destructive
  differential check documented by public scanners (Nmap's
  ``http-vuln-cve2015-1635``): an unpatched ``HTTP.sys`` answers ``416
  Requested Range Not Satisfiable`` (the malformed range was parsed by the
  vulnerable integer-overflow code path), while a patched one answers ``400
  Bad Request`` before ever reaching it. Anything else is inconclusive and is
  **not** reported - this module never turns a bare version-matching banner
  into a "vulnerable" verdict on its own.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

# Bounded so a hostile server can't feed us a pathological header value.
_MAX_HEADER_VALUE = 512

# "<product>/<version>" tokens, e.g. "Apache/2.4.49", "nginx/1.18.0",
# "Microsoft-IIS/8.5", "PHP/7.2.24", "(Varnish/6.6)".
_PRODUCT_VERSION_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9._-]*)\s*/\s*([0-9]+(?:\.[0-9]+){0,3}[A-Za-z0-9.-]*)"
)

_HEADERS_OF_INTEREST = ("server", "x-powered-by", "via")

# The classic, publicly-documented safe differential probe for MS15-034.
_MS15_034_RANGE_HEADER = "bytes=0-18446744073709551615"


def _ci_headers(headers: Any) -> dict[str, str]:
    """Collapse a header mapping into a lower-cased ``{name: value}`` dict."""
    out: dict[str, str] = {}
    try:
        items = headers.items()
    except AttributeError:
        items = []
    for k, v in items:
        out[str(k).strip().lower()] = str(v).strip()[:_MAX_HEADER_VALUE]
    return out


def _parse_product_versions(raw: str) -> list[tuple[str, str]]:
    """Extract every ``product/version`` pair from a banner-style header value."""
    return [(m.group(1), m.group(2)) for m in _PRODUCT_VERSION_RE.finditer(raw[:_MAX_HEADER_VALUE])]


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts) or (0,)


def _version_lt(a: str, b: str) -> bool:
    return _version_tuple(a) < _version_tuple(b)


@dataclass(frozen=True)
class ServerFingerprint:
    """One ``product/version`` pair extracted from a response header."""

    header: str
    raw_value: str
    product: str
    version: str
    evidence: str


@dataclass(frozen=True)
class PocFinding:
    """A version advisory match, optionally confirmed by an active probe."""

    cve_id: str
    name: str
    product: str
    version: str | None
    severity: str
    confidence: str
    evidence: str
    poc_method: str

    def to_vulnerability(self, url: str) -> dict[str, Any]:
        """Render into the scanner's ``VULNERABILITY_FOUND`` payload shape."""
        return {
            "type": "Vulnerable Server Component",
            "name": self.name,
            "url": url,
            "parameter": self.cve_id,
            "payload": "N/A",
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "detector": "server-fingerprint",
            "cve_id": self.cve_id,
            "product": self.product,
            "version": self.version,
        }


@dataclass
class ServerFingerprintResult:
    """Aggregate output of a :meth:`ServerFingerprinter.fingerprint` pass."""

    url: str
    fingerprints: list[ServerFingerprint] = field(default_factory=list)
    findings: list[PocFinding] = field(default_factory=list)

    def to_vulnerabilities(self) -> list[dict[str, Any]]:
        return [finding.to_vulnerability(self.url) for finding in self.findings]


@dataclass(frozen=True)
class VersionAdvisory:
    """One advisory catalog entry for a fingerprinted ``product``."""

    cve_id: str
    name: str
    severity: str
    # Banner-only path: flagged when the fingerprinted version is strictly
    # below this (the first fixed release). Mutually exclusive with
    # ``exact_versions``/``requires_active_probe``.
    fixed_version: str | None = None
    # Active-probe path: candidate versions that *may* be vulnerable but
    # cannot be confirmed from the banner alone (e.g. an OS-level hotfix that
    # never changes the banner). Only ever reported via a successful
    # ``ServerFingerprinter._verify`` call - never as a banner-only guess.
    exact_versions: tuple[str, ...] = ()
    requires_active_probe: bool = False


_ADVISORIES: dict[str, tuple[VersionAdvisory, ...]] = {
    "Apache": (
        VersionAdvisory(
            "CVE-2021-41773", "Apache HTTP Server path traversal / source disclosure",
            "Critical", fixed_version="2.4.51",
        ),
    ),
    "nginx": (
        VersionAdvisory(
            "CVE-2019-20372", "nginx error_page request-smuggling",
            "Medium", fixed_version="1.17.7",
        ),
    ),
    "Microsoft-IIS": (
        VersionAdvisory(
            "CVE-2015-1635", "MS15-034 HTTP.sys integer-overflow remote code execution / DoS",
            "Critical", exact_versions=("7.5", "8.0", "8.5"), requires_active_probe=True,
        ),
    ),
}


class ServerFingerprinter:
    """Fingerprints server/framework headers and verifies known advisories."""

    def __init__(
        self,
        scanner_core: Any,
        *,
        enable_active_probes: bool = True,
        logger: logging.Logger | None = None,
    ) -> None:
        self.scanner = scanner_core
        self.enable_active_probes = enable_active_probes
        self._log = logger or logging.getLogger(__name__)

    def _parse_headers(self, headers: dict[str, str]) -> list[ServerFingerprint]:
        fingerprints: list[ServerFingerprint] = []
        for header_name in _HEADERS_OF_INTEREST:
            raw = headers.get(header_name)
            if not raw:
                continue
            for product, version in _parse_product_versions(raw):
                fingerprints.append(ServerFingerprint(
                    header=header_name, raw_value=raw, product=product, version=version,
                    evidence=f"{header_name}: {raw}",
                ))
        return fingerprints

    async def _verify(self, adv: VersionAdvisory, base_url: str) -> PocFinding | None:
        if adv.cve_id == "CVE-2015-1635":
            return await self._verify_ms15_034(base_url)
        return None

    async def _verify_ms15_034(self, base_url: str) -> PocFinding | None:
        """Safe, single-request differential probe for CVE-2015-1635 / MS15-034.

        ``HTTP.sys`` parses the ``Range`` header at the kernel driver level
        before IIS even resolves the requested resource, so any URL on the
        site works - including the site root. This never sends the
        multi-range payload sequence associated with the original crash PoCs;
        a single malformed-but-well-formed ``Range`` header is enough to
        distinguish the two code paths without risking a denial of service.
        """
        try:
            resp = await self.scanner.request(
                "GET", base_url, headers={"Range": _MS15_034_RANGE_HEADER}, use_cache=False,
            )
        except Exception as exc:  # noqa: BLE001 - probe failure is inconclusive, not an error
            self._log.debug(f"MS15-034 active probe failed for {base_url}: {exc}")
            return None

        status = int(resp.get("status_code", 0) or 0)
        if status == 416:
            return PocFinding(
                cve_id="CVE-2015-1635",
                name="MS15-034 HTTP.sys integer-overflow remote code execution / DoS",
                product="Microsoft-IIS", version=None, severity="Critical", confidence="CONFIRMED",
                evidence=(
                    "Active safe probe: a crafted 'Range: bytes=0-18446744073709551615' "
                    "request returned HTTP 416 (Requested Range Not Satisfiable), the "
                    "differential signature of an unpatched HTTP.sys kernel driver. "
                    "Single non-destructive request; no crash/DoS condition was triggered."
                ),
                poc_method="active-range-probe",
            )
        if status == 400:
            self._log.debug("MS15-034 active probe: target returned 400 (patched HTTP.sys).")
            return None
        # Any other status (200, 3xx, 5xx, timeout) is inconclusive - a banner
        # that merely *suggests* IIS 7.5/8.0/8.5 is not, on its own, proof of
        # anything, so nothing is reported here.
        return None

    async def _check_advisories(self, base_url: str, fp: ServerFingerprint) -> list[PocFinding]:
        findings: list[PocFinding] = []
        for adv in _ADVISORIES.get(fp.product, ()):
            if adv.requires_active_probe:
                if adv.exact_versions and fp.version not in adv.exact_versions:
                    continue
                if not self.enable_active_probes:
                    continue
                result = await self._verify(adv, base_url)
                if result is not None:
                    findings.append(result)
                continue
            if adv.fixed_version and fp.version and _version_lt(fp.version, adv.fixed_version):
                findings.append(PocFinding(
                    cve_id=adv.cve_id, name=adv.name, product=fp.product, version=fp.version,
                    severity=adv.severity, confidence="MEDIUM",
                    evidence=(
                        f"{fp.product}/{fp.version} is below the fixed version "
                        f"{adv.fixed_version} for {adv.cve_id} (banner-derived; the target "
                        "was not actively exploited or otherwise confirmed)."
                    ),
                    poc_method="banner-only",
                ))
        return findings

    async def fingerprint(self, base_url: str) -> ServerFingerprintResult:
        """Fingerprint ``base_url`` and verify any matching advisories.

        Never raises: a request failure yields an empty result rather than
        propagating, matching every other optional recon pass.
        """
        try:
            resp = await self.scanner.request("GET", base_url)
        except Exception as exc:  # noqa: BLE001 - defensive, must not abort recon
            self._log.debug(f"Server fingerprinting request failed for {base_url}: {exc}")
            return ServerFingerprintResult(url=base_url)

        headers = _ci_headers(resp.get("headers", {}))
        fingerprints = self._parse_headers(headers)
        findings: list[PocFinding] = []
        for fp in fingerprints:
            findings.extend(await self._check_advisories(base_url, fp))

        return ServerFingerprintResult(url=base_url, fingerprints=fingerprints, findings=findings)
