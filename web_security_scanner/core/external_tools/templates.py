"""Category 6 -- template/DSL-based scanning: nuclei.

nuclei emits one JSON object per matched template via ``-jsonl -silent``.
``template_id`` alone lets callers cross-reference against the scanner's own
:mod:`web_security_scanner.core.vuln_classes` taxonomy later, without this
adapter having to know that mapping.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .base import AsyncToolAdapter, sanitize_url

__all__ = ["NucleiAdapter"]

_TAG_RE = re.compile(r"^[a-z0-9,\-]+$")


class NucleiAdapter(AsyncToolAdapter):
    binary = "nuclei"
    name = "nuclei"
    default_timeout_s = 600.0

    def build_command(
        self,
        url: str,
        *,
        templates: str | None = None,
        tags: str | None = None,
        severity: str | None = None,
        rate_limit: int | None = None,
    ) -> list[str]:
        sanitize_url(url)
        cmd = [self.binary, "-u", url, "-jsonl", "-silent"]
        if templates is not None:
            if not templates or templates.startswith("-"):
                raise ValueError(f"invalid templates path: {templates!r}")
            cmd += ["-t", templates]
        if tags is not None:
            if not _TAG_RE.match(tags):
                raise ValueError(f"invalid -tags value: {tags!r}")
            cmd += ["-tags", tags]
        if severity is not None:
            if not re.fullmatch(r"(info|low|medium|high|critical)(,(info|low|medium|high|critical))*", severity):
                raise ValueError(f"invalid -severity value: {severity!r}")
            cmd += ["-severity", severity]
        if rate_limit is not None:
            if rate_limit <= 0:
                raise ValueError("rate_limit must be positive")
            cmd += ["-rate-limit", str(rate_limit)]
        return cmd

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = record.get("info", {})
            findings.append(
                {
                    "template_id": record.get("template-id") or record.get("template_id"),
                    "name": info.get("name"),
                    "severity": info.get("severity"),
                    "matched_at": record.get("matched-at") or record.get("matched_at"),
                    "tags": info.get("tags"),
                }
            )
        return findings
