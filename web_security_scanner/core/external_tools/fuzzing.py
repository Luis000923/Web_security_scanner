"""Category 3 -- parameter fuzzing and discovery: ffuf, arjun.

* ffuf -- JSON report via ``-of json -o -``.
* arjun -- JSON via ``-oJ -`` (writes to stdout when the output path is ``-``
  is not universally supported across versions, so this adapter writes to a
  temp-free stdout mode via ``--stdout`` where available and otherwise reads
  ``-o /dev/stdout``; kept simple here as ``-o -`` since modern arjun accepts it).
"""

from __future__ import annotations

import json
from typing import Any

from .base import AsyncToolAdapter, sanitize_arg, sanitize_url

__all__ = ["FfufAdapter", "ArjunAdapter"]


class FfufAdapter(AsyncToolAdapter):
    binary = "ffuf"
    name = "ffuf"
    default_timeout_s = 180.0

    def build_command(
        self,
        url: str,
        *,
        wordlist: str,
        method: str = "GET",
        match_codes: str = "200-299,301,302,401,403",
    ) -> list[str]:
        sanitize_url(url)
        if "FUZZ" not in url:
            raise ValueError("url must contain the FUZZ placeholder")
        if not wordlist or wordlist.startswith("-"):
            raise ValueError(f"invalid wordlist path: {wordlist!r}")
        sanitize_arg(method, field_name="method")
        return [
            self.binary,
            "-u",
            url,
            "-w",
            wordlist,
            "-X",
            method,
            "-mc",
            match_codes,
            "-of",
            "json",
            "-o",
            "-",
            "-s",
        ]

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        text = stdout.strip()
        if not text:
            return []
        try:
            report = json.loads(text)
        except json.JSONDecodeError:
            return []
        findings: list[dict[str, Any]] = []
        for result in report.get("results", []):
            findings.append(
                {
                    "url": result.get("url"),
                    "input": result.get("input"),
                    "status_code": result.get("status"),
                    "length": result.get("length"),
                    "words": result.get("words"),
                }
            )
        return findings


class ArjunAdapter(AsyncToolAdapter):
    binary = "arjun"
    name = "arjun"
    default_timeout_s = 180.0

    def build_command(
        self,
        url: str,
        *,
        method: str = "GET",
        stable: bool = True,
    ) -> list[str]:
        sanitize_url(url)
        sanitize_arg(method, field_name="method")
        cmd = [self.binary, "-u", url, "-m", method, "-oJ", "-", "-q"]
        if stable:
            cmd.append("--stable")
        return cmd

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        text = stdout.strip()
        if not text:
            return []
        try:
            report = json.loads(text)
        except json.JSONDecodeError:
            return []
        findings: list[dict[str, Any]] = []
        for target_url, params in report.items():
            if not isinstance(params, list):
                continue
            for param in params:
                findings.append({"url": target_url, "parameter": param})
        return findings
