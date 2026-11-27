"""Category 2 -- crawling and route/DOM extraction for SPAs: katana, gospider, kiterunner.

* katana -- JSON Lines via ``-jsonl -silent``.
* gospider -- JSONL via ``--json``, one crawled-URL record per line.
* kiterunner -- JSON via ``-o json``, route-bruteforce results (OpenAPI-aware).
"""

from __future__ import annotations

from typing import Any

from .base import AsyncToolAdapter, iter_json_lines, sanitize_url

__all__ = ["KatanaAdapter", "GospiderAdapter", "KiterunnerAdapter"]


class KatanaAdapter(AsyncToolAdapter):
    binary = "katana"
    name = "katana"
    default_timeout_s = 180.0

    def build_command(
        self,
        url: str,
        *,
        depth: int = 2,
        js_crawl: bool = True,
    ) -> list[str]:
        sanitize_url(url)
        if depth < 1:
            raise ValueError("depth must be >= 1")
        cmd = [self.binary, "-u", url, "-jsonl", "-silent", "-d", str(depth)]
        if js_crawl:
            cmd.append("-jc")
        return cmd

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for record in iter_json_lines(stdout):
            endpoint = record.get("request", {}).get("endpoint") or record.get("url")
            findings.append(
                {
                    "url": endpoint,
                    "method": record.get("request", {}).get("method", "GET"),
                    "status_code": record.get("response", {}).get("status_code"),
                    "source": record.get("source"),
                }
            )
        return findings


class GospiderAdapter(AsyncToolAdapter):
    binary = "gospider"
    name = "gospider"
    default_timeout_s = 180.0

    def build_command(
        self,
        url: str,
        *,
        depth: int = 2,
        threads: int = 5,
    ) -> list[str]:
        sanitize_url(url)
        if depth < 1:
            raise ValueError("depth must be >= 1")
        if threads < 1:
            raise ValueError("threads must be >= 1")
        return [
            self.binary,
            "-s",
            url,
            "--json",
            "-d",
            str(depth),
            "-t",
            str(threads),
            "-q",
        ]

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for record in iter_json_lines(stdout):
            findings.append(
                {
                    "url": record.get("output") or record.get("url"),
                    "type": record.get("type"),
                    "status_code": record.get("status"),
                    "source": record.get("input"),
                }
            )
        return findings


class KiterunnerAdapter(AsyncToolAdapter):
    binary = "kr"
    name = "kiterunner"
    default_timeout_s = 300.0

    def build_command(
        self,
        url: str,
        *,
        wordlist: str,
    ) -> list[str]:
        sanitize_url(url)
        if not wordlist or wordlist.startswith("-"):
            raise ValueError(f"invalid wordlist path: {wordlist!r}")
        return [self.binary, "scan", url, "-w", wordlist, "-o", "json"]

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for record in iter_json_lines(stdout):
            findings.append(
                {
                    "url": record.get("url"),
                    "method": record.get("method"),
                    "status_code": record.get("status_code"),
                    "content_length": record.get("content_length"),
                }
            )
        return findings
