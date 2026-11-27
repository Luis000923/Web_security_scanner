"""Category 5 -- out-of-band confirmation: interactsh.

Wraps the ``interactsh-client`` CLI in single-shot polling mode: it prints
the generated correlation URL/domain on startup and then streams one JSON
object per received interaction (DNS/HTTP/SMTP) to stdout until it exits or
is killed. This adapter runs it for a bounded ``timeout`` and reports
whatever interactions arrived in that window -- OOB confirmation is
inherently asynchronous (the payload that triggers a callback may already
have been sent by a different phase of the scan), so ``findings`` here
is "interactions observed during this polling window", not "the complete
set an injected payload will ever produce".
"""

from __future__ import annotations

from typing import Any

from .base import AsyncToolAdapter, iter_json_lines

__all__ = ["InteractshAdapter"]


class InteractshAdapter(AsyncToolAdapter):
    binary = "interactsh-client"
    name = "interactsh"
    default_timeout_s = 30.0

    def build_command(self, *, server: str | None = None) -> list[str]:
        cmd = [self.binary, "-json", "-no-color"]
        if server is not None:
            if not server or server.startswith("-"):
                raise ValueError(f"invalid server: {server!r}")
            cmd += ["-server", server]
        return cmd

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for record in iter_json_lines(stdout, prefix="{"):
            findings.append(
                {
                    "protocol": record.get("protocol"),
                    "remote_address": record.get("remote-address"),
                    "full_id": record.get("full-id"),
                    "raw_request": record.get("raw-request"),
                    "timestamp": record.get("timestamp"),
                }
            )
        return findings
