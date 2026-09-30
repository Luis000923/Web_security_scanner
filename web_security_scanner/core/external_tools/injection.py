"""Category 4 -- confirmed injection/exploitation engines: sqlmap, tplmap, ysoserial.

Unlike the recon/crawling/fuzzing tools, none of these three has a stable
machine-readable stdout format the way ``-json`` does elsewhere:

* sqlmap has no native JSON report mode on stdout (the REST API,
  ``sqlmapapi.py``, does -- that integration belongs in a follow-up HTTP-based
  adapter, not here); this adapter drives the CLI in ``--batch`` mode and
  parses its human-readable "Parameter: ... Type: ... Payload: ..." blocks
  with a tolerant regex. A parse miss degrades to zero findings, never a
  crash (see :meth:`AsyncToolAdapter.run`'s parse try/except).
* tplmap likewise prints confirmation blocks rather than JSON; parsed the
  same way.
* ysoserial is not a scanner at all -- it is a gadget-chain *generator* that
  writes a serialized Java object to stdout. There is nothing to "find"; the
  adapter's job is only to build the sanitized argv and hand back the raw
  bytes. Its ``parse`` reports generation metadata (byte length), not
  findings, and callers who need the payload bytes for a subsequent HTTP
  request should read ``ToolResult.stdout`` directly -- note that is decoded
  as UTF-8 with ``errors="replace"`` by the shared framework, which is lossy
  for arbitrary binary; treat it as a length/success signal, not as the
  payload transport for anything binary-safe.
"""

from __future__ import annotations

import re
from typing import Any

from .base import AsyncToolAdapter, sanitize_arg, sanitize_url

__all__ = ["SqlmapAdapter", "TplmapAdapter", "YsoserialAdapter"]

_SQLMAP_PARAM_BLOCK_RE = re.compile(
    r"Parameter:\s*(?P<param>\S+)\s*\((?P<place>\S+)\)\s*"
    r"Type:\s*(?P<type>[^\n]+)\s*"
    r"Title:\s*(?P<title>[^\n]+)\s*"
    r"Payload:\s*(?P<payload>[^\n]+)",
    re.MULTILINE,
)

_TPLMAP_CONFIRM_RE = re.compile(
    r"engine\s+(?P<engine>\S+)\s+plugin\s+is\s+(?:able|confirmed)"
    r".{0,200}?injection\s+point.{0,10}?[:\s]+(?P<point>\S+)",
    re.IGNORECASE | re.DOTALL,
)


class SqlmapAdapter(AsyncToolAdapter):
    binary = "sqlmap"
    name = "sqlmap"
    default_timeout_s = 600.0

    def build_command(
        self,
        url: str,
        *,
        data: str | None = None,
        cookie: str | None = None,
        level: int = 1,
        risk: int = 1,
        technique: str | None = None,
    ) -> list[str]:
        sanitize_url(url)
        if not (1 <= level <= 5):
            raise ValueError("level must be 1-5")
        if not (1 <= risk <= 3):
            raise ValueError("risk must be 1-3")
        cmd = [
            self.binary,
            "-u",
            url,
            "--batch",
            "--level",
            str(level),
            "--risk",
            str(risk),
            "--disable-coloring",
        ]
        if data is not None:
            sanitize_arg(data, field_name="data")
            cmd += ["--data", data]
        if cookie is not None:
            sanitize_arg(cookie, field_name="cookie")
            cmd += ["--cookie", cookie]
        if technique is not None:
            if not re.fullmatch(r"[BEUSTQ]+", technique):
                raise ValueError(f"invalid --technique value: {technique!r}")
            cmd += ["--technique", technique]
        return cmd

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for match in _SQLMAP_PARAM_BLOCK_RE.finditer(stdout):
            findings.append(
                {
                    "parameter": match.group("param"),
                    "place": match.group("place"),
                    "type": match.group("type").strip(),
                    "title": match.group("title").strip(),
                    "payload": match.group("payload").strip(),
                }
            )
        return findings


class TplmapAdapter(AsyncToolAdapter):
    binary = "tplmap"
    name = "tplmap"
    default_timeout_s = 300.0

    def build_command(
        self,
        url: str,
        *,
        data: str | None = None,
    ) -> list[str]:
        sanitize_url(url)
        cmd = [self.binary, "-u", url]
        if data is not None:
            sanitize_arg(data, field_name="data")
            cmd += ["-d", data]
        return cmd

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for match in _TPLMAP_CONFIRM_RE.finditer(stdout):
            findings.append(
                {
                    "engine": match.group("engine"),
                    "injection_point": match.group("point"),
                }
            )
        return findings


class YsoserialAdapter(AsyncToolAdapter):
    """Generates a serialized-object gadget chain; not a finding-producing scanner."""

    binary = "ysoserial"
    name = "ysoserial"
    default_timeout_s = 60.0

    def build_command(self, gadget: str, command: str) -> list[str]:
        sanitize_arg(gadget, field_name="gadget")
        sanitize_arg(command, field_name="command")
        if not re.fullmatch(r"[A-Za-z0-9]+", gadget):
            raise ValueError(f"invalid gadget chain name: {gadget!r}")
        return [self.binary, gadget, command]

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        # No structured findings -- report generation metadata instead so
        # callers can at least tell "did this produce a non-empty payload".
        if not stdout:
            return []
        return [{"generated_bytes": len(stdout.encode("utf-8", errors="replace"))}]
