"""Category 7 -- symbolic analysis and instrumentation: z3, frida, joern.

These three are the odd ones out relative to the rest of the package: they
are not HTTP scanners, they analyze or instrument *code*, and their natural
interfaces are not all "one CLI invocation, one report":

* z3 -- ``z3-solver`` is normally used as an in-process Python library
  (``import z3``), not a subprocess. This adapter wraps the separate ``z3``
  CLI binary instead (SMT-LIB2 file in, ``sat``/``unsat``/model on stdout),
  which is the form that fits this package's "external binary" contract. A
  caller doing in-process constraint solving (e.g. exploring branch
  conditions symbolically during triage) should import ``z3`` directly
  instead of going through this adapter -- it exists for the case where the
  SMT-LIB2 problem was generated as a file by another tool in the pipeline.
* frida -- requires an attached device/process; this wraps
  ``frida -U -f <target> -l <script.js> --no-pause``, treating each
  console.log line from the injected script as one finding. A real triage
  pipeline supplies the instrumentation script; this adapter does not write
  one.
* joern -- wraps ``joern-scan``, the report-producing CLI front-end for
  Joern's code-property-graph queries, rather than driving the interactive
  Scala REPL (``joern`` proper), which is not scriptable as a single bounded
  subprocess call.
"""

from __future__ import annotations

import json
from typing import Any

from .base import AsyncToolAdapter, sanitize_arg

__all__ = ["Z3Adapter", "FridaAdapter", "JoernAdapter"]


class Z3Adapter(AsyncToolAdapter):
    binary = "z3"
    name = "z3"
    default_timeout_s = 60.0

    def build_command(self, smt2_path: str, *, model: bool = True) -> list[str]:
        if not smt2_path or smt2_path.startswith("-"):
            raise ValueError(f"invalid SMT-LIB2 path: {smt2_path!r}")
        cmd = [self.binary]
        if model:
            cmd.append("-model")
        cmd.append(smt2_path)
        return cmd

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        lines = stdout.splitlines()
        if not lines:
            return []
        status = lines[0].strip()
        model_text = "\n".join(lines[1:]).strip()
        return [{"status": status, "model": model_text or None}]


class FridaAdapter(AsyncToolAdapter):
    binary = "frida"
    name = "frida"
    default_timeout_s = 30.0

    def build_command(
        self,
        target: str,
        script_path: str,
        *,
        spawn: bool = True,
        usb: bool = True,
    ) -> list[str]:
        sanitize_arg(target, field_name="target")
        if not script_path or script_path.startswith("-"):
            raise ValueError(f"invalid script path: {script_path!r}")
        cmd = [self.binary]
        if usb:
            cmd.append("-U")
        if spawn:
            cmd += ["-f", target, "--no-pause"]
        else:
            cmd += ["-n", target]
        cmd += ["-l", script_path]
        return cmd

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith(("[", "Attaching", "Spawned")):
                continue
            findings.append({"message": line})
        return findings


class JoernAdapter(AsyncToolAdapter):
    binary = "joern-scan"
    name = "joern"
    default_timeout_s = 600.0

    def build_command(self, source_path: str) -> list[str]:
        if not source_path or source_path.startswith("-"):
            raise ValueError(f"invalid source path: {source_path!r}")
        return [self.binary, "--json", source_path]

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        text = stdout.strip()
        if not text:
            return []
        # joern-scan prints log lines before the JSON payload on some
        # versions; take the last JSON-looking line/object rather than
        # requiring the whole stream to be pure JSON.
        for candidate in reversed(text.splitlines()):
            candidate = candidate.strip()
            if not candidate.startswith(("{", "[")):
                continue
            try:
                report = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            entries = report if isinstance(report, list) else report.get("results", [])
            findings: list[dict[str, Any]] = []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                findings.append(
                    {
                        "query": entry.get("query") or entry.get("name"),
                        "file": entry.get("file") or entry.get("filename"),
                        "line": entry.get("lineNumber") or entry.get("line"),
                        "evidence": entry.get("evidence") or entry.get("code"),
                    }
                )
            return findings
        return []
