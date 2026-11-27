"""Category 1 -- infrastructure recon and port mapping: nmap, naabu, masscan.

All three take a host/CIDR target and emit machine-readable output the
scanner never has to screen-scrape:

* nmap -- XML via ``-oX -`` (stdout), parsed with :mod:`xml.etree`.
* naabu -- JSON Lines via ``-json``, one open-port record per line.
* masscan -- JSON via ``-oJ -``.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any

from .base import AsyncToolAdapter, iter_json_lines, sanitize_host

__all__ = ["NmapAdapter", "NaabuAdapter", "MasscanAdapter"]


class NmapAdapter(AsyncToolAdapter):
    binary = "nmap"
    name = "nmap"
    default_timeout_s = 300.0

    def build_command(
        self,
        host: str,
        *,
        ports: str | None = None,
        service_detection: bool = True,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        sanitize_host(host)
        cmd = [self.binary, "-oX", "-", "-Pn"]
        if service_detection:
            cmd.append("-sV")
        if ports:
            if not all(c.isdigit() or c in ",-" for c in ports):
                raise ValueError(f"invalid -p port spec: {ports!r}")
            cmd += ["-p", ports]
        for extra in extra_args or []:
            if extra.startswith("-") is False:
                raise ValueError(f"extra_args entries must be flags: {extra!r}")
            cmd.append(extra)
        cmd.append(host)
        return cmd

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        if not stdout.strip():
            return []
        root = ET.fromstring(stdout)  # noqa: S314 -- our own subprocess's stdout, not user XML
        findings: list[dict[str, Any]] = []
        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            address = addr_el.get("addr") if addr_el is not None else None
            for port_el in host_el.findall("ports/port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                findings.append(
                    {
                        "host": address,
                        "port": int(port_el.get("portid", "0")),
                        "protocol": port_el.get("protocol"),
                        "state": state_el.get("state") if state_el is not None else None,
                        "service": service_el.get("name") if service_el is not None else None,
                        "product": service_el.get("product") if service_el is not None else None,
                        "version": service_el.get("version") if service_el is not None else None,
                    }
                )
        return findings


class NaabuAdapter(AsyncToolAdapter):
    binary = "naabu"
    name = "naabu"
    default_timeout_s = 180.0

    def build_command(
        self,
        host: str,
        *,
        ports: str | None = None,
        rate: int | None = None,
    ) -> list[str]:
        sanitize_host(host)
        cmd = [self.binary, "-host", host, "-json", "-silent"]
        if ports:
            if not all(c.isdigit() or c in ",-" for c in ports):
                raise ValueError(f"invalid -p port spec: {ports!r}")
            cmd += ["-p", ports]
        if rate is not None:
            if rate <= 0:
                raise ValueError("rate must be positive")
            cmd += ["-rate", str(rate)]
        return cmd

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for record in iter_json_lines(stdout):
            findings.append(
                {
                    "host": record.get("host") or record.get("ip"),
                    "port": record.get("port"),
                    "protocol": record.get("protocol", "tcp"),
                }
            )
        return findings


class MasscanAdapter(AsyncToolAdapter):
    binary = "masscan"
    name = "masscan"
    default_timeout_s = 300.0

    def build_command(
        self,
        host: str,
        *,
        ports: str = "1-65535",
        rate: int = 1000,
    ) -> list[str]:
        sanitize_host(host)
        if not all(c.isdigit() or c in ",-" for c in ports):
            raise ValueError(f"invalid -p port spec: {ports!r}")
        if rate <= 0:
            raise ValueError("rate must be positive")
        return [self.binary, host, "-p", ports, "--rate", str(rate), "-oJ", "-"]

    def parse(self, stdout: str) -> list[dict[str, Any]]:
        text = stdout.strip()
        if not text:
            return []
        # masscan's -oJ stream is a comma-separated list of objects without an
        # enclosing array in some versions; normalize defensively.
        text = text.strip(",")
        if not text.startswith("["):
            text = f"[{text}]"
        try:
            records = json.loads(text)
        except json.JSONDecodeError:
            return []
        findings: list[dict[str, Any]] = []
        for record in records:
            for port_entry in record.get("ports", []):
                findings.append(
                    {
                        "host": record.get("ip"),
                        "port": port_entry.get("port"),
                        "protocol": port_entry.get("proto"),
                        "state": port_entry.get("status"),
                    }
                )
        return findings
