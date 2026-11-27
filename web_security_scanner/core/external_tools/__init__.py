"""Async adapters for specialized external security tools.

Seven categories, sixteen adapters, one shared contract
(:class:`~web_security_scanner.core.external_tools.base.AsyncToolAdapter`):

1. Recon/infra mapping     -- nmap, naabu, masscan       (:mod:`.recon`)
2. Crawling/DOM extraction -- katana, gospider, kiterunner (:mod:`.crawling`)
3. Parameter fuzzing       -- ffuf, arjun                (:mod:`.fuzzing`)
4. Confirmed injection     -- sqlmap, tplmap, ysoserial   (:mod:`.injection`)
5. OOB confirmation        -- interactsh                 (:mod:`.oob`)
6. Template scanning       -- nuclei                     (:mod:`.templates`)
7. Symbolic/instrumentation -- z3, frida, joern           (:mod:`.symbolic`)

None of these run by default and none is a hard dependency of the scanner
core: every adapter degrades gracefully (``ToolResult.tool_missing=True``)
when its binary is absent from ``PATH``, and nothing in
``web_security_scanner/`` calls into this package yet -- it is available for
a scan phase or research track to opt into explicitly. See
:data:`ADAPTER_REGISTRY` for a name -> class lookup.
"""

from __future__ import annotations

from .base import (
    AsyncToolAdapter,
    ToolAdapterError,
    ToolNotFoundError,
    ToolResult,
    ToolTimeoutError,
    sanitize_arg,
    sanitize_host,
    sanitize_url,
)
from .crawling import GospiderAdapter, KatanaAdapter, KiterunnerAdapter
from .fuzzing import ArjunAdapter, FfufAdapter
from .injection import SqlmapAdapter, TplmapAdapter, YsoserialAdapter
from .oob import InteractshAdapter
from .recon import MasscanAdapter, NaabuAdapter, NmapAdapter
from .symbolic import FridaAdapter, JoernAdapter, Z3Adapter
from .templates import NucleiAdapter

__all__ = [
    "AsyncToolAdapter",
    "ToolAdapterError",
    "ToolNotFoundError",
    "ToolTimeoutError",
    "ToolResult",
    "sanitize_arg",
    "sanitize_host",
    "sanitize_url",
    "NmapAdapter",
    "NaabuAdapter",
    "MasscanAdapter",
    "KatanaAdapter",
    "GospiderAdapter",
    "KiterunnerAdapter",
    "FfufAdapter",
    "ArjunAdapter",
    "SqlmapAdapter",
    "TplmapAdapter",
    "YsoserialAdapter",
    "InteractshAdapter",
    "NucleiAdapter",
    "Z3Adapter",
    "FridaAdapter",
    "JoernAdapter",
    "ADAPTER_REGISTRY",
]

#: name -> adapter class, for callers that select a tool by config string
#: (e.g. a future ``--external-tools nmap,nuclei`` CLI flag) instead of
#: importing the class directly.
ADAPTER_REGISTRY: dict[str, type[AsyncToolAdapter]] = {
    "nmap": NmapAdapter,
    "naabu": NaabuAdapter,
    "masscan": MasscanAdapter,
    "katana": KatanaAdapter,
    "gospider": GospiderAdapter,
    "kiterunner": KiterunnerAdapter,
    "ffuf": FfufAdapter,
    "arjun": ArjunAdapter,
    "sqlmap": SqlmapAdapter,
    "tplmap": TplmapAdapter,
    "ysoserial": YsoserialAdapter,
    "interactsh": InteractshAdapter,
    "nuclei": NucleiAdapter,
    "z3": Z3Adapter,
    "frida": FridaAdapter,
    "joern": JoernAdapter,
}
