"""Async adapter framework for specialized external security tools.

Why this exists
----------------
The scanner's own testers cover the request/response DAST surface. Several
attack classes are better served by purpose-built external binaries (port
scanners, template engines, symbolic solvers) than by reimplementing them.
This module gives every such integration one common shape: a subprocess is
spawned via :func:`asyncio.create_subprocess_exec` with an explicit
``argv`` list, never through a shell, so shell metacharacters in any
attacker-influenced string (a target host, a URL, a header value) cannot be
interpreted -- there is no shell to interpret them. ``shlex.quote`` and
``shell=True`` never appear in this package; that is the security property,
not an implementation detail.

The remaining injection surface is *argument* injection: a value that
should be a positional argument (a hostname, a URL) but begins with ``-``
and gets parsed as a flag by the target binary instead. :func:`sanitize_arg`
closes that specifically, and every adapter validates the shape of its own
target arguments before building ``argv``.

Design
------
:class:`AsyncToolAdapter` is the shared contract:

* ``binary`` names the executable this adapter wraps (looked up on ``PATH``
  with :func:`shutil.which`, never assumed to be installed).
* :meth:`available` is a cheap, non-throwing existence check callers should
  use before deciding to run a scan phase that depends on this tool.
* :meth:`run` resolves the binary, spawns it with a hard timeout, and always
  returns a :class:`ToolResult` -- even when the binary is missing, it
  returns a result with ``returncode is None`` and ``tool_missing=True``
  rather than raising, so a missing optional dependency never aborts the
  scan. :exc:`ToolNotFoundError` is available for callers that *do* want to
  fail loudly (e.g. a CLI ``--require-tool`` flag).
* Subclasses implement :meth:`build_command` (turn typed arguments into an
  ``argv`` list, after validating them) and :meth:`parse` (turn raw stdout
  into typed findings). Nothing else is tool-specific.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, ClassVar

__all__ = [
    "ToolAdapterError",
    "ToolNotFoundError",
    "ToolTimeoutError",
    "ToolResult",
    "AsyncToolAdapter",
    "sanitize_arg",
    "sanitize_host",
    "sanitize_url",
]

logger = logging.getLogger(__name__)

#: Bytes of combined stdout+stderr kept in memory per invocation. Mirrors the
#: 5 MiB response cap used elsewhere in the async core (see
#: `phase5-adversarial-reads` -- an external process is just as capable of
#: producing an unbounded stream as a hostile HTTP server).
MAX_OUTPUT_BYTES = 5 * 1024 * 1024

#: Default hard wall-clock budget for a single invocation. Individual
#: adapters override this for tools that are legitimately slower
#: (sqlmap, nuclei full-template runs).
DEFAULT_TIMEOUT_S = 120.0

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62})?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62})?)*$"
)
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


class ToolAdapterError(Exception):
    """Base class for all external-tool adapter errors."""


class ToolNotFoundError(ToolAdapterError):
    """Raised when a caller opts into strict mode and the binary is absent."""

    def __init__(self, binary: str) -> None:
        super().__init__(
            f"'{binary}' not found on PATH -- install it or skip this phase"
        )
        self.binary = binary


class ToolTimeoutError(ToolAdapterError):
    """Raised only by callers that opt into strict mode; run() itself never
    raises on timeout, it reports it on ToolResult.timed_out."""

    def __init__(self, binary: str, timeout: float) -> None:
        super().__init__(f"'{binary}' exceeded {timeout:.0f}s timeout")
        self.binary = binary
        self.timeout = timeout


@dataclass(slots=True)
class ToolResult:
    """Outcome of one adapter invocation, regardless of success mode.

    Exactly one of three states holds: the tool ran to completion
    (``returncode`` is an int), it was killed for exceeding its timeout
    (``timed_out=True``), or the binary was never found
    (``tool_missing=True``). Callers that only care about "did I get
    findings" can check ``findings`` and ignore the rest.
    """

    tool: str
    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    tool_missing: bool = False
    truncated: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True only for a completed run with a zero exit code."""
        return not self.tool_missing and not self.timed_out and self.returncode == 0


def sanitize_arg(value: str, *, field_name: str = "argument") -> str:
    """Reject a value that would be dangerous as a subprocess argument.

    ``create_subprocess_exec`` never invokes a shell, so this is not about
    shell metacharacters (``;``, ``|``, backticks are inert here -- they are
    passed to the child process as literal bytes of one argv element). It
    guards against two remaining classes of abuse:

    * flag/argument injection -- a value starting with ``-`` that the target
      binary would parse as an option instead of positional data;
    * control characters / NUL bytes, which some tools mishandle and which
      have no legitimate place in a hostname, URL or header value here.
    """
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    if "\x00" in value:
        raise ValueError(f"{field_name} must not contain a NUL byte")
    if _CONTROL_CHARS_RE.search(value):
        raise ValueError(f"{field_name} must not contain control characters")
    if value.startswith("-"):
        raise ValueError(
            f"{field_name} must not start with '-' (flag/argument injection guard): {value!r}"
        )
    return value


def sanitize_host(value: str) -> str:
    """Validate a bare hostname, IPv4 address, or IPv4 CIDR block.

    Used by recon adapters (nmap/naabu/masscan) whose target argument is a
    network address, not a full URL.
    """
    sanitize_arg(value, field_name="host")
    candidate, _, cidr = value.partition("/")
    if cidr:
        if not cidr.isdigit() or not (0 <= int(cidr) <= 32):
            raise ValueError(f"invalid CIDR suffix: {value!r}")
    if _IPV4_RE.match(candidate) or _HOSTNAME_RE.match(candidate):
        return value
    raise ValueError(f"not a valid hostname/IPv4[/CIDR]: {value!r}")


def sanitize_url(value: str) -> str:
    """Validate an ``http(s)://`` target URL used by crawling/fuzzing/injection adapters."""
    sanitize_arg(value, field_name="url")
    if not re.match(r"^https?://[^\s]+$", value):
        raise ValueError(f"not a valid http(s) URL: {value!r}")
    return value


async def _read_capped(stream: asyncio.StreamReader, cap: int, sink: list[bytes]) -> bool:
    """Read a stream up to ``cap`` bytes into ``sink``, appending as it goes.

    ``sink`` is mutated in place (rather than returned) so that a caller who
    cancels this coroutine on a timeout still has whatever was read so far --
    several adapters (interactsh in particular) treat "ran for the full
    timeout" as the normal termination mode, not a failure, and discarding
    partial output on timeout would make them useless.
    """
    total = 0
    truncated = False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        remaining = cap - total
        if remaining <= 0:
            truncated = True
            continue
        if len(chunk) > remaining:
            sink.append(chunk[:remaining])
            truncated = True
        else:
            sink.append(chunk)
        total += len(chunk)
    return truncated


def iter_json_lines(stdout: str, *, prefix: str = "") -> Iterator[Any]:
    """Yield each JSON value of a JSON-lines ``stdout``, in order.

    Blank lines, lines not starting with ``prefix`` (after stripping) and
    lines that are not valid JSON are skipped silently: tools interleave
    banners and progress output with their ``-json`` records.
    """
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith(prefix):
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


class AsyncToolAdapter(ABC):
    """Common contract for every external-tool integration in this package."""

    #: Executable name looked up on PATH. Subclasses set this.
    binary: ClassVar[str]
    #: Human-readable identifier used in ToolResult.tool and logs.
    name: ClassVar[str]
    #: Per-adapter default; overridable per-call via run(timeout=...).
    default_timeout_s: ClassVar[float] = DEFAULT_TIMEOUT_S

    def __init__(self, *, binary_path: str | None = None) -> None:
        """``binary_path`` overrides the PATH lookup (tests, custom installs)."""
        self._binary_path_override = binary_path

    def resolve_binary(self) -> str | None:
        """Return the resolved executable path, or None if not installed."""
        if self._binary_path_override is not None:
            return self._binary_path_override
        return shutil.which(self.binary)

    async def available(self) -> bool:
        """Cheap existence check callers can use to skip a phase gracefully."""
        return self.resolve_binary() is not None

    @abstractmethod
    def build_command(self, *args: Any, **kwargs: Any) -> list[str]:
        """Build the argv list (binary path first) for one invocation.

        Must validate every attacker-influenced value with :func:`sanitize_arg`
        / :func:`sanitize_host` / :func:`sanitize_url` before it lands in the
        returned list. Never returns a string; argv is always a list, so
        there is no join/quote step where an injection could creep back in.
        """

    @abstractmethod
    def parse(self, stdout: str) -> list[dict[str, Any]]:
        """Turn raw stdout into a list of normalized finding dicts."""

    async def run(
        self,
        *args: Any,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        strict: bool = False,
        **kwargs: Any,
    ) -> ToolResult:
        """Resolve the binary, run it, and always return a ToolResult.

        With ``strict=False`` (the default), a missing binary or a timeout
        is reported on the returned ToolResult and this method never raises
        for those two cases -- the calling scan phase can check
        ``result.tool_missing`` / ``result.timed_out`` and continue.
        With ``strict=True``, those two cases raise
        :exc:`ToolNotFoundError` / :exc:`ToolTimeoutError` instead, for
        callers (e.g. a CI-style ``--require-tools`` check) that want a
        hard failure.
        """
        resolved = self.resolve_binary()
        if resolved is None:
            if strict:
                raise ToolNotFoundError(self.binary)
            logger.warning("external tool %r not found on PATH; skipping", self.binary)
            return ToolResult(
                tool=self.name,
                command=(),
                returncode=None,
                stdout="",
                stderr="",
                duration_s=0.0,
                tool_missing=True,
            )

        command = self.build_command(*args, **kwargs)
        command[0] = resolved
        effective_timeout = timeout if timeout is not None else self.default_timeout_s

        start = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
        assert proc.stdout is not None and proc.stderr is not None
        stdout_sink: list[bytes] = []
        stderr_sink: list[bytes] = []
        stdout_task = asyncio.create_task(
            _read_capped(proc.stdout, MAX_OUTPUT_BYTES, stdout_sink)
        )
        stderr_task = asyncio.create_task(
            _read_capped(proc.stderr, MAX_OUTPUT_BYTES, stderr_sink)
        )
        try:
            await asyncio.wait_for(
                asyncio.gather(stdout_task, stderr_task, proc.wait()),
                timeout=effective_timeout,
            )
            timed_out = False
        except asyncio.TimeoutError:
            timed_out = True
            for task in (stdout_task, stderr_task):
                task.cancel()
            with _suppress_process_lookup():
                proc.kill()
                await proc.wait()
            if strict:
                raise ToolTimeoutError(self.binary, effective_timeout) from None
        except asyncio.CancelledError:
            # The caller's own task was cancelled (SIGINT via a TUI/CLI
            # cancelling its scan task, a task group shutting down, ...).
            # Without this, the child process is orphaned: asyncio.wait_for
            # raising CancelledError does not touch the subprocess it was
            # awaiting on. Kill it, drain the reader tasks so they don't
            # outlive this coroutine, and re-raise -- cancellation must still
            # propagate to the caller.
            for task in (stdout_task, stderr_task):
                task.cancel()
            with _suppress_process_lookup():
                proc.kill()
                await proc.wait()
            raise

        duration = time.monotonic() - start
        stdout_bytes = b"".join(stdout_sink)
        stderr_bytes = b"".join(stderr_sink)
        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")
        truncated = len(stdout_bytes) >= MAX_OUTPUT_BYTES

        # Parse whenever there is output to parse, even on timeout/non-zero
        # exit: several adapters (interactsh in particular) treat "ran until
        # the timeout" as their normal termination mode, and a tool that
        # printed partial JSON before crashing may still have emitted usable
        # records. A malformed or partial payload must not crash the scan --
        # parse() failures are caught and logged, never propagated.
        findings: list[dict[str, Any]] = []
        if stdout_text:
            try:
                findings = self.parse(stdout_text)
            except Exception:  # noqa: BLE001 -- a malformed tool output must not crash the scan
                logger.exception("failed to parse %r output", self.name)

        return ToolResult(
            tool=self.name,
            command=tuple(command),
            returncode=proc.returncode if not timed_out else None,
            stdout=stdout_text,
            stderr=stderr_text,
            duration_s=duration,
            timed_out=timed_out,
            truncated=truncated,
            findings=findings,
        )


class _suppress_process_lookup:
    """Context manager: a process that already exited races proc.kill()."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return exc_type is not None and issubclass(exc_type, ProcessLookupError)
