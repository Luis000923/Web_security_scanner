"""Adaptive perimeter-evasion wrapper around a probe/request cycle.

A perimeter WAF (ModSecurity/CRS, Cloudflare, AWS WAF managed rules, ...)
rejects a request it fingerprinted as malicious with an explicit block
response -- conventionally **403 Forbidden** or **406 Not Acceptable** --
before the origin application ever sees it. :class:`WafEvasionEngine` reacts
to exactly that signal: when a probe comes back blocked, it rewrites the
payload through a short chain of lexical-obfuscation transforms (drawn from
:mod:`~web_security_scanner.core.transforms`) and resends, one mutation at a
time, until either a response gets through (**bypassed**) or the whole chain
is exhausted and every mutation was blocked too (**confirmed block** --
strong signal the perimeter is filtering on the underlying payload semantics,
not just its literal encoding).

This module has no opinion about *how* a probe is sent -- it wraps a plain
``async def probe(vector: str) -> dict`` callable (the same response-dict
shape :meth:`~...core.scanner_core_async.AsyncScannerCore.request` and
:meth:`~...modules.vulnerability_testers.base_tester_async.
VulnerabilityTester.probe` already return), so a caller binds the target
URL/injection point with a small closure and gets adaptive retry for free::

    from web_security_scanner.modules.waf_evasion import WafEvasionEngine

    engine = WafEvasionEngine()

    async def _send(vector: str) -> dict:
        response, _elapsed = await tester.probe(point, vector, base_url=url)
        return response

    result = await engine.send_with_evasion(_send, payload.vector, category="sql_injection")
    if result.outcome is WafEvasionOutcome.BYPASSED:
        ...  # result.final_vector / result.final_response got through

Opt-in via ``--enable-waf-evasion`` (see :mod:`~...modules.exploit_engine`,
which wires this engine into its own non-destructive Proof-of-Impact probe
for CRITICAL/HIGH surface targets).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..core.payload_loader import Payload
from ..core.payload_mutator import PayloadMutator
from ..core.transforms.base import UnknownTransformError, UnsafeTransformError

__all__ = [
    "PERIMETER_BLOCK_STATUSES",
    "DEFAULT_EVASION_TRANSFORMS",
    "WafEvasionOutcome",
    "WafEvasionResult",
    "WafEvasionEngine",
]

# Explicit perimeter-block signatures this engine reacts to. Deliberately
# narrower than base_tester_async._WAF_BLOCK_STATUSES ({401, 403, 406}): 401
# is an authentication challenge the *origin application* issues for a
# missing/invalid credential, not necessarily an edge WAF rejection --
# retrying it with a lexically mutated payload cannot change whether a
# credential is present, so it would just waste probes. 403 Forbidden and 406
# Not Acceptable are the two status codes a perimeter WAF conventionally
# returns for a request it fingerprinted and rejected outright.
PERIMETER_BLOCK_STATUSES: frozenset[int] = frozenset({403, 406})

# Mutation chain tried, in order, on each retry. Each entry is applied to the
# *original* vector independently (never chained onto a previous mutation),
# so one weak mutation can't poison every later attempt. Roughly increasing
# lexical distance from the original: case noise, partial percent-encoding,
# SQL keyword-splitting, full double-encoding.
DEFAULT_EVASION_TRANSFORMS: tuple[str, ...] = (
    "random_case",
    "partial_percent_encode",
    "sql_comment_injection",
    "double_url_encode",
)

ProbeFn = Callable[[str], Awaitable[dict[str, Any]]]


class WafEvasionOutcome(str, Enum):
    """Verdict of one adaptive-retry cycle."""

    #: The first attempt already cleared the perimeter -- no mutation needed.
    NOT_BLOCKED = "NOT_BLOCKED"
    #: The original vector was blocked; a later mutation got through.
    BYPASSED = "BYPASSED"
    #: The original vector and every configured mutation were all blocked.
    CONFIRMED_BLOCKED = "CONFIRMED_BLOCKED"


@dataclass(frozen=True)
class WafEvasionResult:
    """Outcome of :meth:`WafEvasionEngine.send_with_evasion`."""

    outcome: WafEvasionOutcome
    attempts: int
    final_vector: str
    final_response: dict[str, Any]
    transform_chain: tuple[str, ...]
    blocked_statuses: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "attempts": self.attempts,
            "final_vector": self.final_vector,
            "final_status": self.final_response.get("status_code"),
            "transform_chain": list(self.transform_chain),
            "blocked_statuses": list(self.blocked_statuses),
        }


class WafEvasionEngine:
    """Mutate-and-retry a probe call while it keeps hitting a perimeter block.

    Framework-agnostic by design: it never sends an HTTP request itself, only
    drives whatever ``probe`` callable it is handed. Reuses
    :class:`~...core.payload_mutator.PayloadMutator` for the actual rewrite,
    so the same ``binary_safe`` gate that protects deserialization/IDOR
    payloads elsewhere in the codebase applies here too -- an unsafe or
    unknown transform is skipped (logged at debug) rather than corrupting the
    vector or aborting the retry loop.
    """

    def __init__(
        self,
        *,
        transforms: tuple[str, ...] = DEFAULT_EVASION_TRANSFORMS,
        max_retries: int = 4,
        block_statuses: frozenset[int] = PERIMETER_BLOCK_STATUSES,
        mutator: PayloadMutator | None = None,
    ) -> None:
        self._transforms = transforms
        self._max_retries = max(0, int(max_retries))
        self._block_statuses = block_statuses
        self._mutator = mutator or PayloadMutator()
        self._log = logging.getLogger(self.__class__.__name__)

    @staticmethod
    def is_perimeter_block(
        response: dict[str, Any] | None,
        *,
        block_statuses: frozenset[int] = PERIMETER_BLOCK_STATUSES,
    ) -> bool:
        """``True`` when ``response['status_code']`` is an explicit perimeter block."""
        if not response:
            return False
        status = response.get("status_code")
        return isinstance(status, int) and status in block_statuses

    def _mutate_vector(self, category: str, vector: str, transform_name: str) -> str | None:
        """Apply one named transform to the original ``vector``.

        Returns ``None`` (instead of raising) for an unknown or
        ``binary_safe``-unsafe transform name so the retry loop degrades
        gracefully -- one bad entry in the chain just gets skipped, same
        convention as :meth:`~...modules.vulnerability_testers.
        base_tester_async.VulnerabilityTester._apply_runtime_mutations`.
        """
        probe_payload = Payload(vector=vector, category=category, context="waf_evasion")
        try:
            return self._mutator.mutate(probe_payload, [transform_name]).vector
        except (UnknownTransformError, UnsafeTransformError) as exc:
            self._log.debug("Skipping WAF-evasion transform %s (%s)", transform_name, exc)
            return None

    async def send_with_evasion(
        self,
        probe: ProbeFn,
        vector: str,
        *,
        category: str = "generic",
    ) -> WafEvasionResult:
        """Send ``vector`` via ``probe``; adaptively retry through mutations
        while the response is an explicit perimeter block.

        Every candidate in :attr:`DEFAULT_EVASION_TRANSFORMS` (or a custom
        ``transforms`` chain passed to the constructor) is tried, capped at
        ``max_retries``, against the *original* vector -- not chained onto
        each other -- until one clears the block or the chain is exhausted.
        """
        response = await probe(vector)
        if not self.is_perimeter_block(response, block_statuses=self._block_statuses):
            return WafEvasionResult(
                outcome=WafEvasionOutcome.NOT_BLOCKED,
                attempts=1,
                final_vector=vector,
                final_response=response,
                transform_chain=(),
                blocked_statuses=(),
            )

        blocked_statuses: list[int] = []
        first_status = response.get("status_code")
        if isinstance(first_status, int):
            blocked_statuses.append(first_status)

        applied: list[str] = []
        attempts = 1
        final_vector = vector
        for transform_name in self._transforms[: self._max_retries]:
            mutated_vector = self._mutate_vector(category, vector, transform_name)
            if mutated_vector is None:
                continue

            attempts += 1
            final_vector = mutated_vector
            response = await probe(mutated_vector)
            applied.append(transform_name)

            if not self.is_perimeter_block(response, block_statuses=self._block_statuses):
                return WafEvasionResult(
                    outcome=WafEvasionOutcome.BYPASSED,
                    attempts=attempts,
                    final_vector=mutated_vector,
                    final_response=response,
                    transform_chain=tuple(applied),
                    blocked_statuses=tuple(blocked_statuses),
                )

            status = response.get("status_code")
            if isinstance(status, int):
                blocked_statuses.append(status)

        return WafEvasionResult(
            outcome=WafEvasionOutcome.CONFIRMED_BLOCKED,
            attempts=attempts,
            final_vector=final_vector,
            final_response=response,
            transform_chain=tuple(applied),
            blocked_statuses=tuple(blocked_statuses),
        )
