"""Parameter-semantics heuristics: what a query parameter is *for*.

Motivation
----------
Web-flow-control parameters — ``next``, ``redirect``, ``return_to``, ``url`` —
carry a URL or a path, and the application validates that value before using
it. That validation is exactly what a differential injection oracle mistakes
for a vulnerability: inject ``' OR '1'='1`` into Django's
``/accounts/login/?next=/dashboard/`` and the app answers with a *different*
page (a 302 to a safe default, a "redirect URL is not valid" form error, or a
login page whose hidden ``next`` field changed length). Nothing was ever parsed
as SQL, LDAP or BSON, yet a length/status diff is enough for the injection
testers to fire.

The result is a steady stream of Critical/High false positives concentrated on
a handful of parameter names — the single worst kind of noise for a downstream
triage LLM, because the *label* is wrong while the evidence looks plausible.

Policy
------
On a parameter recognised as a redirect / path destination we require
**hard evidence** — an interpreter or database error signature, a confirmed
timing oracle, an out-of-band callback, or observed code execution. A mere
response divergence (status change, body-length shift, reflection) is not
enough and the finding is dropped. Hard-evidence findings survive but their
severity is capped below High unless the confidence is ``CONFIRMED``, so a
control-flow parameter can never top a report on a single ambiguous signal.

Auditability and ablation
-------------------------
Every verdict carries an ``action`` (``pass`` / ``kept`` / ``capped`` /
``suppressed`` / ``exempt``) and the evidence strength it was based on;
:meth:`RedirectParamVerdict.to_audit` renders that as the
``param_semantics_verdict`` record the base tester attaches to the finding
(suppressed findings keep it too, in ``param_semantics_suppressed`` and on the
``LOG_MESSAGE`` that reports the drop). The whole gate is switched off by the
``--no-param-semantics`` CLI flag (tester config key ``param_semantics``),
which is recorded in the run manifest.

The module is pure and dependency-free so testers, report code and the dataset
normaliser can all share one definition of "this is a redirect parameter".
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

# --------------------------------------------------------------------------- #
# Redirect / flow-control parameter names
# --------------------------------------------------------------------------- #
# Exact names first (fast path), then a loose pattern for the framework-flavoured
# variants (``redirect_uri``, ``returnUrl``, ``checkout_return_to`` ...). Kept
# deliberately tight: a name has to be *about* a destination, not merely contain
# a word like "id" or "page".
REDIRECT_PARAM_NAMES: frozenset[str] = frozenset({
    # Django / Flask / Rails / Laravel login flows
    "next", "next_url", "nexturl", "next_page",
    "redirect", "redirect_to", "redirect_uri", "redirect_url", "redirectto",
    "redirecturi", "redirecturl", "redir", "rd", "rdr",
    "return", "return_to", "return_url", "returnto", "returnurl",
    "returnpath", "back", "back_url", "backurl", "back_to",
    "continue", "continue_url", "goto", "go", "forward", "forward_url",
    "destination", "dest", "target_url", "callback_url",
    "success_url", "failure_url", "cancel_url", "logout_redirect",
    "service", "returnuri", "origin", "referer", "referrer",
    # Generic single-purpose URL/path holders
    "url", "uri", "link", "location", "path", "file_url", "image_url",
})

# ``*_url`` / ``*_uri`` / ``*redirect*`` / ``*return_to*`` and friends.
_REDIRECT_PARAM_RE = re.compile(
    r"(?:^|[_\-.])(?:next|redir(?:ect)?|return|back|goto|continue|forward|"
    r"dest(?:ination)?|success|failure|cancel)(?:[_\-.]?(?:to|url|uri|path|page))?$"
    # Bare ``callback`` is a JSONP function name, not a destination; only the
    # URL-suffixed forms (``callback_url``, ``callbackUri``...) are redirects.
    r"|(?:^|[_\-.])callback[_\-.]?(?:url|uri|path|page)$"
    r"|(?:^|[_\-.])(?:url|uri|urls)$"
    r"|^(?:next|redirect|return|back|goto|continue|forward|dest|destination)$",
    re.IGNORECASE,
)

# Names that are destinations only when the value proves it (see
# :func:`is_flow_control_point`). Matched whole, never as a substring.
_AMBIGUOUS_DEST_RE = re.compile(
    r"^(?:target|page|src|source|from|to|ref|r|u|view|load|template|site|domain)$",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------- #
# Evidence strength
# --------------------------------------------------------------------------- #
# A tester labels *why* it fired via ``evidence_kind`` on the finding dict.
# Only the hard kinds prove the payload reached an interpreter.
HARD_EVIDENCE_KINDS: frozenset[str] = frozenset({
    "error_signature",     # DBMS / LDAP / BSON parser error in the body
    "interpreter_error",   # generic engine stack trace
    "time_confirmed",      # timing oracle that survived a confirmation probe
    "oob",                 # out-of-band callback received
    "code_execution",      # command / template output observed
    "canary",              # unique canary rendered back by the interpreter
    # Divergence causally attributed to the payload's active syntax by the
    # syntactic-twin control (core.causal_oracle.CAUSAL_EVIDENCE_KIND). That
    # module's contract already documents it as registered here; it is hard
    # enough to survive the gate but NOT execution-grade, so it never earns
    # the CONFIRMED severity-cap waiver below.
    "differential_causal",
})

# Signals that only say "the response changed" — never conclusive on a
# parameter whose whole job is to be validated and redirected to.
SOFT_EVIDENCE_KINDS: frozenset[str] = frozenset({
    "differential",        # boolean-based / response-length or status diff
    "status_change",
    "reflection",
    "time_unconfirmed",    # latency spike we could not reproduce
})

# Within HARD_EVIDENCE_KINDS, only these are distinct enough from "URL
# validation rejected it" that a CONFIRMED oracle is allowed to waive the
# severity cap outright. error_signature / interpreter_error are pattern
# matches against response text: however reproducible and attributable via
# the double-oracle, a generic validator's own error page can coincidentally
# contain the same substring, so "CONFIRMED" there still isn't proof of
# execution the way a timing oracle, an OOB callback, observed code
# execution or a rendered canary is.
_CONFIRMED_BYPASS_KINDS: frozenset[str] = frozenset({
    "time_confirmed", "oob", "code_execution", "canary",
})

# Severity ladder used to cap a soft-ish finding on a flow-control parameter.
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_LABEL = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Highest severity a non-CONFIRMED finding may keep on a redirect parameter.
MAX_SEVERITY_ON_REDIRECT_PARAM = "Medium"


def is_redirect_param(name: str | None) -> bool:
    """True when ``name`` looks like a URL/path destination parameter.

    >>> is_redirect_param("next"), is_redirect_param("redirect_uri")
    (True, True)
    >>> is_redirect_param("id"), is_redirect_param("username")
    (False, False)
    """
    if not name:
        return False
    key = str(name).strip().lower()
    if not key:
        return False
    if key in REDIRECT_PARAM_NAMES:
        return True
    return bool(_REDIRECT_PARAM_RE.search(key))


def looks_like_url_value(value: str | None) -> bool:
    """True when ``value`` is a URL or an absolute/relative path.

    Used as a corroborating signal: a parameter named ``target`` holding
    ``/dashboard/`` is a redirect destination; one holding ``42`` probably is
    not. Percent-encoding is decoded first so ``%2Fdashboard%2F`` counts.
    """
    if not value:
        return False
    raw = unquote(str(value)).strip()
    if not raw:
        return False
    if raw.startswith(("/", "//", "\\\\", "./", "../")):
        return True
    parsed = urlparse(raw)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return True
    return False


def is_flow_control_point(name: str | None, value: str | None = None) -> bool:
    """True when the (name, value) pair identifies a web-flow-control input.

    The name alone is sufficient for the well-known destination parameters
    (:func:`is_redirect_param`). An *ambiguous* name — ``target``, ``page``,
    ``src``, ``ref``, ``u`` — only qualifies when the benign value observed on
    the endpoint is itself a URL or a path, which is the signal that the app
    treats it as a destination rather than as an identifier.
    """
    if is_redirect_param(name):
        return True
    if not name or not looks_like_url_value(value):
        return False
    return bool(_AMBIGUOUS_DEST_RE.match(str(name).strip().lower()))


def cap_severity(severity: str | None, ceiling: str = MAX_SEVERITY_ON_REDIRECT_PARAM) -> str:
    """Clamp ``severity`` to ``ceiling``, preserving anything already lower."""
    rank = _SEVERITY_RANK.get(str(severity or "Medium").strip().lower(), 2)
    cap = _SEVERITY_RANK.get(str(ceiling).strip().lower(), 2)
    return _SEVERITY_LABEL[min(rank, cap)] if rank > cap else str(severity or "Medium")


# --------------------------------------------------------------------------- #
# Auditability
# --------------------------------------------------------------------------- #
# Gate outcomes recorded in the ``param_semantics_verdict`` audit field.
ACTION_PASS = "pass"              # not a flow-control point: policy not applicable
ACTION_KEPT = "kept"              # flow-control point, finding left unchanged
ACTION_CAPPED = "capped"          # kept, severity demoted to the ceiling
ACTION_SUPPRESSED = "suppressed"  # dropped before emission
ACTION_EXEMPT = "exempt"          # tester's vuln class lives on these params

# Evidence-strength buckets recorded alongside the action.
STRENGTH_HARD = "hard"
STRENGTH_SOFT = "soft"
STRENGTH_UNLABELLED = "unlabelled"
STRENGTH_UNKNOWN = "unknown"      # a label outside both registries

# Testers whose vulnerability class is *defined* on destination parameters:
# an open redirect, an SSRF, a path traversal or a CRLF/Location injection on
# ``next`` / ``url`` / ``path`` is the finding itself, not noise explained by
# URL validation. The gate records them as ``exempt`` and never alters them.
# A tester may also opt in by setting a truthy ``flow_control_native`` class
# attribute (checked by the base tester).
FLOW_CONTROL_NATIVE_TESTERS: frozenset[str] = frozenset({
    "OpenRedirectTester", "SSRFTester", "PathTraversalTester", "CRLFTester",
})


def evidence_strength(evidence_kind: str | None) -> str:
    """Bucket an ``evidence_kind`` label as hard / soft / unlabelled / unknown.

    >>> evidence_strength("error_signature"), evidence_strength("differential")
    ('hard', 'soft')
    >>> evidence_strength(None), evidence_strength("header_reflection")
    ('unlabelled', 'unknown')
    """
    kind = str(evidence_kind or "").strip().lower()
    if not kind:
        return STRENGTH_UNLABELLED
    if kind in HARD_EVIDENCE_KINDS:
        return STRENGTH_HARD
    if kind in SOFT_EVIDENCE_KINDS:
        return STRENGTH_SOFT
    return STRENGTH_UNKNOWN


class RedirectParamVerdict:
    """Outcome of applying the redirect-parameter policy to a finding.

    ``keep`` is False when the finding must be discarded outright. When True,
    ``severity`` / ``confidence`` are the (possibly demoted) values to report
    and ``reason`` explains the adjustment for the log and the dataset.

    The audit attributes (``action``, ``evidence_kind``, ``evidence_strength``,
    ``flow_control``, ``original_severity``) make every decision inspectable:
    :meth:`to_audit` renders them as the ``param_semantics_verdict`` record the
    base tester attaches to the finding.
    """

    __slots__ = ("keep", "severity", "confidence", "reason", "action",
                 "evidence_kind", "evidence_strength", "flow_control",
                 "original_severity")

    def __init__(self, keep: bool, severity: str, confidence: str, reason: str = "",
                 *, action: str = ACTION_PASS, evidence_kind: str = "",
                 evidence_strength: str = STRENGTH_UNLABELLED,
                 flow_control: bool = False,
                 original_severity: str | None = None) -> None:
        self.keep = keep
        self.severity = severity
        self.confidence = confidence
        self.reason = reason
        self.action = action
        self.evidence_kind = evidence_kind
        self.evidence_strength = evidence_strength
        self.flow_control = flow_control
        self.original_severity = (original_severity if original_severity is not None
                                  else severity)

    def to_audit(self, *, parameter: str | None = None,
                 tester: str | None = None) -> dict[str, object]:
        """Return the JSON-serialisable ``param_semantics_verdict`` record."""
        record: dict[str, object] = {
            "action": self.action,
            "reason": self.reason,
            "parameter": parameter,
            "flow_control": self.flow_control,
            "evidence_kind": self.evidence_kind or None,
            "evidence_strength": self.evidence_strength,
            "original_severity": self.original_severity,
            "final_severity": self.severity if self.keep else None,
        }
        if tester is not None:
            record["tester"] = tester
        return record

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"RedirectParamVerdict(keep={self.keep}, action={self.action!r}, "
                f"severity={self.severity!r}, confidence={self.confidence!r}, "
                f"reason={self.reason!r})")


def apply_redirect_param_policy(
    *,
    parameter: str | None,
    evidence_kind: str | None,
    severity: str | None,
    confidence: str | None,
    baseline_value: str | None = None,
    cap_unlabelled: bool = False,
) -> RedirectParamVerdict:
    """Decide whether an injection finding on ``parameter`` survives.

    Non-redirect parameters pass through untouched. On a redirect parameter:

    * soft evidence (a response divergence, a reflection, an unconfirmed timing
      spike) -> dropped, since URL validation and the redirect itself explain
      the divergence without any injection;
    * hard evidence (DB/LDAP/BSON error, confirmed timing oracle, OOB callback,
      observed execution) -> kept, but severity is capped at ``Medium``. The
      cap is waived only for execution-grade kinds (timing/OOB/code-execution/
      canary — see :data:`_CONFIRMED_BYPASS_KINDS`) whose confidence is already
      ``CONFIRMED``; a pattern-matched error signature stays capped at every
      confidence tier, since even a double-oracle-clean match cannot rule out
      a validator's own error page coincidentally containing the signature;
    * an unlabelled finding (``evidence_kind`` missing) has not proven
      execution. By default it is treated as soft and dropped; with
      ``cap_unlabelled=True`` it is kept with its severity capped instead —
      the mode the base tester uses for testers that do not (yet) emit an
      ``evidence_kind``, because a capped finding stays visible and its audit
      record lets the cap be undone, whereas a drop would hide it;
    * an unknown label (outside both registries) is treated as soft.

    Every verdict carries ``action`` / ``evidence_strength`` / ``flow_control``
    so the caller can record an audit trail (:meth:`RedirectParamVerdict.to_audit`).
    """
    sev = str(severity or "Medium")
    conf = str(confidence or "MEDIUM").upper()
    kind = str(evidence_kind or "").strip().lower()
    strength = evidence_strength(kind)

    if not is_flow_control_point(parameter, baseline_value):
        return RedirectParamVerdict(True, sev, conf, action=ACTION_PASS,
                                    evidence_kind=kind, evidence_strength=strength)

    def _verdict(keep: bool, final_sev: str, action: str, reason: str) -> RedirectParamVerdict:
        return RedirectParamVerdict(
            keep, final_sev, conf, reason, action=action, evidence_kind=kind,
            evidence_strength=strength, flow_control=True, original_severity=sev)

    if strength == STRENGTH_UNLABELLED and cap_unlabelled:
        capped = cap_severity(sev)
        if capped == sev:
            return _verdict(True, sev, ACTION_KEPT,
                            f"unlabelled evidence on redirect/flow-control "
                            f"parameter {parameter!r}; severity already at or "
                            f"below {MAX_SEVERITY_ON_REDIRECT_PARAM}")
        return _verdict(True, capped, ACTION_CAPPED,
                        f"severity {sev} -> {capped}: unlabelled evidence on "
                        f"redirect/flow-control parameter {parameter!r} (the "
                        f"tester did not state why it fired)")

    if strength != STRENGTH_HARD:
        return _verdict(False, sev, ACTION_SUPPRESSED,
                        f"redirect/flow-control parameter {parameter!r}: "
                        f"{kind or 'unlabelled'} evidence is explained by URL "
                        f"validation or the redirect itself, not by injection")

    if conf == "CONFIRMED" and kind in _CONFIRMED_BYPASS_KINDS:
        return _verdict(True, sev, ACTION_KEPT,
                        f"{kind} evidence at CONFIRMED confidence waives the "
                        f"severity cap on parameter {parameter!r}")

    capped = cap_severity(sev)
    if capped != sev:
        return _verdict(True, capped, ACTION_CAPPED,
                        f"severity {sev} -> {capped}: {kind} evidence on "
                        f"redirect/flow-control parameter {parameter!r} without a "
                        f"CONFIRMED oracle")
    return _verdict(True, sev, ACTION_KEPT, "")
