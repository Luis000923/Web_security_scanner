"""Causality attribution for differential injection oracles.

Why this module exists
----------------------
A differential injection oracle asks one question: *did the response change when
the operator payload was sent?* On a template that can actually absorb a payload
that is a weak test. On a rigid one it is close to vacuous: OWASP Benchmark's
benign GET baseline is a single character, so :meth:`response_differs_significantly`
crosses its 10 % length threshold for *any* response at all -- including the ones
produced by a mechanism that never parsed anything as an operator (a path that
resolves to a non-existent file, a session cookie the app now rejects, a
validation error page).

Measured consequence, OWASP Benchmark, 194 vulnerable instances: 185 of the 354
correctly-located findings named the wrong vulnerability class (79 NoSQL, 75
SQL, 31 LDAP). The same instances also count as true positives in the benchmark's
own per-case boolean, because that flag records *whether* a case is vulnerable
and never *which* class. The location is right and the label is wrong.

The control payload
-------------------
The fix is the standard falsification control, and it is one extra round-trip:
send the payload's **semantic twin** -- the same bytes with the meaning inverted
-- and look at what the target does.

===========================  ==========================
payload (asserts true)       twin (asserts false)
===========================  ==========================
``' AND 1=1--``              ``' AND 1=2--``
``{"$ne": ""}``              ``{"$eq": ""}``
``{"$gt": ""}``              ``{"$lt": ""}``
``*)(uid=*``                 ``*)(uid=_``
===========================  ==========================

An interpreter evaluates both and returns two different answers. Anything that
is not an interpreter returns *the same* answer twice -- the 404, the error
page, the empty body -- because it reacted to the payload being present, not to
what it said. Same answer twice is the falsification, and it is the only
outcome that withholds a report.

Two properties the twin must have, both load-bearing
---------------------------------------------------
1. **Same byte length.** The dominant false-positive mechanism is a response
   whose length tracks the length of the input. A control of a different size
   would move that length too, the two would differ for a reason that has
   nothing to do with the operator, and the oracle would attribute causality to
   the very effect it is meant to explain away. Every inversion in this module
   is length-preserving, and :func:`semantic_twin` returns ``None`` rather than
   a twin it cannot build to that rule.
2. **Same family, not just the same size.** ``UNION SELECT`` has no same-length
   inversion that is still a well-formed ``UNION SELECT``, so it has no twin.
   Those payloads keep the pre-existing behaviour: the oracle can only *falsify*
   a finding, never withhold one for want of a control.

Consequently the oracle is asymmetric on purpose. A missing or unreachable twin
is *not* evidence against the finding (``no-control`` / ``twin-unavailable``
both keep it) -- absence of a control is not a refutation. Only an actively
contradicting twin withholds (``twin-matches-payload``).

Evidence labelling
------------------
A causally attributed divergence is not the same claim as a bare one, so it
carries its own ``evidence_kind``: :data:`CAUSAL_EVIDENCE_KIND`
(``"differential_causal"``), registered in
:data:`web_security_scanner.core.param_semantics.HARD_EVIDENCE_KINDS`. The
unattributed verdict is labelled :data:`UNATTRIBUTED_EVIDENCE_KIND` and is never
emitted, because no finding should advertise evidence that was not established.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Any, ClassVar, Protocol, cast
from urllib.parse import quote

__all__ = [
    "CAUSAL_EVIDENCE_KIND",
    "UNATTRIBUTED_EVIDENCE_KIND",
    "CausalAttribution",
    "CausalOracleMixin",
    "attribute_divergence",
    "responses_equivalent",
    "semantic_twin",
    "twin_is_available",
]

#: Evidence kind for a response divergence that survived the control payload.
CAUSAL_EVIDENCE_KIND = "differential_causal"

#: Evidence kind for a divergence the control payload explained away. Internal:
#: a finding carrying it is withheld, so no report should ever show it.
UNATTRIBUTED_EVIDENCE_KIND = "differential_unattributed"

# Class tokens. Deliberately not the i18n strings from ``vulnerabilities.*``:
# those are translated, and a control oracle whose behaviour depends on the
# report language is not a control oracle.
NOSQL = "nosql"
SQLI = "sqli"
LDAP = "ldap"


# --------------------------------------------------------------------------- #
# Inversion tables
# --------------------------------------------------------------------------- #

#: NoSQL operator -> its semantic opposite, all pairs byte-equal in length.
#: Every value is a real MongoDB operator, so a genuine interpreter evaluates
#: both members of each pair rather than rejecting one as malformed.
#:
#: ``$in`` is deliberately absent. Its opposite, ``$nin``, is one byte wider and
#: the length-preserving repair (a trailing space inside the operator name) only
#: works in one direction: a real driver reads ``"$in "`` as an unknown operator,
#: but there is no single byte to drop from ``"$nin"``. An asymmetric table
#: hides that, so ``{"$in": []}`` is an honestly uncontrollable payload that keeps
#: the pre-existing behaviour.
_NOSQL_OPPOSITES: dict[str, str] = {
    "$ne": "$eq",
    "$eq": "$ne",
    "$gt": "$lt",
    "$lt": "$gt",
    "$gte": "$lte",
    "$lte": "$gte",
    "$nin": "$in ",
}

#: JavaScript equality -> its negation, byte for byte. ``==`` is two characters and
#: ``!=`` is two; ``===`` is three and ``!==`` is three. This is the control that
#: the dominant NoSQL cross-class family needs: OWASP Benchmark's ``$where``
#: payloads are JS functions whose predicates are a chain of ``== 'value'``
#: comparisons, and a body quoted with double quotes escapes every rule that
#: looks for a single-quoted literal, so before this entry the single most
#: frequent source of a mislabelled NoSQL finding had no control at all and kept
#: the pre-existing behaviour.
_NOSQL_EQUALITY_OPPOSITES: dict[str, str] = {
    "===": "!==",
    "==": "!=",
    "!==": "===",
    "!=": "==",
}
_JS_EQUALITY_RE = re.compile(r"={2,3}|!={1,2}")

#: A bare ``true`` inside a JavaScript predicate. Word boundaries on both sides so
#: it cannot match inside an identifier (``truely``, ``untrue``).
_JS_TRUE_LITERAL_RE = re.compile(r"\btrue\b")

#: A JavaScript regex literal that matches everything, and the same-width one
#: that matches nothing: ``/.*/`` -> ``/^$/``. Applies inside a ``$where`` body,
#: where the SQL-oriented ``{"$regex": "..."}`` rule cannot see it.
_JS_REGEX_LITERAL_RE = re.compile(r"/\.\*/|/(\.\+)/")

#: ``{"$exists": true}`` -> ``{"$exists": null}``: "the field is present" against
#: "the field's value is null", which for a real document means not present.
#: Same width, opposite meaning, both valid operators. ``$exists`` is absent from
#: :data:`_NOSQL_OPPOSITES` on purpose -- it maps to itself and needs the
#: argument inverted rather than the operator. The key may be single- or
#: double-quoted and the separator may be padded, so the pattern anchors on the
#: operator name and captures everything up to the value.
_NOSQL_EXISTS_TRUE_RE = re.compile(r"(\$exists['\"]?\s*:\s*)true", re.IGNORECASE)

#: ``{"$regex":"..."}`` bodies: a matcher and a same-width non-matcher.
_NOSQL_REGEX_BODIES: tuple[tuple[str, str], ...] = (
    (".*", "^$"),
    (".+", "^$"),
)

#: ``$where`` JavaScript predicates: same width, flipped comparison.
_NOSQL_WHERE_BODIES: tuple[tuple[str, str], ...] = (
    ("1==1", "1==0"),
    ("1==0", "1==1"),
)

_NOSQL_OP_RE = re.compile(r"\$[A-Za-z]+")
_QUOTED_BODY_RE = re.compile(r":\s*'([^']*)'")
#: A numeric tautology anywhere in the payload, with no left or right boundary.
#: Boundaries look like the right guard and are the wrong one: the WAF-evasion
#: family spells its whitespace as an escape whose *last* character is a digit
#: (``%0b1=1``, ``%a01=1``, ``%091=1``), so a ``(?<!\d)`` lookbehind refuses the
#: comparison on exactly the payloads an evasion chain produces -- the ones most
#: likely to be reported by mistake. An unanchored pattern still cannot invent
#: one: it needs two digit runs around an ``=``, which is the comparison.
_NUMERIC_CMP_RE = re.compile(r"(\d{1,9})\s*=\s*(\d{1,9})")
#: A closed parenthesised expression compared against a scalar -- the subquery
#: probe ``(SELECT 1 FROM users WHERE ...) = 1``. Group 1 is the scalar.
_SUBQUERY_CMP_RE = re.compile(r"\)\s*=\s*(\d{1,9})")
# A value compared against itself, with the quotes that make it a string
# comparison: '1'='1, '1'=='1. Nothing is required after the right operand --
# these payloads routinely end on the literal (' OR '1'='1) -- which is why a
# naive "'\w+'='\w+'" pattern misses half the default NoSQL payload list.
_QUOTED_SELF_CMP_RE = re.compile(
    r"(?P<left>[A-Za-z0-9]{1,8})'\s*=+\s*'(?P<right>[A-Za-z0-9]{1,8})")

#: LDAP wildcard ``*`` as a whole token: string edge or a non-alphanumeric
#: neighbour. ``*)(uid=*`` yields two candidates and the *last* one is the
#: quantifier the injected clause introduced.
_LDAP_WILDCARD_RE = re.compile(r"(?<![A-Za-z0-9])\*(?![A-Za-z0-9])")

#: Replacement for an LDAP ``*``. Same width, and not a value any attribute
#: plausibly holds, so "has a uid" and "has uid = _" disagree.
_LDAP_NON_MATCH = "_"


# --------------------------------------------------------------------------- #
# Twin construction
# --------------------------------------------------------------------------- #

def _flip_value(value: str) -> str:
    """Return ``value`` with its last character replaced by a different one.

    Width-preserving by construction, which is the whole point: ``1`` -> ``2``,
    ``10`` -> ``11``, ``a`` -> ``b``, ``A`` -> ``B``. Case and character class
    are preserved, so the twin cannot change the payload's length, its encoding
    or the shape of the expression it sits in.
    """
    if not value:
        return value
    last = value[-1]
    if last.isdigit():
        return value[:-1] + str((int(last) + 1) % 10)
    if last.islower():
        return value[:-1] + chr((ord(last) - ord("a") + 1) % 26 + ord("a"))
    if last.isupper():
        return value[:-1] + chr((ord(last) - ord("A") + 1) % 26 + ord("A"))
    return value[:-1] + ("0" if last != "0" else "1")


def _flip_token(token: str) -> str:
    """Replace the last *character* of a token with a same-class different one.

    The value analogue of :func:`_flip_value`, for tokens that are not single
    digits: ``/root`` -> ``/ropt``, ``admin`` -> ``admi``. Width is preserved
    exactly, which is what lets an equality filter's asserted value be inverted
    without changing the filter's length -- and therefore without changing the
    response length by the one thing the twin must not change.
    """
    if not token:
        return token
    return _flip_value(token)


def _invert_self_comparison(payload: str) -> str | None:
    """Flip a tautology into a contradiction, keeping every width.

    ``' OR '1'='1`` -> ``' OR '1'='0``;  ``' AND 1=1--`` -> ``' AND 1=2--``.

    The twin is a *behavioural discriminator*, not a formal logical negation:
    ``A OR TRUE`` and ``A OR FALSE`` are not each other's complement. That is
    enough for the control and it is all the control needs. The question is
    never "is the twin false?" but "does the target treat these two payloads
    differently?" -- an interpreter does, anything that merely rejected the
    input as malformed does not.

    Returns ``None`` when the comparison is *already* a contradiction. Widening
    it into a tautology needs more bytes than it has, and a control of the wrong
    size is worse than no control at all.
    """
    match = _QUOTED_SELF_CMP_RE.search(payload)
    if match and match.group("left") == match.group("right"):
        right = match.group("right")
        # Flip only the right operand: the comparison keeps its width and its
        # shape, and stops asserting what it asserted.
        at = match.start("right") + len(right) - 1
        return payload[:at] + _flip_value(right[-1]) + payload[at + 1:]

    match = _NUMERIC_CMP_RE.search(payload)
    if match:
        left_run, right = match.group(1), match.group(2)
        # Two ambiguities, one rule. The operands of a numeric comparison are
        # *numbers*, so compare them as numbers: ``01=1`` -- what a payload
        # carrying a ``%a0`` escape in front of the comparison looks like -- is
        # the tautology it was meant to be, not a contradiction. And a
        # percent-escape whose trailing digit runs into the comparison
        # (``%201=1``) leaves the left operand's edge undetermined: the run
        # could be "201", "01" or "1". Reading it shortest-first settles it, since
        # the escape's own digits stay with the escape.
        for width in range(1, len(left_run) + 1):
            if int(left_run[-width:]) != int(right):
                continue
            return (payload[: match.start(2)] + _flip_value(right)
                    + payload[match.end(2):])
        return None  # already false; see the docstring

    # A subquery compared against a scalar: ``(SELECT ...)=1``. The left side is
    # an expression, not a literal, so the rule above cannot see the comparison
    # and would report a tautology it can only find as a trailing ``=1``. The
    # ``)`` anchor is what makes this unambiguous -- a bare ``=1`` with an
    # unclosed parenthesis is a fragment, not a comparison.
    match = _SUBQUERY_CMP_RE.search(payload)
    if match:
        return (payload[: match.start(1)]
                + _flip_value(match.group(1)) + payload[match.end(1):])
    return None


def _nosql_twin(payload: str) -> str | None:
    """Invert a NoSQL operator payload, preserving its length exactly."""
    exists = _NOSQL_EXISTS_TRUE_RE.search(payload)
    if exists:
        return (payload[: exists.start()] + exists.group(1) + "null"
                + payload[exists.end():])

    # Every operator, not just the first: a body-injection payload carries a
    # whole expression (``username[$in][]=admin&username[$in][]=root``) where
    # the first token is uncontrollable and a later one may not be. Bailing on
    # the first match would hand back `None` for a payload that does have a
    # usable control further along.
    for match in _NOSQL_OP_RE.finditer(payload):
        opposite = _NOSQL_OPPOSITES.get(match.group(0))
        if opposite is None:
            continue
        twin = (payload[: match.start()] + opposite + payload[match.end():])
        # The "$nin" -> "$in " entry buys its length back with a trailing space;
        # check the totals rather than trust the table to stay honest.
        if len(twin) == len(payload):
            return twin
        break  # the table is a fixed bijection: one miss means all miss

    # A quoted body directly after an operator: invert its semantics.
    body = _QUOTED_BODY_RE.search(payload)
    if body and _NOSQL_OP_RE.search(payload):
        inner = body.group(1)
        for asserted, negated in _NOSQL_REGEX_BODIES:
            if inner == asserted and len(negated) == len(inner):
                return _replace_body(payload, body, negated)
        if re.search(r"\$where", payload, re.IGNORECASE):
            for asserted, negated in _NOSQL_WHERE_BODIES:
                if inner == asserted and len(negated) == len(inner):
                    return _replace_body(payload, body, negated)
        return None

    # The quoted self-comparison rule goes first: it is the more specific one and
    # it is the rule the string-form payloads were designed around. The
    # JavaScript fallback below is deliberately last for that reason.
    inverted = _invert_self_comparison(payload)
    if inverted is not None:
        return inverted

    # A JavaScript predicate: flip the catch-all regex literal it leans on, or the
    # equalities it asserts. This is the control the dominant NoSQL cross-class
    # family needs and it has no other. A ``$where`` body is a JS function quoted
    # with *double* quotes, so every rule above -- which all look for a
    # single-quoted literal or a ``{"$op": ...}`` pair -- reads it as opaque, and
    # the rule just tried only understands single-quoted ``'x'='y'``.
    regex_literal = _JS_REGEX_LITERAL_RE.search(payload)
    if regex_literal is not None:
        replacement = "/^$/" if regex_literal.group(0).endswith(".*/") else "/^?/"
        twin = _JS_REGEX_LITERAL_RE.sub(lambda _m: replacement, payload, count=1)
        if len(twin) == len(payload):
            return twin
    equality = _JS_EQUALITY_RE.search(payload)
    if equality is not None:
        return (payload[: equality.start()]
                + _NOSQL_EQUALITY_OPPOSITES[equality.group(0)]
                + payload[equality.end():])

    # A bare boolean literal is a proposition on its own: ``$where`` bodies are
    # full of ``return true``. ``null`` is the equal-width counterpart -- also
    # falsy-adjacent in the sense that matters here, since the twin must make the
    # predicate *fail* where the payload made it succeed. No truthy/falsy pair of
    # equal width exists in JavaScript (``false`` is 5 and ``true`` is 4), which is
    # why the table is one entry instead of two.
    literal = _JS_TRUE_LITERAL_RE.search(payload)
    if literal is not None:
        return (payload[: literal.start()] + "null"
                + payload[literal.end():])
    return None


def _replace_body(payload: str, match: re.Match[str], replacement: str) -> str:
    """Rewrite a quoted operator body, keeping the surrounding delimiters."""
    return payload[: match.start(1)] + replacement + payload[match.end(1):]


def _sqli_twin(payload: str) -> str | None:
    """Invert a SQL boolean payload, preserving its length exactly."""
    return _invert_self_comparison(payload)


#: The right-hand side of an LDAP equality filter: ``homeDirectory=/root``.
#: Group 1 is the asserted value. Used only when the payload carries no wildcard,
#: where inverting the pattern is not an option.
#:
#: The value charset stops at the filter's own punctuation on purpose. A greedy
#: ``\S+`` swallows the trailing ``))`` of ``cn=admin))`` and would then flip a
#: closing parenthesis -- breaking the filter's structure instead of its
#: proposition, which is not an inversion at all. Restricting to the characters
#: that can actually appear in an attribute value keeps the edit inside the
#: assertion.
_LDAP_VALUE_EQ_RE = re.compile(r"(?<=[=<>~])([A-Za-z0-9._/-]+)")


def _ldap_twin(payload: str) -> str | None:
    """Replace the injected LDAP wildcard with an equal-width non-matcher.

    ``*)(uid=*`` -> ``*)(uid=_``. A filter engine answers the two differently
    (``uid=*`` matches, ``uid=_`` does not). A target that never built a filter
    answers identically, and that is the falsification.
    """
    matches = list(_LDAP_WILDCARD_RE.finditer(payload))
    if matches:
        last = matches[-1]
        twin = payload[: last.start()] + _LDAP_NON_MATCH + payload[last.end():]
        if len(twin) == len(payload):
            return twin

    # No wildcard to flip: the filter asserts a *value*, not a pattern.
    # ``admin)(|(homeDirectory=/root))`` is a conjunction over an equality
    # filter, and the equality is the proposition. Changing the right-hand side
    # to an equal-width string that cannot match inverts it -- on a real
    # directory the two filters return different entries, and on a target that
    # never built a filter they return the same error.
    equality = _LDAP_VALUE_EQ_RE.search(payload)
    if equality is not None:
        flipped = _flip_token(equality.group(1))
        twin = payload[: equality.start(1)] + flipped + payload[equality.end(1):]
        if twin != payload and len(twin) == len(payload):
            return twin
    return None


_TWIN_RULES = {
    NOSQL: _nosql_twin,
    SQLI: _sqli_twin,
    LDAP: _ldap_twin,
}


def semantic_twin(payload: str, vuln_class: str) -> str | None:
    """Return a same-length control payload with the opposite meaning.

    ``None`` means *no control exists* for this payload, which the callers must
    read as "keep the pre-existing behaviour" and never as "the finding is
    false". Payloads are refused rather than approximated whenever a
    length-preserving inversion cannot be built, because a control of the wrong
    size is worse than no control: it would move the very response length that
    motivates the control in the first place.

    >>> semantic_twin("' AND 1=1-- -", "sqli")
    "' AND 1=2-- -"
    >>> semantic_twin("*)(uid=*", "ldap")
    '*)(uid=_'
    >>> semantic_twin("' UNION SELECT 1,2-- -", "sqli") is None
    True
    """
    rule = _TWIN_RULES.get(str(vuln_class or "").strip().lower())
    if rule is None:
        return None
    text = str(payload or "")
    twin = rule(text)
    if twin is None or twin == text or len(twin) != len(text):
        return None
    return twin


# --------------------------------------------------------------------------- #
# Verdict
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class CausalAttribution:
    """Outcome of comparing a payload's response against its control's.

    ``attributed`` is the answer to "may this finding be reported?". It is True
    in every case except ``twin-matches-payload``: a control we could not build
    or could not fetch has not refuted anything, and a finding is not supposed
    to disappear because the scanner ran out of budget.
    """

    attributed: bool
    reason: str
    twin: str | None = None
    twin_status: int | None = None

    @property
    def evidence_kind(self) -> str:
        """The ``evidence_kind`` this verdict licenses, or ``""`` to withhold."""
        if not self.attributed:
            return UNATTRIBUTED_EVIDENCE_KIND
        return CAUSAL_EVIDENCE_KIND if self.twin else ""


#: Whitespace runs carry no meaning for "did the target behave differently", and
#: collapsing them stops a pretty-printed error page from counting as a
#: behavioural difference against its own twin.
_WS_RE = re.compile(r"\s+")


def _normalised_body(response: dict[str, Any] | None) -> str:
    if not isinstance(response, dict):
        return ""
    return _WS_RE.sub(" ", str(response.get("text", "") or "")).strip()


#: Where a request can leave its own mark on the body it came back with, and how
#: to recognise each spelling. OWASP Benchmark numeric-entity-escapes every
#: non-alphanumeric character it reflects (``*)(uid=*`` arrives as
#: ``&#x2a;&#x29;&#x28;uid&#x3d;&#x2a;``), which is why a reflection check written
#: against the raw body sees nothing; the scanner needs the escaped spellings too.
_ECHO_PLACEHOLDER = "\x00"


def _numeric_entity_form(text: str) -> str:
    """Reproduce a framework's per-character entity escaping of ``text``."""
    return "".join(
        char if char.isalnum() else f"&#x{ord(char):x};" for char in text
    )


def _echo_forms(*tokens: str | None) -> tuple[str, ...]:
    """Every encoding under which ``tokens`` can appear inside a response body.

    Only forms long enough to be a marker of their own are returned. A one- or
    two-character payload (``1``, ``*)``) would have its echo stripped from
    unrelated parts of the page, which is a much worse error than missing an
    echo that a length rule would have caught anyway.
    """
    forms: list[str] = []
    for token in tokens:
        if not token or len(token) < 3:
            continue
        for form in (
            token,
            _numeric_entity_form(token),
            html.escape(token, quote=True),
            quote(token, safe=""),
        ):
            if form and len(form) >= 3 and form not in forms:
                forms.append(form)
    return tuple(forms)


def _echo_free(body: str, forms: tuple[str, ...]) -> str:
    """Remove the echo of the scanner's own input from ``body``."""
    for form in forms:
        body = body.replace(form, _ECHO_PLACEHOLDER)
    return body


#: Longest run of the payload that has to survive in a body for the echo to be
#: called observable. 24 characters is short enough to catch a body that kept the
#: frame of the payload and dropped a literal out of the middle of it, and long
#: enough that no error page assembled from the payload's fragments by accident
#: reaches it.
_ECHO_MIN_SLICE = 24


def _echo_visible(body: str, tokens: tuple[str | None, ...]) -> bool:
    """True when ``body`` visibly carries ``tokens`` back to the scanner.

    Whole-token matching is not enough, and the reason is the interesting one.
    OWASP Benchmark normalises the input before echoing it: a payload carrying
    ``LIKE '%<314 digits>%'`` comes back as ``LIKE '%'``, so the literal token is
    absent from the body even though the body is nothing but the payload. What
    survives is a long contiguous run of it, so that is what is looked for.

    ``tokens`` accepts ``None`` entries (``payload`` is optional at the call
    site in :func:`attribute_divergence`) and skips them the same as an empty
    string -- there is nothing to search for in either case.
    """
    if not body:
        return False
    for token in tokens:
        if not token:
            continue
        if any(form in body for form in _echo_forms(token)):
            return True
        if len(token) >= _ECHO_MIN_SLICE:
            for start in range(len(token) - _ECHO_MIN_SLICE + 1):
                if token[start:start + _ECHO_MIN_SLICE] in body:
                    return True
    return False


def twin_is_available(response: dict[str, Any] | None) -> bool:
    """True when ``response`` carries an actual observation of the control.

    ``status_code`` 0 is what :meth:`AsyncScannerCore._request_with_resilience`
    hands back for every transport failure, so a twin that never reached the
    target is recognised here rather than silently read as "the target said
    nothing interesting".
    """
    if not isinstance(response, dict) or not response:
        return False
    status = response.get("status_code")
    if not isinstance(status, int) or status <= 0:
        return False
    return "text" in response


def responses_equivalent(
    a: dict[str, Any] | None,
    b: dict[str, Any] | None,
    *,
    absolute_tolerance: int = 8,
    relative_tolerance: float = 0.02,
    ignore: tuple[str, ...] = (),
) -> bool:
    """True when two responses are the *same* answer, not merely similar.

    This is the mirror image of ``response_differs_significantly`` and it is
    deliberately stricter, because the question is the opposite one. Asking
    "did these differ?" over a threshold tuned to catch 10 % drift calls a
    3-character baseline and a 4-character baseline different; asking "are
    these the same?" wants to be hard to satisfy.

    Status must match exactly. Bodies match when their whitespace-collapsed
    forms are equal. Beyond that the rule is asymmetric on purpose:

    * **Equal length, different content is a real difference.** A JSON API that
      answers ``{"ok":1}`` to one operator and ``{"ok":0}`` to its twin has
      answered twice, in the same number of bytes. A length-only tolerance would
      call that "the same" and erase exactly the control result this oracle
      exists to read.
    * **A length change within the noise floor is treated as the same answer.**
      Request ids, timestamps and nonces differ between two probes of the same
      endpoint whatever the payload was, and reading that as a behavioural
      difference would attribute causality to the scanner's own footprint.
    * **A length change beyond the floor is a real difference** -- a different
      result set, an error page instead of a table.

    ``ignore`` lists spellings of the request that must be removed from both
    bodies before comparing. It exists for a specific reason: on a target that
    echoes its input, the payload's body and the twin's body differ *only* in
    the echoed bytes, so an unstripped comparison reads the scanner's own
    footprint as the target's behaviour and attributes causality to a payload
    that changed nothing. Reflection is not interpretation -- which is why this
    branch of the scanner is blind to it, and why that blindness is correct
    rather than a gap. A target that both echoes and interprets still differs
    outside the echo.

    The floor is 8 bytes, and small on purpose. The false positives this oracle
    is built to falsify produce *byte-identical* bodies -- the same 404, the
    same error page, the same empty response -- because the mechanism that
    triggered them never looked at what the payload said. No tolerance is
    needed to catch those, and every extra byte of tolerance here buys back FP
    suppression at the cost of suppressing a real one-row difference on a small
    page. This function's errors are not symmetric: a false "equivalent" deletes
    a detection, a false "different" keeps a false positive.
    """
    if not isinstance(a, dict) or not isinstance(b, dict):
        return True  # nothing to compare: never manufacture a difference
    if a.get("status_code") != b.get("status_code"):
        return False
    body_a, body_b = _normalised_body(a), _normalised_body(b)
    if ignore:
        body_a, body_b = _echo_free(body_a, ignore), _echo_free(body_b, ignore)
    if body_a == body_b:
        return True
    delta = abs(len(body_a) - len(body_b))
    if delta == 0:
        return False  # same size, different bytes: two answers, not one
    longest = max(len(body_a), len(body_b))
    tolerance = max(absolute_tolerance, int(longest * relative_tolerance))
    # A length-only tolerance is not enough: two short bodies that differ in
    # *content* (a different error page, not a nonce) can still land within
    # `tolerance` of each other's length by coincidence, and get called "the
    # same answer" even though nothing about them actually matches beyond
    # size. What the tolerance is meant to forgive is noise *appended or
    # inserted* into an otherwise-identical body (a request id, a timestamp),
    # not a body that merely happens to be a similar length. So measure what
    # changed, not just by how much the totals differ: strip the common
    # prefix and the common suffix the two bodies share, and only the
    # leftover -- the part that isn't shared at all -- has to fit inside the
    # tolerance.
    min_len = min(len(body_a), len(body_b))
    prefix = 0
    while prefix < min_len and body_a[prefix] == body_b[prefix]:
        prefix += 1
    suffix = 0
    max_suffix = min_len - prefix
    while suffix < max_suffix and body_a[-1 - suffix] == body_b[-1 - suffix]:
        suffix += 1
    changed_a = len(body_a) - prefix - suffix
    changed_b = len(body_b) - prefix - suffix
    return delta <= tolerance and max(changed_a, changed_b) <= tolerance


def attribute_divergence(
    test_response: dict[str, Any],
    twin_response: dict[str, Any] | None,
    twin: str | None,
    *,
    payload: str | None = None,
) -> CausalAttribution:
    """Decide whether a response divergence survives its control payload.

    * no twin was built -> keep (the control cannot falsify anything)
    * twin unreachable / transport error -> keep (absence of a control is not a
      refutation; this is what keeps a budget-exhausted control from deleting a
      real detection)
    * twin answers exactly like the payload -> **withhold**: the target reacted
      to the payload being present, not to what it asserted
    * twin answers differently -> attribute: only the meaning moved the target

    ``payload`` is the string whose echo must not count as behaviour. Omitting it
    only costs the echo stripping in :func:`responses_equivalent`; the verdict is
    still sound, just less able to see through a reflecting target.

    A reflecting target cannot produce a trustworthy attribution at all, and the
    reason is worth stating precisely because stripping is not enough. OWASP
    Benchmark normalises the input before echoing it -- a payload carrying
    ``LIKE '%314-digit-string%'`` comes back as ``LIKE '%'`` -- so the two bodies
    differ at a position where the payload and the twin differ, but no literal
    search finds the token to strip. Every difference between the payload's body
    and the twin's body is then still explicable as the echo of a one-byte
    difference in the request, and reading it as behaviour would assert causality
    for a finding that is pure reflection. So once reflection is established, a
    body difference is not evidence: ``twin-diverges`` stops attributing.

    The cost is a real false-negative risk on a reflecting endpoint that both
    echoes and interprets, where the interpretation shows up outside the echo.
    That trade is deliberate and is the same one the reflection guard already
    makes in these testers: a reflected injection is not evidence of an injected
    one, and a wrong ``differential_causal`` label is worse than a missed
    detection, because it survives into the report as if it had been proven.
    """
    if twin is None:
        return CausalAttribution(True, "no-control")
    if not twin_is_available(twin_response):
        return CausalAttribution(True, "twin-unavailable", twin)
    status = twin_response.get("status_code") if isinstance(twin_response, dict) else None
    forms = _echo_forms(payload, twin)
    if responses_equivalent(test_response, twin_response, ignore=forms):
        return CausalAttribution(
            False, "twin-matches-payload", twin,
            status if isinstance(status, int) else None,
        )
    if _echo_visible(_normalised_body(test_response), (payload, twin)) or _echo_visible(
        _normalised_body(twin_response), (payload, twin)
    ):
        return CausalAttribution(
            False, "twin-diverges-echo", twin,
            status if isinstance(status, int) else None,
        )
    return CausalAttribution(
        True, "twin-diverges", twin,
        status if isinstance(status, int) else None,
    )


# --------------------------------------------------------------------------- #
# Async wiring
# --------------------------------------------------------------------------- #

class _ProbeCapable(Protocol):
    """The slice of :class:`VulnerabilityTester` the control needs."""

    config: dict[str, Any]

    async def probe(
        self,
        point: Any,
        payload: str,
        *,
        base_url: str = "",
        use_cache: bool | None = None,
    ) -> tuple[dict[str, Any], float, str]: ...


class CausalOracleMixin:
    """Adds the control-payload step to a differential injection oracle.

    Mixed into the injection testers rather than added to
    :class:`VulnerabilityTester` so the causality policy stays in one auditable
    module and the base class -- whose regions belong to other claims -- is left
    alone. The mixin needs nothing but ``self.config`` and ``self.probe``, both
    supplied by the tester it is mixed into.

    Configuration
    -------------
    ``config['causal_oracle']`` (CLI: ``--no-causal-oracle``). Default True.
    False restores the pre-control behaviour, which is what the ablation arm of
    the experiment needs; it is a *measurement* switch, not a compatibility
    shim.
    """

    #: Class token selecting the inversion rule: :data:`NOSQL`, :data:`SQLI`
    #: or :data:`LDAP`. Left empty the oracle is inert for that tester.
    causal_class: ClassVar[str] = ""

    #: Per-tester override: falsification controls run once per payload that
    #: reaches the differential branch, not once per payload in the list.
    def causal_oracle_enabled(self) -> bool:
        """True when the control-payload step should run for this tester."""
        if not self.causal_class:
            return False
        return bool(getattr(self, "config", {}).get("causal_oracle", True))

    async def confirm_cause(
        self,
        point: Any,
        payload: str,
        *,
        test_response: dict[str, Any],
        base_url: str = "",
    ) -> CausalAttribution:
        """Fetch the control for ``payload`` and return the attribution.

        Lazy by construction: it is called only from the branch that has
        already decided a response divergence is worth looking at, so the extra
        round-trip is paid per *candidate* and not per *payload*. On a scan that
        produced 354 findings out of 186 326 requests that is a rounding error.
        """
        if not self.causal_oracle_enabled():
            return CausalAttribution(True, "disabled")
        twin = semantic_twin(payload, self.causal_class)
        if twin is None:
            return CausalAttribution(True, "no-control")
        tester = cast(_ProbeCapable, self)
        twin_response, _elapsed, _url = await tester.probe(point, twin, base_url=base_url)
        return attribute_divergence(
            test_response, twin_response, twin, payload=payload,
        )
