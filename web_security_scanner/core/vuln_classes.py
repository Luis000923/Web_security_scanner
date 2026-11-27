"""Vulnerability-class vocabulary, shared by the metrics and the label loaders.

Why this is its own module
--------------------------
Two vocabularies have to be reconciled to score class agreement, and they live
on opposite sides of the pipeline:

* what the **ground truth** calls a class -- the OWASP Benchmark ``category``
  column uses ``sqli``, ``pathtraver``, ``ldapi``; the JSON tables used by
  ``scripts/evaluate.py`` use ``SQLInjection``, ``PathTraversal``;
* what the **scanner** calls it -- findings are typed
  ``vulnerabilities.sql_injection``, ``vulnerabilities.xss``, ...

Neither side is wrong and neither can be changed without invalidating reports
that already exist, so the mapping has to live somewhere both can import. It
cannot live in :mod:`web_security_scanner.core.benchmark_ground_truth`, because
that module imports :mod:`web_security_scanner.core.ieee_metrics` and a
module-level import in the other direction would be a cycle. This module is the
leaf both depend on, and it imports nothing but ``re``.

The conservative direction
--------------------------
An unrecognised label resolves to ``None`` and therefore never matches. A
scanner that reports a class nobody can name has not demonstrated that it
found the *right* class, and quietly treating the unknown label as a wildcard
would make class agreement a metric that rises when the report gets vaguer.
The asymmetry is deliberate: unknown *expected* class is not the same problem
(an unlabelled ground-truth point cannot be scored at all, and is handled by
restricting the denominator instead), while unknown *reported* class is a
defect of the finding.

What this is not
----------------
Not a vulnerability taxonomy and not a claim about which classes matter. It is
a string-normaliser with an alias table, so that
:func:`web_security_scanner.core.ieee_metrics.MetricResult.recall_class_matched`
can be computed by hand from a report and a ground-truth table and land on the
same number.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

__all__ = [
    "CANONICAL_CLASSES",
    "canonical_class",
    "class_matches",
]

#: Anything that is not a lower-case letter or a digit is a separator. Applied
#: after the namespace is stripped, so ``command-injection``,
#: ``command_injection`` and ``Command Injection`` all reduce to one token.
_SEP_RE = re.compile(r"[^a-z0-9]+")

#: Namespaces a reported type may be qualified with. Findings are typed
#: ``vulnerabilities.sql_injection``; the last dotted segment is the class.
_NS_SEP_RE = re.compile(r"[./:|#]")

#: ``squashed alias -> canonical class``. Keys are already squashed (lowercase,
#: separators removed); values are the canonical names used everywhere in this
#: package and in the per-category tables.
#:
#: The benchmark's ``category`` column and the scanner's own vocabulary are both
#: listed explicitly, plus the spellings a hand-written JSON ground truth is
#: likely to use. Anything absent is treated as unknown.
_ALIASES: Mapping[str, str] = {
    # --- SQL ---------------------------------------------------------------
    "sqli": "sqli",
    "sql": "sqli",
    "sqlinj": "sqli",
    "sqlinjection": "sqli",
    "sqlblindinjection": "sqli",
    # --- NoSQL -------------------------------------------------------------
    "nosqli": "nosqli",
    "nosql": "nosqli",
    "nosqlinjection": "nosqli",
    # "blindnoq" is the established spelling for a time-independent NoSQL probe.
    # A bare "blind" is *not* mapped: it is equally an XSS or a SQLi label, and
    # guessing here is the kind of widening that makes an agreement metric
    # meaningless.
    "blindnoq": "nosqli",
    "mongo": "nosqli",
    "mongodb": "nosqli",
    "mongoos": "nosqli",
    # --- XSS ---------------------------------------------------------------
    "xss": "xss",
    "crosssitescripting": "xss",
    "domxss": "xss",
    "reflectedxss": "xss",
    "storedxss": "xss",
    # --- Path traversal ----------------------------------------------------
    "pathtraver": "pathtraver",
    "pathtraversal": "pathtraver",
    "directorytraversal": "pathtraver",
    "filetread": "pathtraver",
    "fileread": "pathtraver",
    "lfi": "pathtraver",
    "pathdisclosure": "pathtraver",
    # --- Command injection -------------------------------------------------
    "cmdi": "cmdi",
    "commandinjection": "cmdi",
    "oscommandinjection": "cmdi",
    "commandinjectionblind": "cmdi",
    "oscmdi": "cmdi",
    "rce": "cmdi",
    # --- LDAP --------------------------------------------------------------
    "ldapi": "ldapi",
    "ldap": "ldapi",
    "ldapinjection": "ldapi",
    # --- XPath -------------------------------------------------------------
    "xpathi": "xpathi",
    "xpath": "xpathi",
    "xpathinjection": "xpathi",
    # --- SSRF / XXE --------------------------------------------------------
    "ssrf": "ssrf",
    "serversiderequestforgery": "ssrf",
    "xxe": "xxe",
    "xmlexternalentity": "xxe",
    # --- Crypto and session families --------------------------------------
    # Present so a ground truth that labels these is scored on the class rather
    # than silently dropped from the class-labelled population.
    "crypto": "crypto",
    "weakcrypto": "crypto",
    "insecurecrypto": "crypto",
    "weakencryption": "crypto",
    "hash": "hash",
    "weakhash": "hash",
    "insecurehash": "hash",
    "weakrand": "weakrand",
    "weakrandom": "weakrand",
    "insecurerandom": "weakrand",
    "trustbound": "trustbound",
    "trustboundary": "trustbound",
    "brokenaccesscontrol": "trustbound",
    "securecookie": "securecookie",
    "insecurecookie": "securecookie",
    "cookievulnerability": "securecookie",
    "insecurecookies": "securecookie",
}

#: The canonical class names this vocabulary can produce. Published so a report
#: can state which classes were scoreable without hard-coding the table.
CANONICAL_CLASSES: frozenset[str] = frozenset(_ALIASES.values())


def _squash(text: str) -> str:
    """Lower-case and drop every non-alphanumeric character."""
    return _SEP_RE.sub("", (text or "").strip().lower())


def canonical_class(raw: str) -> str | None:
    """Reduce any spelling of a vulnerability class to its canonical name.

    ``None`` when the label is empty or not in the vocabulary. Callers must
    treat ``None`` as "cannot be scored", never as "matches everything".

    >>> canonical_class("vulnerabilities.sql_injection")
    'sqli'
    >>> canonical_class("PathTraversal")
    'pathtraver'
    >>> canonical_class("missing_header") is None
    True
    """
    if not raw:
        return None
    # Strip a namespace first: squashing "vulnerabilities.sql_injection" whole
    # would produce "vulnerabilitiessqlinjection", which is not in the table.
    tail = _NS_SEP_RE.split(raw.strip().lower())[-1]
    return _ALIASES.get(_squash(tail))


def class_matches(reported_type: str, expected_class: str) -> bool:
    """Whether a finding's reported class is the class the labels expect.

    Both sides are canonicalised, so a mismatch is a genuine disagreement about
    the vulnerability and not a spelling difference. Unknown on either side is
    ``False``: the caller already restricted the population to class-labelled
    instances, so an unknown *expected* class never reaches this function, and
    an unknown *reported* class is exactly the case where agreement cannot be
    demonstrated.
    """
    reported = canonical_class(reported_type)
    if reported is None:
        return False
    return reported == canonical_class(expected_class)
