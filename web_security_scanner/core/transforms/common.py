"""Built-in payload transforms (WAF / signature evasion primitives).

Importing this module registers every transform below under its slug. It is
imported for its side effects by :func:`..base.build_default_registry`.
"""

from __future__ import annotations

import random
import urllib.parse

from .base import BaseTransform, register

__all__ = [
    "UrlEncodeTransform",
    "DoubleUrlEncodeTransform",
    "HexEntityTransform",
    "HtmlEntityTransform",
    "RandomCaseTransform",
]


@register("url_encode")
class UrlEncodeTransform(BaseTransform):
    """Standard percent-encoding of every byte that is not unreserved.

    ``<script>`` -> ``%3Cscript%3E``. ``safe=""`` so ``/``, ``&``, ``=`` etc.
    are encoded too (the vector is a value, not a URL).
    """

    def transform(self, value: str) -> str:
        return urllib.parse.quote(value, safe="")


@register("double_url_encode")
class DoubleUrlEncodeTransform(BaseTransform):
    """Percent-encode twice: ``<`` -> ``%3C`` -> ``%253C``.

    Defeats filters that normalize a single decoding pass before matching but
    still hits stacks that decode twice (proxy + app).
    """

    def transform(self, value: str) -> str:
        once = urllib.parse.quote(value, safe="")
        return urllib.parse.quote(once, safe="")


@register("hex_entity")
class HexEntityTransform(BaseTransform):
    """Every character to a hexadecimal HTML numeric character reference.

    ``<`` -> ``&#x3c;``. Rendered identically by an HTML parser, opaque to a
    substring signature.

    Only an HTML parser decodes numeric character references -- a base64
    gadget-chain vector or a bare IDOR id passed through this would reach the
    sink as the literal ``&#x..;`` text, not the original bytes/value.
    """

    binary_safe = False

    def transform(self, value: str) -> str:
        return "".join(f"&#x{ord(ch):x};" for ch in value)


@register("html_entity")
class HtmlEntityTransform(BaseTransform):
    """Every character to a decimal HTML numeric character reference.

    ``<`` -> ``&#60;``. The decimal counterpart of :class:`HexEntityTransform`,
    same ``binary_safe = False`` caveat (needs an HTML parser downstream).
    """

    binary_safe = False

    def transform(self, value: str) -> str:
        return "".join(f"&#{ord(ch)};" for ch in value)


class RandomCaseTransform(BaseTransform):
    """Randomly flip the case of alphabetic characters.

    ``SELECT`` -> ``sElECt``. Case-insensitive engines (SQL keywords, HTML tag
    names, ``javascript:`` schemes) ignore it; a case-sensitive regex does not.
    Non-letters are left untouched, so the transform never changes payload
    length or semantics.

    Pass ``seed`` for a deterministic result (tests, reproducible scans);
    otherwise each call draws from the process RNG.

    ``binary_safe = False``: a base64 alphabet is case-sensitive (``A`` and
    ``a`` decode to different bits), so flipping letter case in a serialized
    Java/.NET gadget-chain vector silently corrupts it into garbage that
    still *looks* like a plausible payload -- the scan would report a false
    negative instead of an obvious error.
    """

    binary_safe = False

    def __init__(self, seed: int | None = None) -> None:
        self._seed = seed

    def transform(self, value: str) -> str:
        flip = (
            random.Random(self._seed).random
            if self._seed is not None
            else random.random
        )
        return "".join(
            (ch.upper() if flip() < 0.5 else ch.lower()) if ch.isalpha() else ch
            for ch in value
        )


@register("random_case")
class _SeededRandomCaseTransform(RandomCaseTransform):
    """Registry default: a fixed seed keeps the mutator reproducible run-to-run.

    Callers that want fresh randomness instantiate ``RandomCaseTransform()``
    directly instead of pulling ``"random_case"`` from the registry.
    """

    def __init__(self) -> None:
        super().__init__(seed=0x5A17)
