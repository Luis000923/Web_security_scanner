"""Apply ordered transform chains to :class:`Payload` vectors.

:class:`PayloadMutator` is the bridge between the typed payload corpus
(:mod:`web_security_scanner.core.payload_loader`) and the string-rewrite
primitives in :mod:`web_security_scanner.core.transforms`. It never mutates the
input — :meth:`PayloadMutator.mutate` returns a **new** frozen ``Payload`` whose
``vector`` has been rewritten and whose every other metadata field is carried
over unchanged.

    from web_security_scanner.core.payload_mutator import PayloadMutator

    mutator = PayloadMutator()
    evaded = mutator.mutate(payload, ["random_case", "url_encode"])
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import replace

from .payload_loader import Payload
from .transforms.base import (
    BaseTransform,
    UnknownTransformError,
    UnsafeTransformError,
    build_default_registry,
)

__all__ = ["PayloadMutator", "SENSITIVE_CATEGORIES"]

# Corpus categories whose vector is either raw serialized bytes a gadget
# chain depends on byte-for-byte (deserialization) or a bare identifier whose
# only meaningful content *is* its literal value (idor) -- never text meant
# for an HTML/JS/SQL parser. A transform whose ``binary_safe`` flag is False
# (entity-encoding, case-flipping, fullwidth Unicode -- see
# :class:`~.transforms.base.BaseTransform`) either corrupts these silently or
# turns them into something meaningless, without raising: the request still
# goes out and the scan just quietly stops finding what it should. See
# :meth:`PayloadMutator.mutate`.
SENSITIVE_CATEGORIES = frozenset({"deserialization", "idor"})


class PayloadMutator:
    """Rewrite payload vectors through named transform chains.

    By default every built-in transform is available. Pass ``registry`` to pin a
    specific set (e.g. ``{**build_default_registry(), "rot13": Rot13Transform()}``
    to add one, or a small dict to restrict a scan profile).
    """

    def __init__(self, registry: Mapping[str, BaseTransform] | None = None) -> None:
        self._registry: dict[str, BaseTransform] = (
            dict(registry) if registry is not None else build_default_registry()
        )

    # ---- introspection ----------------------------------------------------

    def available(self) -> tuple[str, ...]:
        """Names of every transform this mutator can apply, sorted."""
        return tuple(sorted(self._registry))

    def _resolve(self, name: str) -> BaseTransform:
        try:
            return self._registry[name]
        except KeyError:
            raise UnknownTransformError(
                f"unknown transform {name!r}; available: {self.available()}"
            ) from None

    # ---- mutation -------------------------------------------------------

    def apply(self, vector: str, transform_names: Iterable[str]) -> str:
        """Run ``transform_names`` left-to-right over a raw vector string."""
        for name in transform_names:
            vector = self._resolve(name).transform(vector)
        return vector

    def safe_transforms_for(self, payload: Payload) -> tuple[str, ...]:
        """Registered transform names safe to run against ``payload``.

        Every transform for an ordinary payload; only the ``binary_safe``
        ones (see :class:`~.transforms.base.BaseTransform`) when
        ``payload.category`` is in :data:`SENSITIVE_CATEGORIES`.
        """
        if payload.category not in SENSITIVE_CATEGORIES:
            return self.available()
        return tuple(n for n in self.available() if self._registry[n].binary_safe)

    def mutate(
        self, payload: Payload, transform_names: list[str], *, enforce_safety: bool = True,
    ) -> Payload:
        """Return a new ``Payload`` with its vector rewritten by the chain.

        Transforms are applied in list order (``["a", "b"]`` -> ``b(a(vector))``).
        An empty list still yields a fresh, equal instance. An unknown transform
        name raises :class:`~.transforms.base.UnknownTransformError` and the
        original payload is left untouched.

        ``enforce_safety`` (default ``True``): when ``payload.category`` is in
        :data:`SENSITIVE_CATEGORIES` (``deserialization``, ``idor``), any
        requested transform whose ``binary_safe`` flag is ``False`` raises
        :class:`~.transforms.base.UnsafeTransformError` instead of running --
        e.g. case-flipping a base64 Java gadget chain or HTML-entity-encoding
        a numeric IDOR id would otherwise silently turn a working exploit
        vector into an inert string, with no error to signal the scan just
        stopped testing what it claims to be testing. Pass ``False`` only for
        an explicit, deliberate experiment where that risk is understood.
        """
        if enforce_safety and payload.category in SENSITIVE_CATEGORIES:
            unsafe = [
                n for n in transform_names
                if n in self._registry and not self._registry[n].binary_safe
            ]
            if unsafe:
                raise UnsafeTransformError(
                    f"{unsafe} unsafe for category={payload.category!r} payload "
                    f"{payload.id or payload.vector[:40]!r}; safe transforms: "
                    f"{self.safe_transforms_for(payload)}"
                )
        new_vector = self.apply(payload.vector, transform_names)
        return replace(payload, vector=new_vector)
