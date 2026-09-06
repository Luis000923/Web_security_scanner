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
from .transforms.base import BaseTransform, UnknownTransformError, build_default_registry

__all__ = ["PayloadMutator"]


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

    def mutate(self, payload: Payload, transform_names: list[str]) -> Payload:
        """Return a new ``Payload`` with its vector rewritten by the chain.

        Transforms are applied in list order (``["a", "b"]`` -> ``b(a(vector))``).
        An empty list still yields a fresh, equal instance. An unknown transform
        name raises :class:`~web_security_scanner.core.transforms.base.UnknownTransformError`
        and the original payload is left untouched.
        """
        new_vector = self.apply(payload.vector, transform_names)
        return replace(payload, vector=new_vector)
