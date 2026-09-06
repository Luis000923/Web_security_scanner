"""Transformation interface and registry for payload mutation.

A :class:`BaseTransform` is a pure, stateless string rewrite: it takes the raw
injection vector and returns a new one that is *semantically equivalent for a
vulnerable target* but lexically different, so a static WAF / IDS signature that
matched the original no longer fires.

Transforms are registered by name via :func:`register` so new ones can be added
without touching :class:`~web_security_scanner.core.payload_mutator.PayloadMutator`::

    from web_security_scanner.core.transforms.base import BaseTransform, register

    @register("rot13")
    class Rot13Transform(BaseTransform):
        name = "rot13"

        def transform(self, value: str) -> str:
            return codecs.encode(value, "rot13")
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TypeVar

__all__ = [
    "BaseTransform",
    "UnknownTransformError",
    "register",
    "get_transform",
    "available_transforms",
    "build_default_registry",
]


class UnknownTransformError(KeyError):
    """Raised when a transform name is not present in the registry."""


class BaseTransform(ABC):
    """Abstract base for a single, stateless payload rewrite.

    Subclasses set the class attribute :attr:`name` (the registry key) and
    implement :meth:`transform`. Instances must be safe to share and reuse
    across threads and event loops — keep them free of mutable state.
    """

    #: Registry key. Subclasses must override with a short, stable slug.
    name: str = ""

    @abstractmethod
    def transform(self, value: str) -> str:
        """Return a rewritten copy of ``value``."""
        raise NotImplementedError

    def __call__(self, value: str) -> str:
        return self.transform(value)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<{self.__class__.__name__} name={self.name!r}>"


# ---- registry -----------------------------------------------------------

_REGISTRY: dict[str, BaseTransform] = {}

_T = TypeVar("_T", bound=BaseTransform)


def register(name: str) -> Callable[[type[_T]], type[_T]]:
    """Class decorator: instantiate the (zero-arg) transform and store it under ``name``."""

    def _wrap(cls: type[_T]) -> type[_T]:
        instance = cls()
        instance.name = name
        _REGISTRY[name] = instance
        return cls

    return _wrap


def get_transform(name: str) -> BaseTransform:
    """Return the registered transform for ``name`` or raise."""
    try:
        return _REGISTRY[name]
    except KeyError:
        raise UnknownTransformError(
            f"unknown transform {name!r}; available: {sorted(_REGISTRY)}"
        ) from None


def available_transforms() -> tuple[str, ...]:
    """Names of every registered transform, sorted."""
    return tuple(sorted(_REGISTRY))


def build_default_registry() -> dict[str, BaseTransform]:
    """A fresh mapping copy of the global registry (import side effects applied)."""
    from . import common  # noqa: F401  (import registers the built-in transforms)

    return dict(_REGISTRY)
