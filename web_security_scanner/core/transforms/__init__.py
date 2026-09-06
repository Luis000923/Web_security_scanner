"""Extensible payload transformation / mutation primitives.

``base`` defines the :class:`BaseTransform` interface and a name -> instance
registry; ``common`` provides the built-in encoders. Importing this package
registers every built-in transform.
"""

from __future__ import annotations

from .base import (
    BaseTransform,
    UnknownTransformError,
    available_transforms,
    build_default_registry,
    get_transform,
    register,
)
from .common import (
    DoubleUrlEncodeTransform,
    HexEntityTransform,
    HtmlEntityTransform,
    RandomCaseTransform,
    UrlEncodeTransform,
)

__all__ = [
    "BaseTransform",
    "UnknownTransformError",
    "register",
    "get_transform",
    "available_transforms",
    "build_default_registry",
    "UrlEncodeTransform",
    "DoubleUrlEncodeTransform",
    "HexEntityTransform",
    "HtmlEntityTransform",
    "RandomCaseTransform",
]
