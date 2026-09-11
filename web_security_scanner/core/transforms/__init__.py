"""Extensible payload transformation / mutation primitives.

``base`` defines the :class:`BaseTransform` interface and a name -> instance
registry; ``common`` provides the built-in encoders and ``evasion`` the
entropy-driven WAF-evasion transforms. Importing this package registers every
built-in transform.
"""

from __future__ import annotations

from .base import (
    BaseTransform,
    UnknownTransformError,
    UnsafeTransformError,
    available_transforms,
    binary_safe_transforms,
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
from .evasion import (
    AdaptiveEntropyTransform,
    FullwidthUnicodeTransform,
    PartialPercentEncodeTransform,
    SqlCommentInjectionTransform,
    WhitespaceDelimiterTransform,
)

__all__ = [
    "BaseTransform",
    "UnknownTransformError",
    "UnsafeTransformError",
    "register",
    "get_transform",
    "available_transforms",
    "binary_safe_transforms",
    "build_default_registry",
    "UrlEncodeTransform",
    "DoubleUrlEncodeTransform",
    "HexEntityTransform",
    "HtmlEntityTransform",
    "RandomCaseTransform",
    "PartialPercentEncodeTransform",
    "WhitespaceDelimiterTransform",
    "FullwidthUnicodeTransform",
    "AdaptiveEntropyTransform",
    "SqlCommentInjectionTransform",
]
