"""Mutable coverage-mode state, shared by every container launcher.

Kept in its own module so server.py can read it without importing the
heavier coverage.py (which pulls in the runtime + lazy s3lib).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .coverage import CoverageConfig

_COVERAGE: "Optional[CoverageConfig]" = None


def set_coverage(cfg: "Optional[CoverageConfig]") -> None:
    global _COVERAGE
    _COVERAGE = cfg


def get_coverage() -> "Optional[CoverageConfig]":
    return _COVERAGE
