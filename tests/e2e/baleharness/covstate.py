"""Mutable coverage-mode state, shared by every container launcher.

Kept in its own module so server.py can read it without importing the
heavier coverage.py (which pulls in the runtime + lazy s3lib).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .coverage import CoverageConfig

_COVERAGE: CoverageConfig | None = None


def set_coverage(cfg: CoverageConfig | None) -> None:
    global _COVERAGE
    _COVERAGE = cfg


def get_coverage() -> CoverageConfig | None:
    return _COVERAGE
