"""Coverage-mode state, split out so container launchers (server.py, mount.py)
can read it without importing coverage.py and its runtime/s3lib deps."""

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
