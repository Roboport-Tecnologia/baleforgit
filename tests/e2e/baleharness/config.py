"""Shared constants for the e2e harness."""

from __future__ import annotations

from pathlib import Path

from baleharness.jwtutil import forge_jwt_with_filename


# This module lives at tests/e2e/baleharness/config.py, so the e2e dir (which
# holds the Dockerfile/entrypoint) is one level up and the repo root is three.
E2E_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_IMAGE_TAG = "baleforgit-server-e2e:latest"
COVERAGE_IMAGE_TAG = "baleforgit-server-e2e-coverage:latest"
HEALTHZ_TIMEOUT_S = 60
SSH_READY_TIMEOUT_S = 60
CONTAINER_NAME_PREFIX = "baleforgit-e2e"
JWT_TTL_YEARS = 100
BIG_FILE_BYTES = 35 * 1024 * 1024  # 35 MB (~547 chunks at 64 KiB target).
SMALL_FILE_BYTES = 8 * 1024
GC_PAYLOAD_BYTES = 256 * 1024  # a handful of CDC chunks → real xorbs/shards staged
# The clean filter holds payloads in RAM up to a 4 GiB default, so no realistic
# e2e file ever spills to a tmpfile. The spilled-clean phase caps the threshold
# via BALE_MAX_INLINE_CLEAN and pushes a file above it to drive `handle_clean`'s
# tmpfile branch + the file-backed `clean_cache::verify_chunks` path.
SPILL_INLINE_THRESHOLD = 1024 * 1024  # 1 MiB
# Above the threshold, not a 1 MiB multiple (partial trailing chunk), and a
# 6-chunk index so verify's priority_order exercises its middle-sample shuffle.
SPILL_FILE_BYTES = 5 * 1024 * 1024 + 4096
# E2E_HUB_TOKEN is opaque inside the container; just needs to match what
# BALE_GRANTS expects.
E2E_HUB_TOKEN = "e2e-hub-token-not-a-secret"
E2E_OWNER = "e2e"
E2E_REPO = "repo"
E2E_REPO_2 = "repo2"
E2E_REPO_3 = "mixed-files"
E2E_REPO_SPILL = "spilled-clean"
# The offline-no-network phase routes git-bale's CAS traffic through a counting
# proxy and asserts only push/pull cross it; it pushes its own `main`.
E2E_REPO_OFFLINE = "offline-net"
# Dedicated repos for the gc staging-reconciliation phases. Each gc phase
# pushes its own `main`, so they can't share a bare repo with the push-side
# phases above (or each other) without a non-fast-forward collision.
E2E_REPO_GC1 = "gc-abandon"
E2E_REPO_GC2 = "gc-keep"
E2E_REPO_GC3 = "gc-mixed"
E2E_USER = "e2e"
# The browser-download phase downloads bigfile.bin (pushed to repo2) through
# GET /v1/files/{id}, using this JWT to exercise the filename-binding branch.
BROWSER_DL_FILENAME = "bigfile.bin"
BROWSER_DL_JWT = forge_jwt_with_filename(BROWSER_DL_FILENAME)

# Tolerance for "no growth" assertions on disk: filesystems may round up to
# block boundaries even when nothing logically changed.
SIZE_TOLERANCE_BYTES = 4096
