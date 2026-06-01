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
LOCAL_PAYLOAD_BYTES = 6 * 1024 * 1024  # big enough to chunk into several xorbs
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
# The churn phase hammers ONE reused repo with many edit→commit→push rounds,
# taking cold clones at several points to prove the accumulating server state
# stays consistent — and the server stays up — push after push. Guards the
# "data corrupted + server crashed after the Nth push" class of regression.
E2E_REPO_CHURN = "churn"
# The offline-no-network phase routes git-bale's CAS traffic through a counting
# proxy and asserts only push/pull cross it; it pushes its own `main`.
E2E_REPO_OFFLINE = "offline-net"
# Dedicated repos for the gc staging-reconciliation phases. Each gc phase
# pushes its own `main`, so they can't share a bare repo with the push-side
# phases above (or each other) without a non-fast-forward collision.
E2E_REPO_GC1 = "gc-abandon"
E2E_REPO_GC2 = "gc-keep"
E2E_REPO_GC3 = "gc-mixed"
# The resync-after-wipe phase owns its own isolated container; this is the bare
# repo it force-pushes to after the server's CAS is wiped out from under it.
E2E_REPO_RESYNC = "resync-wipe"
# The global-dedup-shard phase owns its own isolated container; this is the bare
# repo it seeds, then re-pushes after planting a server dedup shard in the cache.
E2E_REPO_DEDUP_SHARD = "dedup-shard"
E2E_USER = "e2e"
# The browser-download phase downloads bigfile.bin (pushed to repo2) through
# GET /v1/files/{id}, using this JWT to exercise the filename-binding branch.
BROWSER_DL_FILENAME = "bigfile.bin"
BROWSER_DL_JWT = forge_jwt_with_filename(BROWSER_DL_FILENAME)

# Tolerance for "no growth" assertions on disk: filesystems may round up to
# block boundaries even when nothing logically changed.
SIZE_TOLERANCE_BYTES = 4096

# Churn phase tuning. Many rounds, each editing a multi-chunk file (so CDC
# dedup is exercised), plus rotating add/delete of extra files and a plain
# (non-bale) text file in the same commits. Clones are taken at a few rounds
# to reconstruct the full accumulated history against the reused server state.
CHURN_ROUNDS = 12
CHURN_FILE_A_BYTES = 768 * 1024  # edited every round via a rotating region poke
CHURN_FILE_B_BYTES = 512 * 1024  # written once, then left alone (dedups forever)
CHURN_EDIT_BYTES = 64 * 1024  # ~one CDC chunk replaced per round
CHURN_EXTRA_BYTES = 256 * 1024  # rotating add/delete files
CHURN_CLONE_AFTER_ROUNDS = (3, 7, 11)  # 0-indexed; 11 is the final round

# HUGE churn — opt-in, scaled stress run. `HUGE_CHURN=N` targets ~N minutes of
# wall-clock (`HUGE_CHURN=1` ≈ 1 min, `=5` ≈ 5 min, …): rounds scale linearly
# with N, several big base files are edited in random subsets each round, with
# random (balanced) add/delete of extra files — some plain text. A cold clone
# every CLONE_EVERY rounds walks the most recent CLONE_EVERY revisions (a
# sliding window that tiles the history, so every revision is cold-verified
# once while the per-clone cost stays constant — total time linear in N, not
# quadratic). The RNG seed is logged and overridable via HUGE_CHURN_SEED.
MiB = 1024 * 1024
HUGE_CHURN_ROUNDS_PER_MIN = 60  # rounds per unit of N (calibrated to ~1 min)
HUGE_CHURN_CLONE_EVERY = 15  # cold clone cadence AND the walk-window width
HUGE_CHURN_BASE_FILES = (
    ("big1.bin", 12 * MiB),
    ("big2.bin", 9 * MiB),
    ("big3.bin", 6 * MiB),
    ("med1.bin", 4 * MiB),
    ("med2.bin", 2 * MiB),
)  # 33 MiB total
HUGE_CHURN_WALK_STRIDE = 1  # verify every revision within the window
HUGE_CHURN_EDIT_FILES = (2, 4)  # (min, max) base files edited per round
HUGE_CHURN_EDIT_BYTES = (256 * 1024, 2 * MiB)  # (min, max) region replaced
# add_prob == del_prob keeps the worktree size roughly constant across rounds,
# so per-round cost (and thus total time) stays linear in N.
HUGE_CHURN_ADD_PROB = 0.30  # chance a round adds a new file
HUGE_CHURN_PLAIN_ADD_PROB = 0.25  # of those adds, fraction that are plain text
HUGE_CHURN_NEW_BYTES = (1 * MiB, 6 * MiB)  # (min, max) size of a new bale file
HUGE_CHURN_DEL_PROB = 0.30  # chance a round deletes a previously-added file
