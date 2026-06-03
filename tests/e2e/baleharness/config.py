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
# The multi-remote phase pushes the same content to two repos on one server: an
# `origin` (A) and a second remote (B) added afterwards. It proves the second
# push registers the file under B's repo scope so a clone of B can check out
# (the per-repo scope check would otherwise 404). Dedicated repos so no other
# phase's `main` collides.
E2E_REPO_MR_A = "multi-remote-a"
E2E_REPO_MR_B = "multi-remote-b"
# Third repo for the "target already has the commits but not the bale objects"
# case (a remote populated by an older/argless client): pushing a new branch to
# it must re-register the objects under its scope, NOT skip them because its
# remote-tracking refs already cover the history.
E2E_REPO_MR_C = "multi-remote-c"
# The term-list-merge phase guards the server's term-list consistency check. A
# pre-fix per-term INSERT OR IGNORE could merge two differently-segmented
# registrations of one file_hash (file_terms is global), leaving Σterms >
# file_size — which underflows xet's last-term trim and panics the client on
# reconstruction. The phase reproduces that corrupt state by injecting duplicate
# terms via the server's meta.db, then asserts the guard rejects it cleanly.
E2E_REPO_MERGE_A = "term-merge-a"
MERGE_FILE_BYTES = 4 * 1024 * 1024
# The cold-repush phase measures whether re-pushing content already on the server
# (with the local dedup cache wiped, so only the server's global-dedup query can
# save it) RE-STORES that content. A big file goes to repo A alone, then is
# re-pushed to repo B bundled with a small new file so it repacks into fresh xorb
# hashes — if global dedup doesn't recognize it, the server stores it again. The
# phase reads the server's on-disk xorb growth to tell double-storage from a clean
# re-registration. Big ≫ small so the verdict is unambiguous from disk growth.
E2E_REPO_COLD_A = "cold-repush-a"
E2E_REPO_COLD_B = "cold-repush-b"
COLD_BIG_BYTES = 16 * 1024 * 1024
COLD_SMALL_BYTES = 1 * 1024 * 1024
# Staged variant of cold-repush, reproducing the exact reported scenario: push a
# file, wipe the cache, APPEND to it and commit WITHOUT pushing (so the modified
# file is staged, not re-sourced from a server — staged files clean before any
# from-refs download can repopulate the cache), then push to a fresh repo. Most
# at-risk path for re-storing the unchanged prefix; measured via server disk.
E2E_REPO_COLD_STAGED_A = "cold-staged-a"
E2E_REPO_COLD_STAGED_B = "cold-staged-b"
# The compression phase pushes two compressible files — one xet stores as plain
# LZ4 (scheme 1), one as BG4-LZ4 (scheme 2) — so the server's xorb decompress
# arms (verify on upload, decompress on browser download) get exercised. The
# default sha256-chained payloads are incompressible, so every other phase only
# ever stores scheme-0 (uncompressed) frames. Own repo + commits.
E2E_REPO_COMPRESS = "compression"
COMPRESS_FILE_BYTES = 4 * 1024 * 1024  # a few CDC chunks per file
# The resync-after-wipe phase owns its own isolated container; this is the bare
# repo it force-pushes to after the server's CAS is wiped out from under it.
E2E_REPO_RESYNC = "resync-wipe"
# The global-dedup-shard phase owns its own isolated container; this is the bare
# repo it seeds, then re-pushes after planting a server dedup shard in the cache.
E2E_REPO_DEDUP_SHARD = "dedup-shard"
# The fs write-failure phase owns an isolated container started with
# BALE_TEST_FS_WRITE_FAIL=1, so every blob write hits write_atomic's tmp-cleanup
# arm. It pushes here, asserts nothing landed (xorbs/ + tmp/ empty), then proves
# a clean restart recovers and round-trips the same content.
E2E_REPO_WRITEFAIL = "fs-writefail"
# The fs concurrent-put phase pushes byte-identical content to two repos at the
# same instant, racing write_atomic on the same content-addressed dst; it asserts
# both pushes succeed, exactly one copy lands, and tmp/ is empty (no leak, no
# double-store under concurrency).
E2E_REPO_CPUT_A = "fs-cput-a"
E2E_REPO_CPUT_B = "fs-cput-b"
FS_WRITEFAIL_BYTES = 512 * 1024  # a few CDC chunks → a real xorb POST to fail
FS_CPUT_BYTES = 4 * 1024 * 1024  # large enough to overlap the two pushes in time
# The shard-stage quota phase (TODO item 9) isolates the SECOND quota gate (in
# upload_shard) from the xorb-stage one. Owner A uploads content unlimited; owner
# B — capped below that content's size via the admin quota API — then pushes the
# SAME bytes. B's xorbs all dedup against A's (xorb-stage skipped, zero disk
# growth), so the only thing that can reject B's push is the shard-stage
# delta-quota check (unaccounted_xorb_bytes_for_owner). Distinct owners so B's cap
# never touches A.
SHARDQ_OWNER_A = "shardq-a"
SHARDQ_REPO_A = "src"
SHARDQ_OWNER_B = "shardq-b"
SHARDQ_REPO_B = "recv"
SHARDQ_FILE_BYTES = 1024 * 1024  # 1 MiB shared content
SHARDQ_QUOTA_BYTES = 256 * 1024  # B's cap, well below the 1 MiB it tries to register
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
