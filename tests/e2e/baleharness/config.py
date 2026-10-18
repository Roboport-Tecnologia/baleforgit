"""Shared constants for the e2e harness."""

from __future__ import annotations

from pathlib import Path

from baleharness.jwtutil import forge_jwt_with_filename

E2E_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_IMAGE_TAG = "baleforgit-server-e2e:latest"
COVERAGE_IMAGE_TAG = "baleforgit-server-e2e-coverage:latest"
HEALTHZ_TIMEOUT_S = 60
SSH_READY_TIMEOUT_S = 60
CONTAINER_NAME_PREFIX = "baleforgit-e2e"
JWT_TTL_YEARS = 100
BIG_FILE_BYTES = 35 * 1024 * 1024  # ~560 CDC chunks at the 64 KiB target
SMALL_FILE_BYTES = 8 * 1024
GC_PAYLOAD_BYTES = 256 * 1024  # a handful of CDC chunks → real xorbs/shards staged
LOCAL_PAYLOAD_BYTES = 6 * 1024 * 1024  # big enough to chunk into several xorbs
# Clean holds payloads in RAM up to 4 GiB, so no e2e file spills on its own; the
# spilled-clean phase lowers BALE_MAX_INLINE_CLEAN to reach `handle_clean`'s
# tmpfile branch and the file-backed `clean_cache::verify_chunks`.
SPILL_INLINE_THRESHOLD = 1024 * 1024  # 1 MiB
# Above the threshold, not a 1 MiB multiple (partial trailing chunk), and a
# 6-chunk index so verify's priority_order exercises its middle-sample shuffle.
SPILL_FILE_BYTES = 5 * 1024 * 1024 + 4096
# Opaque; only has to match BALE_GRANTS.
E2E_HUB_TOKEN = "e2e-hub-token-not-a-secret"
E2E_OWNER = "e2e"
E2E_REPO = "repo"
E2E_REPO_2 = "repo2"
E2E_REPO_3 = "mixed-files"
E2E_REPO_SPILL = "spilled-clean"
# Churn: many edit→commit→push rounds on ONE repo with periodic cold clones;
# guards "data corrupted + server crashed after the Nth push".
E2E_REPO_CHURN = "churn"
# The offline-no-network phase routes git-bale's CAS traffic through a counting
# proxy and asserts only push/pull cross it; it pushes its own `main`.
E2E_REPO_OFFLINE = "offline-net"
# Each gc phase pushes its own `main`; a shared bare repo would hit non-fast-forward.
E2E_REPO_GC1 = "gc-abandon"
E2E_REPO_GC2 = "gc-keep"
E2E_REPO_GC3 = "gc-mixed"
# Multi-remote: the push to B (added after `origin` A) must register the file
# under B's scope, or a clone of B 404s on the per-repo scope check.
E2E_REPO_MR_A = "multi-remote-a"
E2E_REPO_MR_B = "multi-remote-b"
# C has the commits but not the bale objects (an older/argless client pushed
# it): a new-branch push must re-register them, not skip them because its
# remote-tracking refs already cover the history.
E2E_REPO_MR_C = "multi-remote-c"
# Term-list-merge: two differently-segmented registrations of one file_hash
# merged in the global file_terms leave Σterms > file_size, which underflows
# xet's last-term trim and panics the client. The phase injects that state into
# meta.db and asserts the server's consistency check rejects it cleanly.
E2E_REPO_MERGE_A = "term-merge-a"
MERGE_FILE_BYTES = 4 * 1024 * 1024
# Cold-repush: with the local dedup cache wiped, re-pushing A's big file to B
# (bundled with a small new file, so it repacks into fresh xorbs) must be saved
# by server global dedup, not stored twice. Judged by on-disk xorb growth, so
# big ≫ small keeps the verdict unambiguous.
E2E_REPO_COLD_A = "cold-repush-a"
E2E_REPO_COLD_B = "cold-repush-b"
COLD_BIG_BYTES = 16 * 1024 * 1024
COLD_SMALL_BYTES = 1 * 1024 * 1024
# Staged cold-repush: push, wipe the cache, APPEND and commit WITHOUT pushing
# (it cleans before any download can repopulate the cache), then push to a
# fresh repo. Most at-risk path for re-storing the unchanged prefix.
E2E_REPO_COLD_STAGED_A = "cold-staged-a"
E2E_REPO_COLD_STAGED_B = "cold-staged-b"
# Compression: one LZ4 (scheme 1) and one BG4-LZ4 (scheme 2) file, to exercise
# the server's decompress arms; every other phase's sha256-chained payload is
# incompressible and only ever stores scheme 0.
E2E_REPO_COMPRESS = "compression"
COMPRESS_FILE_BYTES = 4 * 1024 * 1024  # a few CDC chunks per file
# Resync-after-wipe (own container): force-pushed after the server's CAS is wiped.
E2E_REPO_RESYNC = "resync-wipe"
# Global-dedup-shard (own container): re-pushed after planting a dedup shard in the cache.
E2E_REPO_DEDUP_SHARD = "dedup-shard"
# FS write-failure (own container, BALE_TEST_FS_WRITE_FAIL=1): every blob write
# hits write_atomic's tmp-cleanup arm; nothing may land, and a clean restart
# must round-trip the same content.
E2E_REPO_WRITEFAIL = "fs-writefail"
# FS concurrent-put: byte-identical pushes to two repos race write_atomic on one
# content-addressed dst; both succeed, one copy lands, tmp/ stays empty.
E2E_REPO_CPUT_A = "fs-cput-a"
E2E_REPO_CPUT_B = "fs-cput-b"
FS_WRITEFAIL_BYTES = 512 * 1024  # a few CDC chunks → a real xorb POST to fail
FS_CPUT_BYTES = 4 * 1024 * 1024  # large enough to overlap the two pushes in time
# Shard-stage quota: owner B, capped below A's content, pushes the SAME bytes.
# Every xorb dedups against A's (xorb-stage gate skipped), so only upload_shard's
# delta check (unaccounted_xorb_bytes_for_owner) can reject it.
SHARDQ_OWNER_A = "shardq-a"
SHARDQ_REPO_A = "src"
SHARDQ_OWNER_B = "shardq-b"
SHARDQ_REPO_B = "recv"
SHARDQ_FILE_BYTES = 1024 * 1024  # 1 MiB shared content
SHARDQ_QUOTA_BYTES = 256 * 1024  # B's cap, well below the 1 MiB it tries to register
E2E_USER = "e2e"
# Browser-download: GET /v1/files/{id} of repo2's bigfile.bin with a filename-bound JWT.
BROWSER_DL_FILENAME = "bigfile.bin"
BROWSER_DL_JWT = forge_jwt_with_filename(BROWSER_DL_FILENAME)

# "No growth" slack: filesystems round up to block boundaries.
SIZE_TOLERANCE_BYTES = 4096

CHURN_ROUNDS = 12
CHURN_FILE_A_BYTES = 768 * 1024  # edited every round via a rotating region poke
CHURN_FILE_B_BYTES = 512 * 1024  # written once, then left alone (dedups forever)
CHURN_EDIT_BYTES = 64 * 1024  # ~one CDC chunk replaced per round
CHURN_EXTRA_BYTES = 256 * 1024  # rotating add/delete files
CHURN_CLONE_AFTER_ROUNDS = (3, 7, 11)  # 0-indexed; 11 is the final round

# HUGE churn (opt-in): `HUGE_CHURN=N` targets ~N minutes. Each cold clone walks
# only the last CLONE_EVERY revisions — windows tile the history, so every
# revision is verified once and total time stays linear in N, not quadratic.
# Seed is logged; override with HUGE_CHURN_SEED.
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
# add_prob == del_prob keeps the worktree size, and so per-round cost, flat.
HUGE_CHURN_ADD_PROB = 0.30  # chance a round adds a new file
HUGE_CHURN_PLAIN_ADD_PROB = 0.25  # of those adds, fraction that are plain text
HUGE_CHURN_NEW_BYTES = (1 * MiB, 6 * MiB)  # (min, max) size of a new bale file
HUGE_CHURN_DEL_PROB = 0.30  # chance a round deletes a previously-added file
