# Clean filter performance: investigation, options, fix

Single-session record of the work done on the `filter.bale.process` clean
path. Captured here so the next person picking up perf doesn't have to
re-walk the dead ends.

## Problem statement

`git diff` on a bale-tracked binary file that has been *slightly modified*
(e.g. 16 bytes appended to a 350 MiB blob) was slow — ~0.9 s on a 350 MiB
file. Pure CDC + xorb staging at `git add` time is unavoidable, but `git
diff` doesn't need any of that — it just needs a pointer to compare
against the indexed pointer.

## Harness

`crates/git-bale/scripts/profile_diff.sh` — sets up an offline bale repo
in a tempdir, writes a random binary (`SIZE_MIB`, default 35), adds +
commits it, appends `APPEND_BYTES` (default 16), and times `git diff`
across `ITERS` iterations plus an unmodified control. Env knobs let
profilers wrap iter 2 (`PROFILE=samply`) or retain the workdir
(`KEEP=1`). Falls back gracefully on missing tools.

Example baseline numbers on a 350 MiB payload:

| step | wall time |
|---|---|
| `git add` (cold clean) | 0.92 s |
| `git diff` iter 1 (cache size-mismatched, full clean) | **0.91 s** |
| `git diff` iter 2+ (cache repopulated by iter 1) | 0.31 s |

## Standalone profiler target

`crates/git-bale/examples/profile_clean.rs` — exercises the same xet-data
clean path that `handle_clean` runs, but as a single unsigned binary so
that **samply on macOS can actually follow it** (the macOS `Stdin`
signing on `/usr/bin/git` blocks `DYLD_INSERT_LIBRARIES`, and samply
doesn't follow children through `posix_spawn`). Three modes:

- `--full` — `FileUploadSession` + `clean_file(Sha256Policy::Compute)` +
  `finalize`. Mirror of current production path.
- `--full-no-sha` — same but `Sha256Policy::Skip`.
- `--hash-only` — `data_client::hash_files_async`. CDC + merkle hash, no
  xorbs, no shards, no `redb`.

Optional `--staging <dir>` reuses a staging dir across runs to exercise
the xet dedup path.

Build with `CARGO_PROFILE_RELEASE_DEBUG=line-tables-only` so samply can
symbolize:

```bash
CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
  cargo build --release --example profile_clean -p git-bale

samply record --save-only --no-open --rate 4000 --unstable-presymbolicate \
  -o /tmp/clean.profile.json.gz \
  -- target/release/examples/profile_clean --full <input-file>
```

`--unstable-presymbolicate` writes a sibling `.syms.json` so the profile
can be parsed offline (symbol resolution prefers `code_id` matching —
the `breakpadId` in the profile has a trailing `0` that `debug_id` in
the sidecar does not, but `codeId` matches `code_id` directly).

## Profile findings (350 MiB random binary, 12 threads sampled)

Initial misread: I summed `update_blocks` (SHA-256 block compression)
self-time across all 12 hf-xet worker threads, saw ~26% of CPU samples,
and predicted skipping SHA-256 would cut ~26% of wall time. **Wrong** —
that's CPU-time not wall-clock; SHA-256 runs concurrently with CDC and
xorb building, so it almost completely hides behind everything else.

Hot call paths (% of CPU samples, summed across workers):

- `shard_file_manager.rs::register_shards` → `session_directory.rs::copy_from`: **~45%**
- `deduper_process_chunks` (CDC dedup loop): **~28%**
- `consolidate_shards_in_directory` (called from `LocalClient::drop` at process exit): **~25%**
- `drop_in_place<LocalClient>`: **~9%**

Empirical comparison (median of 3 on the same 367 MB file):

| mode | wall | throughput | savings vs `--full` |
|---|---|---|---|
| `--full` | **0.739 s** | 473 MiB/s | — |
| `--full-no-sha` | 0.701 s | 500 MiB/s | ~5% |
| `--hash-only` | 0.498 s | 702 MiB/s | ~33% |

The real wall-clock cost above hash-only is `xorb format → shard format
→ redb → LocalClient` — the upload-side machinery — not SHA-256. xet
dedup helps when staging is warm: a second `--full` against the same
staging dir on the modified file runs in **0.55 s** (vs 0.78 s cold), so
the dedup machinery already skips xorb *writes* for known chunks. But
the floor is still 0.55 s because every clean must re-CDC + re-blake3
the entire file to know what to dedup.

The actual `git diff` iter-1 is 0.91 s — **0.37 s above the warm-dedup
baseline**. That gap is git's pkt-line plumbing + the
`read_binary_to(&mut tmp)` round-trip in `filter_process.rs`: we write
the entire file out to a `NamedTempFile`, then `clean_file` reopens it
and reads it back, then `compute_chunks` reads it a third time to
populate the cache. Disk write + two disk reads on a 350 MB blob.

## Options evaluated

### A. `Sha256Policy::Skip` in `handle_clean`

One-line change, ~5% wall-time win. Breaks byte-comparison with old
pointers (which carry `sha256`), so `git diff` would always report
"modified" even when content didn't change. Rejected: too little win for
the wire-format break.

### B-safe-1: hash-only at clean time, raw bytes side-table, promote to xorbs at push

Defers xorb building to push-pending. **Unsafe.** Smudge runs anytime
git materializes a blob (`git checkout`, `git stash pop`, `git reset
--hard`, branch switches, `git diff --binary`), and between commit and
push the lukewarm smudge path needs staged xorbs to fall back to. With
deferred staging:

1. `git checkout other-branch` then back: smudge needs xorbs that don't exist → unrecoverable for the just-committed file.
2. File modified before push: push-pending re-chunks the worktree, but the new bytes have a different merkle hash than the committed pointer references → uploading xorbs that don't satisfy any committed pointer; old bytes are gone → **silent data loss**.
3. File deleted before push: committed pointer with no backing bytes anywhere → permanent dangling reference.
4. `git stash`: stash creates a commit whose blob is the pointer; pop runs smudge → fails.

Rejected: the "any committed pointer can be smudged back to bytes"
invariant is load-bearing per `CLAUDE.md`'s "treat user data as
load-bearing" rule.

### B-safe-2: optimize the in-place clean

Profile suggests `ShardFileManager` and `LocalClient::drop` are heavier
than the workload requires (per-clean shard consolidation, redb open per
call, exit-time cleanup attributed to every filter-process invocation).
Real wins available but requires reaching into xet-data internals.
Deferred.

### B-safe-3: smarter clean-cache that handles append

Cache today stores `(size, xxh3 1-MiB chunks)` for verification.
Currently bails on size mismatch and runs full clean.

**Naive form:** on size grew but xxh3 prefix verifies, re-CDC the tail
only. Works for the hash side (`xet_core_structures::merklehash::file_hash`
accepts a chunk-hash vec directly). But producing a *staged* pointer
requires:

1. A new shard entry mapping the new file_hash to `[(xorb_A, prefix_chunks), (xorb_B, new_tail_chunks)]`.
2. A new `xorb_B` containing the tail chunks.

`FileUploadSession::clean_file` only takes a file path — feed it the
tail and the resulting shard entry references only the tail, not the
prefix. Splicing pre-existing chunks + new chunks into a single shard
entry needs either a new xet-data API or reaching into the shard / dedup
interface directly. Significant work, not a small bale-side change.

Deferred. The dedup pipeline already does most of this job (warm staging
runs at 0.55 s vs 0.78 s cold), so the marginal win over xet's existing
behavior is bounded.

### What landed: in-memory pkt-line drain

The 0.91 s `git diff` iter-1 minus the 0.55 s xet floor is **0.37 s of
pure git/filter plumbing overhead** — three disk passes over the same
350 MB blob that's already passing through RAM via pkt-line. Removing
that doesn't touch any safety invariant: same bytes, same chunker, same
xorbs in the same staging layout. The only question is whether bytes
touch disk before reaching xet.

## The fix

`crates/git-bale/src/filter_process.rs`:

```rust
enum CleanPayload {
    InMemory(Vec<u8>),
    Spilled(NamedTempFile),
}

const MAX_INLINE_CLEAN: usize = 4 * 1024 * 1024 * 1024; // 4 GiB
```

`drain_clean_payload` reads pkt-line packets and accumulates into a
`Vec<u8>` until it would exceed `MAX_INLINE_CLEAN`, at which point it
transfers the accumulated bytes into a `NamedTempFile` and continues
spilling there. Picking 4 GiB bounds peak RSS for the common bale
workload (single-digit-GiB binaries) while keeping virtually every
realistic file on the fast path.

`do_clean` dispatches based on which branch the payload took:

- **InMemory:** cache verify runs against the buffer
  (`clean_cache::verify_chunks_in_memory`); on miss, `handle_clean_in_memory`
  hands the `Vec<u8>` to `xet_data::clean_bytes` (consumes it) and
  populates the cache index from the same buffer
  (`compute_chunks_from_slice`) before it's freed.
- **Spilled:** unchanged from the original code path —
  `verify_chunks(path, …)` and `handle_clean(tmp, …)` exactly as before.

`crates/git-bale/src/clean_cache.rs`:

- `compute_chunks_from_slice(bytes: &[u8]) -> Vec<Chunk>` — same 1-MiB
  xxh3 layout as the file-based variant. Single-pass; no I/O.
- `verify_chunks_in_memory(cached: &[Chunk], bytes: &[u8]) -> bool` —
  serial verify (no thread pool: data is already in RAM so memcpy + xxh3
  dominate and fan-out adds nothing). Bails on first mismatch.

Tests in `clean_cache::tests`:

- `in_memory_round_trips_and_matches_file_path_variant` — cross-checks the
  two `compute_chunks*` implementations chunk-for-chunk so they can't
  drift.
- `in_memory_verify_detects_mid_chunk_edit`
- `in_memory_verify_rejects_size_mismatch`
- `in_memory_empty_file_yields_one_zero_chunk`

## Results

| scenario | before | after | delta |
|---|---|---|---|
| `git diff` after append (iter 1, full clean) | 0.91 s | **0.77 s** | ~15% |
| `git diff` iter 2+ (cache hit on new size) | 0.31 s | 0.28 s | ~10% |
| `git diff` (cache hit, content unchanged) | 0.16 s | **0.01 s** | huge |

The huge drop on the unchanged-content case is git's stat-cache kicking
in: the cache-hit code path now finishes fast enough that git's mtime
cache validates the next call without re-invoking the filter at all.

The iter-1 saving (~150 ms on a 350 MiB blob) is smaller than the
~250 ms predicted from "skip one disk write" — APFS file cache absorbs
most of the tmp-file write — but it's real, monotonic, and safe.

## What did NOT change (and why)

- **Staging architecture.** Clean still writes xorbs/shards to
  `.git/bale/staging/` synchronously during `git add`. Smudge invariant
  preserved.
- **`Sha256Policy`.** Still `Compute`. Old pointers with `sha256` are
  still byte-comparable to new pointers.
- **Cache schema (v3).** No new fields. xet's chunk boundaries are NOT
  in our cache; we only store xxh3 sentinels for size + content-change
  detection.
- **xet-data integration depth.** No reaching into xet's shard / dedup
  internals.

## Future directions, if you want to push further

In order of payoff vs invasiveness:

1. **B-safe-2: optimize xet's per-clean overhead.** `ShardFileManager`
   does per-clean shard consolidation and `LocalClient::drop` runs heavy
   work at process exit (attributed to every filter-process). Either
   would benefit from amortizing across the long-running filter session
   that `git add` already opens. Investigate whether xet exposes hooks
   to defer / skip.
2. **B-safe-3 with shard splicing.** Land a new xet-data API to build a
   shard entry from `[(existing_chunk_hash, ...), (new_chunk_data, ...)]`
   without re-CDC-ing the prefix. Then teach clean-cache to record xet's
   chunk boundaries (schema v4) and resume CDC from the last cached
   boundary on an append. Cuts iter-1 from 0.77 s to ~0.20 s on a
   350 MiB append (estimate: prefix xxh3 verify + tail CDC + one xorb
   write).
3. **Parent-process detection.** `git diff` and `git status` could skip
   xorb staging entirely (just produce a pointer for byte comparison) if
   the filter knew its caller. `getppid` + `proc_name`/`ps` works but is
   cross-platform-fragile.

## Repro

```bash
# Build with debuginfo
CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
  cargo build --release --example profile_clean -p git-bale

# End-to-end git-diff harness
SIZE_MIB=350 crates/git-bale/scripts/profile_diff.sh

# Standalone profile target (works under samply on macOS)
samply record --save-only --no-open --rate 4000 --unstable-presymbolicate \
  -o /tmp/clean.profile.json.gz \
  -- target/release/examples/profile_clean --full /path/to/big.bin

# View profile (opens local web UI)
samply load /tmp/clean.profile.json.gz
```
