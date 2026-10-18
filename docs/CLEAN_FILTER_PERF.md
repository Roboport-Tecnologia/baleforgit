# Clean filter performance: investigation, options, fix

Record of one session on the `filter.bale.process` clean path, kept so the
next perf pass doesn't re-walk the dead ends. Numbers are a point-in-time
snapshot; the current clean-cache design is in
[`ARCHITECTURE.md`](ARCHITECTURE.md#pointer-cache-clean-short-circuit).

## Problem statement

`git diff` on a slightly modified bale-tracked binary (16 bytes appended
to a 350 MiB blob) took ~0.9 s. CDC + xorb staging is unavoidable at
`git add`, but `git diff` only needs a pointer to compare against the
indexed one.

## Harness

`crates/git-bale/scripts/profile_diff.sh` builds release `git-bale`
(`BUILD=0` skips), sets up a bale repo in a tempdir (clean is offline, so
its dummy server URL is never dialed), writes a random binary (`SIZE_MIB`,
default 35), commits it, appends `APPEND_BYTES` (default 16), and times
`git diff` over `ITERS` iterations plus an unmodified control.
`PROFILE=samply` wraps iter 2; `KEEP=1` keeps the workdir.

Baseline on a 350 MiB payload:

| step | wall time |
|---|---|
| `git add` (cold clean) | 0.92 s |
| `git diff` iter 1 (cache size-mismatched, full clean) | **0.91 s** |
| `git diff` iter 2+ (cache repopulated by iter 1) | 0.31 s |

## Standalone profiler target

`crates/git-bale/examples/profile_clean.rs` runs the same xet-data clean
path as `handle_clean` in a single unsigned binary, so **samply on macOS
can follow it** (the signed `/usr/bin/git` blocks `DYLD_INSERT_LIBRARIES`,
and samply doesn't follow children through `posix_spawn`). Modes:

- `--full` — `FileUploadSession` + `clean_file(Sha256Policy::Compute)` +
  `finalize`; mirrors the spilled production path.
- `--full-no-sha` — same but `Sha256Policy::Skip`.
- `--hash-only` — `data_client::hash_files_async`. CDC + merkle hash, no
  xorbs, no shards, no `redb`.

`--staging <dir>` reuses a staging dir across runs to exercise xet
dedup. Build with line tables so samply can symbolize:

```bash
CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
  cargo build --release --example profile_clean -p git-bale

samply record --save-only --no-open --rate 4000 --unstable-presymbolicate \
  -o /tmp/clean.profile.json.gz \
  -- target/release/examples/profile_clean --full <input-file>
```

`--unstable-presymbolicate` writes a sibling `.syms.json` for offline
parsing. Match symbols on `codeId` ↔ `code_id`: the profile's
`breakpadId` has a trailing `0` that the sidecar's `debug_id` lacks.

## Profile findings (350 MiB random binary, 12 threads sampled)

Initial misread: `update_blocks` (SHA-256 compression) self-time summed
across the 12 hf-xet workers was ~26% of CPU samples, suggesting skipping
SHA-256 would cut ~26% of wall time. **Wrong**: that's CPU time, and
SHA-256 runs concurrently with CDC and xorb building, so it almost
entirely hides behind them.

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

The wall-clock cost above hash-only is the upload-side machinery (xorb
format → shard format → redb → `LocalClient`), not SHA-256. Warm staging
helps: a second `--full` on the modified file against the same staging
dir runs in **0.55 s** (vs 0.78 s cold), since xet skips xorb writes for
known chunks. But 0.55 s is the floor: every clean re-CDCs and
re-BLAKE3s the whole file to know what to dedup.

`git diff` iter 1 is 0.91 s, **0.37 s above that floor**. The gap was
git's pkt-line plumbing plus the then-current `read_binary_to(&mut tmp)`
round-trip: the whole file written to a `NamedTempFile`, re-read by
`clean_file`, and read a third time by `compute_chunks` for the cache. One
disk write and two reads of a 350 MB blob.

## Options evaluated

### A. `Sha256Policy::Skip` in `handle_clean`

One-line change, ~5% win. Breaks byte-comparison with existing pointers
(which carry `sha256`), so `git diff` would report "modified" for
unchanged content. Rejected: too little win for a wire-format break.

### B-safe-1: hash-only at clean time, raw bytes side-table, promote to xorbs at push

Defers xorb building to push-pending. **Unsafe.** Smudge runs whenever
git materializes a blob (checkout, `stash pop`, `reset --hard`, branch
switches, `diff --binary`), and between commit and push the lukewarm
smudge path needs staged xorbs. With deferred staging:

1. `git checkout other-branch` then back: smudge needs xorbs that don't exist → unrecoverable for the just-committed file.
2. File modified before push: push-pending re-chunks the worktree, but the new bytes have a different merkle hash than the committed pointer references → uploading xorbs that don't satisfy any committed pointer; old bytes are gone → **silent data loss**.
3. File deleted before push: committed pointer with no backing bytes anywhere → permanent dangling reference.
4. `git stash`: stash creates a commit whose blob is the pointer; pop runs smudge → fails.

Rejected: "any committed pointer can be smudged back to bytes" is
load-bearing (`CLAUDE.md`, "Treat user data as load-bearing").

### B-safe-2: optimize the in-place clean

`ShardFileManager` and `LocalClient::drop` look heavier than the
workload needs (per-clean shard consolidation, a redb open per call,
exit-time cleanup charged to every filter-process). Real wins, but they
need xet-data internals. Deferred.

### B-safe-3: smarter clean-cache that handles append

The cache stores `(size, xxh3 1-MiB chunks)` and runs a full clean on
any size mismatch.

**Naive form:** if the size grew but the xxh3 prefix verifies, re-CDC
only the tail. That works for the hash (`xet_core_structures::merklehash::file_hash`
takes a chunk-hash vec), but a *staged* pointer also needs:

1. A new shard entry mapping the new file_hash to `[(xorb_A, prefix_chunks), (xorb_B, new_tail_chunks)]`.
2. A new `xorb_B` containing the tail chunks.

xet's `clean_file` takes only a file path; feeding it the tail yields a
shard entry for the tail alone. Splicing existing and new chunks into one
entry needs a new xet-data API or direct use of the shard/dedup
internals: significant work.

Deferred. Warm-staging dedup already does most of this (0.55 s vs 0.78 s
cold), so the marginal win is bounded.

### What landed: in-memory pkt-line drain

The 0.37 s between iter 1 and the xet floor is plumbing: three disk
passes over a blob that is already in RAM via pkt-line. Removing them
touches no safety invariant (same bytes, chunker, xorbs and staging
layout); only whether bytes hit disk before reaching xet changes.

## The fix

`crates/git-bale/src/filter_process.rs` (names as of today; the payload
type is now shared with smudge):

```rust
enum Payload {
    InMemory(Vec<u8>),
    Spilled(NamedTempFile),
}

const MAX_INLINE_CLEAN: usize = 4 * 1024 * 1024 * 1024; // 4 GiB, BALE_MAX_INLINE_CLEAN overrides
```

`drain_payload_spilling` accumulates pkt-line data in a `Vec<u8>` until
it would exceed the inline limit, then moves it into a `NamedTempFile`
and keeps spilling there. 4 GiB bounds peak RSS while keeping virtually
every realistic file (single-digit GiB) on the fast path.

`do_clean` dispatches on the payload:

- **InMemory:** cache verify runs on the buffer
  (`clean_cache::verify_chunks_in_memory`); on a miss,
  `handle_clean_in_memory` builds the cache index from the buffer
  (`compute_chunks_from_slice`), then hands the `Vec<u8>` to xet-data's
  `data_client::clean_bytes`, which consumes it.
- **Spilled:** the original path, `verify_chunks(…, tmp.path(), …)` and
  `handle_clean(…, tmp, …)`.

`crates/git-bale/src/clean_cache.rs` gained `compute_chunks_from_slice`
(same 1-MiB xxh3 layout as the file variant, no I/O) and
`verify_chunks_in_memory` (serial: the data is in RAM, so a thread pool
adds nothing; bails on the first mismatch).

The `spilled-clean` e2e phase covers the spill path by capping
`BALE_MAX_INLINE_CLEAN` at 1 MiB.

## Results

| scenario | before | after | delta |
|---|---|---|---|
| `git diff` after append (iter 1, full clean) | 0.91 s | **0.77 s** | ~15% |
| `git diff` iter 2+ (cache hit on new size) | 0.31 s | 0.28 s | ~10% |
| `git diff` (cache hit, content unchanged) | 0.16 s | **0.01 s** | huge |

The unchanged-content drop is git's stat cache: the cache-hit path now
finishes fast enough that git validates the next call by mtime without
invoking the filter.

The iter-1 saving (~150 ms) is below the ~250 ms predicted from skipping
the tmp-file write, since APFS's file cache absorbs most of it, but it's
real and safe.

## What did NOT change (and why)

- **Staging architecture.** Clean still writes xorbs/shards
  synchronously during `git add` (to `.git/bale/staging/`, or the local
  store in fully-local mode), preserving the smudge invariant.
- **`Sha256Policy`.** Still `Compute`, so pointers stay byte-comparable.
- **Cache schema.** Unchanged by this work (then v3; now v4, which binds
  entries to the object store for unrelated reasons). It holds only xxh3
  sentinels, not xet's chunk boundaries.
- **xet-data integration depth.** No use of xet's shard/dedup internals.

## Future directions

By payoff vs invasiveness:

1. **B-safe-2: cut xet's per-clean overhead.** Amortize per-clean shard
   consolidation and `LocalClient::drop`'s exit-time work across the
   long-running filter session `git add` already opens, if xet exposes
   hooks to defer or skip them.
2. **B-safe-3 with shard splicing.** A new xet-data API that builds a
   shard entry from `[(existing_chunk_hash, ...), (new_chunk_data, ...)]`,
   plus a clean-cache schema bump recording xet's chunk boundaries so
   CDC resumes from the last cached boundary on append. Estimated iter 1
   on a 350 MiB append: 0.77 s → ~0.20 s (prefix verify + tail CDC + one
   xorb write).
3. **Parent-process detection.** `git diff`/`git status` could skip xorb
   staging and only produce a pointer if the filter knew its caller.
   `getppid` + `proc_name`/`ps` works but is fragile across platforms.

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
