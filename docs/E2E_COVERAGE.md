# E2E coverage — intentionally untested paths

Behavior is verified end-to-end only (`tests/e2e/`, run with
`python3 tests/e2e/run.py [--coverage]`). The prior coverage TODO is closed —
every load-bearing path now has a phase. This doc lists the production code the
suite deliberately does **not** cover, so a future `--coverage` audit doesn't
re-flag it as a gap. Each entry is a *reason it can't (or shouldn't) be reached
black-box*, not a backlog item.

## Defensive guards not reachable through the wire

- **`storage-fs` `write_atomic` rename-race-loser** (`Err(_) if dst exists →
  Ok(false)`): on Linux `rename(2)` over an existing regular file replaces it
  atomically, so a concurrent same-dst writer never lands here. Non-Linux /
  Windows guard. The convergence it protects is covered by `failure-fs-cput`.
- **`storage-fs` `write_atomic` rename-hard-fail** (`Err(e)` with dst absent):
  needs a rename-specific fault (e.g. a read-only `xorbs/`); not induced. The
  write/fsync-failure cleanup arm *is* covered by `failure-fs-writefail` (via the
  test-only `BALE_TEST_FS_WRITE_FAIL` hook).
- **`storage-fs` `get_xorb_range` inverted-range** (`end < start → BadRequest`):
  the `get_xorb_transfer` handler's `parse_byte_range_header` rejects `end < start`
  (400) first, and the signed-Range match forces `q.e >= q.s`, so `q.s..(q.e+1)`
  is never inverted. Defensive guard for other `BlobStore` callers. The
  `start>len` reject and `end.min(len)` clamp arms *are* covered by `upload-guards`.
- **`bale-server-shard/xorb.rs` `verify_xorb_body` `DecompressFailed`**: xet's
  LZ4/BG4 decoders tolerate raw payload corruption and emit right-length output,
  so black-box body corruption lands on `HashMismatch`/`LengthMismatch` (both
  covered by `upload-guards`), never a true decode error.
- **Metadata term-list merge (divergent segmentation)**: reproducing two
  *different-length* term lists for one `file_hash` needs global chunk-level dedup
  hits, gated on `hash % 1024 == 0` — and the release client can't lower that
  modulus (`HF_XET_*` is debug-only). The last-line `lookup_file` consistency
  guard *is* covered by `term-merge` (which injects the over-summing list
  directly, since the trigger isn't black-box-reproducible).
- **Boilerplate / DoS arms**: `CoreError→ApiError` mapping arms for variants never
  produced, the 64 MiB body-limit rejections, and the per-statement `.map_err`
  DB-error closures (single-store txns that roll back atomically — a safe
  drop-on-error, not a partial-write window).

## Phases auto-skipped under `--coverage`

`failure-kill`, `failure-conndrop`, `failure-dbbusy` (and the S3 variants)
SIGKILL the server (or a sidecar), and LLVM's atexit hook can't flush `.profraw`
on SIGKILL. They run and assert normally in a non-coverage run; only their
coverage capture is skipped (`cli.py` adds them to `--coverage` skips).

## Platform-gated code

- `storage-fs` `open_private` non-unix branch (`#[cfg(not(unix))]`) and the
  WinFsp mount backend (`mount/backend/winfsp.rs`) never compile/run on the Linux
  CI harness. Windows is verified via the cross-check build, not this suite (see
  the Windows cross-check note in the project memory / `docs/DEVELOPMENT.md`).

## CLI paths deliberately not invoked

- `git-bale install --global` / `--system`: would clobber the host's real
  gitconfig. The harness only ever exercises `install --local` / `init-local`.
