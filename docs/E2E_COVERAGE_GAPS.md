# E2E coverage gap analysis

Snapshot of where the `python3 tests/e2e/run.py --coverage` report leaks
production-code coverage, and what would close each gap. Resume work
from this document — sections are independent and each lists the source
locations and the proposed e2e change.

**Snapshot context**: run on macOS (Darwin), `--coverage` mode (so the
SIGKILL phases `failure-kill`, `failure-conndrop`, `failure-dbbusy`,
`s3-failure-kill`, `s3-failure-conndrop` auto-skipped). Overall totals:
46.8% fn / 51.5% line / 49.5% region. `bale-server-shard` was excluded
from the analysis on purpose.

Report tree at `target/coverage-e2e/html/index.html`. Per-file HTML
under `target/coverage-e2e/html/coverage/`. A small helper at
`/tmp/extract_uncovered.py` parses one file:

```
python3 /tmp/extract_uncovered.py <path>.html
# `U <lineno>: <code>` = fully uncovered, `R <lineno>: <code>` = partial
```

Classification tags used below:

- **MISSING-E2E** — real production path that *could* be covered by a
  new/changed e2e phase. The fix is documented.
- **TEST-ONLY-PROD-CRATE** — code lives in a prod crate but only
  `#[cfg(test)] mod tests` or a `cargo test` integration test exercises
  it. The e2e binaries never reach it.
- **ERROR-PATH-NOT-INDUCED** — production error branch that exists but
  no e2e phase triggers the precondition (usually because the e2e
  client never sends malformed inputs). Most are reachable only via
  hand-rolled HTTP probes.
- **CLI-NOT-EXERCISED** — a `git-bale` subcommand or argv branch the
  harness never types.
- **DEAD-UNREACHABLE** — no test reaches it; not on a path that occurs
  in practice. Deletion candidate.
- **E2E-SKIPPED-IN-COV-MODE** — production path is in the e2e but the
  phase is auto-skipped under `--coverage` (SIGKILL phases).
- **PLATFORM** — gated behind `cfg(...)` that didn't apply on the host.

---

## 1. The single biggest gap: mount-session profraws dropped on SIGPIPE — FIXED (~890 lines)

The `mount-rev` and happy `mount-diff` phases *did* mount and read
correctly (their assertions passed), but every `.profraw` they produced
was being **lost**, so the coverage report showed the whole mount
subsystem at ~0%. Original (pre-fix) evidence:

- `mount/reader.rs` — 0/350 (entire file uncovered)
- `mount/vfs.rs` — 0/303 (entire file uncovered)
- `mount/backend/libfuse.rs:65-150, 443-628` — 0% (the `mount()` body
  and every `op_*` FUSE callback)
- `mount/mod.rs:42-94` (`run_rev`) — 0%; `run` is partially covered
  only via the pathspec-empty subphase
- `mount/diff.rs:86-177` (`change_to_entry`) — 0%

**Actual root cause** (the `_wait_mounted` timeout hypothesis was wrong —
the mounts came up in <0.5s): on macOS, fuse-t kills the mount process
with **SIGPIPE from inside `fuse_main_real`** during unmount teardown
(the FUSE channel fd is closed while fuse-t is still writing to it).
Rust's default SIGPIPE disposition is `SIG_DFL`, so the process is
terminated before `main` returns — bypassing the atexit-registered
llvm profile flush. The diagnostic was a `proc.returncode == -13`
(`-SIGPIPE`) on every mount session, with the binary's last stderr line
being "filesystem ready" (i.e. `fuse_main_real` never returned).

**Fix applied**:
- `mount/backend/libfuse.rs` installs a SIGPIPE handler (gated behind a
  new `coverage` cargo feature) right before `fuse_main_real`. The
  handler calls `__llvm_profile_write_file()` then `_exit(0)` — both
  async-signal-safe — so the profile is flushed before the process dies.
  No-op in prod builds (the feature is off and the extern isn't linked).
- `crates/git-bale/Cargo.toml` adds the `coverage` feature.
- `tests/e2e/run.py` `build_instrumented_git_bale()` builds with
  `--features coverage`; `_mount_session` extends the mount-up wait to
  120s under `--coverage` and warns if a mount proc exits non-zero
  (the canary for this regression). `MountUnavailable` now carries the
  binary's full stderr, logged by the skip handlers.

**Result** (verified): overall line coverage 51.5% → **65.3%**.
mount/reader.rs 0%→74.5%, mount/vfs.rs 0%→68.0%, mount/mod.rs
11.3%→71.3%, mount/diff.rs 53.0%→71.8%, libfuse.rs 4.6%→76.7%.

Per-file detail (all MISSING-E2E unless noted):

- **mount/mod.rs:42-94** — `run_rev` body.
- **mount/mod.rs:96-114** — `resolve_commit_and_tree`.
- **mount/mod.rs:137** — empty-pathspec branch of mount-diff (pathspec
  subphase always passes a non-empty arg). Trivial separate phase.
- **mount/mod.rs:144-176** — happy mount-diff label resolution + config
  load + Reader::new + DiffVfs::build + mount call.
- **mount/mod.rs:182-196** — `sanitize_label`. **TEST-ONLY-PROD-CRATE**
  today (covered by `#[cfg(test)] mod tests`); in e2e
  `mount-diff` always passes explicit `--label-a/--label-b`. Add a
  no-label phase with revs that need sanitizing (branch names with `/`).
- **mount/diff.rs:51** — `mount-diff REV REV` distinct-commits error.
  Trivial assert phase.
- **mount/diff.rs:86-177** — `change_to_entry` Add/Delete/Modify arms.
  Delete arm needs a phase where rev_b removes a file present in rev_a.
- **mount/diff.rs:175** — `Rewrite => None`. **DEAD-UNREACHABLE** unless
  rename-detection is enabled in `gix::diff` config (it isn't).
- **mount/reader.rs:100-498** — Whole `Reader`. Unblocked by §1 fix.
- **mount/reader.rs:339-345** — plain blob >16 MiB error. **DEAD-UNREACHABLE**
  unless a fixture commits a non-bale-tracked file >16 MiB.
- **mount/reader.rs:504-512** — `install_active` / `active`.
  **DEAD-UNREACHABLE**, no callers in the workspace. **Delete.**
- **mount/vfs.rs:75-453** — Whole VFS. Unblocked by §1 fix.
- **mount/vfs.rs:253-256** — `eager_insert` empty-components early
  return. **DEAD-UNREACHABLE** (gix tree paths are never empty).
- **mount/vfs.rs:178-181** — `populate_dir_locked` Err warn-and-clear.
  **DEAD-UNREACHABLE** unless a bad tree object exists.
- **mount/backend/libfuse.rs:59-61** — `Default for LibfuseBackend`.
  **DEAD-UNREACHABLE**, no callers. **Delete.**
- **mount/backend/libfuse.rs:195-220, 238** — `LibfuseUnavailable::fmt`
  + `Err(LibfuseUnavailable)` path. **DEAD on this host** (fuse-t IS
  installed). Add a `mount-no-libfuse` phase that hides the dylib (e.g.
  invalid `DYLD_LIBRARY_PATH` or temporarily moves it), asserts exit 2
  and the install hint.
- **mount/backend/libfuse.rs:253-256** — "disappeared between check and
  mount" Err. **DEAD-UNREACHABLE** in practice.
- **mount/backend/libfuse.rs:202-204, 212** — Linux variant of the
  Display impl. **PLATFORM**, only reachable on Linux coverage.

---

## 2. MISSING-E2E gaps, ranked by payoff

| # | Phase to add | Lines unlocked | Files |
|---|---|---|---|
| 1 | ~~Fix happy mount sessions (see §1)~~ **DONE** | ~890 | mount/* |
| 2 | ~~`GET /v1/files/{file_id}` browser download~~ **DONE** (`browser-download` phase, +115 lines) | ~150 | bale-server-http:698-892 |
| 3 | Spilled-clean (>4 GiB) path | ~130 | filter_process.rs:253-477, clean_cache.rs:220-382 |
| 4 | HTTPS-origin phase | ~80 | resolver.rs:101-190, 281-337 |
| 5 | OTLP-collector sub-phase | ~60 | bale-server-bin/telemetry.rs |
| 6 | `PUT /v1/quotas/{owner}` admin-quota phase | ~40 | bale-server-http:1241-1266, meta-sqlite:597-615, http:288 |
| 7 | `phase_uninstall` | ~40 | install.rs |
| 8 | `phase_track` (swap manual `.gitattributes` write for `git-bale track`) | ~30 | track.rs, main.rs:148-153 |
| 9 | Cross-repo M12 scope probe at the wire | ~10 + load-bearing security | bale-server-http:565 |
| 10 | Datasets/spaces token-mint phase | ~15 | tokens.rs:70-79, http:1271-1273 |
| 11 | JWT-owner-mismatch on `/v1/usage/{owner}` | ~5 | http:1187-1190 |
| 12 | Manifest-cache-only fallback (wipe chunks but keep manifests) | ~5 | local_reconstruct.rs:49 |
| 13 | scp-style remote URL (`git@host:owner/repo.git`) | ~15 | remote.rs:83-98 |
| 14 | Env-var-driven config (`BALE_SERVER_URL`, `BALE_TOKEN`, `BALE_CACHE_DIR`, `BALE_TOKEN_EXPIRATION`, `HF_XET_CACHE`, `XDG_CACHE_HOME`) | ~20 | config.rs, main.rs:179 |
| 15 | `core.hooksPath` pre-set then `install --local` | ~5 | install.rs:121-126 |
| 16 | `mount-diff REV REV` + no-label `sanitize_label` exercise | ~25 | mount/mod.rs:182, diff.rs:51 |
| 17 | Mount with deletion (rev_a has file, rev_b doesn't) | ~15 | mount/diff.rs:133-147 |
| 18 | Boot server without `BALE_ADMIN_TOKEN_HEX` | ~10 | bin/main.rs:179-188 |
| 19 | `git-bale -v push-pending` for verbosity arms | 2 | main.rs:119-120 |
| 20 | Pre-create hand-written `pre-push` hook then `install --local` (assert refusal) | ~10 | install.rs:67-76 |

Notes on a few of these:

**Phase 2 (`/v1/files/{file_id}`)** — **DONE**, the `browser-download`
phase. Implemented as three sub-cases against the bigfile pushed to
repo2: (a) opaque hub token + no filename → 200, bytes match HEAD, no
`Content-Disposition`; (b) a forge-style JWT carrying `FilenameSHA256`
(registered as its own repo2 read grant, since static authz matches the
bearer verbatim) + matching filename → 200 with `Content-Disposition:
attachment; filename="bigfile.bin"`; (c) same JWT + tampered filename →
400. `forge_jwt_with_filename()` builds the JWT; `http_get_file()` is the
probe. Lifted bale-server-http line coverage 63.9% → 76.4%.

**Phase 3 (>4 GiB spilled clean)**: two options: (a) push an actual
>4 GiB file in a dedicated phase, or (b) make `MAX_INLINE_CLEAN`
env-overridable in `filter_process.rs` and drop to ~1 MiB for one
phase. Option (b) is dramatically cheaper. This single fix unlocks
~50 lines in `filter_process.rs` (L253-274, L310-313, L337-338,
L402-477) and ~80 lines in `clean_cache.rs` (L220-382 — the
file-backed verify path + `priority_order`).

**Phase 4 (HTTPS origin)**: reuse the `authz-http` mock forge.
Configure `origin` as `http://<mock>/<owner>/<repo>.git` and run
push/clone. Covers the entire `Http | Https` branch in
`resolver.rs:101-108`, `authenticate_http` (143-190), and
`git_credential_fill` (281-337).

**Phase 5 (OTLP collector)**: Python socket draining POSTs to
`/v1/traces` and `/v1/metrics`. Run server with
`OTEL_EXPORTER_OTLP_ENDPOINT=http://host.containers.internal:PORT`.
Covers `telemetry.rs:72-122, 141-151`. Could fold into the `usage`
phase since the server is already up.

**Phase 6 (admin quota PUT)**: also exercises the 401-on-missing-bearer,
not-hex-bearer, wrong-admin-token, and `effective_quota` Some(n)
branches at once.

**Phase 9 (M12 wire-level scope probe)**: mirrors the cargo m12 test
but in production deployment shape (real SSH, real HTTP). Push file F
in `e2e/repo`, mint a token for `e2e/repo2`, `GET /v1/reconstructions/F`,
assert **404** (not 403). This is one of the load-bearing security
invariants from CLAUDE.md "Don't 'fix' these without being asked".

---

## 3. Production paths reachable only via hand-rolled HTTP (ERROR-PATH-NOT-INDUCED)

Real branches that production traffic from `git-bale` never trips
because the client never sends malformed inputs. The e2e could cover
them with direct `urllib` probes bypassing the binary:

- POST `/v1/xorbs/.../{hash}` with body bytes ≠ hash → `verify_xorb_body`
  mismatch (http:356-358).
- POST with wrong-length hex hash → `decode_hash` bad-length (wire:38).
- POST `/v1/xorbs` with read-scope token → 403 in auth middleware
  (http:220-223).
- POST shard whose entries cite an absent xorb (http:398-414).
- POST shard with `chunk_idx_start >= chunk_idx_end` (http:417-420).
- POST shard with verifications.len() != entries.len() (http:494-496).
- GET `/xorb/default/{hash}` with forged sig / stale `x=` / mismatched
  `Range` header (http:1052, 1055, 1063).
- GET reconstruction with inverted `bytes=10-5` range (http:1094).
- Authz-http upstream failures: stop the mock mid-request /
  return non-JSON body / non-empty base path missing trailing slash
  (authz-http:54, 121, 138, 146).
- Two clients pushing identical content concurrently → `FsBlobStore::write_atomic`
  race-loser branch (storage-fs:115-119).
- POST a xorb body > 64 MiB cap (http:317).
- POST a shard > 64 MiB cap (http:391).
- Two-owner cross-dedup push under a quota that trips the
  shard-upload quota recheck (http:471-475, 477-484).

Each is small in line count but several are load-bearing
security/safety invariants worth wire-level coverage.

---

## 4. Production code only reached by `cargo test` (TEST-ONLY-PROD-CRATE)

Lives in production crates but reached only by `#[cfg(test)] mod tests`
or `crates/bale-server-tests/`. None are dead in the cargo-test sense.
**Deletion candidates** are flagged below.

- `config.rs:90-105` — `BaleConfig::load()` (strict loader).
  **No production caller found**; production uses the resolver path.
  Verify and **delete** if confirmed.
- `pointer.rs:28-32, 34-36, 61-68` — `write_pointer`,
  `encode_pointer` (Vec wrapper), `read_pointer`.
  **No production callers**. **Delete.**
- `pktline.rs:137-148, 215-224` — `impl Read for PktReader`,
  `impl BufRead`, `impl Write for PktWriter`. **No consumers in the
  workspace use these traits via the framing types**. **Delete.**
- `pktline.rs:160-162` — `into_inner`. No caller. **Delete.**
- `bale-server-authz-mem` — whole `AlwaysAllow` impl. Used only by
  cargo tests; `bale-server-bin` constructs the grants-table impl.
  Keep as test helper.
- `bale-server-authz-http:74-84` — `HttpAuthz::with_client`.
  Production uses `::new`. Keep as test ctor.
- `bale-server-core:24-26, 49-51` — `Hash32::from_bytes` and newtype
  `from_bytes` helpers. Keep as test ctors.
- `meta-sqlite:91-106` — `count_xorbs`, `count_files`. Explicit
  test/diagnostics helpers.
- `meta-sqlite:114` — `":memory:"` → `"sqlite::memory:"` open-path
  branch. Cargo tests only.
- `clean_cache.rs:108, 111, 150-209` — defensive guards (version
  mismatch, malformed JSON, empty-file zero-chunk, defensive false
  returns in `verify_chunks_in_memory`).
- `manifest_cache.rs:54, 58, 61` — three defensive arms (IO error,
  malformed JSON, version mismatch).
- `pktline.rs` — most protocol-error arms (L36-48, L91-95, L117-129).
- `remote.rs:47-50, 99, 109` — `parse_remote` error arms covered by
  unit tests.
- `resolver.rs:414-425` — `validate_segment` rejection arms covered
  by `validate_segment_rejects_traversal_and_shell_meta`.
- `track.rs` — entire file. Unit tests + the CLI dispatch arm in
  `main.rs:148-154` are both unreachable from e2e until §2 phase 8
  swaps `git-bale track` in for the manual `.gitattributes` write.

---

## 5. Genuinely dead / unreachable in production (DEAD-UNREACHABLE)

Trim candidates — no test path reaches them and the user binary won't
either:

- `bale-server-http:174-176` — `CoreError::Conflict` arm of the `From`
  impl. Conflict is never produced anywhere in the codebase.
- `bale-server-http:598-607` — reconstruction 500s for layout-missing
  / inverted-range. Both invariants are guarded against by upload-side
  validation.
- `bale-server-http:1074-1078` — `HeaderValue::try_from(format!("bytes
  {}-{}/*", u64, u64))` 500 fallback. Always valid ASCII.
- `bale-server-http:941-1018` — `get_dedup_chunk` + `wrap_chunk_hash`.
  git-bale uses `local_config` (no global dedup query). Reached only
  by cargo m6.
- `bale-server-storage-fs:175-182` and `bale-server-storage-s3:211-233`
  — `BlobStore::get_shard` impls. No HTTP handler calls these; only
  cargo tests do. (Worth confirming the trait still needs `get_shard`
  on `BlobStore` at all.)
- `bale-server-core:213-215, 240-245, 264-273` — trait default impls
  overridden by all concrete impls.
- `bale-server-core:95` — `RepoRef::owner()` None arm; forge always
  supplies `owner/name`.
- `bale-server-bin:271-273` — `is_loopback` only called when
  `BALE_PUBLIC_URL` is unset, which never happens in e2e.
- `mount/reader.rs:504-512` — `install_active` / `active`. No callers
  in the workspace. **Delete.**
- `mount/backend/libfuse.rs:59-61` — `Default for LibfuseBackend`.
  No callers. **Delete.**
- `meta-sqlite:219-232, 716-718` — i64 overflow guard + `internal`
  wrapper. Defensive against schema corruption.
- `push_pending.rs:53, 92-96, 171-186, 213` — staging-dir-missing /
  no-size-marker compatibility branches that the current writer
  never emits.
- `filter_process.rs:67-71, 107-187, 197-209, 503-506` — protocol-error
  reporting branches. Real git always sends conformant frames;
  reachable only by a hand-rolled pkt-line client.
- `clean_cache.rs:194-209` — defensive false returns in
  `verify_chunks_in_memory`.
- Most `tracing::warn!`/`tracing::debug!` arms in `filter_process.rs`,
  `push_pending.rs`, `staging.rs` — best-effort IO failure paths not
  induced.
- `local_reconstruct.rs:50-80` — chunk-cache-read-Err / length-mismatch
  / sum-mismatch warn-and-Miss arms. Require chunk-cache corruption
  or manifest-construction bugs not in production.
- `filter_process.rs:301-304` — clean-cache size-divergence log.
  Would require modifying a file to a different size and re-staging
  within the same long-running filter-process. **MISSING-E2E** if you
  add a modify-then-restage phase.

---

## 6. CLI subcommands the e2e never invokes (CLI-NOT-EXERCISED)

- `git-bale track` — entire `track.rs`, dispatch arm in
  `main.rs:148-153`. Fix: §2 phase 8.
- `git-bale uninstall [--all]` — `install.rs:42-57, 94-107, 187-198`,
  `main.rs:137-146`. Fix: §2 phase 7.
- `git-bale install --global` / `--system` — `install.rs:153-154`
  Scope arms, `main.rs:196-206`. Sensibly skipped (would clobber the
  host gitconfig).

---

## 7. E2E-SKIPPED-IN-COV-MODE (kept skipped on purpose)

The harness auto-skips `failure-kill`, `failure-conndrop`,
`failure-dbbusy`, `s3-failure-kill`, `s3-failure-conndrop` because
LLVM's atexit hook can't flush profraws on SIGKILL. The branches they
exercise (server crash + restart recovery, mid-PUT-to-S3 retry, sqlite
busy-timeout) consequently show as uncovered.

Not actionable without re-architecting how profraws are captured —
either move to runtime-flush via `__llvm_profile_write_file` on a
signal handler, or accept the gap and rely on the prod (non-coverage)
run for those phases.

---

## Bottom line / priority order

1. ~~**Fix mount-session coverage capture** (§1).~~ **DONE** — single
   biggest lift, took the report from 51.5% to 65.3% line coverage. Root
   cause was SIGPIPE dropping profraws, not a mount timeout; fixed with a
   coverage-only SIGPIPE handler that flushes the llvm profile.
2. ~~**Browser `/v1/files/...` phase** (§2.2).~~ **DONE** — `browser-download`
   phase, +115 lines on bale-server-http (63.9% → 76.4%), overall 65.3% →
   67.6% line coverage.
3. **Spilled-clean threshold knob** (§2.3). ~130 lines.
4. **HTTPS-origin + OTLP collector + admin-quota + uninstall + track
   phases** (§2.4–§2.8). ~210 lines combined, each phase modest in
   complexity.
5. **Wire-level security probes** (§3 cross-repo M12 scope, JWT-owner
   mismatch, signed-URL tampering). Small in lines, but load-bearing
   for the invariants called out in CLAUDE.md.
6. **Trim dead code** (§4 deletion candidates + §5). Improves the
   coverage signal without writing new tests:
   - `config::BaleConfig::load`
   - `pointer::{write_pointer, encode_pointer, read_pointer}`
   - `PktReader::{Read, BufRead, into_inner}`, `PktWriter::Write`
   - `mount::reader::{install_active, active}`
   - `Default for LibfuseBackend`
   - `BlobStore::get_shard` (if it really has no production caller)
