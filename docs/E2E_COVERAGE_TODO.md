# E2E coverage TODO — important untested paths

Prioritized list of **important** server paths the e2e suite does not exercise,
derived from an llvm-cov audit of the `--coverage` run. Unlike
[`E2E_COVERAGE_GAPS.md`](E2E_COVERAGE_GAPS.md) (which catalogs *intentional* gaps
— dead code, defensive arms, cargo-test-only ctors), every item here is a gap
that **should be closed**: each touches a prime directive (no data corruption,
no data races, load-bearing security/scope checks, correctness under partial
failure).

Each item is self-contained: file:line, what's untested, why it matters, and a
one-line sketch of the e2e phase that would cover it. Work top-down — Tier 1 is
the highest integrity-per-effort and items 1–3 fit in a single new adversarial
phase using machinery that already exists.

## How this was measured (re-verify after each fix)

The `--coverage` run merges profraws from the server + every `git-bale` client
process into `target/coverage-e2e/profiles/merged.profdata`, against the
instrumented server binary `target/coverage-e2e/baleforgit-server`.

```bash
# Full regen (rebuilds instrumented image + binary, runs whole suite, renders HTML):
#   NOTE: on macOS, podman needs --state-dir under /Users (it can't mount /tmp),
#   and long runs need the podman VM clock kept in sync (JWT "clocks differ"):
#     podman machine ssh "sudo date -s @$(date -u +%s)"   # before + periodically
python3 tests/e2e/run.py --coverage --state-dir target/coverage-e2e/state

# Inspect one file's uncovered lines (count 0 = never executed):
LLVMCOV="$(rustc --print sysroot)/lib/rustlib/$(rustc --print host-tuple)/bin/llvm-cov"
PROF=target/coverage-e2e/profiles/merged.profdata
"$LLVMCOV" show target/coverage-e2e/baleforgit-server -instr-profile=$PROF \
  -path-equivalence=/src,"$(pwd)" -show-line-counts -use-color=false \
  /src/crates/bale-server-http/src/lib.rs | grep -nE '\|\s+0\|'
```

A fix is "done" when the targeted lines below flip from count 0 to non-zero in a
fresh run **and** the new phase asserts the *behavior* (rejection/clamp/etc.),
not just that the line ran.

## Harness entry points (where new phases go)

- `tests/e2e/baleharness/phases/adversarial.py` — wrong-token, `tampered-xorb`,
  quota-exceeded. **Home for Tier 1 items 1–3.** `phase_adversarial_tampered_xorb`
  (~L128) is the closest existing pattern, but note it corrupts on disk and
  *smudges* (download side) — it does NOT POST a bad body to the server.
- `tests/e2e/baleharness/phases/usage.py` — already issues raw authenticated /
  forged HTTP requests (`http_get_file`); reuse for signed-URL + usage-authz tests.
- `tests/e2e/baleharness/phases/compression.py` — already POSTs real xorb bodies
  to `/v1/xorbs/...`; closest reference for constructing item 1's request.
- `tests/e2e/baleharness/phases/failure.py` + the `failure-s3-conndrop` phase —
  fault-injection template (host-side TcpProxy) for Tier 3 error-path items.
- `BALE_TEST_*_DELAY_MS` env hooks (see `local.py`) — deterministic-race template
  for Tier 3 concurrency items.
- Register new phases in `tests/e2e/baleharness/cli.py` (phase registry).

---

## Tier 1 — load-bearing, zero coverage, cheap to close

> **✅ DONE (2026-06-03).** Items 1–3 are covered by the new `upload-guards`
> e2e phase (`tests/e2e/baleharness/phases/adversarial.py`,
> `phase_adversarial_upload_guards`; registered as `upload-guards` in `cli.py`,
> group g3). A `--coverage --only upload-guards` run confirmed the target lines
> flip from 0: http `204/205` (scope→403), `335` (HashMismatch), `336`
> (LengthMismatch / `other`), `986/989/997` (forged/expired/Range-mismatch
> signed-URL 401s); xorb `168` (LengthMismatch), `181/182` (HashMismatch).
> **One residual:** `xorb.rs:162-166` `DecompressFailed` stays 0 — xet's
> decompressors tolerate raw payload corruption and emit right-length output, so
> a true decode *error* isn't reachable by black-box body corruption. Reaching it
> would need a frame-format-coupled craft (e.g. a deliberately invalid LZ4 block);
> judged not worth the fragility. The LengthMismatch arm already covers the
> `verify_xorb_body`-rejection-other-than-HashMismatch path.

### 1. Server-side upload integrity gate has NO negative test  ⭐ highest value
- **Where:** `crates/bale-server-http/src/lib.rs:333-338` (the `verify_xorb_body`
  call + rejection), backed by `crates/bale-server-shard/src/xorb.rs:181-183`
  (`HashMismatch`) and `161-173` (`DecompressFailed` / `LengthMismatch`).
- **Untested:** the rejection arms. The upload happy path runs constantly; the
  reject path runs 0×.
- **Why it matters:** this is *the* guard preventing a writer from poisoning
  content-addressed storage with bytes that don't match the URL hash (see the
  comment at `lib.rs:331-332`). The existing `tampered-xorb` phase corrupts
  *after* upload and exercises the **client/download** chunk-hash check —
  it never touches this server **upload** gate. A regression that no-op'd or
  inverted `verify_xorb_body` would pass the entire suite while allowing CAS
  poisoning. **Verified by hand.**
- **Phase sketch:** stage/clean a file offline, then POST the staged xorb body to
  `/v1/xorbs/default/{hash}` with a valid write token but (a) a wrong `{hash}` in
  the URL, and (b) a body with one flipped byte. Assert HTTP 400 ("xorb body does
  not match URL hash" / "verification failed") and that nothing lands on disk.
  Add a third variant POSTing a body with a corrupt compressed frame and one with
  a rewritten `uncompressed_length` to hit `DecompressFailed` / `LengthMismatch`.

### 2. Signed transfer-URL enforcement is unverified
- **Where:** `crates/bale-server-http/src/lib.rs:985-998` (in `get_xorb_transfer`).
- **Untested:** forged `sig` (986), expired `x` (989), and `Range` header not
  matching the signed range (997). Happy path ran 127×; none of the three guards
  fired.
- **Why it matters:** prime directive — "signed transfer URLs must enforce the
  Range match and use constant-time signature compare." Both the constant-time
  compare and the Range binding are completely unverified end-to-end. fs-backend
  only (S3 presigns bypass this handler — phase should self-skip on `--backend s3`).
- **Phase sketch:** obtain a real reconstruction fetch URL, then re-request with
  (a) a flipped `sig`, (b) `x` set to the past, (c) a `Range` header different
  from the signed `s`/`e`. Assert 401 each. Reuse `usage.py`'s raw-HTTP helper.

### 3. Read-scope token doing a write is never rejected
- **Where:** `crates/bale-server-http/src/lib.rs:204-208` (`auth_middleware` scope
  branch).
- **Untested:** the `claims.scope == Read` + mutating-method → reject branch. The
  middleware ran 298× and rejected 2 invalid tokens, but the read-vs-write scope
  distinction never fired.
- **Why it matters:** only thing stopping a read-scoped token from uploading
  xorbs/shards or registering files. Load-bearing, unverified.
- **Phase sketch:** mint a read-scope token (harness already issues read grants),
  attempt `POST /v1/xorbs/...` → assert 403.

---

## Tier 2 — deepest corruption directive, moderate effort

### 4. Metadata write-once guard only tested for *identical* re-registration
- **Where:** `crates/bale-server-meta-sqlite/src/lib.rs:167-175` (`write_file_in_tx`
  `terms_exist` skip-branch) and `342-349` (`lookup_file` term-sum-vs-recorded
  mismatch refusal). Mirror in `crates/bale-server-meta-postgres/src/lib.rs`.
- **Status:** the skip-branch IS covered (count 6) — but **only** for an
  identically-segmented re-registration (cold-cache re-push). The mismatch-refusal
  arm at 342-349 never fires.
- **Why it matters:** the guard exists because the same content re-segments into a
  *different number of terms* against a different pre-existing xorb set; a merge
  yields Σunpacked > file_size and corrupts every reconstruction of that hash
  (xet's last-term trim underflows). The **divergent-segmentation** property — the
  actual corruption trigger — is untested, as is the last-line-of-defense
  `lookup_file` mismatch guard that refuses to serve an over-describing list before
  the client panics. This is the single gap closest to "no data corruption ever."
  Also unverified: the comment's serialization claim under two concurrent
  same-hash `register_files`.
- **Phase sketch:** push file X to repo A (segmentation S1); warm a *different*
  xorb set; push the same X to repo B so xet re-segments (S2); clone B and assert
  reconstructed bytes == original (proving terms were not merged). Optionally a
  stress variant firing two `register_files` of the same hash concurrently.

---

## Tier 3 — real, but needs fault-injection / concurrency hooks

### 5. `write_atomic` partial-failure + race arms
- **Where:** `crates/bale-server-storage-fs/src/lib.rs:88-91` (write/fsync failure
  → remove tmp + error), `104-108` (rename-race loser → `Ok(false)`), `109-115`
  (rename hard-fail, dst absent → remove tmp + error).
- **Untested:** all three. The pre-write idempotent fast-path (L69-70) IS covered;
  these harder arms are not.
- **Why it matters:** "never leave a half-written xorb visible / no tmp leak under
  partial failure" + "two concurrent uploads of the same content converge." A
  regression that renamed-before-fsync, forgot tmp cleanup, or mishandled the
  rename race would pass CI silently.
- **Phase sketch:** (a) fault injection — push into a full/quota-capped tmpfs or
  inject a write error; assert the put fails, `dst` absent, `tmp/` empty (fs
  analogue of `failure-s3-conndrop`). (b) concurrency — two clients push the *same*
  new large file concurrently (cold cache); assert exactly one stored copy, both
  succeed, `tmp/` empty. Deterministic via a `BALE_TEST_*` delay between the L69
  existence check and the rename.

### 6. `get_xorb_range` bounds/clamp arms (sub-range reads)
- **Where:** `crates/bale-server-storage-fs/src/lib.rs:131-133` (inverted range →
  BadRequest), `144-148` (`start > len` reject + upper clamp `end.min(len)`).
- **Untested:** the suite only ever requests a full/in-bounds range (smudge passes
  `0..file_size`), so the clamp never clamps and neither bound check fires.
- **Why it matters:** Range-read correctness — a wrong clamp returns wrong bytes
  (silent corruption) or underflows `(end - start) as usize`. The BlobStore trait
  is a contract any caller can hit with a partial range.
- **Phase sketch:** issue a `get_xorb_range`/transfer request with a `url_range`
  ending before the xorb's true end, plus `start > len` and inverted-range
  variants; assert correct subset bytes and 400 on the bad ranges.

---

## Tier 4 — access-control / accounting, lower blast radius

### 7. Cross-owner usage authorization + admin-token path
- **Where:** `crates/bale-server-http/src/lib.rs:1106, 1113-1117`
  (`require_admin_or_owner`). Ran 4×, but the hex-admin-bearer accept path and the
  "token not scoped to this owner" → FORBIDDEN both count 0 (the usage phase passes
  an owner-scoped JWT, so every call took the JWT branch).
- **Why it matters:** `/v1/usage/{owner}` and `/v1/usage/repo/...` expose per-owner
  / per-repo storage accounting. A regression letting owner A read owner B's usage
  would pass today.
- **Phase sketch:** (a) call `/v1/usage/{owner}` with the hex `admin_token_hex`
  (already plumbed) → 200; (b) call `/v1/usage/{other_owner}` with a token scoped
  to a different owner → 403.

### 8. `PUT /v1/quotas/{owner}` admin endpoint entirely uncovered
- **Where:** `crates/bale-server-http/src/lib.rs:1170-1195` (whole `put_owner_quota`
  handler: admin-disabled 404, missing/non-hex bearer, constant-time admin-token
  compare, successful `set_owner_quota`). Plus
  `crates/bale-server-meta-sqlite/src/lib.rs:515-537` (`set_owner_quota` both the
  upsert and the `None`→DELETE arms — count 0).
- **Why it matters:** an authenticated mutating endpoint with a constant-time token
  compare, shipping with zero proof it authenticates or persists. Tests currently
  set quotas only via `BALE_DEFAULT_QUOTA_BYTES`/env, never this API.
- **Phase sketch:** `PUT /v1/quotas/{owner}` with hex admin token + `{"limit_bytes":N}`
  → 204; bad token → 401; then confirm a subsequent over-quota push is rejected
  (proves the write took effect). Add a `None` (clear) variant.

### 9. Shard-stage quota check + `unaccounted_xorb_bytes_for_owner`
- **Where:** `crates/bale-server-http/src/lib.rs:437-453` (shard-stage delta-quota
  branch) and `crates/bale-server-meta-sqlite/src/lib.rs:601-635`
  (`unaccounted_xorb_bytes_for_owner`, entirely count 0).
- **Untested:** the `quota-exceeded` phase trips the *xorb-stage* check (L312)
  first and the push dies there, so the shard-stage path — which uses different,
  subtler accounting (delta of *unaccounted* referenced xorb bytes, not gross body
  length) — never runs.
- **Why it matters:** distinct logic enforcing quota when all xorbs already exist
  via dedup but file registration still crosses the limit; mis-counting wrongly
  admits or rejects an owner.
- **Phase sketch:** pre-seed an owner near quota with shared content, then push a
  file that's pure dedup of existing xorbs (so xorb POSTs dedup and pass) but whose
  registration crosses the quota; assert the shard-stage rejection.

---

## Verified already covered — do NOT re-investigate

- **Cross-repo 404 on reconstruction** (`http/lib.rs:527`, `file_in_repo` →
  NotFound) — the load-bearing per-repo scope check ("404 not 403 on cross-repo
  probes") fires 3× via the multi-remote / push-pending probe phases.
- **`lookup_file` None after passing `file_in_repo`** (`http/lib.rs:547`) — the
  marker-exists-but-terms-gone consistency window fires 2×.
- **Compression decode arms** — the `compression` phase exercises both LZ4
  (scheme 1) and BG4-LZ4 (scheme 2) decode paths in `verify_xorb_body` and
  `decompress_xorb_chunks_into` (non-zero counts). Only the *error* arms are open
  (covered by Tier 1 item 1).
- **fs `presign_xorb_range`** — runs 444×, always `Ok(None)` (fs store does no
  signing); signed-URL generation lives in the transfer-URL handler / S3 store, not
  here. Item 2 covers the enforcement side.

## Known-unreachable (leave alone — defensive guards)

- `xorb.rs:79-84` `TooLarge` (>4 GiB body; upload caps at 64 MiB),
  `xorb.rs:110` `checked_add` overflow (impossible from a u24),
  `xorb.rs:151-158` / `201-208` `other =>` arms (parse already rejected the scheme
  — correctly commented "Unreachable").
- `http/lib.rs` `CoreError→ApiError` mapping arms (161-163), `unauthorized` helper
  (175-177), 64 MiB body-limit rejections (300, 367) — boilerplate / DoS limits.
- `meta-sqlite` `.map_err(...)` DB-error closures throughout — single-store txns
  that roll back atomically on error; reachable only via fault injection
  (`failure-dbbusy`), and each is a safe drop-on-error, not a partial-write window.
- `storage-fs:26-32` `open_private` non-unix branch — `#[cfg(not(unix))]`,
  uncoverable on the Linux harness by design (Windows cross-check is the venue).
