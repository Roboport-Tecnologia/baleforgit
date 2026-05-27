# Data-loss / corruption audit (2026-05-27)

A pass over every crate in the workspace looking for places where user data could be lost, corrupted, or silently served wrong. One sub-agent per crate; findings consolidated below, then reviewed by three personas (engineer, mathematician, game developer).

Treat this as a snapshot in time — line numbers will drift. Re-verify before acting on any specific finding.

---

## Consolidated findings

### 🔴 Critical — data integrity bugs

**1. Write ordering reversed for xorbs.**
`bale-server-http/src/lib.rs:362-363` writes the xorb blob before `register_xorb_layout`. A crash between the two leaves the xorb in CAS with no frame layout. The `xorb_exists` check on subsequent shard uploads then admits files referencing this xorb, and every reconstruction returns 500 forever. **Fix:** register layout first (idempotent), then put blob.

**2. Multi-step shard upload is not atomic.**
`bale-server-http/src/lib.rs:428-490` loops `register_xorb` per CAS block, runs the quota check, loops `register_file` per file, *then* writes the shard blob. A crash mid-loop leaves orphan metadata rows and/or files referencing a never-written shard. **Fix:** reorder `put_shard` before `register_file`, or transactional wrap.

**3. No end-to-end integrity verification on smudge.**
`crates/git-bale/src/filter_process.rs:474-482` and `local_reconstruct.rs:74` write reconstructed bytes to the worktree without verifying the pointer's `sha256`. A corrupted chunk cache or malicious manifest would silently land bad bytes. Worse: the clean-cache repopulator at `filter_process.rs:520-564` would then cache the corruption, making it sticky across `git add`.

**4. Clean cache uses non-cryptographic xxh3-64 for content verification.**
`crates/git-bale/src/clean_cache.rs:44,76,233`. 64-bit non-crypto hash is the load-bearing check for "have I cleaned these bytes before." A collision returns a stale pointer → wrong content committed. **Fix:** cross-check with the pointer's `sha256` or with `blake3`.

**5. Reachable panic in reconstruction from adversarial shard.**
`bale-server-http/src/lib.rs:563, 819` — `layout[(t.chunk_idx_end - 1) as usize]`. The shard parser doesn't enforce `chunk_idx_start < chunk_idx_end <= layout.len()`. An attacker uploads a shard with `chunk_idx_end == 0` to their own repo, then reads it → underflow panics the request task.

**6. No `Content-MD5`/SHA-256 header on S3 PUT.**
`crates/bale-server-storage-s3/src/lib.rs:136-150`. Server pre-verifies the body but the actual S3-bound bytes are not integrity-checked by S3. A bit-flip in transit is undetected until a future smudge fails.

**7. Plaintext `http://` accepted for upstream `/check_access`.**
`crates/bale-server-authz-http/src/lib.rs:43-58`. Operator typo leaks `hub_bearer` JWTs to on-path attackers. Combine with default-on redirect-following in reqwest → a 3xx to attacker host re-targets the POST body. **Fix:** force HTTPS + `redirect::Policy::none()`.

### 🟠 High — durability gaps

**8. Parent-directory fsync silently swallowed / missing.**
`bale-server-storage-fs/src/lib.rs:108-112` ignores dir fsync errors. `git-bale` atomic-write helpers (`clean_cache.rs:117-131`, `manifest_cache.rs:69-84`, `install.rs:134-149`, `staging.rs:40-47`) never fsync the parent at all. On power loss the rename can be lost.

**9. SQLite `synchronous` pragma never set; no `busy_timeout`.**
`bale-server-meta-sqlite/src/lib.rs:121-133`. Under WAL the default is `NORMAL` (data loss tail allowed on power-loss). No `busy_timeout` means concurrent writers immediately get `SQLITE_BUSY` mid-shard-upload, leaving partially-indexed shards.

**10. `BALE_DATA_ROOT` defaults to `./xet-data`.**
`bale-server-bin/src/main.rs:26`. In containers without a mounted volume, every restart silently loses data. Should `bail!` instead.

**11. Staging dir durability depends entirely on xet-data's `LocalClient`.**
`git-bale/src/filter_process.rs:283-307`. If it doesn't fsync, then `git add foo; <reboot>; git push` loses the xorbs and produces unresolvable pointers committed to the index.

**12. Quota race / TOCTOU.**
Two concurrent same-owner uploads both pass the check (`bale-server-http/src/lib.rs:445-453`); `ARCHITECTURE.md` acknowledges "soft" but overshoot is unbounded.

**13. JWT lacks `aud`/`iss`/`nbf`/`jti`.**
`bale-server-tokens/src/lib.rs:6-14`. A token minted on one bale install validates on any other sharing the secret. m5's `forged_jwt` test passes "for the right reason but tests almost nothing" — `alg: none` / algorithm-confusion not exercised.

### 🟡 Medium — design concerns worth fixing

- **Shard magic tag never validated** (`bale-server-shard/src/lib.rs:196-208`) and **no shard-content hash verification at upload** (`bale-server-http/src/lib.rs:483-485`) — server computes the storage key from the body, so client-side mangling is invisible. Per-term `FileVerificationEntry` is parsed but never cross-checked.
- **`RangeJson` is structurally identical for half-open chunk ranges and end-inclusive byte ranges** (`bale-server-wire/src/lib.rs:64-87`). Type system can't tell them apart — recipe for a future off-by-one in reconstruction. Doc even contradicts the inclusive `url_range` use.
- **`now_unix()` in `bale-server-http` fail-opens** (`:239-244` returns `0` on clock error, making every signed URL valid).
- **S3 startup bucket probe is non-fatal** (`bale-server-storage-s3/src/lib.rs:83-95`) — typo'd bucket silently accepted.
- **`BALE_PUBLIC_URL` unset only `warn!`s** (`bale-server-bin/src/main.rs:30-48`) — clients get unreachable signed URLs.

### 🧪 Test coverage gaps (highest-priority)

1. **Concurrent identical uploads** + **crash mid-upload** — directly hits the "consistency under partial failure" invariant; **zero coverage**.
2. **Genuinely-signed URL replayed with different Range** — only tested against real S3, not against the in-process handler.
3. **Quota TOCTOU** — m13 covers the recheck but not the race that motivates it.
4. **Disk-full / S3 5xx mid-upload** — no fault injection anywhere.
5. **SQLite `database is locked` on file-backed DB** — all tests use `:memory:`.

---

## Persona reviews

Three independent reviewers, same findings, different lenses.

### 🛠 The Engineer (15 years of pager duty)

*"I've seen this movie before."*

- **Real fixes, do this week:** #1, #2 (same bug in two outfits — both write blob-before-metadata; #2 is worse because metadata can outlive the shard blob). #5 (5-line bounds check). #3 (defense in depth, not "users losing data today"). #7 (20 minutes — reject `http://`, kill redirects).
- **Disagrees with severity on #4 (xxh3-64):** clean cache is local to a dev's own working tree; threat model is collision-on-your-own-files. "Stop calling it critical." Bump to blake3 for consistency, that's it.
- **Paper:** #6 (S3 already validates), #10 (deployment footgun, document it), #13/`jti` ("theater unless you build a revocation store, which you aren't"), #12 quota TOCTOU ("a few MB of slop on a GB quota is not a real concern").
- **Missing from the list:** **no GC story** — refcounts vs. mark-sweep, decide *now*, write the test before the code. Also: backpressure on reconstructions, multipart S3 abort semantics, clock-skew tolerance.
- **80% safety with the smallest set:** reorder writes (metadata commits last or rename-to-final), #5 bounds, sha256 verify on smudge assembly, reject `http://` + disable redirects, set `synchronous=NORMAL` + `busy_timeout=5000`, write the crash-mid-upload + concurrent-upload tests. **Everything else: skip until something pages you.**

### 🧮 The Mathematician

*"This is not as the authors believe."*

- **Actually computed #4's birthday bound:** approximately n² / 2⁶⁵.
  - At 10⁶ chunks in one file: ~2.7×10⁻⁸ (vanishing).
  - At 10⁹ cleans over a lifetime: **~2.7%**. *Not* vanishing for heavy users.
  - And the fix is free: `xet-data` already computes BLAKE3 during clean — key the cache on the hash you were going to compute anyway.
- **Phrased #3 as a broken invariant:** "If pointer's sha256/file_size are authentic and reconstruction returns matching bytes, the smudged file equals the original." Proof breaks because (a) the stream is never re-hashed against `sha256` before write, (b) the bad result is *then* cached. Fix: make `sha256` a refinement type `VerifiedBytes` whose only constructor is "I just hashed and they matched."
- **One algebraic fix for both #7 and #13:** *parse, don't validate.* Type the JWT verifier as `Verifier<HS256>` (no runtime `alg`). Type the authz URL as `HttpsUrl` (constructor refuses non-https). Closes alg=none, alg-confusion, http://, *and* 30x-redirect-to-attacker in one stroke each.
- **#1 / #2 reframed:** "The protocol designates the metadata write as the linearization point, but the code's ordering allows states where blob exists without metadata, or vice versa." Fix: blob → content-addressed tmp, then `register_*` in SQLite, then `rename`. Commit point becomes the metadata insert, atomic by definition.
- **More type-system fixes:** #5 wants `NonZero<u32>` on the parsed field. The `RangeJson` doubles-as-both-semantics issue is "a category error the compiler should be rejecting" — split into `ChunkRange` and `ByteRange`, no `From`.
- **Three things the auditors missed:**
  1. **The shard parser is the trust boundary for the entire metadata DB.** No invariant says "every `(xorb_hash, chunk_idx)` row in SQLite was attested by a shard whose BLAKE3 matches its filename." This is how one attacker rewrites another user's reconstruction terms globally.
  2. **The chunk cache is shared across repos; M12 scope check lives only server-side.** A client previously authorized for repo A can read repo-B chunks by hash if they have them locally. State this in the threat model.
  3. **`xet-data` pin `=1.5.2` is load-bearing for on-disk shard format.** SQLite metadata is a *projection* of historical shard parses, with no parser-version tag. **Time bomb on par with the write-ordering bugs.**

### 🎮 The Game Developer

*"This kills the build farm."*

- **Unshippable as a depot — five blockers:** #1, #2, #3, #4, #5. Stack them: "this is not a depot, it's a roulette wheel."
- **#3 + #4 together are the actual nightmare:** 2³² birthday space + no smudge verification = artist edits `Foo.uasset`, clean returns a pointer to *someone else's* `Bar.uasset`, commit/push go green, build farm pulls it, **QA finds a purple checkerboard in a cutscene three days later and git history shows nothing wrong.**
- **CI farm of 200 cold clones:** #1/#2 make 200 machines return 500 in lockstep on any orphaned upload. #9 (no `busy_timeout`) → `SQLITE_BUSY` storm under fan-out. #6 silent S3 corruption returns "almost matching" bytes. Missing from list: **connection pool / backpressure / retry-after on `/v1/reconstructions/`** (thundering herd is inevitable).
- **Artist workstation crash mid-`git add`:** #11 is the existential one — if xet-data's `LocalClient` doesn't fsync the staging dir, **the artist re-bakes the level: 6 hours of GPU time.** Verify this assumption today.
- **Concurrent uploads — Friday-at-6pm real, not theoretical.** Two artists with overlapping bake outputs (large studios share bakes constantly), `async` handler, shared router, zero serialization. **"Will fire within a week of go-live on any farm > 20 seats."**
- **Game-dev gaps not in the list:**
  1. **Resumable upload** — WAN flake on 12 GB push = start over. Studio-killer.
  2. **Path-scoped / sparse smudge** for CI machines that only need one map.
  3. **End-to-end SHA256 verify on download** — verification entries already exist in the shard, *use them*.
  4. **Quarantine admin endpoint** for "this xorb is poisoned, force re-upload." Don't ship without it.
  5. **Pre-push integrity scrub** of `.git/bale/staging/` — recompute hashes before POST.

---

## Convergence

All three independently nominate **#1/#2 (write ordering) and #5 (panic) as must-fix-now**, and all three flag **the GC / scope / parser-trust gaps not on the list** as the next-most-important work after the top fixes.

They split on **#4 (xxh3-64)**: engineer says "stop calling it critical," mathematician proves it's 2.7% lifetime probability, game dev calls it a ship-blocker. The mathematician's number reconciles them — vanishing per-file, real per-lifetime-of-a-build-farm.

## Suggested execution order

1. Reorder writes in #1 and #2 (metadata commits last, or content-addressed-tmp-then-rename for blob). Single architectural primitive fixes both.
2. Bounds check in #5 (or `NonZero<u32>` on the parsed field).
3. Final `sha256` verify on smudge assembly (#3), and cross-check before populating clean-cache (closes #3 + #4 together).
4. Force `https://` + `redirect::Policy::none()` on `HttpAuthz` client (#7).
5. SQLite pragmas: `synchronous=NORMAL` + `busy_timeout=5000` (#9).
6. Add the two missing tests: crash-mid-upload, concurrent identical upload.

After that, decide whether the type-driven path the mathematician suggested (`HashHex`, `HttpsUrl`, `Verifier<HS256>`, `ChunkRange`/`ByteRange`, `VerifiedBytes`) is worth the refactor — it closes a surprising amount of surface area for low LOC.

Open questions worth answering before further work: GC story for orphan xorbs, schema-version pinning for `xet-data =1.5.2`, threat-model statement on shared chunk cache vs. M12 scope.
