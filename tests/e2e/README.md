# Full end-to-end test

A standalone Python harness that drives the release `git-bale` binary
against a bundled podman container running both `baleforgit-server` and
`openssh-server`, over the production-shaped transport (SSH for git
push/clone and for the Bale forge-auth handshake). Beyond the user flows
(stage / unstage / stash / pop / commit / push / clone), it pushes a 35 MB
binary at three slightly different revisions so dedup-driven storage deltas
can be checked against on-disk bytes and the `/v1/usage` API.

**Not run by `cargo test`.** Invoke it directly:

```bash
python3 tests/e2e/run.py                 # filesystem blob store + SQLite (the defaults)
python3 tests/e2e/run.py --backend s3    # the whole suite on an S3 (MinIO) blob store
python3 tests/e2e/run.py --meta postgres # the whole suite on a Postgres metadata store
```

A per-phase timing summary (wallclock, plus throughput on byte-heavy
phases) prints at the end of every run.

## Prereqs

- `git` and `ssh`/`ssh-keygen` on the host PATH.
- `podman` (preferred) or `docker` with a working daemon/VM. On macOS,
  `podman machine start` must have been run.
- Release builds of `git-bale` and `bale-e2e-tools`. The harness does
  **not** invoke cargo (except in `--coverage` mode):

  ```bash
  cargo build --release -p git-bale -p bale-e2e-tools
  ```

  `bale-e2e-tools` is a test-only helper that crafts xorbs/shards with xet's
  exact keyed-BLAKE3 hashing (stdlib Python has no BLAKE3). Used by
  `fetch-overlap`, `dedup-repeated-chunk`, `quota-atomic` and
  `file-hasher-selfcheck`.
- Python 3.9+, stdlib only.
- *Optional* (`mount-*` phases only): libfuse2 on Linux, fuse-t on macOS,
  [WinFsp](https://winfsp.dev/) on Windows. On Linux/macOS the mount phases
  skip cleanly without the driver; on Windows the harness **auto-installs
  WinFsp** (MSI via `msiexec /qn`, needs admin) and skips only if that fails.

The harness runs natively on Linux, macOS **and Windows** hosts. The server
always runs as a **Linux container**; only the git-bale *client* runs on the
host. On a Windows host:

- Install **Git for Windows** (`git`, `ssh`, `ssh-keygen`, and the `sh` git
  uses for hooks + `GIT_SSH_COMMAND`) and **Docker Desktop** or **podman**
  with a Linux-container (WSL2) backend.
- The run/state dir (and `--git-bale` binary) must live on a drive shared
  with the container runtime (e.g. under `C:\Users\...`) so the `/data` and
  `/home/git` bind mounts resolve. The harness finds
  `target\release\git-bale.exe` automatically.
- Windows-specific handling: SSH keys are locked via `icacls` (Win32 OpenSSH
  rejects loose-ACL keys); no `ssh-agent`, and git-bale's forge-auth `ssh`
  runs bare (it only honors `GIT_SSH_COMMAND` on Unix), finding the key via
  the default `%USERPROFILE%\.ssh` lookup; bind-mount paths use forward
  slashes; mount phases use a WinFsp directory mount. `GIT_SSH_COMMAND`
  passes `-F <empty file>` because Git-for-Windows's MSYS `ssh` reads bare
  `nul` as a relative filename. The container's sshd runs with
  `StrictModes=no`: the `/home/git` bind mount can't represent Unix modes on a
  Windows host, so `authorized_keys` looks world-writable and StrictModes
  would deny every publickey auth.
- Repo-root `.gitattributes` pins `*.sh` and the Dockerfiles to `eol=lf`;
  otherwise `core.autocrlf=true` gives `entrypoint.sh` a CRLF shebang and the
  container dies at startup ("exec ... no such file or directory").

## What it covers

| Phase           | What it verifies                                                                                    |
|-----------------|-----------------------------------------------------------------------------------------------------|
| `basic`         | Stage / unstage / re-stage (pointer cache hit) / stash / pop / commit / push on an 8 KiB file.      |
| `multi-remote`  | Push to `origin` (repo A), then add a second remote (repo B) and push again: the pre-push hook must register the file under B's scope even though A's push drained staging, so a fresh clone of B checks out. |
| `term-merge`    | Appends duplicate terms to a pushed file's global term list in the metadata store (Σterms = 3×size, the shape an old per-term merge produced); a cold clone must be refused cleanly by the `lookup_file` guard instead of handing the client a reconstruction that panics it. |
| `cold-repush`   | Push a big file to repo A, wipe every local dedup index, re-push it to repo B bundled with a small new file (forcing a fresh xorb hash): server xorb growth must stay well under the big file's size (global dedup, not double storage), and B clones byte-exact. |
| `cold-repush-staged` | Like `cold-repush`, but the file is appended to and committed (staged, never pushed) before the cold-cache push to a fresh repo. *Measures* how much of the unchanged prefix is re-stored; asserts only integrity. |
| `offline-no-network` | A counting TCP proxy in front of the CAS server proves add/status/diff/commit/checkout/stash/pop/unstage/gc make **zero** server connections; `git push` (positive control) MUST make the count non-zero. |
| `push-pending-noop` | `git-bale push-pending` with no `.git/bale/staging/` is a clean no-op (exit 0) — the pre-push hook runs on every push, so a push with no bale changes must not error. |
| `push-pending-corrupt` | DATA-LOSS GUARD: a staged xorb deleted after `git add` + commit (marker outlives its bytes) makes `push-pending` fail the local reconstruct — it must NOT clear the marker or report success on a file it couldn't upload, and nothing reaches the server. |
| `track`         | `git-bale track` appends `filter=bale` lines to `.gitattributes`: creates the file when absent, dedups already-tracked patterns, normalizes a missing trailing newline (LF or CRLF) so a new pattern isn't fused onto the last line, skips empty patterns, and errors on an unreadable (directory) `.gitattributes`. |
| `compression`   | Pushes an LZ4-friendly and a BG4-LZ4-friendly file, asserts both frame schemes are stored, then downloads each via `GET /v1/files/{id}` and cold-clones them, covering the server's decompress arms that incompressible payloads never reach. |
| `bigfile`       | 35 MB binary pushed at three revisions; storage growth per push matches the *actual* edit size.     |
| `usage`         | `GET /v1/usage/{owner}` and `GET /v1/usage/repo/{owner}/{repo}` numbers agree with on-disk bytes. Also checks `require_admin_or_owner`: the hex admin bearer reads any owner (200), a JWT scoped to a different owner is forbidden (403). |
| `browser-download` | `GET /v1/files/{id}` streaming download of the 35 MB file: hub token without filename → 200 with no `Content-Disposition`; forge JWT + matching filename → 200 with `attachment; filename=…`; tampered filename → 400. |
| `dedup`         | A *second file* with bit-identical content adds zero new xorb bytes.                                |
| `idempotency`   | Re-pushing with no new commits doesn't grow server storage.                                         |
| `clone`         | Cold-clone over SSH; every historical revision checks out with the correct sha256.                  |
| `mount-rev`     | `git-bale mount HEAD` exposes both a plain blob and a bale-tracked file via FUSE; bytes match.      |
| `mount-diff`    | `git-bale mount-diff v1 v3` exposes both labeled sides of a 35 MB binary; each side reconstructs.   |
| `mount-diff-mixed` | `mount-diff` over a fresh repo with both a plain text file and a bale-tracked binary; both sides of each match `git show` byte-for-byte, and `diff -q` reports the labelled sides differ. |
| `mount-edge`    | `mount`/`mount-diff` arg + diff validation in `mount/mod.rs`: identical labels rejected, empty diff (`no files differ`) and empty/filtered mount (`no files in`) error instead of mounting empty, and omitting `--label-a/-b` derives labels via `sanitize_label` (`HEAD~2`→`HEAD_2`). Skips when libfuse/fuse-t is absent. |
| `mount-local`   | Fully-local `mount HEAD` with fresh caches and no server reconstructs a Bale file from the local store (byte-exact); after corrupting the store's xorbs, the read fails with EIO instead of serving wrong bytes. Skips when libfuse/fuse-t is absent. |
| `offline-restart` | Hot-path smudge works with the server stopped; data persists across a fresh container.            |
| `wrong-token`   | Push with a bogus `bale.token` is rejected and does not corrupt the data dir.                       |
| `tampered-xorb` | A xorb whose bytes were flipped on disk makes the cold-smudge checkout FAIL (sha256 verification) and leaves no wrong bytes in the worktree. |
| `quota`         | A server brought up with `BALE_DEFAULT_QUOTA_BYTES=1024` rejects a 35 MB push cleanly.              |
| `quota-admin`   | `PUT /v1/quotas/{owner}`: 404 when the admin token is unset, 401 on missing/non-hex/wrong bearer, 204 to set a 1 KiB cap (then a push is rejected) and 204 to clear it with `null` (then the same push succeeds + cold-clones). Proves the admin endpoint authenticates and that `set_owner_quota`'s upsert + DELETE arms persist. |
| `shard-quota`   | Isolates `upload_shard`'s delta-quota gate from the xorb-stage one. Owner A seeds 1 MiB unlimited; owner B (capped at 256 KiB via the admin API) pushes the same bytes → B's xorbs all dedup (no disk growth, xorb-stage skipped) so only the shard-stage `unaccounted_xorb_bytes_for_owner` check can — and does — reject. Asserts the quota message + unchanged server xorb bytes. |
| `upload-guards` | Direct-HTTP negative tests of the server's load-bearing guards: a real xorb body POSTed under a wrong URL hash (and a length-tampered body) is rejected by `verify_xorb_body` with 400 and stores nothing; a read-scope token POSTing gets 403; and (fs only) a signed transfer URL with a forged sig, a past expiry, or a mismatched `Range` each gets 401. Also drives `get_xorb_range`'s bound checks via validly-signed URLs (harness holds the transfer secret): an end past the xorb clamps to a whole-xorb 206, a start past the end is 400. |
| `shard-guards` | Direct-HTTP attacks from a writer to another repo, each 400/404 and leaving nothing usable: replaying a victim file's terms (from a reconstruction) with missing or forged verification hashes doesn't register it into the attacker's repo (reconstruction stays 404); binding an unregistered file hash to someone else's xorb is rejected; a chunk hash claimed only by a client CAS block never reaches the dedup index; an LZ4-bomb xorb frame is rejected in well under a second with the server still healthy. Also races two valid encodings of each freshly staged xorb and proves the pushed clone is intact. |
| `xorb-layout-heal` | (fs only) An alternate-encoding upload of a staged xorb fails mid-blob-write (`BALE_TEST_FS_WRITE_FAIL`), then after a restart the original encoding is pushed: the mid-xorb term's signed `url_range` must start at the *stored* blob's frame boundary, and a cold clone of both files must be byte-exact. |
| `global-dedup-hit` | A second user with a fresh `HOME` and caches pushes content another repo already stored. It must dedup against the server (zero xorb POSTs), which proves the dedup response's keyed-BLAKE3 chunk wrapping matches xet's, and its shard (terms into the other repo's xorb) must pass proof-of-possession verification. The clone is byte-exact. |
| `oversize-xorb` | Searches seeds (offline `git add`, inspect staging) for an incompressible file whose xorb serializes over 64 MiB (raw chunks + 8-byte headers), then pushes and cold-clones it. Guards the xorb body limit. |
| `large-file` | Pushes and cold-clones a 600 MiB file. That is past xet's 2 × 256 MiB threshold, so the client fetches the reconstruction in `Range` blocks; it guards `/v1/reconstructions` Range support (terms overlapping the block, `offset_into_first_range`, 416 at EOF). |
| `fetch-overlap` | Uses `bale-e2e-tools` to register a file whose terms overlap within one xorb (`[X 0..5]` then `[X 0..10]`), pushes a hand-made pointer, and cold-clones it. The reconstruction's fetch entries must be disjoint merged ranges; overlapping per-term entries make xet slice a short block and panic. |
| `dedup-repeated-chunk` | Uses `bale-e2e-tools` to upload a xorb that repeats a chunk (`a b a c`, distinct sizes). The `/v1/chunks` response must list all four positions, since clients dedup by position. Then a file referencing the repeat is cold-cloned byte-exact. |
| `quota-atomic` | Two shards that each fit an owner's quota but together don't are posted at the same instant: exactly one must succeed (the in-transaction recheck), and usage stays within quota. Then an owner that only uploads xorbs, never registering files, is refused once those unreferenced uploads reach its quota. |
| `canonical-scope` | Uses a mock `/check_access` that resolves names case-insensitively and returns an id-based scope key (`id/42`) plus accounting `owner` (`7`), like the gitea fork. A push via `canon/repo` must be readable via `Canon/Repo` and charged to owner `7`, and must stay readable after the mock's owner changes (a simulated transfer). |
| `file-hasher-selfcheck` | `bale-e2e-tools selfcheck`: the server's incremental merkle file hasher equals xet's `file_hash` on every sequence length. No container. |
| `anon-public-clone` | Via a mock forge modelling visibility: a public repo cold-smudges with no credential helper (the forge sees only an anonymous `download` call); a private repo's anonymous probe gets 401 and the resolver falls back to `git credential fill`, then succeeds. |
| `failure-kill`     | Server is SIGKILL'd mid-upload; restart on the same data dir and a retry `git push` recovers cleanly. |
| `failure-conndrop` | A TCP proxy in front of the CAS port is killed mid-upload (server stays up); retry succeeds.        |
| `failure-dbbusy`   | A sidecar `sqlite3` shell holds an IMMEDIATE write lock on `meta.db`; the user-side push still succeeds because sqlx's busy_timeout waits the lock out. **Self-skips under `--meta postgres`** (no `meta.db`). |
| `failure-s3-conndrop` | **S3-only** (self-skips on fs): the server↔MinIO TCP link is dropped mid-PUT via a host-side `TcpProxy`; the AWS SDK's retries and/or a client retry on the recovered link converge, and the file reconstructs from the bucket with one copy stored. |
| `failure-s3-presign-unreachable` | **S3-only**: presigned download URLs point at an unresolvable host (`BALE_S3_PUBLIC_ENDPOINT_URL`) while server writes still reach MinIO. The push succeeds, but a cold clone's checkout must abort promptly via the `BALE_DOWNLOAD_STALL_SECS` watchdog instead of hanging in xet's retry backoff. |
| `failure-fs-writefail` | **fs-only** (self-skips on S3): a server started with `BALE_TEST_FS_WRITE_FAIL=1` takes `write_atomic`'s write/fsync-failure arm on every blob write; the push fails with **nothing** stored (`xorbs/`/`shards/`/`tmp/` all empty — no half-write, no tmp leak), then a clean restart (no hook) round-trips the same content. |
| `failure-fs-cput` | **fs-only** (self-skips on S3): two byte-identical pushes fired concurrently to two repos race `write_atomic` on the same content-addressed dst; both succeed, on-disk xorb bytes stay ≈ one payload (no double-store), `tmp/` is empty, and both cold-clone to the original bytes. |
| `gc-abandon-checkout` | `git-bale gc`: push a baseline, stage a change, abandon it (`git reset` + `git checkout`); the post-checkout hook's gc fully wipes the orphaned staging. The user-reported bug. |
| `gc-keeps-unpushed`   | DATA-LOSS GUARD: two stacked *unpushed* commits (tip names only v2); manual `git-bale gc` must NOT drop v1's staging. Push + cold-clone then reconstructs every revision byte-for-byte. |
| `gc-mixed`            | Committed-but-unpushed v1 survives while a staged-then-abandoned (never-committed) v2 is forgotten; v1 stays pushable + reconstructable end to end. |
| `push-pending-only-pushed` | PRIVACY GUARD: an uncommitted edit with a staged marker (as `git status` re-cleans leave) is NOT uploaded by `git push` of an unrelated commit — its marker stays staged, the pushed file's is drained, and server disk grows by only one file. A follow-up `git push <url> …` (the hook gets the URL as the remote name) with that marker still present must succeed and drain only the pushed file. |
| `push-pending-noverify-heal` | A commit pushed with `git push --no-verify` (bytes never uploaded; a clone of it fails) is uploaded by the next normal push even though it's outside that push's ref delta — the target already references it — and a fresh clone of the earlier commit then reconstructs. |
| `churn`               | Sustained churn against ONE reused repo: 12 rounds of edit→commit→push (rotating region edits on a multi-chunk file, plus add/delete of extra files and a plain non-bale text file), with cold clones at rounds 3/7/11 that each reconstruct the FULL accumulated history byte-for-byte. Integrity verified at every step (staged + committed pointers, post-push worktree), `/healthz` probed after each push (a push that crashes the server fails it), and server disk asserted monotonic. The regression guard for the "data corrupted + server crashed after the Nth push" class of bug. Scales up via `HUGE_CHURN=N` — see [Scaling churn](#scaling-the-churn-phase-huge_churn). |
| `resync-wipe`         | Disaster recovery: push a binary, restart the server with a BLANK CAS (fresh data dir, same bare repo), then delete `.git`, re-init, re-add, and `git push -f`. The first push is *rejected* — every chunk dedups against the client's stale xet cache, so the xorbs the blank server lacks are never re-uploaded — and the client surfaces a plain-language cache-mismatch explanation (naming the active cache dir + `BALE_XET_CACHE`), not a bare `400 Bad Request on /shards`; the rejected push leaves staging intact and writes nothing to the server. Recovery then follows that advice: a second `git push -f` with `BALE_XET_CACHE` pointed at a fresh dir re-uploads everything and succeeds, and a cold clone reconstructs the file byte-for-byte. |
| `spilled-clean`       | Caps `BALE_MAX_INLINE_CLEAN` at 1 MiB so a 5 MiB `git add` drives the clean filter's spill-to-tmpfile path; an unstage + re-add hits the file-backed clean-cache verify, then push + cold/hot resmudge round-trips the spilled file. |
| `global-dedup-shard`  | The server's `GET /v1/chunks` dedup shard must ingest without crashing the upload session. Seeds a repo, fetches the dedup shard for a known chunk straight from the endpoint and asserts its footer is well-formed (lookup offsets == `footer_offset`, never 0), then plants that shard into the client's xet `shard-cache/` and pushes again — the second push's `FileUploadSession` scans + ingests it via `read_all_truncated_hashes`, the path that underflowed (debug panic / release OOM) when `file_lookup_offset` was 0. Deterministic: doesn't rely on the 1/1024 global-dedup chunk sampling, which the release binary can't lower. |
| `progress-demo`       | Asserts the pre-push upload summary line for a fresh and a fully-deduped push; under `--only progress-demo` it becomes an interactive visual demo. See [below](#the-upload-progress-indicator-progress-demo). |
| `local-basic`         | **No-server.** `git-bale init-local` sets up a per-repo store (`bale.local=true`, `bale.localStore=.git/bale/store`). A `git add` + `git commit` writes xorbs/shards to the durable store (no staging drain needed); a fresh checkout with manifests wiped reconstructs the file byte-for-byte from the store alone, with no server running. |
| `local-gc-abandon`    | **No-server.** Stage a file, then abandon it (`git reset` + `git checkout`); the post-checkout gc hook drops the orphaned markers and clean-cache entry. A re-add + checkout reconstructs correctly (no stale pointer). |
| `local-shared-dedup`  | **No-server.** Two repos share one store at `~/bale-local` (`--shared`). Adding the same content in both repos results in zero additional xorb bytes in the shared store — chunk-level dedup works cross-repo through the shared store. |
| `local-prune-shared`  | **No-server.** With a shared store, commit a file in repo A (live) and a file in repo B then drop repo B's reference (dead). `git-bale prune --shared` removes the dead object and leaves the live one intact; repo A can still reconstruct its file after prune. |
| `local-clean-gc-race` | **No-server.** DATA-LOSS GUARD: a dead marker leaves gc ready to sweep the whole store while a second `git add` is held (`BALE_TEST_CLEAN_MARKER_DELAY_MS`) between writing its xorb and its marker; gc fires in that window and the second file must still reconstruct. |
| `local-concurrent-stress` | **No-server.** Natural-timing contention: backgrounded `git add`s racing `git-bale gc` in a per-repo store, and adds in two repos racing `prune --shared` on a shared one. No deadlock, and every committed file reconstructs. |
| `local-cache-hit-gc-race` | **No-server.** DATA-LOSS GUARD: a re-add that hits the clean-cache is held before emitting its pointer (`BALE_TEST_CLEAN_CACHE_HIT_DELAY_MS`) while gc runs; the filter's store lock must block gc so the unindexed content isn't swept. |
| `local-gc-grace` | **No-server.** `BALE_GC_GRACE_SECS` protects a recently-cleaned, unreferenced marker and reclaims it once it ages past the grace. (Every other phase runs with the grace at `0`.) |
| `local-stash-reflog`  | **No-server.** Stash v1, then v2: gc must keep the marker of content reachable only from `stash@{1}` (reflogs are live, like git's own gc). After `stash drop stash@{0}` + gc, v2's marker is gone, v1's survives, and `stash pop` reconstructs v1. |
| `local-worktree-gc`   | **No-server.** A linked worktree (`git worktree add`) stages a file while main holds an abandoned one. Markers live in the common git dir; main's gc drops only its own dead marker and the linked worktree's content still reconstructs, staged and then committed (gc run from both worktrees). |
| `local-prune-cross-repo` | **No-server.** Repo B cleans + commits `x`, repo A fetches and checks it out (no marker in A), B forgets `x` and abandons `y`. `prune --shared` reclaims `y` but keeps `x` (two-pass liveness tested against every registered repo); A still reconstructs `x`. |
| `local-tampered-store` | **No-server.** Corrupt every xorb in a per-repo store; `git checkout` must fail (sha256 verification) and no wrong bytes may appear in the worktree. |
| `local-autostash` | **No-server.** Stage a bale file, start `rebase --autostash` that stops on a conflict (the stash lives only in `rebase-merge/autostash`), run gc, resolve + `rebase --continue`: the marker survives and the file is restored byte-for-byte. |
| `local-prune-missing-repo` | **No-server.** Repo A cleans + commits `x`, repo B fetches it, A is deleted; `prune --shared --force` reclaims B's orphan but keeps `x` (B reaches it, though its only marker died with A); B still reconstructs `x`. |
| `local-store-owner` | **No-server.** Repo A owns a non-shared `--store`; `init-local --store` of the same dir from repo B is refused, and with B pointed at it by hand, B's gc refuses (exit 1) without sweeping and B's `git add` fails; A still reconstructs. |
| `local-moved-shared-repo` | **No-server.** A shared repo is renamed on disk; its next gc re-registers it, so `prune --shared --force` (skipping the stale path) reclaims the orphan but keeps the repo's committed content. |
| `local-reclone-same-path` | **No-server.** Repo A commits into an external `--store` and pushes to a plain bare remote; A is deleted, re-cloned at the same path, and re-`init-local`ed (zero markers). The post-checkout gc, an explicit gc, and a gc that drops the last (dead) marker must all leave the store intact, and `a.bin` must still restore. |
| `local-in-gitdir-store-claim` | **No-server.** A store inside repo A's git dir is refused to repo B's `init-local --store` (shared or not); in the other order, repo C claims D's in-gitdir store first, D's `init-local` is refused, and D's gc (configured by hand) refuses without sweeping C's content. |
| `local-pointer-passthrough` | **No-server.** Repo B is cloned from a plain bare remote with no filter (worktree holds pointer text), then `init-local --shared` onto A's store; `git add --renormalize .` must keep the committed pointer blob unchanged, and checkout restores the real bytes. A tracked user JSON that merely has a 64-hex `"hash"` key is cleaned normally and round-trips. |
| `local-moved-repo` | **No-server.** A repo using the default store is moved; a new add+commit works, nothing is recreated at the old path, and both files restore. A repo whose external `--store` is moved away gets a failing `git add`, and the store is not recreated empty. |
| `local-store-switch` | **No-server.** A file committed into the default store; `init-local --store X` switches stores; unstaging and re-adding the unchanged file (a clean-cache hit) must re-clean into X, and checkout restores it from X. Then the store is wiped and re-created at the same path by `init-local` (new `.bale-id`): the next re-add must also re-clean. |
| `local-prune-force-moved` | **No-server.** Shared repo B commits `b.bin` and is moved without re-registering; `prune --shared --force` from A drops B-only content. Re-adding `b.bin` in the moved B must re-stage the worktree bytes (no stale clean-cache hit), and checkout restores them. |

### Running the whole suite on S3

```bash
python3 tests/e2e/run.py --backend s3
```

`--backend s3` brings up a MinIO sidecar (`quay.io/minio/minio`, pinned
release) on a per-run podman network and runs the **entire phase registry**
against servers that use MinIO as their `BlobStore` — same flows, same
assertions. Composes with `--skip` / `--only` / `--order` and `--meta`.

A process-global backend (set once in `cli.main`) makes `start_container`
inject the `BALE_S3_*` env + network args into *every* container it launches.
Each server gets its own bucket prefix derived from its `data_root`: stable
across a restart on the same dir (so `failure-kill` / `offline-restart` find
their data) and distinct across phases (the analogue of per-phase data dirs).
`ServerHandle.disk_*_bytes()` sizes that prefix via `mc ls`, so the
storage-accounting assertions (`bigfile` growth, `usage`-vs-disk, `dedup`,
quota, churn monotonicity) work unchanged; `tampered-xorb` corrupts bucket
objects instead of files.

Backend-specific phases self-skip on the other backend: `failure-s3-conndrop`
(server↔MinIO drop mid-PUT) and `failure-s3-presign-unreachable` are S3-only;
`failure-fs-writefail`, `failure-fs-cput`, `xorb-layout-heal` and the
signed-URL part of `upload-guards` are fs-only.

### Running the whole suite on Postgres

```bash
python3 tests/e2e/run.py --meta postgres
```

`--meta postgres` brings up a Postgres sidecar (`postgres:16-alpine`) and runs
the **entire phase registry** against servers that use Postgres as their
`MetadataStore` instead of the in-container SQLite `meta.db`. Composes with
`--skip` / `--only` / `--order` and with `--backend s3` (both sidecars share
one network, so `--backend s3 --meta postgres` swaps both stores).

It mirrors the S3 backend: `start_container` injects `BALE_POSTGRES_URL` +
the network arg into every container, and each server gets its own database
(`bale_<slug>_<hash>`, from its `data_root`) — stable across a restart,
distinct across phases. The harness creates each database via
`podman exec psql` before the server starts; the server reaches Postgres
through the host's primary IP and published port (the same route MinIO
uses). The blob store is untouched, so the storage-accounting assertions now
cross-check the Postgres accounting queries against on-disk bytes, and
`term-merge` injects its corrupt terms via `psql` instead of `sqlite3`.

`failure-dbbusy` (holds a SQLite write lock to exercise sqlx's
`busy_timeout`) **self-skips** under `--meta postgres`; every other phase runs.

## Flags

- `--git-bale PATH` — the release binary, if not at `target/release/git-bale`
  (also honors `$GIT_BALE_BIN`).
- `--image-tag TAG` — tag for the bundled image (default
  `baleforgit-server-e2e:latest`).
- `--no-build` — skip the image build; the image must already exist.
- `--keep-tmpdir` — keep the run's work directory (to inspect `.git/bale/*`
  and the server's `xorbs/`/`shards/`).
- `--skip PHASE` — skip a phase (repeatable).
- `--only PHASE` — run *only* the named phase(s) (repeatable), e.g.
  `--only resync-wipe`. Unknown names error out (coverage-only phase names are
  accepted). Composes with `--skip` (skip wins). g2-tail phases still need
  `bigfile`'s state: `--only usage` runs nothing.
- `--order {forward,reverse,random}` — within-group phase order (default
  `forward`); group order is fixed and `bigfile` always heads g2.
- `--seed N` — RNG seed for `--order random` (logged when random).
- `--state-dir PATH` — use PATH as the work dir instead of a tempdir, keep it,
  and (on success) write `.e2e_state.json` (secrets + `rev_state`) for a
  follow-up `--reuse-from`.
- `--reuse-from PATH` — reuse a prior `--state-dir` run's server data, bare
  repos and secrets with a fresh client work dir; only `read_only` phases run.
  Mutually exclusive with `--state-dir`.
- `--backend {fs,s3}` — blob store for every server (default `fs`). See
  [Running the whole suite on S3](#running-the-whole-suite-on-s3).
- `--meta {sqlite,postgres}` — metadata store for every server (default
  `sqlite`). See [Running the whole suite on Postgres](#running-the-whole-suite-on-postgres).
  `--backend s3` and `--meta postgres` are each mutually exclusive with
  `--coverage` and `--reuse-from` (their sidecars are torn down at end of run);
  coverage mode covers those crates with its own extra phases instead.
- `--coverage` — see [Coverage mode](#coverage-mode). Rejects `--git-bale` and
  a non-default `--image-tag`.
- `--coverage-dir PATH` — coverage output dir (default
  `<repo>/target/coverage-e2e/`); implies `--coverage`.

`run_matrix.py` runs `run.py` five times (forward/reverse/random orders, clean
and `--reuse-from` preserved state) and never builds the image. `--s3` /
`--postgres` collapse it to one `--backend s3` / `--meta postgres` run; it also
takes `--seed`, `--keep-tmpdir`, `--stop-on-failure` and `--quiet`.

## The upload progress indicator (`progress-demo`)

git-bale's pre-push hook draws a live, git-styled
`Uploading bales: 47% (4/8), … | …/s` line on stderr once an upload runs past
~200 ms, then finalizes it in place to
`Uploading bales: 100% (N/N), <size> | <rate>, done.` (the summary prints even
when the push was too fast for the live line). The size is bytes actually
transferred; partial dedup appends ` (+ <size> deduped)`, and a push the
server already fully had reports `<size> already on server, done.`. The
`progress-demo` phase exercises it two ways:

- **In a normal sweep** it pushes fixed variants through
  `git-bale push-pending` with stderr *captured* and asserts the summary: one
  fresh multi-file push (size clause present) and one fully-deduped push
  (`100% (1/1), <size> already on server, done.`). No env vars, no live bar.
- **Via `--only progress-demo`** it becomes a hand-driven *visual* demo. Run
  it **from an interactive terminal**: output capture is off so the hook
  inherits your TTY (git-bale only draws the live line on a TTY), and a
  throttle proxy stretches the upload so the bar is watchable. Env knobs:

  - `FILE_TIMER` (default `1`, decimals OK) — seconds per file, realised as a
    client→server byte throttle in front of the CAS port. Under ~`0.2` the
    200 ms threshold *suppresses* the live line (the summary still prints);
    `3`–`5` makes it climb slowly; `0` disables the throttle.
  - `FILE_COUNT` (default `5`) — distinct files to add + push, each 4 MiB of
    unique incompressible content.

  ```bash
  FILE_TIMER=3 FILE_COUNT=8 python3 tests/e2e/run.py --only progress-demo --no-build
  ```

## Scaling the churn phase (`HUGE_CHURN`)

The `churn` phase normally runs a quick 12-round pass. `HUGE_CHURN=N`
(positive integer) **together with `--only churn`** runs a randomized stress
variant targeting **roughly N minutes** of wall-clock (measured: N=1 → 60 s,
N=2 → 122 s on a warm image). Outside `--only churn` it is ignored, so a full
sweep never balloons.

```bash
HUGE_CHURN=5 python3 tests/e2e/run.py --only churn --no-build
```

- **Rounds** scale linearly (60 × N) against one reused repo — the direct
  stress for corruption/crash after the Nth push.
- Each round edits a **random subset** of 5 base files (33 MiB total) at
  random offsets/lengths, rewrites a plain text file, and randomly adds /
  deletes extra files (some plain). Balanced add/delete odds keep the
  worktree size, and so per-round cost, roughly constant.
- A **cold clone every 15 rounds** verifies the last 15 revisions
  byte-for-byte. The windows tile the history, so every revision is
  cold-verified exactly once at constant cost per clone (full-history walks
  would make total time quadratic in N).

Per-step integrity checks are the same as the normal pass. The RNG seed is
logged; `HUGE_CHURN_SEED=<int>` replays the exact sequence.

## Coverage mode

`python3 tests/e2e/run.py --coverage` runs the suite against instrumented
builds of both binaries and renders one HTML report. The default path keeps
the release/stripped binaries and original image tag, so functional testing
and coverage stay separate.

- Builds `git-bale` with `RUSTFLAGS=-C instrument-coverage` into
  `target/coverage-e2e/cargo/` (so `target/release/git-bale` is untouched).
- Builds the image with `--build-arg COVERAGE=1` as
  `baleforgit-server-e2e-coverage:latest`; the Dockerfile then compiles the
  server instrumented and skips `strip` so the `__llvm_prf_*` sections survive.
- Bind-mounts `<coverage-dir>/profiles/` into every container at `/coverage`
  (`LLVM_PROFILE_FILE=/coverage/server-%m-%p.profraw`); host processes write
  `host-%m-%p.profraw` to the same dir.
- At teardown, `llvm-profdata merge` + `llvm-cov show -format=html` over both
  binaries (the server binary is `cp`'d out of the image). Report:
  `<coverage-dir>/html/index.html`. Coverage mode is POSIX-only.

**Extra phases** (coverage only, but valid `--only`/`--skip` names) cover the
pluggable impls the default suite doesn't:
- `s3-basic` + `s3-dedup` (`s3lib.py`) — `bale-server-storage-s3`.
- `authz-http` — `HttpAuthz` against a Python `/check_access` mock: three
  repos where the mock returns 200 / 403 / 500, plus a token-mint probe with
  an unknown hub bearer for 401.
- `https-origin` — the resolver's HTTP-origin auth (`MockForgeServer` with
  `enforce_auth` + a canned `credential.helper`) for both scopes; the
  download's anonymous probe gets 401, exercising the `git credential fill`
  fallback.
- `otlp` — a server with `OTEL_EXPORTER_OTLP_ENDPOINT` /
  `_TRACES_ENDPOINT` pointed at a host-side collector must export
  `/v1/traces` (`bale-server-bin::telemetry` init is a no-op otherwise).
- `postgres` — `bale-server-meta-postgres` (since `--meta postgres` excludes
  `--coverage`): one instrumented server on a Postgres sidecar doing push →
  re-push → cold clone → `/v1/usage/repo`.

Coverage mode **auto-skips** `failure-kill`, `failure-conndrop` and
`failure-dbbusy`: they SIGKILL the server or a sidecar, and LLVM's atexit
hook can't flush profraws on SIGKILL.

Requires `llvm-profdata` and `llvm-cov` (`rustup component add
llvm-tools-preview`), located via `rustc --print sysroot` + `--print
host-tuple` since `rustup which` doesn't proxy them.

## Exit codes

- `0` — all checks passed.
- `1` — a check failed (container logs dumped to stderr) or a setup error
  (missing `git-bale` binary, `--no-build` without the image, conflicting
  flags).
- `2` — unexpected exception (harness bug), or an argparse usage error.
- `77` — environment skip: no `git`/`ssh`/`ssh-keygen` on PATH, or no working
  podman/docker. CI uses it to tell "didn't run" from "failed".
- `130` — interrupted (Ctrl-C).

## Files

| File                       | Purpose                                                                |
|----------------------------|------------------------------------------------------------------------|
| `Dockerfile`               | Multi-stage build of the bundled `baleforgit-server` + `sshd` image (`COVERAGE=1` build arg for an instrumented, unstripped server). |
| `entrypoint.sh`            | Generates ssh host keys, `authorized_keys`, bare repos + `/<owner>` symlinks and the fake `git-bale-authenticate`; starts sshd; execs `baleforgit-server` as `bale`. Passes through `BALE_S3_*`, `BALE_POSTGRES_URL`, quota/admin and `LLVM_PROFILE_FILE` env when set. |
| `run.py`                   | Entry point: runs `baleharness.cli.main` and re-exports the names `s3lib.py` imports via `from run import …`. |
| `run_matrix.py`            | Multi-run driver for `run.py` (see [Flags](#flags)). |
| `s3lib.py`                 | The coverage-only `s3-basic` / `s3-dedup` phases. Not an entry point. |
| `baleharness/cli.py`       | `main()`: flags, setup/teardown, and the phase `REGISTRY`. |
| `baleharness/registry.py`  | Group order + `--order` handling. |
| `baleharness/phases/`      | One module per phase category: `scenario`, `adversarial`, `server_guards`, `failure`, `push_pending`, `gc`, `local`, `mount`, `track`, `compression`, `anon`, `dedup_shard`, `resync`, `progress`, `coverage_phases`. |
| `baleharness/s3backend.py` | `MinioGuard`, `Network`, `S3StorageView`, the `data_root`→prefix derivation, and the process-global backend that makes `start_container` S3-aware. Importable without `run`, so `server.py` avoids a cycle. |
| `baleharness/pgbackend.py` | The Postgres analogue: `PostgresGuard` (sidecar + per-database provisioning), `data_root`→database naming, and the global backend that injects `BALE_POSTGRES_URL`. Reuses `s3backend.Network`. |
| `baleharness/*.py` (rest)  | Shared plumbing: `server` (`start_container`, `ServerHandle`), `client` (isolated HOME, ssh, `GIT_SSH_COMMAND`), `repo`/`gitutil`, `mocks` (TCP proxy, mock forge/authz/OTLP, metadata-store query + SQLite lock helpers), `mount`/`winfsp`, `coverage`/`covstate`, `config` (sizes, repo names), `payloads`, `jwtutil`, `timing`, `usage`, `storage`, `state`, `proc`, `runtime`, `logutil`. |

## Reproducibility

Payloads are sha256-chained from a fixed seed so a failing assertion
points at the same bytes on every machine. Random material (JWT keys,
SSH keys, container names) regenerates each run — that's deliberate, so
state never leaks across runs.

---

## Design

The *why* behind choices that aren't obvious from the code, so they don't
get re-litigated.

### Why Python, not Rust

The harness *is* the user: it drives `git-bale` and `baleforgit-server` as
black boxes through the filesystem, git and the network. In Rust it would
either reuse library code from the crates under test (defeating the point)
or duplicate the whole driver surface. Stdlib Python gives cross-platform
`subprocess`/`urllib`/`pathlib` and a twenty-line HS256 JWT — no pip, no
virtualenv. (`bale-e2e-tools` is the one Rust helper, only because stdlib has
no BLAKE3.)

### Why podman for the server

Production `baleforgit-server` runs on Linux. Running it natively on
macOS/Windows would mean cross-compiling and bypassing the deployment shape;
a container exercises (nearly) the image ops would deploy. podman is
preferred only because rootless podman is the easier default on Linux dev
machines; the harness falls back to docker.

### Why bundle sshd in the same container

`git-bale` has *two* SSH touchpoints: the git transport (`git push`/`clone`
over `ssh://git@host/...`) and the forge-auth handshake
(`ssh git@host git-bale-authenticate <owner>/<repo> <op>`). In production
both hit the same `git@<forge-host>` (see `docs/BALE_FORGE_PROTOCOL.md`), so
sshd lives beside the server: one logical host, SSH and CAS on different
ports. The entrypoint generates the fake `git-bale-authenticate` with
`$BALE_PUBLIC_HOST_URL` and `$E2E_HUB_TOKEN` baked in, so the
non-interactive SSH shell needn't source rc files.

### Why `ssh://` URLs with the port in the URL

scp-style URLs (`git@host:owner/repo.git`) can't carry a port, which would
need a per-container `Port` entry kept in sync in `~/.ssh/config`.
`ssh://git@127.0.0.1:PORT/owner/repo.git` carries it, so both git's
transport and git-bale's ssh derive `-p PORT` from the URL.

The `ssh://` path is absolute on the remote, so the entrypoint symlinks
`/<owner>` → `/home/git/<owner>` for each repo in `$TEST_REPOS`. The
resolver splits the path on the FIRST `/` to get owner/repo for the
forge-auth handshake, so the layout must keep owner one segment deep: extra
nesting (e.g. `repos/`) would make `validate_segment` fail or yield the wrong
owner.

`GIT_SSH_COMMAND` is
`ssh -F <empty file> -i <key> -o IdentitiesOnly=yes -o UserKnownHostsFile=… -o StrictHostKeyChecking=no -o BatchMode=yes`,
so ssh ignores user/system config. On Unix git-bale's forge-auth ssh honors
`GIT_SSH_COMMAND` too (as git does); a per-run `ssh-agent` (`SSH_AUTH_SOCK`)
is a backstop. On Windows git-bale runs bare `ssh`, which finds the key at
the default `%USERPROFILE%\.ssh\id_ed25519`.

### Why an isolated $HOME

git reads `~/.gitconfig`, ssh reads `~/.ssh/config`/`known_hosts`, and the
pre-push hook's subprocesses inherit `HOME`. `HOME` (and `USERPROFILE` on
Windows) and `GIT_CONFIG_GLOBAL` point into the run's work dir, and
`GIT_CONFIG_NOSYSTEM=1` blocks system config: a clean slate that leaves the
developer's configs untouched. The client env also sets
`BALE_GC_GRACE_SECS=0` so gc reclaims promptly; only `local-gc-grace` raises
it.

### Why we *don't* set `bale.serverUrl` + `bale.token`

That pair makes the resolver skip the SSH forge handshake, which is the
production path we want exercised. Only two phases pin both: `wrong-token`
(a bogus token, to test rejection) and `offline-no-network` (a self-minted
JWT, so the counting proxy sees every CAS contact and nothing else).

### Bind-mount permissions

The container's `bale` user is UID 10001, while the host `/data` belongs to
the test user, so the entrypoint chowns `/data` to `bale` (mode 0755). The
server writes xorbs/shards as **0600** files under 0755 dirs.

The harness can **stat** them from the host (`stat(2)` needs only `+x` on
the parents), so `disk_xorb_bytes()` / `disk_shard_bytes()` size the store
directly. It can **not open** them: under rootless podman they belong to a
host subuid (rootful: UID 10001), and 0600 grants "other" nothing, so a
host-side read or write fails with `PermissionError [Errno 13]`.

So anything touching xorb/shard **contents** goes through the container
(default `exec` user root): `ServerHandle.read_data_file` (`cat`) and
`write_data_file` (`cat > $path`) — used by `compression`, `tampered-xorb`
(corrupt + restore), `upload-guards` and `xorb-layout-heal`. `meta.db` is
likewise reached via `sqlite3` inside the container (`mocks.py`). Moving the
work dir off `/tmp` doesn't change ownership; the fix is the container, not
the path.

### Phase orchestration

`REGISTRY` in `baleharness/cli.py` maps each phase to `(group, read_only,
thunk)`. Groups run in a fixed order (`registry.py`); `--order` only permutes
within a group:

- `g1` — independent phases with their own repos on the shared server (or
  no server).
- `g2-head` — `bigfile` alone; it fills `rev_state` and is never reordered.
- `g2-tail` — phases that consume `bigfile`'s pushes/`rev_state`; they
  auto-skip when it's empty.
- `g3` — everything else that doesn't need `bigfile`: phases with their own
  container + data dir (so they can kill, wipe or reconfigure the server),
  phases with their own repos on the shared server, and the server-less
  `local-*` phases.

`read_only` marks the phases eligible under `--reuse-from`, which only reads
the preserved server state. `offline-restart` is deliberately *one*
phase: it stops the server, smudges offline, then starts a fresh container
on the same data dir — restructure it before inserting anything between
those steps.

The walk is intentionally linear, not a dependency graph or parallel: the
suite takes minutes, and parallelism would buy little and obscure failures.

### Adding a new phase

1. Write `phase_<name>(...)` in the matching `baleharness/phases/<category>.py`
   (see [Files](#files)), or a new module for a new category.
2. Take `timings: Timings` and wrap IO-heavy stretches in
   `with timings.measure("name", bytes_moved=…)` so wallclock and throughput
   show in the summary.
3. Add it to `REGISTRY` in `baleharness/cli.py` `main()` with its group and
   `read_only` flag. Race phases widen windows with the client's
   `BALE_TEST_*_DELAY_MS` hooks (server: `BALE_TEST_FS_WRITE_FAIL`); phases
   crafting xorbs/shards use `bale-e2e-tools`.
4. Add a row to the phase table above.
5. Run `uvx ruff check --fix tests/e2e && uvx ruff format tests/e2e`.

### Gotchas

- The `pre-push` hook from `git-bale install --local` runs
  `exec git-bale push-pending "$@"` — bare name — so the client env puts the
  binary's directory first on `PATH`. The harness drives the *prebuilt*
  binary: rebuild it before a `--no-build` rerun or client changes go
  untested.
- If `podman info` fails (e.g. the macOS `podman machine` isn't started) the
  harness exits 77.
- `.dockerignore` is an allow-list (`Cargo.toml`, `Cargo.lock`, `crates/`,
  `tests/e2e/entrypoint.sh`). If the Dockerfile starts needing another path,
  add it there.
- `tampered-xorb` corrupts every stored xorb and restores them in a
  `finally`; it runs after the g2 pushes so a failed restore can't affect
  earlier checks.
- 35 MB at xet's 64 KiB chunk target is ~547 chunks. `bigfile`'s v2/v3
  storage deltas assume CDC keeps an edit local; if chunking parameters
  change, `phase_big_file_dedup`'s tolerance envelopes may need widening.
- On macOS, if the podman VM can't bind-mount the default temp work dir,
  pass `--state-dir` under `/Users/...`.
- Long runs can fail JWT validation with "clocks differ" when the podman VM
  clock drifts from the host; keep it synced (e.g. a periodic `date -s` in
  the VM — `chronyc` doesn't fix it).
