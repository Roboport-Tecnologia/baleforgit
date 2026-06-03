# Full end-to-end test

A standalone Python harness that drives the release `git-bale` binary
against a bundled podman container running both `baleforgit-server` and
`openssh-server`. Exercises the production-shaped transport (SSH for git
push/clone, SSH for the Bale forge-auth handshake) across stage /
unstage / stash / pop / commit / push / clone — including a 35 MB binary
with two slight modifications so the dedup-driven storage deltas can be
verified against the on-disk numbers and the `/v1/usage` API.

**Not run by `cargo test`.** Invoke it directly:

```bash
python3 tests/e2e/run.py                # filesystem blob store + SQLite (the defaults)
python3 tests/e2e/run.py --backend s3   # the WHOLE suite against an S3 (MinIO) blob store
python3 tests/e2e/run.py --meta postgres # the WHOLE suite against a Postgres metadata store
```

## Prereqs

- `git` and `ssh`/`ssh-keygen` on the host PATH.
- `podman` (preferred) or `docker` with a working daemon/VM. On macOS,
  `podman machine start` must have been run.
- A release-built `git-bale` binary. The harness does **not** invoke
  cargo — produce the binary out-of-band:

  ```bash
  cargo build --release -p git-bale
  ```

- Python 3.9+. Only stdlib is used.
- *Optional* (`mount-rev`/`mount-diff` phases only): libfuse2 on Linux,
  fuse-t on macOS, [WinFsp](https://winfsp.dev/) on Windows. On Linux/macOS
  the mount phases skip cleanly when the driver is missing; on Windows the
  harness **auto-installs WinFsp** (downloads the MSI and runs `msiexec /qn`,
  which needs admin) and skips only if that can't be done.

The harness runs natively on Linux, macOS, **and Windows** hosts (stdlib
only — `pathlib`, `subprocess`, `urllib`). The server always runs as a
**Linux container** under podman/docker regardless of host OS; only the
git-bale *client* runs on the host. On a Windows host:

- Install **Git for Windows** (provides `git`, `ssh`, `ssh-keygen`, and the
  `sh` git uses for hooks + `GIT_SSH_COMMAND`) and **Docker Desktop** or
  **podman** with a Linux-container (WSL2) backend.
- The run/state dir (and `--git-bale` binary) must live on a drive shared
  with the container runtime (e.g. under `C:\Users\...`) so the `/data` and
  `/home/git` bind mounts resolve.
- Point `--git-bale` at `target\release\git-bale.exe` (the harness looks for
  the `.exe` automatically).
- Windows-specific handling: SSH keys are locked via `icacls` (Win32 OpenSSH
  rejects loose-ACL keys); no `ssh-agent` (git-bale's forge-auth `ssh` finds
  the key via the default `%USERPROFILE%\.ssh` lookup); bind-mount paths use
  forward slashes; mount phases use a WinFsp directory mount. `GIT_SSH_COMMAND`
  passes `-F <empty file>` (not the null device — Git-for-Windows's bundled
  MSYS `ssh` reads bare `nul` as a relative filename). The container's sshd runs
  with `StrictModes=no` because the `/home/git` bind mount on a Windows host
  can't represent Unix modes, so `authorized_keys` looks world-writable and
  StrictModes would deny every publickey auth.
- Repo-root `.gitattributes` pins `*.sh` and the Dockerfiles to `eol=lf`: with
  `core.autocrlf=true` a Windows checkout would otherwise give `entrypoint.sh` a
  CRLF shebang, and the container would exit at startup ("exec ... no such file
  or directory") before it could serve.

## What it covers

| Phase           | What it verifies                                                                                    |
|-----------------|-----------------------------------------------------------------------------------------------------|
| `basic`         | Stage / unstage / re-stage (pointer cache hit) / stash / pop / commit / push on a 8 KiB file.       |
| `offline-no-network` | A counting TCP proxy in front of the CAS server proves add/status/diff/commit/checkout/stash/pop/unstage/gc make **zero** server connections; `git push` (positive control) MUST make the count non-zero. |
| `push-pending-noop` | `git-bale push-pending` with no `.git/bale/staging/` is a clean no-op (exit 0) — the pre-push hook runs on every push, so a push with no bale changes must not error. |
| `push-pending-corrupt` | DATA-LOSS GUARD: a staged xorb deleted after `git add` (marker outlives its bytes) makes `push-pending` fail the local reconstruct — it must NOT clear the marker or report success on a file it couldn't upload, and nothing reaches the server. |
| `track`         | `git-bale track` appends `filter=bale` lines to `.gitattributes`: creates the file when absent, dedups already-tracked patterns, normalizes a missing trailing newline (LF or CRLF) so a new pattern isn't fused onto the last line, skips empty patterns, and errors on an unreadable (directory) `.gitattributes`. |
| `bigfile`       | 35 MB binary pushed at three revisions; storage growth per push matches the *actual* edit size.     |
| `usage`         | `GET /v1/usage/{owner}` and `GET /v1/usage/repo/{owner}/{repo}` numbers agree with on-disk bytes. Also checks `require_admin_or_owner`: the hex admin bearer reads any owner (200), a JWT scoped to a different owner is forbidden (403). |
| `dedup`         | A *second file* with bit-identical content adds zero new xorb bytes.                                |
| `idempotency`   | Re-pushing with no new commits doesn't grow server storage.                                         |
| `clone`         | Cold-clone over SSH; every historical revision checks out with the correct sha256.                  |
| `mount-rev`     | `git-bale mount HEAD` exposes both a plain blob and a bale-tracked file via FUSE; bytes match.      |
| `mount-diff`    | `git-bale mount-diff v1 v3` exposes both labeled sides of a 35 MB binary; each side reconstructs.   |
| `mount-diff-mixed` | `mount-diff` over a fresh repo with both a plain text file and a bale-tracked binary; both sides of each match `git show` byte-for-byte, and `diff -q` reports the labelled sides differ. |
| `mount-edge`    | `mount`/`mount-diff` arg + diff validation in `mount/mod.rs`: identical labels rejected, empty diff (`no files differ`) and empty/filtered mount (`no files in`) error instead of mounting empty, and omitting `--label-a/-b` derives labels via `sanitize_label` (`HEAD~2`→`HEAD_2`). Skips when libfuse/fuse-t is absent. |
| `offline-restart` | Hot-path smudge works with the server stopped; data persists across a fresh container.            |
| `wrong-token`   | Push with a bogus `bale.token` is rejected and does not corrupt the data dir.                       |
| `tampered-xorb` | A xorb whose bytes were flipped on disk does NOT produce matching content via cold smudge.          |
| `quota`         | A server brought up with `BALE_DEFAULT_QUOTA_BYTES=1024` rejects a 35 MB push cleanly.              |
| `quota-admin`   | `PUT /v1/quotas/{owner}`: 404 when the admin token is unset, 401 on missing/non-hex/wrong bearer, 204 to set a 1 KiB cap (then a push is rejected) and 204 to clear it with `null` (then the same push succeeds + cold-clones). Proves the admin endpoint authenticates and that `set_owner_quota`'s upsert + DELETE arms persist. |
| `shard-quota`   | Isolates `upload_shard`'s delta-quota gate from the xorb-stage one. Owner A seeds 1 MiB unlimited; owner B (capped at 256 KiB via the admin API) pushes the same bytes → B's xorbs all dedup (no disk growth, xorb-stage skipped) so only the shard-stage `unaccounted_xorb_bytes_for_owner` check can — and does — reject. Asserts the quota message + unchanged server xorb bytes. |
| `upload-guards` | Direct-HTTP negative tests of the server's load-bearing guards: a real xorb body POSTed under a wrong URL hash (and a length-tampered body) is rejected by `verify_xorb_body` with 400 and stores nothing; a read-scope token POSTing gets 403; and (fs only) a signed transfer URL with a forged sig, a past expiry, or a mismatched `Range` each gets 401. Also drives `get_xorb_range`'s bound checks via validly-signed URLs (harness holds the transfer secret): an end past the xorb clamps to a whole-xorb 206, a start past the end is 400. |
| `failure-kill`     | Server is SIGKILL'd mid-upload; restart on the same data dir and a retry `git push` recovers cleanly. |
| `failure-conndrop` | A TCP proxy in front of the CAS port is killed mid-upload (server stays up); retry succeeds.        |
| `failure-dbbusy`   | A sidecar `sqlite3` shell holds an IMMEDIATE write lock on `meta.db`; the user-side push still succeeds because sqlx's busy_timeout waits the lock out. **Self-skips under `--meta postgres`** (no `meta.db`). |
| `failure-s3-conndrop` | **S3-only** (self-skips on fs): the server↔MinIO TCP link is dropped mid-PUT via a host-side `TcpProxy`; the AWS SDK's retries and/or a client retry on the recovered link converge, and the file reconstructs from the bucket with one copy stored. |
| `failure-fs-writefail` | **fs-only** (self-skips on S3): a server started with `BALE_TEST_FS_WRITE_FAIL=1` takes `write_atomic`'s write/fsync-failure arm on every blob write; the push fails with **nothing** stored (`xorbs/`/`shards/`/`tmp/` all empty — no half-write, no tmp leak), then a clean restart (no hook) round-trips the same content. |
| `failure-fs-cput` | **fs-only** (self-skips on S3): two byte-identical pushes fired concurrently to two repos race `write_atomic` on the same content-addressed dst; both succeed, on-disk xorb bytes stay ≈ one payload (no double-store), `tmp/` is empty, and both cold-clone to the original bytes. |
| `gc-abandon-checkout` | `git-bale gc`: push a baseline, stage a change, abandon it (`git reset` + `git checkout`); the post-checkout hook's gc fully wipes the orphaned staging. The user-reported bug. |
| `gc-keeps-unpushed`   | DATA-LOSS GUARD: two stacked *unpushed* commits (tip names only v2); manual `git-bale gc` must NOT drop v1's staging. Push + cold-clone then reconstructs every revision byte-for-byte. |
| `gc-mixed`            | Committed-but-unpushed v1 survives while a staged-then-abandoned (never-committed) v2 is forgotten; v1 stays pushable + reconstructable end to end. |
| `churn`               | Sustained churn against ONE reused repo: 12 rounds of edit→commit→push (rotating region edits on a multi-chunk file, plus add/delete of extra files and a plain non-bale text file), with cold clones at rounds 3/7/11 that each reconstruct the FULL accumulated history byte-for-byte. Integrity verified at every step (staged + committed pointers, post-push worktree), `/healthz` probed after each push (a push that crashes the server fails it), and server disk asserted monotonic. The regression guard for the "data corrupted + server crashed after the Nth push" class of bug. Scales up via `HUGE_CHURN=N` — see [Scaling churn](#scaling-the-churn-phase-huge_churn). |
| `resync-wipe`         | Disaster recovery: push a binary, restart the server with a BLANK CAS (fresh data dir, same bare repo), then delete `.git`, re-init, re-add, and `git push -f`. The first push is *rejected* — every chunk dedups against the client's stale xet cache, so the xorbs the blank server lacks are never re-uploaded — and the client surfaces a plain-language cache-mismatch explanation (naming the active cache dir + `BALE_XET_CACHE`), not a bare `400 Bad Request on /shards`; the rejected push leaves staging intact and writes nothing to the server. Recovery then follows that advice: a second `git push -f` with `BALE_XET_CACHE` pointed at a fresh dir re-uploads everything and succeeds, and a cold clone reconstructs the file byte-for-byte. |
| `spilled-clean`       | Caps `BALE_MAX_INLINE_CLEAN` at 1 MiB so a 5 MiB `git add` drives the clean filter's spill-to-tmpfile path; an unstage + re-add hits the file-backed clean-cache verify, then push + cold/hot resmudge round-trips the spilled file. |
| `global-dedup-shard`  | The server's `GET /v1/chunks` dedup shard must ingest without crashing the upload session. Seeds a repo, fetches the dedup shard for a known chunk straight from the endpoint and asserts its footer is well-formed (lookup offsets == `footer_offset`, never 0), then plants that shard into the client's xet `shard-cache/` and pushes again — the second push's `FileUploadSession` scans + ingests it via `read_all_truncated_hashes`, the path that underflowed (debug panic / release OOM) when `file_lookup_offset` was 0. Deterministic: doesn't rely on the 1/1024 global-dedup chunk sampling, which the release binary can't lower. |
| `local-basic`         | **No-server.** `git-bale init-local` sets up a per-repo store (`bale.local=true`, `bale.localStore=.git/bale/store`). A `git add` + `git commit` writes xorbs/shards to the durable store (no staging drain needed); a fresh checkout with manifests wiped reconstructs the file byte-for-byte from the store alone, with no server running. |
| `local-gc-abandon`    | **No-server.** Stage a file, then abandon it (`git reset` + `git checkout`); the post-checkout gc hook drops the orphaned markers and clean-cache entry. A re-add + checkout reconstructs correctly (no stale pointer). |
| `local-shared-dedup`  | **No-server.** Two repos share one store at `~/bale-local` (`--shared`). Adding the same content in both repos results in zero additional xorb bytes in the shared store — chunk-level dedup works cross-repo through the shared store. |
| `local-prune-shared`  | **No-server.** With a shared store, commit a file in repo A (live) and a file in repo B then drop repo B's reference (dead). `git-bale prune --shared` removes the dead object and leaves the live one intact; repo A can still reconstruct its file after prune. |

### Running the whole suite on S3

```bash
python3 tests/e2e/run.py --backend s3
```

`--backend s3` brings up a MinIO sidecar (`quay.io/minio/minio`, ~120 MB on
first pull) on a per-run podman network, then runs the **entire phase
registry** (every phase in the table above) against a server that uses MinIO
as its `BlobStore` instead of the local filesystem — the same flows, the same
assertions, just a different backend. It composes with `--skip` / `--only` /
`--order`.

How it works: a process-global backend (set once in `cli.main`, mirroring the
coverage-mode global) makes `start_container` auto-inject the `BALE_S3_*` env +
shared-network args for *every* container it launches. Each server is scoped to
its own bucket prefix derived from its `data_root` — stable across a restart on
the same dir (so `failure-kill` / `offline-restart` land on the same subtree)
and distinct across phases (the bucket-level analogue of the fs suite's
per-phase data dirs). `ServerHandle.disk_*_bytes()` answers from `mc ls` against
that prefix instead of the local `data_root/xorbs` tree, so the storage-accounting
assertions (`bigfile` growth, `usage`-vs-disk, `dedup`, quota, churn monotonicity)
work unchanged; `tampered-xorb` corrupts a bucket object instead of an on-disk
file. The fs failure phases already cover the S3 failure scenarios end to end
(SIGKILL mid-upload, client↔server drop, busy DB) since meta.db and the staging
retry path are backend-agnostic.

The one S3 scenario with no fs analogue — a **server↔MinIO** TCP drop mid-PUT
(distinct from `failure-conndrop`'s client↔server drop) — is its own phase,
`failure-s3-conndrop`. It self-skips under the fs backend and runs only under
`--backend s3`.

### Running the whole suite on Postgres

```bash
python3 tests/e2e/run.py --meta postgres
```

`--meta postgres` brings up a Postgres sidecar (`postgres:16-alpine`) on the
same kind of per-run podman network, then runs the **entire phase registry**
against a server that uses Postgres as its `MetadataStore` instead of the
in-container SQLite `meta.db` — same flows, same assertions, just the metadata
backend swapped. It composes with `--skip` / `--only` / `--order` **and** with
`--backend s3` (the two sidecars share one network, so `--backend s3 --meta
postgres` swaps both the blob store and the metadata store at once).

How it works mirrors the S3 backend exactly: a process-global backend (set once
in `cli.main`) makes `start_container` inject `BALE_POSTGRES_URL` + the
shared-network arg for *every* container it launches. Each server gets its own
**database** (e.g. `bale_server_data_<hash>`) derived from its `data_root` —
stable across a restart on the same dir (so `failure-kill` / `offline-restart`
land on the same database and its metadata persists) and distinct across phases
(the database-level analogue of the fs suite's per-phase `meta.db`). The
harness provisions each database via `podman exec psql` before the server
starts; the server connects over the published port via the host's primary IP
(the same bridge→host route MinIO uses). The blob store is untouched, so
`ServerHandle.disk_*_bytes()` and every storage-accounting assertion
(`bigfile`, `usage`-vs-disk, `dedup`, quota, churn monotonicity) work
unchanged — they now cross-check the Postgres accounting queries against the
on-disk bytes.

The one SQLite-specific scenario — `failure-dbbusy`, which locks `meta.db` via
a sidecar `sqlite3` shell to exercise sqlx's `busy_timeout` — **self-skips under
`--meta postgres`** (there is no `meta.db`, and Postgres MVCC doesn't need that
wait). Every other phase runs.

A timing summary (per-phase wallclock + throughput on the
bytes-relevant phases) prints at the end of every run.

> Note: a small `s3lib.py` survives with two phases (`phase_s3_basic`,
> `phase_s3_dedup`) that **coverage mode** runs against the instrumented image
> to light up `bale-server-storage-s3` in the report. It has no standalone
> entry point — the whole suite on S3 is `run.py --backend s3`.

## Flags

```
python3 tests/e2e/run.py [--git-bale PATH] [--image-tag TAG] [--no-build]
                        [--keep-tmpdir] [--skip PHASE ...] [--only PHASE ...]
```

- `--git-bale PATH` — path to the release binary if not at
  `target/release/git-bale`. Also honors `$GIT_BALE_BIN`.
- `--image-tag TAG` — what to tag the bundled image as.
- `--no-build` — skip `podman build`; the image must already exist.
- `--keep-tmpdir` — don't delete the run's work directory (handy for
  inspecting `.git/bale/*` and the server's `xorbs/shards/` after a run).
- `--skip PHASE` — skip a named phase (repeatable). Phases that depend
  on earlier state (e.g., `usage` depends on `bigfile`) auto-skip when
  their prerequisites were skipped.
- `--only PHASE` — run *only* the named phase(s) (repeatable); every other
  phase is skipped. The quick way to iterate on a single self-contained
  phase — `--only resync-wipe` instead of `--skip`-ing all the others. An
  unknown phase name errors out. Composes with `--skip` (a phase named in
  both is skipped). Note phases needing earlier state still auto-skip:
  `--only usage` runs nothing because `bigfile` didn't populate `rev_state`.
- `--backend {fs,s3}` — blob store backend for **every** server in the run.
  `fs` (default) is the in-container local data dir. `s3` brings up a MinIO
  sidecar on a per-run podman network and runs the *whole* phase registry
  against it — each server (the shared one and every per-phase one) is scoped
  to its own bucket prefix derived from its `data_root`, the bucket-level
  analogue of the fs suite's per-phase data dirs. Mutually exclusive with
  `--coverage` and `--reuse-from` (the bucket is torn down at end of run).
  See [Running the whole suite on S3](#running-the-whole-suite-on-s3) below.
- `--meta {sqlite,postgres}` — metadata store for **every** server in the run.
  `sqlite` (default) is the in-container local `meta.db`. `postgres` brings up a
  Postgres sidecar on the per-run podman network and runs the *whole* phase
  registry against it — each server scoped to its own database derived from its
  `data_root` (the metadata analogue of `--backend s3`'s per-`data_root` bucket
  prefix). Composes with `--backend`, so `--backend s3 --meta postgres` runs the
  suite with both swapped out at once. Mutually exclusive with `--coverage` and
  `--reuse-from` (the sidecar's databases are torn down at end of run) — under
  `--coverage`, the dedicated `postgres` extra phase covers
  `bale-server-meta-postgres` instead. See
  [Running the whole suite on Postgres](#running-the-whole-suite-on-postgres)
  below.
- `--coverage` — see [Coverage mode](#coverage-mode) below.
- `--coverage-dir PATH` — override the coverage output directory
  (implies `--coverage`). Defaults to `<repo>/target/coverage-e2e/`.

## The upload progress indicator (`progress-demo`)

git-bale's pre-push hook draws a live, git-styled
`Uploading bales: 47% (4/8), … | …/s` line on stderr once an upload runs past
~200 ms, then finalizes it in place to
`Uploading bales: 100% (N/N), <size> | <rate>, done.` (the summary prints even
when the push was too fast to ever show the live line). The size shown is the
bytes actually transferred (net of dedup); when dedup skipped some of the push
the summary appends ` (+ <size> deduped)`, and a push whose content the server
already had reports `<size> already on server, done.` instead of an upload
size. The `progress-demo` phase exercises it two ways:

- **In a normal sweep** it pushes a couple of fixed variants through
  `git-bale push-pending` with stderr *captured* and asserts the summary line —
  one fresh multi-file push (size clause present) and one byte-identical,
  fully-deduped push (`100% (1/1), <size> already on server, done.`). No env
  vars, no live bar, nothing printed to the screen.
- **Via `--only progress-demo`** it becomes a hand-driven *visual* demo:

  ```bash
  cargo build --release -p git-bale
  python3 tests/e2e/run.py --only progress-demo --no-build
  ```

  Run it **from an interactive terminal** — the demo pushes with the harness's
  output capture turned off, so the hook inherits your TTY (the condition
  git-bale checks before drawing the live line). A throttle proxy stretches the
  upload so the bar is watchable, and these two env knobs apply:

  - `FILE_TIMER` (default `1`, decimals OK) — seconds the server should
    "take" per file, realised as a client→server byte throttle in front of
    the CAS port so the upload (and the bar) stretches over ~`FILE_TIMER`s
    per file. Set it under ~`0.2` to watch the 200 ms threshold *suppress*
    the live line (the final summary still prints); set it to `3`–`5` to
    watch it climb slowly. `0` = no throttle (instant server).
  - `FILE_COUNT` (default `5`) — how many distinct files to add + push; each
    is 4 MiB of unique (incompressible) content, so none dedup away.

  ```bash
  FILE_TIMER=3 FILE_COUNT=8 python3 tests/e2e/run.py --only progress-demo --no-build
  ```

## Scaling the churn phase (`HUGE_CHURN`)

The `churn` phase normally runs a quick 12-round pass. Set `HUGE_CHURN=N`
(a positive integer) **together with `--only churn`** to run a randomized,
scaled-up stress variant that targets **roughly N minutes** of wall-clock —
`HUGE_CHURN=1` ≈ 1 min, `HUGE_CHURN=5` ≈ 5 min, and so on (measured: N=1 →
60 s, N=2 → 122 s on a warm image):

```bash
HUGE_CHURN=5 python3 tests/e2e/run.py --only churn --no-build
```

What scales with N:

- **Rounds** scale linearly (60 × N), so it's "a lot of changes committed and
  pushed" against one reused repo — the direct stress for the
  crash/corruption-after-the-Nth-push fear.
- Each round edits a **random subset** of several big base files (33 MiB
  across 5 files) at random offsets/lengths, rewrites a plain non-bale text
  file, and randomly adds/deletes extra files (some plain text). Add and
  delete probabilities are balanced so the worktree size stays roughly
  constant and total time stays linear in N.
- A **cold clone every 15 rounds** walks the most recent 15 revisions,
  verifying each reconstructs byte-for-byte. The window slides and tiles the
  history, so every revision is cold-verified exactly once while each clone's
  cost stays constant (a full-history walk at each clone would make total time
  grow quadratically with N).

Integrity is still checked at every step (staged + committed pointers,
post-push worktree, `/healthz` after each push, monotonic server disk). The
run is randomized but reproducible: the RNG seed is logged at the start, and
`HUGE_CHURN_SEED=<int>` pins it so a failure replays the exact same sequence.

`HUGE_CHURN` is ignored outside `--only churn`, so a normal full sweep never
balloons into the multi-minute variant.

## Coverage mode

`python3 tests/e2e/run.py --coverage` runs the suite against instrumented
builds of both binaries and renders a unified HTML coverage report.

- Builds `git-bale` with `RUSTFLAGS=-C instrument-coverage` into
  `target/coverage-e2e/cargo/` (a separate target dir so it doesn't
  clobber `target/release/git-bale`).
- Builds the image with `--build-arg COVERAGE=1` under the tag
  `baleforgit-server-e2e-coverage:latest`. The Dockerfile compiles the
  server with `-C instrument-coverage` and skips `strip` so debug info
  and the `__llvm_prf_*` sections survive.
- Bind-mounts `target/coverage-e2e/profiles/` into every container at
  `/coverage` and sets `LLVM_PROFILE_FILE=/coverage/server-%m-%p.profraw`.
  Host processes write to the same dir via `host-%m-%p.profraw`.
- At teardown, runs `llvm-profdata merge` + `llvm-cov show -format=html`
  against both binaries (the server binary is extracted from the image
  via `podman cp` so the host-side llvm-cov can read its coverage
  sections). The report lands at `target/coverage-e2e/html/index.html`.

Coverage mode runs **extra phases** beyond the fs set so the report
covers every pluggable trait impl:
- `s3-basic` + `s3-dedup` — exercise `bale-server-storage-s3`.
- `authz-http` — drives `bale-server-authz-http::HttpAuthz` via a Python
  mock of the upstream `/check_access`. One server container with
  `BALE_AUTHZ_HTTP_URL` set; three pushes against three test repos so
  the mock can return 200 / 403 / 500 per repo; one direct token-mint
  probe with an unknown hub bearer for the 401 branch.
- `https-origin` — drives the `git-bale` resolver's HTTP-origin auth
  branch (`MockForgeServer` with `enforce_auth` + a canned
  `credential.helper`) so both the upload and download scopes resolve
  over HTTP instead of SSH; the download's anonymous probe gets a 401 so
  the `git_credential_fill` fallback (`authenticate_http_with_fallback`)
  is exercised, not just the anon-accepted public path.
- `otlp` — boots a server with `OTEL_EXPORTER_OTLP_ENDPOINT` /
  `_TRACES_ENDPOINT` pointed at a host-side `OtlpCollector`, pushes a
  small file, and asserts the collector receives a `/v1/traces` export —
  exercising `bale-server-bin::telemetry`'s exporter init + signal-URL
  resolution, which are no-ops whenever the OTLP env is unset.
- `postgres` — exercises `bale-server-meta-postgres`. The whole suite on
  Postgres (`run.py --meta postgres`) is mutually exclusive with
  `--coverage`, so this is the metadata-store analogue of the s3 phases:
  a `PostgresGuard` sidecar on its own network, one instrumented server
  with `BALE_POSTGRES_URL` set (blob store stays fs), and a v1 push →
  v2 re-push → cold clone → `/v1/usage/repo` query covering register_files
  (insert + dedup), the reconstruction lookup, and the usage aggregation.

Coverage mode **auto-skips** phases that SIGKILL the server (`failure-
kill`, `failure-conndrop`, `failure-dbbusy`) — LLVM's atexit hook can't
flush profraws on SIGKILL.

Requires `llvm-profdata` and `llvm-cov` from the `llvm-tools-preview`
component (install with `rustup component add llvm-tools-preview`).
Resolved via `rustc --print sysroot` + `--print host-tuple` since
`rustup which` doesn't proxy them.

The prod (default, no `--coverage`) path is unchanged — it keeps using
the release/stripped binaries and the original image tag, so functional
testing and coverage measurement stay separate.

## Exit codes

- `0` — all checks passed.
- `1` — a check failed; container logs are dumped to stderr.
- `2` — unexpected exception (bug in the harness).
- `77` — environment skip (e.g., podman daemon not running, no
  release binary). CI can branch on this to distinguish "ran clean and
  failed" from "didn't run at all".
- `130` — interrupted (Ctrl-C).

## Files

| File                       | Purpose                                                                |
|----------------------------|------------------------------------------------------------------------|
| `Dockerfile`               | Multi-stage build of the bundled `baleforgit-server` + `sshd` image.   |
| `entrypoint.sh`            | Generates ssh host keys + authorized_keys + bare repos + the fake     |
|                            | `git-bale-authenticate` script, starts sshd, execs `baleforgit-server`. Also pass-through for `BALE_S3_*` env vars when set. |
| `run.py`                   | Entry point: runs `baleharness.cli.main` (the fs *and* `--backend s3` suites) and re-exports the names `s3lib.py` imports via `from run import …`. |
| `baleharness/`             | The harness itself, split into focused modules (see below). `cli.py` owns the phase registry + `main()` + the `--backend` flag; `phases/` holds one module per phase category (`scenario`, `mount`, `adversarial`, `failure`, `coverage_phases`, `gc`, `progress`, `local`). |
| `baleharness/s3backend.py` | `MinioGuard`, `Network`, `S3StorageView`, the `BALE_S3_*` env/run-arg helpers, the `data_root`→prefix derivation, and the process-global "active S3 backend" that makes `start_container` S3-aware under `--backend s3`. Importable without `run`, so `server.py` uses it without a cycle. |
| `baleharness/pgbackend.py` | The metadata-store analogue of `s3backend.py`: `PostgresGuard` (sidecar + per-database provisioning), the `data_root`→database-name derivation, and the process-global "active Postgres backend" that makes `start_container` inject `BALE_POSTGRES_URL` under `--meta postgres`. Reuses `s3backend.Network` so the two sidecars share one podman network. |
| `run_legacy.py`            | Frozen copy of the pre-split monolithic `run.py`, kept only to validate the refactor against. Delete once parity is confirmed. |
| `s3lib.py`                 | Two S3 phases (`phase_s3_basic`, `phase_s3_dedup`) that coverage mode runs against the instrumented image; re-exports the infra from `baleharness.s3backend`. No standalone entry point — the whole suite on S3 is `run.py --backend s3`. |
| `run_matrix.py`            | Multi-run driver for `run.py`. Pass `--s3` to run the whole suite on the S3 backend, `--postgres` for the Postgres metadata store, or both. |
| `README.md`                | This file.                                                             |

## Reproducibility

Payloads are sha256-chained from a fixed seed so a failing assertion
points at the same bytes on every machine. Random material (JWT keys,
SSH keys, container names) regenerates each run — that's deliberate, so
state never leaks across runs.

---

## Design

The notes below are for future-you (or a future agent) extending the
test. They explain the *why* of choices that aren't obvious from the
code, so you don't have to re-litigate them.

### Why Python, not Rust

The harness *is* the user. It treats `git-bale` and `baleforgit-server`
as black-box binaries and drives them through the filesystem, git, and
the network. Writing it in Rust would either re-use library code from
the same crates we're testing (defeating the point) or duplicate the
whole driver surface. Python with stdlib only gives us cross-platform
subprocess, urllib, pathlib, and a hand-rolled HS256 JWT in twenty lines
— no pip dependency, no virtualenv, runs everywhere a developer might
sit.

### Why podman for the server

The production target for `baleforgit-server` is a Linux server. Running
it natively on macOS/Windows hosts during the test would mean
cross-compiling and bypassing the actual deployment shape. Bundling it
in a container means the test exercises the exact image (or close to
it) that ops would deploy. podman is preferred over docker only because
rootless podman is the easier default on Linux dev machines; the
harness falls back to docker automatically.

### Why bundle sshd in the same container

`git-bale` has *two* SSH touchpoints:

1. The git transport itself (`git push` and `git clone` over
   `ssh://git@host/...`).
2. The Bale forge-auth handshake (`ssh git@host
   git-bale-authenticate <owner>/<repo> <op>`).

Both target the same `git@<forge-host>` endpoint in production (Gitea,
Gogs, GitHub Enterprise, etc. — see
`docs/BALE_FORGE_PROTOCOL.md`). Putting sshd in the same container as
the server mirrors that topology: the SSH endpoint and the CAS endpoint
are at different ports of the same logical host. The fake
`git-bale-authenticate` is a one-liner that the entrypoint generates at
startup, baking in `$BALE_PUBLIC_HOST_URL` and `$E2E_HUB_TOKEN` so the
non-interactive SSH shell doesn't need to source rc files.

### Why `ssh://` URLs with the port in the URL

`git-bale`'s resolver parses both scp-style and `ssh://` URLs. scp-style
(`git@host:owner/repo.git`) can't carry a port, which would force us to
keep per-server `Port` entries in a synced `~/.ssh/config` for every
container the test brings up. `ssh://git@host:PORT/owner/repo.git`
carries the port in argv, so both git's SSH transport and git-bale's
own ssh subprocess derive `-p PORT` from the URL without any
ssh-config plumbing.

The path in `ssh://` URLs is absolute on the remote side. The container
entrypoint creates a root-level symlink `/<owner>` →
`/home/git/<owner>` per repo in `$TEST_REPOS` so the absolute path
`/<owner>/<repo>.git` resolves to the actual bare repo. The resolver
splits the path on the FIRST `/` to extract owner/repo, so this same
URL also yields the right `owner/repo` pair for the Bale forge-auth
handshake. Any extra nesting (e.g. `repos/`) would shift the parse and
`validate_segment` would either fail or yield the wrong owner.

`GIT_SSH_COMMAND` passes `-F /dev/null` so git's ssh ignores any
user/system config and only sees the flags we hand it (`-i` for the
identity, `-o UserKnownHostsFile=...`, `-o StrictHostKeyChecking=no`).
git-bale's ssh subprocess derives identity from the default
`$HOME/.ssh/id_ed25519` lookup — `ssh-keygen` placed our key there
under the isolated `$HOME`, so it's found without any further config.

### Why an isolated $HOME

git reads `~/.gitconfig`, ssh reads `~/.ssh/config`/`known_hosts`, and
the pre-push hook spawns subprocesses that inherit `HOME`. Pointing
`HOME` (and `GIT_CONFIG_GLOBAL`) at the per-run tempdir gives us a
clean slate and keeps the developer's real configs untouched.
`GIT_CONFIG_NOSYSTEM=1` blocks system-wide git config too.
`GIT_SSH_COMMAND` does the same for `git`'s own SSH transport.

### Why we *don't* set `bale.serverUrl` + `bale.token`

That combo would make the resolver fast-path. We want the SSH-based
forge handshake to actually run — it's the production code path. The
only phase that opts out is `wrong-token`, which deliberately pins a
bogus token to exercise the unauthorized-rejection path.

### Bind-mount permissions

The container's `bale` user is UID 10001, but the bind-mounted `/data`
on the host is owned by whichever UID created it (the test user). The
entrypoint chowns `/data` to `bale:bale` at startup so the server can
write. Files written by `bale` land mode 0644 by default, which the
host user can still read for the disk-size measurements that the test
performs from outside the container. Rootless podman's user namespace
remapping handles the cross-UID story transparently.

### Phase orchestration

The `REGISTRY` dict in `baleharness/cli.py` maps each phase name to its
group + `read_only` flag + thunk; `--skip` drops a named phase. Phases
that depend on earlier state (e.g. `usage` needs the pushes from
`bigfile`) live in group `g2-tail` and auto-skip when `rev_state` is
empty. The four `local-*` phases live in group `g3`; they never touch the
shared server (no container needed), so they run in an isolated work dir and compose cleanly with `--backend` and `--meta`. `offline-restart` is a *merged* phase that
deliberately can't be split: it stops the server, runs an offline
smudge, then starts a fresh container against the same data dir. If you
add a phase between offline-smudge and restart, restructure the merged
function first.

The orchestration is intentionally linear (the ordered `REGISTRY` walk
in `main()`) rather than a dependency graph. The test takes minutes,
not seconds — parallelism would buy us little and obscure failures.

### Adding a new phase

1. Define `def phase_<your_name>(...)` in the matching
   `baleharness/phases/<category>.py` module (`scenario`, `mount`,
   `adversarial`, `failure`, `coverage_phases`, `gc`, or `progress`). A
   brand-new category gets a new module under `baleharness/phases/`.
2. Take an explicit `timings: Timings` parameter so its wallclock shows
   up in the summary. Use `with timings.measure("name", bytes_moved=…)`
   for any IO-heavy stretch — `bytes_moved` turns into a throughput
   line in the final report.
3. Wire it into the `REGISTRY` dict in `baleharness/cli.py` (`main()`),
   choosing its group (`g1` / `g2-head` / `g2-tail` / `g3`) and
   `read_only` flag. g2-tail phases auto-skip when `rev_state` is empty.
4. Document it in the README phase table above.

### Gotchas

- The `pre-push` hook installed by `git-bale install --local` does
  `exec git-bale push-pending` — bare name, no path. The test sets
  `PATH` so the release binary's directory is first.
- `git-bale` invokes `ssh` directly (not via `GIT_SSH_COMMAND`) for the
  forge handshake; its `ssh` argv has `-p` only if the URL has a port.
  scp-style URLs don't, so the port comes from `~/.ssh/config`.
- macOS podman runs Linux containers via `podman machine`. If
  `podman info` errors, the harness exits 77 with a "machine likely not
  started" hint.
- The `.dockerignore` excludes `target/` and `xet-core/`. The bundled
  Dockerfile only compiles `bale-server-bin`, which has no
  `xet-core`/`git-bale` deps, so the exclusion is harmless.
- The `tampered-xorb` phase mutates `/data/xorbs/...` on disk. It
  restores the original bytes in its `finally` block, but it runs after
  the main pushes so any failure to restore wouldn't affect earlier
  checks anyway.
- 35 MB at the default chunk target of 64 KiB produces ~547 chunks. The
  storage-delta assertions in `bigfile` v2/v3 assume CDC keeps the edit
  localized. If you change chunk parameters in `xet-data`, the tolerance
  envelopes in `phase_big_file_dedup` may need to widen.
