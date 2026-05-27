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
python3 tests/e2e/run.py        # filesystem blob store (the default)
python3 tests/e2e/run_s3.py     # S3 blob store via a MinIO sidecar
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

The harness is cross-platform by design (uses `pathlib`, `subprocess`,
`urllib`, no POSIX-only assumptions). On Windows the container is still
a Linux container under podman/docker — only the test driver runs
natively on the host. Today `git-bale` itself uses `cfg(unix)`-only
APIs, so the Windows host path will refuse to run with a "binary not
found" error until that's fixed; the harness logic itself is portable.

## What it covers

| Phase           | What it verifies                                                                                    |
|-----------------|-----------------------------------------------------------------------------------------------------|
| `basic`         | Stage / unstage / re-stage (pointer cache hit) / stash / pop / commit / push on a 8 KiB file.       |
| `bigfile`       | 35 MB binary pushed at three revisions; storage growth per push matches the *actual* edit size.     |
| `usage`         | `GET /v1/usage/{owner}` and `GET /v1/usage/repo/{owner}/{repo}` numbers agree with on-disk bytes.   |
| `dedup`         | A *second file* with bit-identical content adds zero new xorb bytes.                                |
| `idempotency`   | Re-pushing with no new commits doesn't grow server storage.                                         |
| `clone`         | Cold-clone over SSH; every historical revision checks out with the correct sha256.                  |
| `offline-restart` | Hot-path smudge works with the server stopped; data persists across a fresh container.            |
| `wrong-token`   | Push with a bogus `bale.token` is rejected and does not corrupt the data dir.                       |
| `tampered-xorb` | A xorb whose bytes were flipped on disk does NOT produce matching content via cold smudge.          |
| `quota`         | A server brought up with `BALE_DEFAULT_QUOTA_BYTES=1024` rejects a 35 MB push cleanly.              |
| `failure-kill`     | Server is SIGKILL'd mid-upload; restart on the same data dir and a retry `git push` recovers cleanly. |
| `failure-conndrop` | A TCP proxy in front of the CAS port is killed mid-upload (server stays up); retry succeeds.        |
| `failure-dbbusy`   | A sidecar `sqlite3` shell holds an IMMEDIATE write lock on `meta.db`; the user-side push still succeeds because sqlx's busy_timeout waits the lock out. |

### S3 mode (`run_s3.py`)

Brings up a MinIO sidecar (`quay.io/minio/minio`, ~120 MB on first pull)
on a per-run podman network, then runs four phases against a server that
uses MinIO as its `BlobStore` instead of the local filesystem.

| Phase                  | What it verifies                                                                                       |
|------------------------|--------------------------------------------------------------------------------------------------------|
| `s3-basic`             | Push + cold-clone roundtrip against S3 storage; bucket actually receives xorbs (no silent fs fallback).|
| `s3-dedup`             | CDC chunk-level dedup against MinIO object counts; a duplicate file adds ≤ 4 KiB of bucket bytes.      |
| `s3-failure-kill`      | Server is killed while mid-PUT to MinIO; restart + retry converges via content-addressed idempotency.  |
| `s3-failure-conndrop`  | Server↔MinIO TCP connection dropped mid-PUT via a host-side `TcpProxy`; retry on the recovered link succeeds. |

Each phase writes under its own `BALE_S3_PREFIX` so they share one
bucket without cross-contamination. The S3-conndrop phase requires
podman 4+ (or docker with the equivalent) because it relies on
`host.containers.internal` to make the host-side proxy reachable from
inside the server container; older runtimes will error out at server
start.

A timing summary (per-phase wallclock + throughput on the
bytes-relevant phases) prints at the end of every run.

## Flags

```
python3 tests/e2e/run.py [--git-bale PATH] [--image-tag TAG] [--no-build]
                        [--keep-tmpdir] [--skip PHASE ...]
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
| `run.py`                   | The fs-mode harness.                                                   |
| `run_s3.py`                | The S3-mode harness (MinIO sidecar; 4 phases).                         |
| `s3lib.py`                 | `MinioGuard`, `Network`, `S3StorageView`, and the 4 S3 phase functions.|
| `run_matrix.py`            | Multi-run driver for `run.py`. Pass `--s3` to invoke `run_s3.py` once. |
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

`maybe(name, fn)` skips a named phase. Phases that depend on earlier
state (e.g. `usage` needs the pushes from `bigfile`) guard themselves
with `if rev_state:`. `offline-restart` is a *merged* phase that
deliberately can't be split: it stops the server, runs an offline
smudge, then starts a fresh container against the same data dir. If you
add a phase between offline-smudge and restart, restructure the merged
function first.

The orchestration is intentionally linear (sequential `maybe(...)`
calls in `main()`) rather than a dependency graph. The test takes
minutes, not seconds — parallelism would buy us little and obscure
failures.

### Adding a new phase

1. Define `def phase_<your_name>(...)` in the *Scenario phases* or
   *Adversarial phases* section.
2. Take an explicit `timings: Timings` parameter so its wallclock shows
   up in the summary. Use `with timings.measure("name", bytes_moved=…)`
   for any IO-heavy stretch — `bytes_moved` turns into a throughput
   line in the final report.
3. Wire it into `main()` via `maybe("your-name", lambda: ...)`. If it
   depends on prior `rev_state`, drop it under the `if rev_state:`
   block.
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
