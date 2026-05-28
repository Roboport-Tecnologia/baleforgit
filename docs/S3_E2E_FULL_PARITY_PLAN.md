# S3 e2e full-parity follow-up plan

## Status

A focused S3 e2e suite has shipped — `tests/e2e/run_s3.py` plus helpers in
`tests/e2e/s3lib.py`. It covers four phases against an S3-backed server
(MinIO sidecar):

- `s3-basic` — push + cold-clone roundtrip
- `s3-dedup` — CDC chunk-level dedup verified via MinIO object counts +
  `/v1/usage` API
- `s3-failure-kill` — server killed mid-PUT to MinIO; recovery via
  content-addressed idempotency
- `s3-failure-conndrop` — server↔MinIO TCP connection dropped mid-PUT via
  a host-side `TcpProxy` + `host.containers.internal`

This document is the bridge to **full parity** with the fs suite (13
phases in `tests/e2e/run.py`). Five fs phases are not yet ported to S3.
The infrastructure for porting them is already in place; what remains is
the per-phase scenario logic.

## What's already done (don't redo)

- **MinIO sidecar lifecycle** (`s3lib.MinioGuard`) — image
  `quay.io/minio/minio:RELEASE.2025-01-20T14-49-07Z`, `/minio/health/ready`
  probe with 180 s timeout, idempotent `mc mb -p`, force-rm on stop.
- **Per-run podman network** (`s3lib.Network`) — created in `run_s3.main`,
  destroyed in `finally`. MinIO + every server container join it.
- **Bucket-level introspection** (`s3lib.S3StorageView`) — `xorb_bytes()`,
  `shard_bytes()`, `total_bytes()` scoped to a `BALE_S3_PREFIX`. Backed
  by `mc ls --recursive --json` parsed line-by-line.
- **Object mutation/read** (`MinioGuard.get_object`, `list_objects`) —
  `mc cat` and `mc ls`. **Note**: an explicit `put_object` for arbitrary
  bytes isn't there yet — needed only by the tampered-xorb port (see §
  Remaining work).
- **Server env + run args helpers** — `s3_server_env(minio, prefix=…,
  endpoint_override=…)` and `s3_run_args(network)` produce the dicts/
  lists that `start_container(extra_env=…, extra_run_args=…)` consumes.
- **Hooks in `run.py`** — `start_container` accepts `extra_env` +
  `extra_run_args` (defaults preserve fs behavior); `TcpProxy` accepts
  `bind_host` for the `0.0.0.0` case the S3-conndrop phase needs.
- **`entrypoint.sh` pass-through** — exports any of `BALE_S3_BUCKET`,
  `BALE_S3_ENDPOINT_URL`, `BALE_S3_FORCE_PATH_STYLE`,
  `BALE_S3_ACCESS_KEY_ID`, `BALE_S3_SECRET_ACCESS_KEY`,
  `BALE_S3_REGION`, `BALE_S3_DISABLE_SSE`, `BALE_S3_PREFIX`,
  `BALE_S3_SESSION_TOKEN` when set, so they reach the `bale` user
  through `setpriv`.
- **Per-phase isolation pattern** — every phase in `s3lib.py` uses its
  own `BALE_S3_PREFIX` (e.g. `"basic/"`, `"dedup/"`, `"kill/"`,
  `"s3drop/"`) and its own `data_root` for `meta.db` + git-home. This
  was the load-bearing decision that let the parity port stay tractable:
  bucket-level sharing of MinIO with prefix-level isolation gives each
  phase the same "fresh storage" feel that fs gets from per-phase
  directories, without spinning up a MinIO container per phase.

## Remaining work — 5 phases to port

The shape is mechanical: each port takes the body of the fs phase in
`run.py`, swaps `server.disk_*_bytes()` for `S3StorageView.*_bytes()` (or
removes the assertion where it's not S3-applicable), wraps server starts
with `s3lib._start_s3_server(...)` to inject the per-phase prefix, and
uses content-addressed idempotency arguments where the fs version relied
on filesystem semantics.

### 1. `phase_s3_basic_user_ops` — port of `phase_basic_user_ops` (run.py:1328)

The fs version exercises stage / unstage / re-stage (pointer-cache hit) /
stash / pop / commit / push / cold-resmudge / hot-resmudge on an 8 KiB
file. Most of it is **client-side** and storage-agnostic. The only S3-
specific lines to change:

- `server.disk_total_bytes() != 0` pre-push check → `storage.total_bytes()
  != 0` against the phase prefix.
- `server.disk_total_bytes() <= 0` post-push check → same swap.
- Cold-resmudge after push works unchanged: the smudge runs through
  `/v1/reconstructions/`, the server presigns against MinIO, the client
  fetches via the host-published port. The pre-signed URL property is
  identical to fs.

Prefix: `"basic-user-ops/"`. Should run alongside, not instead of,
`phase_s3_basic` — the existing `s3-basic` is a thinner smoke test.

### 2. `phase_s3_idempotency` — port of `phase_push_idempotency` (run.py:2014)

The fs version asserts that re-pushing with no new commits doesn't grow
server storage. S3 needs the same assertion against `storage.total_bytes()`
before/after the second push (within `SIZE_TOLERANCE_BYTES`).

Caveat: this phase depends on `rev_state` from the bigfile dedup phase in
the fs suite. The S3 suite's equivalent — `phase_s3_dedup` — already
returns enough state implicitly (the repo on the same prefix has commits
to push against). Easiest path: make `phase_s3_dedup` chain into a
re-push idempotency check inline, rather than splitting into two phases.

### 3. `phase_s3_clone_and_verify_history` — port of `phase_clone_and_verify_history` (run.py:2034)

The fs version cold-clones over SSH and verifies every historical
revision checks out with the correct sha256. The fs suite uses
`rev_state["shas"]` and `rev_state["commits"]` from `phase_big_file_dedup`,
which pushes the same file at three revisions.

To port, either:
- Extend `phase_s3_dedup` to push the same file at three revisions
  (mirroring fs lines 1546–1819 of run.py — v1, v2 with an 8-byte poke,
  v3 with a 1 MiB region replacement) and return a `rev_state` dict from
  it, or
- Write a standalone `phase_s3_history` that builds the multi-revision
  history itself, then clones and verifies.

Recommend the first: it keeps the dedup assertions (chunk-level reuse
across small/medium edits) bundled with the history setup, matching the
fs suite's structure.

### 4. `phase_s3_adversarial_wrong_token` — port of `phase_adversarial_wrong_token` (run.py:2207)

Pins a bogus JWT to `bale.serverUrl` + `bale.token`, attempts a push,
expects failure with no bucket growth. Storage assertion swap:
`server.disk_total_bytes()` → `storage.total_bytes()`. Everything else is
client-side.

Prefix: `"wrong-token/"`.

### 5. `phase_s3_adversarial_tampered_xorb` — port of `phase_adversarial_tampered_xorb` (run.py:2285)

This is the only port that needs new `s3lib` code. The fs version walks
`server.data_root / "xorbs"`, picks the first xorb, XORs the last byte,
writes it back, runs the test, and restores the original on `finally`.

For S3, add to `s3lib.MinioGuard`:

```python
def put_object(self, prefix_key: str, body: bytes) -> None:
    """Overwrite an object's bytes via `mc cp` through a tmpfile inside
    the container. Used by the tampered-xorb port."""
    # podman exec -i ... sh -c 'cat > /tmp/v'
    completed = subprocess.run(
        self.rt.cmd(
            "exec", "-i", self.container,
            "sh", "-c", "cat > /tmp/v"
        ),
        input=body, capture_output=True, check=False,
    )
    if completed.returncode != 0:
        raise TestFailure(f"podman exec stdin failed: {completed.stderr!r}")
    self._mc("cp", "/tmp/v", f"local/{MINIO_BUCKET}/{prefix_key}")
```

Then the phase:

```python
keys = minio.list_objects(f"{prefix}xorbs/")
if not keys:
    raise TestFailure("no xorb in bucket to tamper with")
victim_key, _sz = keys[0]
original = minio.get_object(victim_key)
tampered = bytearray(original); tampered[-1] ^= 0xFF
minio.put_object(victim_key, bytes(tampered))
try:
    # ... cold-clone + assert sha256 mismatch detected ...
finally:
    minio.put_object(victim_key, original)
```

Prefix: `"tampered/"`. The phase has to set up the bigfile (or a
multi-chunk payload) inside the same prefix first so there's actually a
xorb to corrupt — easiest is to push a 35 MiB file at the top of the
phase before tampering.

### 6. (No port needed) `phase_failure_transient_db` — orthogonal to storage

The fs version locks `meta.db` from a sidecar `sqlite3` shell and
asserts sqlx's busy_timeout swallows the contention. Storage backend
makes no difference — this would run identically on an S3-backed server.
If you want a `phase_s3_failure_dbbusy` for completeness, it's a copy of
the fs phase with `_start_s3_server` instead of `start_container` and a
prefix of `"dbbusy/"`. Low priority; the fs phase already validates the
SQLite contract.

### 7. (Skip) `phase_offline_and_restart` — fs-specific premise

The fs version stops the server, runs offline smudge from the client's
hot caches (manifest + chunk caches in `.git/bale/`), then restarts the
server against the same data dir and verifies the file. The "offline
smudge from local caches" half is storage-agnostic and unchanged. The
"data survives a container restart" half is trivially true for S3
(MinIO has its own lifecycle; the server's container restart doesn't
touch the bucket). Skipping the S3 port unless there's a specific
restart-related assertion you want to make.

### 8. (Skip) `phase_adversarial_quota_exceeded` — already tested at fs

The quota check runs in the server-side `register_xorb` path against
SQLite usage rows; it doesn't reach the blob store. The fs phase
already validates the rejection path end-to-end. Porting to S3 would
just re-prove that `register_xorb`'s quota check works — no new
coverage. Skip unless you want the symmetry.

## Wiring the new phases into the registry

`run_s3.py:121-129` has the phase registry — a plain dict. To add the
five new phases, extend it:

```python
registry: dict[str, PhaseFn] = {
    "s3-basic":             lambda: phase_s3_basic(**common_kwargs),
    "s3-basic-user-ops":    lambda: phase_s3_basic_user_ops(**common_kwargs),
    "s3-dedup":             lambda: phase_s3_dedup(**common_kwargs),
    "s3-history-clone":     lambda: phase_s3_history_and_clone(**common_kwargs),
    "s3-wrong-token":       lambda: phase_s3_adversarial_wrong_token(**common_kwargs),
    "s3-tampered-xorb":     lambda: phase_s3_adversarial_tampered_xorb(**common_kwargs),
    "s3-failure-kill":      lambda: phase_s3_failure_server_kill_mid_upload(**common_kwargs),
    "s3-failure-conndrop":  lambda: phase_s3_failure_connection_drop_mid_upload(**common_kwargs),
    # Optional:
    # "s3-failure-dbbusy":    lambda: phase_s3_failure_transient_db(**common_kwargs),
}
```

There's no group/ordering machinery in `run_s3.py` — every phase is
isolated by prefix and data_root, so any order works.

## Gotchas to keep in mind

- **Prefix isolation is the contract.** Every phase MUST set its own
  unique `BALE_S3_PREFIX`. A reused prefix means a phase sees leftover
  xorbs from an earlier run and its delta assertions go wrong. The
  helpers (`s3_server_env`, `S3StorageView`) take `prefix` as a
  required positional; don't add a default.
- **`mc du --json` is a one-shot line per directory** (not per object).
  `S3StorageView` uses `list_objects` + sum-of-sizes precisely because
  `mc du`'s output shape would need extra parsing.
- **aws-sdk-s3 retries** are 2 additional attempts on connection errors
  with exponential backoff from ~100 ms. The S3-conndrop phase already
  tolerates both "SDK swallowed the drop" and "SDK gave up" — copy that
  pattern if you add another mid-PUT drop phase.
- **`host.containers.internal`** is a podman 4+ feature. The harness
  doesn't currently probe for it; if you run on older runtimes the
  conndrop phase fails at server start with a DNS error. Could add a
  `podman version` parse in `Network.create` if it becomes a problem.
- **MinIO image pull is slow on first run** (~120 MB). `MinioGuard.start`
  has `READY_TIMEOUT_S = 180` which covers it. Don't shrink without
  testing on a cold cache.
- **`mc cat` for read, `mc cp` for write** — `MinioGuard.get_object`
  exists, `put_object` doesn't yet. Add it when you do the tampered-xorb
  port (template in § 5 above).
- **No `--order`/`--state-dir`/`--reuse-from`** in `run_s3.py`. The S3
  phases are fully isolated, so ordering matrices wouldn't catch
  anything. If you add inter-phase state (e.g., the bigfile-rev-state
  pattern from fs), revisit this.

## Verification

After porting, the wallclock budget for the full S3 suite should be ~3–5
minutes on a warm machine (MinIO image cached, podman warm, release
binary present). Compare against `run.py` baseline.

```bash
cargo build --release -p git-bale
python3 tests/e2e/run_s3.py             # full suite
python3 tests/e2e/run_s3.py --skip s3-failure-conndrop  # if podman <4
python3 tests/e2e/run_matrix.py --s3    # single invocation; matrix is
                                        # a no-op for S3
```

Static checks unaffected: `cargo fmt --check` and `cargo clippy
--workspace --all-targets --all-features -- -D warnings` should still
pass (no Rust changes expected for parity work).

## References

- Original full-plan file (broader 14-module refactor that this scoped
  down from): `~/.claude/plans/i-want-you-to-lazy-mitten.md`
- Existing S3 phases: `tests/e2e/s3lib.py`
- Existing S3 runner: `tests/e2e/run_s3.py`
- fs phases to port: `tests/e2e/run.py` at the line numbers cited above
- Server-side S3 plumbing: `crates/bale-server-bin/src/main.rs:97-160`
- S3 trait impl: `crates/bale-server-storage-s3/src/lib.rs`
- Reference MinIO sidecar: `tests/e2e/s3lib.py` (the Rust-side
  `crates/bale-server-storage-s3/tests/minio.rs` it was modeled on has been
  removed along with all Rust tests)
