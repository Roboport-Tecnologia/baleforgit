# Architecture

This document describes the internals of `baleforgit-server`: how the protocol pieces map to code, what each pluggable trait is for, and the gotchas of the on-disk format inherited from xet-core.

The repo ships one client: the native `git-bale` filter in `crates/git-bale/`, a long-running Git filter that talks to baleforgit-server directly via the Bale wire protocol. Covered below.

## Goals

1. Define a clean Bale wire protocol for chunked CAS upload/download/dedup, served by `baleforgit-server` and consumed by `git-bale`.
2. Keep everything that touches storage, persistence, or authorization behind a **trait** so the same server can run on top of S3, Postgres, or any external repo authority.
3. Reuse xet-core's well-tested hashing, chunking, and shard format semantics (we link `xet-data`/`xet-client`/`xet-runtime`/`xet-core-structures` as library deps); own the wire surface and the server-side state.
4. Make it possible to drop the server in front of an existing git forge without sharing secrets: the forge owns the user model, mints short-lived JWTs, and answers a single `/check_access` callback (see [`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md)).

## Component view

```
                ┌──────────────────────────────────────────────────────┐
                │                  git-bale client                     │
                │   (fetches CAS URL + token from token endpoint)      │
                └────────────────────┬─────────────────────────────────┘
                                     │ HTTPS
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
              ▼                      ▼                      ▼
   ┌─────────────────────┐   ┌──────────────────┐   ┌──────────────────┐
   │  Token endpoint     │   │   CAS API        │   │  Transfer URL    │
   │  (mock HF Hub)      │   │   /v1/...        │   │  /xorb/...       │
   │  /api/{type}s/...   │   │   uploads/dl     │   │  (signed range   │
   │  /bale-{rw}-token/.. │   │   recon/dedup    │   │   GET)           │
   └──────────┬──────────┘   └────────┬─────────┘   └────────┬─────────┘
              │                       │                      │
              ▼                       ▼                      ▼
   ┌────────────────────────────────────────────────────────────────────┐
   │                       baleforgit-server (single Rust binary)              │
   │                                                                    │
   │   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐   │
   │   │ HTTP layer │  │  Service   │  │  Indexer   │  │  Tokens    │   │
   │   │  (axum)    │──│  layer     │──│ (parses    │──│ (mint +    │   │
   │   │            │  │            │  │  shards)   │  │  verify)   │   │
   │   └────────────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘   │
   │                         │               │               │          │
   │   ┌─────────────────────┼───────────────┼───────────────┼──────┐   │
   │   │   Pluggable traits  ▼               ▼               ▼      │   │
   │   │  ┌────────────┐ ┌──────────────┐ ┌──────────────┐          │   │
   │   │  │ BlobStore  │ │ MetadataStore│ │  RepoAuthz   │          │   │
   │   │  └────────────┘ └──────────────┘ └──────────────┘          │   │
   │   └────────────────────────────────────────────────────────────┘   │
   │           │                  │                  │                  │
   │    impls: │            impls:│            impls:│                  │
   │   ┌───────┴───────┐    ┌─────┴─────┐      ┌─────┴───────────────┐  │
   │   │ filesystem    │    │ SQLite    │      │ AlwaysAllow         │  │
   │   │ S3            │    │ Postgres  │      │ ConfigAuthz         │  │
   │   │ Azure (later) │    │           │      │ HttpAuthz (upstream)│  │
   │   └───────────────┘    └───────────┘      └─────────────────────┘  │
   └────────────────────────────────────────────────────────────────────┘
```

## Request flows

### Upload (write-token scope required)

1. Client splits the file via gearhash CDC into chunks (~64 KiB target, 8 KiB min, 128 KiB max).
2. Client may query `GET /v1/chunks/{prefix}/{hash}` (`prefix` is `default` in current xet-core) for any chunk whose hash matches the eligibility rule (last 8 bytes mod 1024 == 0); server replies with a shard whose CAS Info section lists nearby xorbs that contain that chunk (chunk hashes HMAC-wrapped — see *Global dedup* below).
3. Client groups new chunks into xorbs (≤ 64 MiB serialized, ~1024 chunks each) and uploads them with `POST /v1/xorbs/default/{xorb_hash}`. Server verifies the URL hash is well-formed, persists the xorb blob, returns `{was_inserted: bool}`.
4. Client builds a shard with **File Info** (each file → list of terms `(xorb_hash, chunk_index_range, unpacked_segment_bytes)` plus per-term verification hashes) and **CAS Info** (per new xorb: the chunk hashes and their byte offsets inside that xorb). Client POSTs the shard to `/shards`.
5. Server:
   - verifies every referenced xorb already exists (otherwise 400),
   - parses CAS Info and writes one `chunks` row per `(chunk_hash, xorb_hash, chunk_index, byte_start, unpacked_bytes)`,
   - parses File Info and writes ordered `file_terms` rows,
   - persists the shard blob keyed by BLAKE3 over its bytes (internal-only — the Bale protocol doesn't define a shard hash).

### Download (read-token scope sufficient)

1. Client calls `GET /v1/reconstructions/{file_id}` (file_id is the Xet merkle file hash, in Xet hex encoding).
2. Server **scope-checks the file against the caller's repo**: there must be a row in `files` matching `(file_hash, repo_id = claims.repo.repo_id)`. If not, returns **404** (not 403 — so an attacker can't probe for existence in other repos). The `files` table uses `(file_hash, repo_id)` as a composite primary key, so the same content can be registered in multiple repos and each registration independently grants read access (cross-repo dedup at the chunk layer is unchanged).
3. Server looks up the file's terms. For each term it reads the xorb's on-disk frame layout from `xorb_frames` (NOT the `chunks` table — that one stores uncompressed offsets) and computes the on-disk byte range covering `[chunk_idx_start, chunk_idx_end)`. It builds `fetch_info` with one **signed transfer URL** per term and the `url_range` bytes covered.
4. Server returns JSON `QueryReconstructionResponse`.
5. Client fetches each `url` with the prescribed `Range` header. The server (transfer layer) verifies the HMAC signature, verifies the Range header matches the signed range (otherwise 401), and streams the bytes from `BlobStore::get_xorb_range`. Client deserializes chunks, strips `offset_into_first_range` from the first one, concatenates.

`Range:` request-side support on `/v1/reconstructions/*` is **intentionally absent** — the server always returns the full file's terms. Range support on the transfer URL itself is fully implemented (and mandatory, since signatures cover the byte range). The native `git-bale` smudge handler accounts for this by passing `0..file_size` to `xet-data` (see "Native filter" below).

### Global dedup

- Server stores `chunk_hash → xorb_hash` and a notion of "neighborhood" (the other chunks in the same xorb).
- On hit, server builds a synthetic shard whose CAS Info section lists that xorb (and up to `DEDUP_NEIGHBORHOOD` other xorbs) with each chunk hash wrapped as `HMAC-SHA256(per_response_key, chunk_hash)`.
- The per-response random key is written into the shard footer's `chunk_hash_hmac_key`. The client wraps its own candidate chunk hashes with the same key and looks for matches in the response.
- This is what makes Xet's dedup secure: clients can confirm "I have chunk X" without the server ever revealing the full set of chunk hashes it knows about.
- Handler lives at `get_dedup_chunk` in `bale-server-http`. Returns 404 if the chunk hash isn't indexed.
- **Footer offsets are load-bearing even though the shard carries no lookup tables.** `serialize` (`bale-server-shard`) omits the file/xorb/chunk lookup tables (their `*_num_entry` counts are 0), but each lookup *offset* must still point at the section end (`footer_offset`), **not** 0. The client ingests every dedup shard into its `ShardFileManager` and calls `read_all_truncated_hashes`, which — for a lookup-table-less shard — derives the xorb-info byte range as `(xorb_info_offset, file_lookup_offset)` and scans it. A zero `file_lookup_offset` inverts that range: `file_lookup_offset - xorb_info_offset` underflows (debug panic; release a multi-exabyte `Vec::with_capacity` → OOM), killing the push's pre-push hook. This mirrors xet's own serializer, which sets the offset even when the table is absent. See *Tricky bits* and the `global-dedup-shard` e2e phase.

## Pluggable traits

All three live in `bale-server-core`. No HTTP handler accesses storage or auth directly — handlers go through these traits via the `Service<B, M, A>` struct, which holds `Arc<B>` / `Arc<M>` / `Arc<A>` (monomorphised on the chosen impls — see "Auth flow" for why the binary builds two separate `Service`s).

```rust
#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn put_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<bool /* was_inserted */>;
    async fn xorb_exists(&self, hash: &XorbHash) -> CoreResult<bool>;
    async fn get_xorb_range(&self, hash: &XorbHash, byte_range: Range<u64>) -> CoreResult<Bytes>;
    async fn put_shard(&self, hash: &ShardHash, body: Bytes) -> CoreResult<()>;
    async fn get_shard(&self, hash: &ShardHash) -> CoreResult<Bytes>;
    async fn presign_xorb_range(&self, hash: &XorbHash, byte_range: Range<u64>, ttl: Duration)
        -> CoreResult<Option<String>> { Ok(None) }
}

#[async_trait]
pub trait MetadataStore: Send + Sync {
    async fn register_xorb(&self, xorb: &XorbInfo, chunks: &[ChunkRow]) -> CoreResult<()>;
    async fn register_file(&self, file_hash: &FileHash, repo: &RepoRef,
                           terms: &[FileTerm]) -> CoreResult<()>;
    // Atomic batch — `upload_shard` calls this once per shard. SQLite
    // override wraps every file write in a single transaction so a fault
    // can't leave half-committed file rows the client thinks didn't upload.
    async fn register_files(&self, repo: &RepoRef,
                            files: &[(FileHash, Vec<FileTerm>)]) -> CoreResult<()>;

    // On-disk frame layout — populated at xorb upload time by parsing the
    // chunk frame headers; required to translate shard chunk-index ranges
    // into HTTP byte ranges (the chunks table only has uncompressed offsets).
    async fn register_xorb_layout(&self, xorb: &XorbHash, frames: &[XorbFrameRow]) -> CoreResult<()>;
    async fn xorb_frame_layout(&self, xorb: &XorbHash) -> CoreResult<Vec<XorbFrameRow>>;

    async fn xorb_exists(&self, xorb: &XorbHash) -> CoreResult<bool>;
    async fn lookup_file(&self, file_hash: &FileHash) -> CoreResult<Option<Vec<FileTerm>>>;
    // Scope check: true iff `file_hash` is registered in `repo_id`.
    async fn file_in_repo(&self, file_hash: &FileHash, repo_id: &str) -> CoreResult<bool>;
    async fn xorbs_near_chunk(&self, chunk_hash: &ChunkHash, limit: usize)
        -> CoreResult<Vec<XorbInfo>>;
    async fn xorb_chunk_offsets(&self, xorb: &XorbHash) -> CoreResult<Vec<ChunkOffsetRow>>;

    // Per-owner accounting + quotas. Owner = the namespace prefix of repo_id
    // (everything before '/'), denormalised onto `files` for indexed scans.
    async fn raw_bytes_for_owner(&self, owner: &str) -> CoreResult<u64>;
    async fn stored_bytes_for_owner(&self, owner: &str) -> CoreResult<u64>;
    async fn get_owner_quota(&self, owner: &str) -> CoreResult<Option<u64>>;
    async fn set_owner_quota(&self, owner: &str, limit_bytes: Option<u64>) -> CoreResult<()>;
    /// Used at shard upload to project `stored_bytes_for_owner` after a pending
    /// file registration: sums `num_bytes_on_disk` for the subset of `candidates`
    /// that `owner` does NOT already reference.
    async fn unaccounted_xorb_bytes_for_owner(&self, owner: &str, candidates: &[XorbHash])
        -> CoreResult<u64>;
    // Per-repo equivalents — same aggregation shape keyed by full `repo_id`
    // (e.g. "alice/big-model"). Used by the gitea repo settings page.
    async fn raw_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64>;
    async fn stored_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64>;
    // On-disk bytes referenced by this repo and no same-owner sibling — how much
    // the owner's stored bytes drop if it's deleted (cross-owner sharing ignored).
    async fn exclusive_stored_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64>;
}

#[async_trait]
pub trait RepoAuthz: Send + Sync {
    async fn verify_bale_token(&self, bearer: &str) -> CoreResult<TokenClaims>;
    async fn check_repo_access(&self, hub_bearer: &str, repo: &RepoRef, scope: Scope)
        -> CoreResult<UserId>;
    async fn mint_bale_token(&self, user: &UserId, repo: &RepoRef, scope: Scope)
        -> CoreResult<(String, u64)>;
}
```

### Shipped implementations

| Trait | Crate | Impl |
|-------|-------|------|
| `BlobStore` | `bale-server-storage-fs` | `FsBlobStore` — atomic temp→rename writes, byte-range reads |
| `BlobStore` | `bale-server-storage-mem` | `MemBlobStore` — `RwLock<HashMap>`, used for tests and the pluggability check |
| `BlobStore` | `bale-server-storage-s3` | `S3BlobStore` — AWS SDK against any S3-compatible API (AWS S3, MinIO, R2, B2); real presigned `GET` URLs returned from `presign_xorb_range`, so reconstruction bytes never flow through the server's HTTP layer |
| `MetadataStore` | `bale-server-meta-sqlite` | `SqliteMetadataStore` — runtime `sqlx` queries (no compile-time DB) |
| `MetadataStore` | `bale-server-meta-postgres` | `PostgresMetadataStore` — same schema/queries ported to the Postgres dialect (`$n` placeholders, `ON CONFLICT`, `BYTEA`/`BIGINT`, `SUM(...)::BIGINT`); selected when `BALE_POSTGRES_URL` is set. Migrations run under a `pg_advisory_xact_lock` so concurrent server startups don't race the DDL |
| `RepoAuthz` | `bale-server-authz-mem` | `AlwaysAllow` (tests) and `ConfigAuthz` (static map of hub bearers → users → repo scopes) |
| `RepoAuthz` | `bale-server-authz-http` | `HttpAuthz` — delegates `check_repo_access` to a small `POST /check_access` upstream contract. The contract is intentionally generic: any service that knows about users and repos (a git forge, an identity provider, a custom proxy) can implement it. Bale token mint/verify stays local. |

### Planned implementations

- `RepoAuthz` that talks directly to a specific upstream's APIs (e.g. `/api/v4/user` + project-member lookups for a particular git forge), as an alternative to going through the generic `HttpAuthz` shim. Useful when bringing the access-decision logic in-process saves a hop, or when richer upstream concepts (groups, scopes, OAuth) don't fit cleanly behind the minimal `/check_access` contract.

## Wire surface

CAS API (all behind `RepoAuthz::verify_bale_token`):

| Method | Path | Scope | Purpose |
|--------|------|-------|---------|
| GET | `/v1/reconstructions/{file_id}` | read | File reconstruction metadata |
| GET | `/v1/chunks/{prefix}/{chunk_hash}` | read | Global dedup query |
| POST | `/v1/xorbs/default/{xorb_hash}` | write | Xorb upload (rejects with 429 if over the owner's quota) |
| POST | `/shards` | write | Shard upload + indexing (rejects with 429 if over the owner's quota) |
| GET | `/v1/usage/{owner}` | read or admin | Per-owner accounting — accepts either a Bale JWT scoped to the owner OR `BALE_ADMIN_TOKEN_HEX`. See "Owner accounting and quotas". |
| GET | `/v1/usage/repo/{owner}/{repo}` | read or admin | Per-repo accounting — same auth as `/v1/usage/{owner}` (token's `repo.owner()` must match `{owner}`, or admin bearer). Returns `{repo_id, raw_bytes, stored_bytes, dedup_savings_bytes}`. Unknown repos return zeros, not 404. |

Transfer URL (referenced from `fetch_info`, signed query string, no bearer required):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/xorb/default/{xorb_hash}?s=...&e=...&x=...&sig=...` | Byte-range fetch of a xorb |

Browser file download (outside the JWT middleware — bearer rides in the query string because browsers can't carry `Authorization` on a 302 follow):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/files/{file_id}?token=<forge-jwt>&repo=<owner/name>&filename=<name>` | Streams the reconstructed file. Forge (e.g. gitea) calls `check_repo_access` to validate the JWT against `repo`, then the per-repo `file_in_repo` scope check runs locally (404 on miss). `filename` is honored for `Content-Disposition: attachment` only when its SHA-256 matches the `FilenameSHA256` claim in the JWT payload — caller-rewritten filenames on leaked URLs get 400. |

Mock HF Hub token endpoint:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/{models\|datasets\|spaces}/{ns}/{name}/bale-{read\|write}-token/{rev}` | Returns `{accessToken, exp, casUrl}` |

The token endpoint accepts the client's upstream hub bearer in `Authorization: Bearer ...`, calls `RepoAuthz::check_repo_access`, then `RepoAuthz::mint_bale_token`.

Admin endpoint (outside the JWT middleware, gated by a separate static bearer):

| Method | Path | Purpose |
|--------|------|---------|
| PUT | `/v1/quotas/{owner}` | Set or clear the per-owner storage quota. Body: `{"limit_bytes": <u64>}` or `{"limit_bytes": null}` to revert to the default. Auth: `Authorization: Bearer <hex of BALE_ADMIN_TOKEN_HEX>`, constant-time compared. Returns 404 when the admin token isn't configured (endpoint disabled). |

Operational endpoints (no bearer, no scope check, no access log):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/healthz` | Liveness probe. Returns `200 ok` while the process is running. Sits outside the auth middleware *and* the `TraceLayer`, so a probe firing every few seconds doesn't drown out real request logs. |

The binary registers a `SIGINT`/`SIGTERM` handler and hands it to `axum::serve(...).with_graceful_shutdown(...)`: on signal the listener stops accepting new connections and the server returns once in-flight handlers complete. Useful for container orchestrators that send `SIGTERM` and a grace period.

## Native filter: `git-bale`

`crates/git-bale/` is the client: a native Rust `filter.bale.process` driver installed in git config. It speaks Git's long-running filter protocol directly, and calls into `xet-core`'s `FileUploadSession` / `FileDownloadSession` for chunking and reconstruction. The forge protocol it speaks to authenticate is documented in [`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md).

Design properties:

- **Pretty-printed JSON pointer** with stable key order (`hash`, `file_size`, `sha256`). Tracked as a normal blob, parseable without xet-core.
- **Long-running process**: one filter-process subprocess per `git add` / `git checkout` fan-out, not one subprocess per file.
- **Deduplicated per-user chunk cache** instead of a whole-file local store — the worktree file is the only full copy on disk.
- **Deferred upload**: `git add` chunks and stages locally; `git push` (via a pre-push hook) is what actually moves bytes to the server. A `git-bale gc` step (wired into post-checkout/commit/merge hooks) reclaims staging for changes that were unstaged or discarded before they were ever pushed.

Layout on disk:

```
<repo>/big.bin                          # worktree (one copy)
<repo>/.git/bale/manifests/<file_id>.json # per-file reconstruction terms
<repo>/.git/bale/staging/                 # pending xorbs+shards (+ file-index/ markers), drained by push-pending, reconciled by gc
<repo>/.git/bale/clean-cache/<blake3(path)> # path-keyed, chunked-verified pointer cache
~/.cache/bale/chunks/                     # shared chunk pool across repos
```

### Pointer cache (clean short-circuit)

`git status` and `git diff` invalidate git's stat cache for any worktree file whose mtime/size differs from the index entry, then re-run the configured filter to recompute the worktree's hash. For our filter that's full CDC + xorb building + shard write — ~1–2 s for a 30 MiB file. With `git status` invoked routinely by shells, IDEs, and prompts, this gets painful fast.

The clean filter keeps a per-repo pointer cache at `<git_dir>/bale/clean-cache/<blake3(pathname)>`. Each entry is JSON shaped:

```json
{ "v": 3, "size": 30000000, "chunks": [{ "start": 0, "end": 1048576, "hash": "..." }, ...], "pointer": "{...}\n" }
```

Verification order on every clean call:

1. **Drain pkt-line into memory, spilling to a temp file past a threshold.** No hashing during the read — the chunk index is the verification mechanism. The payload stays in a `Vec<u8>` until it would exceed `MAX_INLINE_CLEAN` (4 GiB default; overridable via the `BALE_MAX_INLINE_CLEAN` env var, a byte count, which the e2e harness drops to 1 MiB to exercise the spill path on a small file), at which point accumulated bytes move to a `NamedTempFile`. The in-memory branch skips both the temp-file write and the re-reads that `clean_file`/`compute_chunks` would do.
2. **Size check.** If the drained size ≠ `entry.size`, the cache *can't* match — skip straight to the full clean. This is the cheapest possible negative signal.
3. **Chunked verify.** In-memory payloads verify on the calling thread; spilled payloads use a small thread pool that hashes file regions in 1 MiB chunks. Either way the comparison is against `entry.chunks`, in the order `[first, last, 3 random middle samples, rest]` — edits cluster at file head/tail in practice (headers, appended log lines), so this catches the majority of mismatches in the first two reads. The file-backed workers share an `AtomicBool` and exit early as soon as any chunk diverges.
4. **All chunks match** → write `entry.pointer` back to git and return.

On miss, the full clean runs as before (in-memory or via the spilled temp file), then a fresh chunk index is computed from the payload and saved. Cache hits stay side-effect-free (no staging touch, no marker touch), so a stale cache after `push-pending` drained staging just means future smudges fall to the cold path, which is correct *because the content is now on the server*.

There is one case where falling to the cold path would be wrong: content that was staged, then **orphaned before any push** (e.g. `git add` then `git restore --staged` — which fires the post-checkout hook → `git-bale gc` → sweeps the unreferenced staging). The bytes then exist neither in staging nor on the server, but the path-keyed clean-cache entry survives the worktree edit, so a re-`git add` of the same bytes would short-circuit to a pointer that can't be reconstructed (this broke `git add` → unstage → re-add → `git stash` → `pop`). To prevent it, **gc invalidates the clean-cache entries for any hash it orphans** (`clean_cache::forget_hashes`), so the re-add is a full clean that re-stages. gc only does this for *genuinely* orphaned hashes — those reachable from no local or remote ref; a dropped marker for already-pushed content keeps its cache entry, preserving the cold-path short-circuit above.

**Smudge populates the cache too.** Every successful smudge already has both inputs to the `clean(content) → pointer` mapping in hand: the pointer git just sent us as input, and the reconstructed bytes we just wrote to the temp file. We compute a chunk index against the temp file and save it under the smudge's pathname before responding to git. That makes `git checkout -- foo.bin` fast on the *next* `git status`: the worktree gets back to HEAD's content and the clean cache simultaneously learns its fingerprint, so the subsequent stat-cache-invalidated clean call hits instead of full-cleaning HEAD's content from scratch.

Entries are ~70 bytes per chunk; a 30 MiB file is ~30 chunks = ~2 KiB on disk. No eviction; manual reset is `rm -rf .git/bale/clean-cache/`.

Two filter-process startup optimisations matter specifically because `git diff` pays them on every invocation (one filter-process per command):

- `RawConfig::load` issues a single `git config --null --get-regexp '^bale\\.'` to fetch every `bale.*` key in one fork+exec, instead of four `git config --get` calls. Saves ~15–60 ms.
- `XetRuntime::new()` is lazy. Its worker-thread stack allocations (8 MiB × n threads) aren't needed on a cache hit, so we hold an `Option<Arc<XetRuntime>>` and only fill it when the clean miss path or any smudge actually calls `bridge_sync`. Saves another ~20–50 ms on the cache-hit path.

### Deferred upload and `push-pending`

`clean` (driven by `git add` / `git commit`) does not touch the network. It builds a `FileUploadSession` via `TranslatorConfig::local_config(<git_dir>/bale/staging/)`, which routes xet-data through `LocalClient` — xorbs land at `…/xet/xorbs/xorbs/default.<hex>` and shards at `…/xet/xorbs/shards/<hex>.mdb`. The pointer Git stores is identical to the synchronous-upload flow; only the upload is deferred. Authentication is **not** resolved during clean (no `git credential fill`, no forge auth roundtrip), so `git add` works on a fully offline laptop.

`git-bale push-pending` is the drain step, and its job is broader than "drain staging": it ensures every bale file the push *advertises* is present on — and registered under — the repo of the remote being pushed to. Two classes of file qualify:

1. **Freshly staged** files (`git add` cleaned them offline, no server has them yet). Sourced from `.git/bale/staging/` via `TranslatorConfig::local_config`.
2. **Already-pushed-elsewhere** files: reachable from the refs being pushed but no longer in staging because a prior push to a *different* remote drained them. Since the server scopes file→repo registration per-repo (see *Per-repo scope check*), the target repo doesn't know about these yet, and a clone of the target would 404 on checkout. push-pending discovers them by walking the pushed ref delta for bale pointers (the same gix rev-walk + tree-diff gc uses), then re-sources each one's bytes from whichever configured remote still holds it (`origin` first; a read-scoped reconstruct against each remote in turn). The walk is bounded only by the remote shas git reports on stdin (what each pushed ref currently points to on the remote) — a **new** ref (zero sha) hides nothing, so the full history is reconsidered. It deliberately does **not** hide the remote's `refs/remotes/<name>/*`: git refs being present on a remote says nothing about whether the bale objects were registered under that repo (an old/argless client — or this very bug — could have pushed the commits without them), and hiding them would skip exactly the files that need registering. To keep the resulting over-walk cheap, each candidate is probed against the target (`GET /v1/reconstructions/{hash}` with the target write token: 200 = already registered → skip, otherwise re-source), so a push to an already-populated remote re-downloads nothing. (Consequence: to register objects on a remote that already holds the git history but not the objects — e.g. one populated by an old client — push to a *new* branch on it; re-pushing the same ref it already has is a git no-op and won't re-walk.)

For both classes it does **not** POST staged xorbs/shards verbatim — that would bypass the server's global dedup. Instead each file is reconstructed to a temp file (from staging, or downloaded from a source server) and re-cleaned through a single online `FileUploadSession` pointed at the target. The online session queries server-known chunks and POSTs only genuinely-new xorbs, while *always* uploading its per-session reconstruction shard — and it's that shard POST to `/shards` that makes the server call `register_files(<target repo>, …)`. So a re-translate against the target's write token both uploads new content **and** registers the file under the target repo, even when every xorb already exists on the server (the common "two remotes, one server" case: cheap, because xet keys its shard cache by endpoint, so the same server's chunks dedup and only the registration round-trips). xet's CDC is deterministic, so the merkle hash out of the online session must equal the file hash we sourced for; a mismatch aborts the push.

Auth is minted against the **remote being pushed to**, not `origin` (`resolver::resolve_for_remote`, fed the pre-push hook's `$2` URL) — the write token determines the server-side repo scope of every upload. After the upload session finalizes, only the staged markers are drained (under the store lock); the re-sourced files were never in staging, so there is nothing to drain for them. If no configured remote can reconstruct an already-committed file, the push **fails** rather than advertise a pointer the target can't reconstruct.

While the upload runs, `crates/git-bale/src/progress.rs` draws a single-line, git-styled indicator on stderr — `Uploading bales: 47% (4/8), 14.5 MiB | 3.0 MiB/s` (mirroring git's own `Writing objects: …`), polling the session's `report().total_transfer_bytes*`; the `(n/N)` count is the bale files, with `n` derived from the byte fraction since only byte-level progress is available. The live line (`\r` + content, erased with `\x1b[K`) is held back for the first 200ms — a fast or fully-deduped push never flashes one — and is drawn only when stderr is a terminal. On a successful `finish()` the line is finalized *in place* into `Uploading bales: 100% (N/N), <size> | <rate>, done.` (keeping the size + rate like git's `Writing objects: 100% (6/6), 622 bytes | 622.00 KiB/s, done.`). The `<size>` is the bytes actually transferred, net of dedup; `push-pending` threads xet's per-file `DeduplicationMetrics` (`deduped_bytes`) into the snapshot so a push that partly deduped appends ` (+ <size> deduped)`, and a push whose content the server already had (nothing transferred) reports `<size> already on server, done.` instead of an upload size — this is what lets a re-push to a second repo on the same server read as "deduped, not re-uploaded" rather than a confusing full-size upload. The line is terminated with `\n` so it persists above git's subsequent `Enumerating objects…` instead of being overwritten; this summary is *not* 200ms-gated, so even an instant push reports what it uploaded. Off a terminal (the e2e harness pipes stderr) there's no live line and no escape codes — just that same final summary on success; the harness keys its assertions on exit status and error substrings, not on an empty stderr, so it's unaffected. On the error path `Drop` prints no summary and clears any drawn line, so a failed upload leaves neither a stale line nor a misleading "done" summary.

`git-bale install --local` writes managed git hooks, each carrying a `bale-marker:` line so `git-bale uninstall --local` can remove it without clobbering a hand-written hook. A `pre-push` hook `exec`s `git-bale push-pending "$@"` — git passes the remote name + URL as `$1`/`$2` and pipes the ref updates on stdin, which is how push-pending knows the push *target* and which refs to reconcile (run by hand with no args, it falls back to `origin` and drains only staging); `post-checkout`, `post-commit`, and `post-merge` hooks run `git-bale gc || true`. The pre-push hook is correctness-critical, so install **fails** if a foreign (unmarked) pre-push hook already exists; the gc hooks are best-effort, so install **skips with a warning** rather than clobbering a foreign hook of the same name. Global / system-scope installs don't touch hooks — hooks are inherently per-repo. The hook path comes from gix (`git_dir().join("hooks")`, honoring `core.hooksPath` from the merged config snapshot) so worktrees and overrides resolve correctly.

### Fully-local mode

`git-bale init-local [--store <path>] [--shared]` puts a repo into fully-local (no-server) mode. It:

- Installs the `bale` filter driver + the gc hooks into local git config (same as the filter/gc portions of `install --local`, without the pre-push hook — nothing to drain).
- Writes `bale.local=true` and `bale.localStore=<store>` into the repo's local git config.
- With `--shared`: also sets `bale.localShared=true` and registers the repo in `<store>/repos/` for `git-bale prune --shared`.

Note: the existing `git-bale install --local` is unrelated — its `--local` refers to the git-config scope (as opposed to `--global`/`--system`); `init-local` is the command that enables no-server operation.

**Config keys** (env overrides git-config in all cases):

| git-config key     | env var            | type | meaning |
|--------------------|--------------------|------|---------|
| `bale.local`       | `BALE_LOCAL`       | bool | enables fully-local mode |
| `bale.localStore`  | `BALE_LOCAL_STORE` | path (tilde-expanded) | explicit store directory |
| `bale.localShared` | `BALE_LOCAL_SHARED`| bool | store is shared across repos |

**Object store resolution** (`crate::store::object_store_root`):

| mode | `bale.localStore` set? | result |
|------|------------------------|--------|
| server | — | `.git/bale/staging/` (transient) |
| local | no | `.git/bale/store` (per-repo durable) |
| local | yes | `<bale.localStore>` (explicit, tilde-expanded) |
| local + `--shared` + no `--store` | no | `~/bale-local` |

**Per-repo markers stay per-repo.** The `file-index/` markers, the clean-cache, and the manifest cache always live under `.git/bale/` — they track *this repo's* reachable content. Only xorbs/shards relocate to the configured store. A shared store must never hold one repo's markers; `gc` and `prune` both enforce this.

**Clean (`git add`)** writes xorbs/shards to `object_store_root` (durable in local mode). The offline `LocalClient` path is identical to server-mode staging: content-addressed + atomic writes, so re-adds dedup.

**Smudge:** hot path (manifest + chunk cache) → store reconstruct → **hard error**. In local mode there is no lukewarm staging path and no network fallback. If the store cannot fully reconstruct the file, smudge returns an error rather than a partial file or a silent empty read.

**push-pending:** no-op in local mode. Objects are already durable; `git push` to a git remote moves only the small pointer commits. Large-file data stays machine-local and never reaches the server.

**gc** in local mode: liveness = reachable from any local ref + index + stash (remote-tracking refs are *not* hidden, because there is no server to fall back to). Dead markers are dropped and clean-cache entries for truly-orphaned hashes are invalidated, same as server mode. Shared store: gc is append-only — it never deletes objects or markers from the shared store, because another registered repo may reference the same objects. `git-bale prune --shared` reclaims.

**Store lock (`crate::store::StoreLock`).** Every operation that *mutates* a store takes an exclusive advisory file lock (`flock`/`LockFileEx` via `fs4`) on a sibling lockfile `<store-parent>/.<storename>.lock` — outside the store dir so prune's rename cannot move it. `clean` takes it **briefly, per file**, across {write objects → write marker} (released when `do_clean` returns); `gc` takes it (non-blocking `try_exclusive`) across {read markers → drop dead → sweep}; `push-pending` across its drain; `prune` for its whole run. Reads (smudge) and the clean-cache-hit path never lock. The OS releases on process death, so a crash never leaves a stale lock; different stores have different lockfiles, so unrelated repos never contend.

This closes two distinct windows, and the *combination* is load-bearing:
- **object-vs-marker** — clean writes the objects, then the marker; a sweep landing in between would delete an object the marker doesn't yet protect. The per-file lock (held across both writes) closes it. gc/push-pending/prune block (or `try`-skip) against it.
- **marker-vs-index** — git updates its on-disk index (or writes the ref) *after* the filter returns the pointer, so a marker can exist while git doesn't yet reference the file; a gc reading that stale index/refs would classify the file as dead and sweep its only copy. The lock alone does **not** close this (clean has released it by then). Instead, **gc defers (`crate::gc::git_op_in_flight`) while any git index/ref-update `*.lock` exists** — `index.lock` for `git add`/`commit`, a temporary `index.<temp>.lock` and then `refs/stash.lock` for `git stash`/`stash push` (stash cleans against a temp index and gc can't see its `GIT_INDEX_FILE`), and ref locks generally. Checked *after* taking the store lock, so a clean can't slip in between the check and the marker read. The one lock-free residual that index/ref-lock sniffing can't see — a `git stash`'s commit-object write, between releasing its temp index lock and taking `refs/stash.lock` — is closed by a **reclaim grace**: gc never drops or sweeps a marker whose content was cleaned within `BALE_GC_GRACE_SECS` (default **600s**). `clean` rewrites the marker on *every* add (hit or miss; the cache-hit path does it under the store lock), so a marker's mtime is "time since last cleaned"; an unreferenced-but-recent marker is treated as live and reclaimed only by a later gc once it ages out and is still unreferenced. The trade-off is that genuinely-abandoned content lingers up to the grace before reclamation (and, in server mode, could be uploaded by a `push-pending` within that window — wasteful, not incorrect). The grace + lock + in-flight check together leave no data-loss window.

An earlier design held the clean lock for the whole filter-process lifetime to cover the marker-vs-index window; it **deadlocks** (a git porcelain op keeps the filter alive holding the lock, then nests another clean that blocks on it) and was replaced by the per-file lock + `index.lock` check. Single lock, taken at most once per process, never nested ⇒ no deadlock.

**`git-bale prune --shared`** compacts a shared store:

1. Holds the store lock (`StoreLock`) for the whole run, so a concurrent `git add`/`gc` to the same store blocks until prune finishes rather than racing the swap.
2. Computes the union of file-hashes reachable across all registered repos (`<store>/repos/`).
3. **Aborts if any registered repo path is missing** — its objects may be the only copy. Pass `--force` to skip missing repos.
4. Reconstructs each live file from the old store and re-cleans it into a fresh temp store (deterministic CDC re-dedups). Asserts the round-trip hash matches before swapping.
5. Re-fingerprints the old store and aborts (no changes) if it changed mid-run — defence-in-depth behind the lock — then atomically renames the old store aside and moves the new store into place. The old store is removed on success; a swap failure rolls back so the store is never absent.

`git-bale prune --shared` is safe to run concurrently with `git add` (the add blocks on the store lock); it still serializes against other prunes.

### Staging reconciliation (`git-bale gc`)

`clean` only ever *adds* to staging; only a successful `push-pending` drains it. So if you `git add` a change and then abandon it (`git reset`, `git checkout`, switch branches), its staged xorbs/shards used to linger forever — and worse, the next `push-pending` would upload that orphaned content even though no commit references it. `git-bale gc` (`crates/git-bale/src/gc.rs`) reconciles staging against git reachability.

The invariant that makes this safe: **everything in staging is unpushed** (push-pending wipes the whole dir on success), so a staged file's marker is still needed iff some pointer git could push references it. gc computes the set of "live" bale file hashes from:

1. the **index** (covers staged-but-uncommitted pointers), and
2. pointers introduced by **unpushed commits** — a `rev_walk` over all local refs with remote-tracking refs marked *hidden*, diffing each commit against its first parent so only changed blobs are read. The walk early-outs as soon as every staged hash is accounted for, so the common "you just staged it" case resolves from the index alone.

Any staged marker **not** in the live set is dangling and removed. The set must never *under*-count: dropping a marker for committed-but-unpushed content (e.g. an older version in a stacked commit whose tip no longer names it) would strand that content, because push-pending drains by marker and the lukewarm smudge path is gated on the marker — a later push would then advertise a pointer the server can't reconstruct. Pruning by remote-tracking refs only ever *shrinks* the live set toward content the server already has, which is safe to drop.

Xorbs are shared across files by xet-data's local dedup, so gc never deletes an individual xorb while any marker survives. The object sweep (xorbs + shards + the `file-index/` dir) runs only once **no** marker remains — the same all-or-nothing wipe push-pending performs after a drain. The mixed case (some markers live, some dangling) drops the dead markers but leaves the shared objects for the next push to clear. Reads are header-gated (`find_header` size/kind) so non-pointer blobs are never inflated, and the cheap exit when staging holds no markers keeps the hooks nearly free on most checkouts. Drives the `gc-abandon-checkout` / `gc-keeps-unpushed` / `gc-mixed` phases in `tests/e2e/run.py`.

**gc also invalidates the clean-cache for hashes it genuinely orphans.** A subtlety: the post-checkout hook fires on *file-level* checkouts too (`git checkout -- f`, `git restore --staged f`), not just branch switches. `git add f` then `git restore --staged f` leaves `f` modified in the worktree but unreferenced by the index/commits, so gc sweeps its staging — yet the path-keyed [clean-cache](#pointer-cache-clean-short-circuit) entry for `f` survives the edit and still maps those exact worktree bytes to the now-unbacked pointer. A re-`git add` would then short-circuit to a pointer reconstructable from neither staging (swept) nor the server (never pushed), which broke `git add` → unstage → re-add → `git stash` → `pop`. So when gc drops a marker for a hash reachable from **no** local or remote ref (truly orphaned, as opposed to merely pushed), it calls `clean_cache::forget_hashes` for that hash, forcing the re-add to do a full clean and re-stage. Pushed-but-dangling hashes keep their cache entries so the documented post-push cold-path short-circuit still holds. To distinguish the two, gc runs a second reachability pass with remote-tracking refs as tips (not hidden); a dead hash absent from *that* set is the orphaned case. Guarded by the `basic` phase's stash/pop round-trip.

### Hot vs lukewarm vs cold smudge

On `command=smudge` (filter sees a pointer, must reconstruct), git-bale tries three paths in order, falling through on failure:

1. **Hot path** — cache-only reconstruction:
   1. Load `.git/bale/manifests/<file_id>.json`. Returns `None` for missing / malformed / unknown-version manifests — all three trigger the next path.
   2. For each cached term, ask the local chunk cache (`xet-client::chunk_cache`) for the chunk range. Any miss → fall through.
   3. Concatenate the chunk bytes into a temp file. Length checks guard against stale manifests corrupting the worktree.
2. **Lukewarm path** — staging-dir reconstruction. After `git add` but before `git-bale push-pending`, the xorbs/shards are still under `.git/bale/staging/`. We open a `FileDownloadSession` against `TranslatorConfig::local_config(<git_dir>/bale/staging/)` and call `download_to_writer(info, 0..file_size, dest)`. Any error (missing xorb, missing shard, post-push-pending empty tree) is logged at `debug` and we fall through. This keeps `git add big.bin && rm big.bin && git checkout -- big.bin` working before the user has pushed. Gated on a per-file marker `<staging>/file-index/<file_hex>` written by `clean` — without it, smudges for file hashes we never staged (e.g. `git stash`'s HEAD-restore phase) drop into xet-data's `ReconstructionTermManager`, return zero terms, and trip a `debug_assert_eq!` in its progress tracker that calls `update_item_size(0, true)` after a previous `update_item_size(file_size, true)` already finalized the size. Release builds drop the assert; dev builds panic. `push-pending` clears the markers after a successful drain, and `git-bale gc` drops any marker whose file is no longer reachable, so markers don't outlive the staged bytes they advertise.
3. **Cold path** — `FileDownloadSession::download_to_writer` against the remote bale server, same code path xet-core uses for HF-Hub-hosted Xet content. As a side effect, it also writes the manifest to `.git/bale/manifests/` so subsequent checkouts go through the hot path. The manifest stores only content-addressed `terms` (xorb hash + chunk-index range), **not** `fetch_info` URLs — those signed URLs expire after `SIGNATURE_TTL_SECS` (10 min) and aren't safe to persist.

Critical detail: the cold path passes `0..file_size` (not `FileRange::full()`, which xet-core defaults to) to `download_to_writer`. baleforgit-server has no Range support on `/v1/reconstructions/*`, and xet-data's prefetcher fans out to up to 256 MiB beyond EOF when given an unbounded range — every prefetched block then re-fetches the full file terms and trips xet-data's `SequentialWriter` contiguity check. The cap keeps the prefetcher quiet.

Second critical detail: the cold-path download is wrapped in a **no-progress watchdog** (`download_cold` in `filter_process.rs`, shared with `git-bale mount`). The reconstruction bytes come from presigned blob-store URLs the *client* fetches directly (see the S3 `presign_xorb_range` note), so a blob store that's reachable by the server but **not** by the client — a bundled MinIO presigned as `minio:9000`, a public endpoint pointed at the wrong host — fails only here, on the client. And it fails *badly*: xet-core's retry layer classifies a "host not found" DNS error as **retryable** (reqwest reports it as `is_connect()`), then backs off with `ExponentialBackoff::from_millis(3000)`, whose tokio-retry semantics square the delay each step — so the *second* retry sleeps a jittered interval up to ~2.5 hours. A permanent failure thus parks `git checkout` silently for hours. The watchdog wraps the download writer to count bytes actually written and aborts if none arrive for `BALE_DOWNLOAD_STALL_SECS` (default 30s; `0` disables), dropping the future — which cancels both the in-flight request and its multi-hour backoff sleep — and returns a user-facing error naming the file, not the server config. Counting real writes (not wall-clock) means a slow-but-progressing transfer is never killed.

### Auth resolution

`git-bale` deliberately holds no baleforgit-server secret of its own. Auth is resolved on first-use per scope (one resolution for write/clean, one for read/smudge, cached in the filter-process lifetime). The resolver lives in `crates/git-bale/src/resolver.rs`:

1. **Fast path**: if both `bale.serverUrl` and `bale.token` are set in local git config (or `BALE_SERVER_URL` / `BALE_TOKEN` env), use them as-is. This is the "I'm running my own forge and just want a static service token" mode.
2. **Remote parse**: `git remote get-url origin` → HTTP(S) or SSH `RemoteUrl` (scp-style `git@host:owner/repo.git` also supported). `push-pending` calls `resolve_for_remote` with the *push target's* URL instead of `origin`, so an upload's token (and thus its server-side repo scope) matches the remote git is actually pushing to.
3. **Forge authenticate**:
   - HTTPS → `POST {forge}/<owner>/<repo>.git/info/bale/authenticate?op=<download|upload>`. For `op=download` the client tries **anonymously first** (no `Authorization` header) so a public-repo clone/checkout never prompts; only on a `401`/`403` does it fall back to HTTPS Basic auth pulled from `git credential fill` (which may prompt) and retry. `op=upload` always sends Basic auth — anonymous writes are never granted. The user's password / PAT is verified inside the forge and never travels beyond it. See `authenticate_http_with_fallback` in `resolver.rs`.
   - SSH → `ssh git@host git-bale-authenticate <owner>/<repo> <op>`. Identity-based; the SSH key already proved who the user is (no anonymous path — the transport needs a key). The ssh subprocess honors git's own ssh-command config — `GIT_SSH_COMMAND` env, else `core.sshCommand` (same precedence git uses) — so a custom key/port/`UserKnownHostsFile`/jump-host applies to the forge handshake exactly as it does to git's transport (`ssh_subprocess` in `resolver.rs` runs a configured command through `/bin/sh` with the auth args appended; unset falls back to bare `ssh`). This also keeps the e2e harness's isolated `UserKnownHostsFile` from being bypassed: ssh expands `~` for the default known-hosts file via `getpwuid`, *not* `$HOME`, so without honoring `GIT_SSH_COMMAND` the handshake would write the test server's host keys into the developer's real `~/.ssh/known_hosts`.
   - Both return `{href: <baleforgit-server URL>, header.Authorization: "Bearer <forge-minted JWT>"}`. For a public-repo anonymous download the JWT just carries an anonymous subject; the token-exchange + `check_access` flow is otherwise identical, so **baleforgit-server needs no notion of repo visibility** — the forge owns the public-vs-private decision.
4. **Token exchange**: `GET <baleforgit-server>/api/models/<owner>/<repo>/bale-{rw}-token/<rev>` with `Authorization: Bearer <forge-jwt>` → final bale token via the existing HF-Hub-shaped endpoint. Bale tokens are short-lived (`DEFAULT_TOKEN_TTL_SECS` = 5 min); every CAS client is built with a `ForgeTokenRefresher` that re-runs this resolution to re-mint before the token lapses — see *Tricky bits*.

Step 3's forge protocol is the only piece a forge integrator has to implement — see [`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md) for the wire shape. Combined with the existing `POST /check_access` callback that `bale-server-authz-http` already needs, that's the entire surface for "drop baleforgit-server in front of an existing git forge with no shared secrets".

### `git-bale mount-diff` and `git-bale mount`

Two read-only FUSE mounts share the same VFS, reader, and backend infrastructure; they differ only in the file set they expose.

`mount-diff` shows both sides of a `git diff` with the revision label folded into each basename (`foo__<revA>.txt`, `foo__<revB>.txt`). `mount` shows the full tree at one revision with original filenames intact — useful for browsing a tag or another branch without `git checkout`.

```
git-bale mount-diff <revA> <revB> --mount <dir> \
  [--label-a NAME] [--label-b NAME] [-- <paths>...]
git-bale mount      <rev>         --mount <dir> [-- <paths>...]
```

Neither copies bytes to disk: reads stream out of git's object database (for non-Bale blobs) and the chunk cache / network reconstruction (for Bale pointers). The cold-path reconstruction also backfills `.git/bale/manifests/` so the next mount of the same content is purely local.

Layout (`crates/git-bale/src/mount/`):

- `mod.rs` — CLI entry, label sanitisation, lifecycle. Two entry points: `run` for diff mode, `run_rev` for single-rev mode. `run_rev` opens an `Arc<gix::ThreadSafeRepository>`, resolves the rev to a tree OID, and hands both to the lazy VFS — no tree walk at mount time. A single root `readdir` runs eagerly so an empty / mis-targeted mount errors out with a clear message rather than mounting silently empty.
- `diff.rs` — pure-Rust diff via `gix` (no `git` subprocess): `rev_parse_single` + `tree.changes().for_each_to_obtain_tree`. Rename tracking is **disabled** (`options.track_rewrites(None)`) to skip the post-walk O(N²) similarity pass — see the limitation note below. The pathspec is applied inside the callback against the `BStr` location so non-matching changes don't allocate OID / path strings.
- `vfs.rs` — inode tree, inode 1 = root. Two builders: `build` (diff mode, labels appended, fully populated up front) and `build_single_lazy` (single-rev mode, names verbatim, directories resolved against their gix tree object on first `lookup_child`/`readdir`). Lazy directories carry the unresolved `tree_oid` + repo-relative `path_prefix` so pathspec filters can prune sibling subtrees without reading their tree objects. Inodes are stable for the life of the mount, memoized per `(parent, name)`. Directories are deduplicated; first-write-wins on collision. Internal state lives behind a single `Mutex` — coarse but fine for the parallel FUSE op load; populating a lazy directory is one ODB read while the lock is held.
- `reader.rs` — byte source. Plain blobs are pulled from the ODB via `gix::find_object` and cached fully (capped at 16 MiB per blob). Bale pointers go through the same cache-first / network-fallback reconstruction as the smudge filter, with a bounded in-memory LRU of decompressed file bodies (1 GiB default budget).
- `backend/mod.rs` — `MountBackend` trait plus the two path→node helpers (`cstr_to_path`, `lookup_path`) both backends share. Exactly one backend compiles per target; `mount/mod.rs` reaches it through the `PlatformBackend` / `ensure_available` aliases re-exported here (`libfuse` on unix, `winfsp` on Windows). fuse-t (macFUSE-free macOS) already rides the libfuse path; NFS could slot in without touching the VFS.
- `backend/libfuse.rs` (unix) — hand-rolled FFI to libfuse **2.x**'s high-level API (`fuse_main_real` + `struct fuse_operations`). libfuse is loaded with `libloading` at runtime, *not* linked at build time — workspaces without libfuse still build. On Linux that's `libfuse.so.2` (`libfuse2` / `fuse-libs` / `fuse2` depending on distro); on macOS that's `libfuse-t.dylib` (fuse-t's userspace shim, no kext). Picking 2.x for both platforms is what lets one binding work everywhere: fuse-t reports itself as `FUSE library version: 2.9.9`, and a libfuse-3-shaped `fuse_operations` shifts every slot after `readlink` because 2.x has `getdir` (slot 2) and `utime` (slot 13) that 3 dropped — fuse-t then reads our `op_open` as `truncate`, finds NULL where `open`/`read` should be, and silently returns EIO from its default handler. Cache hints that 3.x would set via `fuse_config` in `init` are passed as `-o` options instead (`use_ino,kernel_cache,attr_timeout=30,entry_timeout=30`). Mounts foreground (`-f`), read-only (`-o ro`), and lets libfuse run callbacks on multiple threads. `fuse_main_real` installs its own SIGINT/SIGTERM handlers, so Ctrl-C cleanly unmounts. The `ensure_available` probe runs first thing in `run`/`run_rev`; if libfuse fails to load the user gets a multi-line install hint and the process exits without doing any other work.
- `backend/winfsp.rs` (Windows) — the analogue against [WinFsp](https://winfsp.dev/)'s FUSE-compat layer, `winfsp-x64.dll` (`-a64`/`-x86` on other arches), again dlopened via `libloading` (no SDK at build time), located on PATH or under `%ProgramFiles*%\WinFsp\bin`. The entry point is `fsp_fuse_main_real(env, …)` — libfuse's `fuse_main_real` plus a leading `struct fsp_fuse_env *` that the C header would synthesize via `fsp_fuse_env()`; we build that env ourselves (CRT `malloc`/`free`, no-op `daemonize`/`set_signal_handlers`, the rest NULL). WinFsp's `struct fuse_operations` is a single version-independent layout transcribed verbatim from `fuse.h` and is **not** the libfuse 2.x layout: `getdir` is slot 1 / `readlink` slot 2, offsets use WinFsp's i64 `fuse_off_t`, and `getattr`/`read` use WinFsp's own `struct fuse_stat` / `struct fuse_file_info` (Win64 field widths reproduced exactly with `#[repr(C)]`), not the platform `stat`. We pass `opsize = size_of::<fuse_operations>()` so WinFsp reads the full struct; unused slots are NULL. argv is `["-f", "-o", "uid=-1,gid=-1", <mountpoint>]` — `<mountpoint>` is a free drive letter (`X:`) or a non-existent directory, not a pre-existing dir (so the unix `exists`/`is_dir` precheck is skipped). Files are reported world-readable (dirs `0555`, files `0444`); WinFsp maps the POSIX "other" bits to an Everyone ACE, so the mounting user can read regardless of the uid/gid we report. `ensure_available` only checks that the user-mode DLL loads — the WinFsp **kernel driver** must also be installed, which surfaces as a non-zero `fsp_fuse_main_real` return rather than at probe time. Ctrl-C terminates the process and WinFsp's driver tears the volume down (no in-process signal handler).

Tricky bits:

- **`getattr` never reconstructs.** Bale pointers carry `file_size` in their JSON, so a `stat` just reads the pointer blob from the ODB and parses the few hundred bytes — no chunks expanded, no network. Plain blobs report ODB blob length. Reconstruction (cache + possibly network) is deferred until the first actual `read`.
- **Path-based libfuse API.** The high-level API hands callbacks paths, not inodes. We walk slash components against the in-memory dir tree on every call. Fine for diffs in the low-thousands of entries; bigger trees should move to `fuse_lowlevel_ops` (inode-native).
- **Lazy single-rev mounts hold the repo handle for the life of the mount.** Each first-touch of a directory issues one `find_object(tree_oid)` against the ODB and populates that directory's children. The commit (and therefore every reachable tree) is immutable, so there is no invalidation — the populated children just stay cached until the FUSE process exits. `mount-diff` is still eager because the diff result is already bounded by the changeset.
- **Active-VFS singleton.** libfuse's path callbacks don't get user-data, so we stash `Arc<DiffVfs>` in a `OnceLock`. One mount per process — a second mount in the same process is rejected. The WinFsp backend does the same with its own `OnceLock`.
- **WinFsp's `fuse_operations` is not libfuse 2.x's.** The Windows backend looks like a copy of `libfuse.rs` but the struct layouts differ and must not be cross-pasted: WinFsp has one version-independent `fuse_operations` (`getdir` at slot 1, `readlink` slot 2), uses i64 `fuse_off_t` everywhere, and `getattr`/`read` take WinFsp's own `struct fuse_stat` / `struct fuse_file_info` (where `fh_old` is a 32-bit `unsigned int`, so `fh` sits at offset 16, vs libfuse's 24). Get a width or slot wrong and reads silently corrupt or the handle round-trip lands on garbage. The widths are transcribed from WinFsp's `inc/fuse/*.h`; `#[repr(C)]` reproduces the C padding. Untested on real hardware in CI — verified only to compile + lint clean for `x86_64-pc-windows-gnu`.
- **Per-open file handles.** `op_open` calls `Reader::open(source)`, which reconstructs once into a `NamedTempFile`. If the result fits the LRU budget it is slurped into `Bytes` and cached; otherwise the tempfile stays alive for the open and `op_read` serves bytes via `pread`. The handle id rides in `fi.fh`; `op_release` drops the handle (tempfile unlinks on Drop). Without this, files larger than the 1 GiB LRU budget would re-run the full reconstruction pipeline on every 128 KiB FUSE read.
- **No working-tree comparisons.** Both modes operate on committed revisions only. Adding worktree support means rebuilding the VFS when the index moves; punted.

Limitation:

- **`mount-diff` does not pair renames.** Rename tracking is turned off at the gix diff platform. A renamed file shows up as a deletion at the old path (visible only on side A as `name__<labelA>.ext`) and an addition at the new path (visible only on side B as `name__<labelB>.ext`), *not* as a single labelled pair under a shared basename. The trade-off is the O(N²) similarity computation gix would otherwise run over every del/add pair after the walk — for diffs with thousands of changes that pass dominates the wall time. If you need rename-aware viewing for a small diff, fall back to `git difftool`.

## Storage layout

### Filesystem `BlobStore`

```
<data_root>/
├── xorbs/<aa>/<bb>/<full-hex>     # immutable xorb blobs, ≤ 64 MiB each
├── shards/<aa>/<bb>/<full-hex>    # archived shards (BLAKE3-keyed)
└── tmp/<uuid>                     # staging for atomic rename
```

`<aa>` / `<bb>` are bytes 0 / 1 of the hash in plain (not Xet) lowercase hex — just for sane directory fan-out, not exposed on the wire. Writes go through `tmp/<uuid>` then `rename(2)` for atomicity: a write/fsync failure removes the tmp and errors (never a half-written blob at the addressed path), and a concurrent same-content write converges (the `rename(2)` replaces or the pre-rename existence check returns early). Test-only: setting `BALE_TEST_FS_WRITE_FAIL` forces `write_atomic` to take the failure-cleanup arm on every write — there's no way to inject ENOSPC without putting `tmp/` on a different filesystem than `xorbs/` (which would break the same-fs rename on the happy path), so the e2e `failure-fs-writefail` phase uses this hook; it is inert in production (the var is never set).

### S3 `BlobStore`

Same key layout under an optional bucket-relative prefix:

```
<prefix>xorbs/<aa>/<bb>/<full-hex>
<prefix>shards/<aa>/<bb>/<full-hex>
```

Idempotency uses `HEAD`-before-`PUT` (a concurrent racer writing the same content-addressed bytes is benign). Reconstruction handlers call `presign_xorb_range` first — when `Some(url)` comes back the URL goes straight into `fetch_info` and the server is no longer in the data path. The S3 presigned URL signs the `Range:` header, so the client must send the exact range advertised in `url_range`. Because the client fetches that URL directly, its host must be one the **client** can reach — not necessarily the one the server uses. When they differ (a bundled MinIO the server reaches at `minio:9000` while clients need `localhost:9000`), set `BALE_S3_PUBLIC_ENDPOINT_URL`: `S3BlobStore` then keeps a second `presign_client` built against that endpoint and signs download URLs with it, while reads/writes stay on `endpoint_url`. Unset, presigning uses `endpoint_url` (correct for AWS S3 / R2 / B2 and any endpoint reachable by both). A mismatch here is invisible on push (server-side) and only surfaces as a client hang on checkout — DNS/connect failures to the unreachable host, retried per term.

### SQLite `MetadataStore` schema

```sql
xorbs       (hash BLOB PK, num_chunks, num_bytes_in_cas, num_bytes_on_disk, created_at)
chunks      (chunk_hash, xorb_hash, chunk_index, byte_start, unpacked_bytes)
              PK (chunk_hash, xorb_hash)
              INDEX (xorb_hash, chunk_index)
xorb_frames (xorb_hash, frame_index, on_disk_start, on_disk_len, uncompressed_len)
              PK (xorb_hash, frame_index)
files       (file_hash, repo_type, repo_id, revision, total_bytes, created_at, owner)
              PK (file_hash, repo_id)   -- composite: same content in N repos
              INDEX (repo_id), INDEX (owner)
file_terms  (file_hash, term_index, xorb_hash, chunk_idx_start, chunk_idx_end,
             unpacked_bytes, verification)
              PK (file_hash, term_index)
owner_quotas (owner TEXT PK, limit_bytes INTEGER NOT NULL)
```

`xorb_frames` is populated at upload time by `parse_xorb_frames` in `bale-server-shard`. It is the *only* source of truth for HTTP byte ranges — the `chunks` table records uncompressed offsets from the shard's CAS Info section, which don't match on-disk positions for any real LZ4-compressed xorb. See the "Tricky bits" note below.

`files` has a composite primary key on `(file_hash, repo_id)`. The same content can be registered in multiple repos (cross-repo dedup at the file level), and each registration independently grants read access via the per-repo scope check.

`files.owner` is the slice of `repo_id` before the first `/`, denormalised so quota and usage aggregations can hit the `files_by_owner` index instead of `LIKE 'alice/%'`. Populated at `register_file` time from `RepoRef::owner()` — there is no backfill or migration path, so a dev DB missing the `owner` column won't open and must be recreated from scratch.

This is the minimum needed to answer reconstruction queries, global-dedup queries, and per-owner accounting. Migrations run automatically on connection open (idempotent `CREATE TABLE IF NOT EXISTS ...`).

### Postgres `MetadataStore`

`bale-server-meta-postgres` is the same schema and the same queries ported to Postgres; it's selected when `BALE_POSTGRES_URL` is set (otherwise the server uses the local SQLite store). The portability the SQLite schema was designed for, made concrete. The dialect differences that matter:

- **Column types.** `BLOB` → `BYTEA`, `INTEGER` → `BIGINT` (every integer column binds an `i64`; Postgres `INTEGER` is 32-bit and would reject the wider binds).
- **Upserts.** `INSERT OR IGNORE` → `INSERT ... ON CONFLICT DO NOTHING`; `INSERT OR REPLACE INTO files` → `INSERT ... ON CONFLICT (file_hash, repo_id) DO UPDATE SET ...`. Same content-addressed idempotency. Note the `files` row is per-repo, but `file_terms` is **write-once per `file_hash`** (see *Tricky bits* — term lists are not canonical), so SQLite probes `SELECT 1 FROM file_terms` and Postgres takes a `pg_advisory_xact_lock` on the file hash before deciding to insert; the per-term conflict clause is only a backstop.
- **Placeholders.** `?` → `$1, $2, …` in the hand-written queries (`QueryBuilder` emits the right form for either driver automatically).
- **Aggregates.** Postgres widens `SUM` over a `bigint` column to `numeric`, which `try_get::<i64>` can't decode, so every `SUM(...)` in the accounting/quota queries is wrapped `COALESCE(SUM(...), 0)::BIGINT`. The cast also turns an 8-EiB overflow into a hard error rather than the silent wrap the `nonneg_i64_to_u64` guard catches on SQLite.
- **Migration concurrency.** Postgres `CREATE TABLE/INDEX IF NOT EXISTS` can race in `pg_catalog` when two server instances start at once, so the whole schema runs inside one transaction guarded by a `pg_advisory_xact_lock`. As with SQLite there is no backfill path — point it at an empty database (or one previously initialised by this server).

## Auth flow

Two layers:

1. **HF-Hub-shaped token endpoint** — accepts a hub-style bearer, calls `RepoAuthz::check_repo_access` + `RepoAuthz::mint_bale_token`, returns `{accessToken, exp, casUrl}`. The `casUrl` is the server's own `public_base_url`, so the client sends subsequent CAS calls right back to us.

2. **Bale token middleware** — wraps every `/v1/*` route. Verifies the `Authorization: Bearer <jwt>` via `RepoAuthz::verify_bale_token`, attaches `TokenClaims` to request extensions, and enforces scope by HTTP method (POST requires write; GET tolerates read). The transfer route `/xorb/default/...` and the token-issuance route `/api/...` are explicitly **outside** the middleware — the former uses signed URLs, the latter uses the hub bearer.

The binary (`bale-server-bin`) picks which `RepoAuthz` impl to wire in at startup:

- `BALE_AUTHZ_HTTP_URL` set → `HttpAuthz` from `bale-server-authz-http`. Token mint/verify stays local; only `check_repo_access` is delegated.
- Otherwise → `ConfigAuthz` from `bale-server-authz-mem`, populated from the `BALE_GRANTS` env var. Intended for dev use — `AlwaysAllow` is a permissive variant that grants every request.

The `Service` struct is generic over the trait impls (`Arc<B>`/`Arc<M>`/`Arc<A>`, not `Arc<dyn ...>`) so the chosen impls get monomorphised at link time. The binary builds a separate `Service` per branch for that reason.

### Why JWTs (HS256) and not opaque tokens?

The verifier needs the user/repo/scope tuple on every request, and the issuer is the same process today, so a self-contained signed token saves us a DB round-trip per request. If/when a `RepoAuthz` impl needs to mint tokens out-of-process (issuer ≠ verifier), switching to RS256 is a one-line change in `bale-server-tokens`.

## Owner accounting and quotas

The server accounts storage usage per **owner** — the namespace before `/` in a `repo_id` (`alice/big-model` → `alice`). Forges that don't allow user/org name collisions can treat users and orgs uniformly; nothing in the server distinguishes them.

Two numbers, both queryable by `GET /v1/usage/{owner}` (which returns JSON `{owner, raw_bytes, stored_bytes, dedup_savings_bytes, quota_bytes}`):

- **`raw_bytes`** — `SUM(files.total_bytes)` for the owner. Each file's `total_bytes` is the sum of its terms' `unpacked_segment_bytes`, recorded at `register_file` time. This is the "no-dedup baseline" the UI shows when illustrating savings.
- **`stored_bytes`** — `SUM(num_bytes_on_disk)` over the distinct xorbs that any of the owner's files reference. **No cross-owner accounting**: a xorb that two owners both reference is counted once for each of them, so an owner's stored-bytes never depends on what another owner does or doesn't push. This matches the demo story ("here's what's actually on disk for me") and keeps quota enforcement stable under cross-owner activity.

`dedup_savings_bytes = raw_bytes - stored_bytes`.

`GET /v1/usage/repo/{owner}/{repo}` returns `{repo_id, raw_bytes, stored_bytes, dedup_savings_bytes, exclusive_bytes}` (no quota field — quotas are owner-scoped) keyed by full `repo_id`. The intended consumer is a per-repo settings page in a forge: `raw_bytes` is the "this repo's total size" to surface to the user, ignoring chunk-level dedup with sibling repos. `stored_bytes` is the on-disk cost of every xorb the repo references, but sibling repos can share xorbs, so it double-counts shared storage and a repo's "stored" cost in isolation is somewhat fictional. **`exclusive_bytes`** is the genuinely-per-repo number: `SUM(num_bytes_on_disk)` over the xorbs this repo's files reference *minus* those referenced by another repo **of the same owner** — i.e. how much the owner's `stored_bytes` would drop if this repo were deleted. Cross-owner sharing is deliberately ignored, mirroring the owner-independent accounting above (a xorb shared only across owners still counts in full for each, so it's exclusive to this repo within its owner's world). It's always `<= stored_bytes`; the gap is storage shared with sibling repos. Same auth rule as the owner endpoint.

### Quota enforcement

Quotas are **soft** — under concurrent uploads two writers can both pass the check then both succeed, slightly overshooting. That tradeoff buys us no extra locking on the hot path. Two enforcement points:

1. **At `POST /v1/xorbs/{prefix}/{hash}`**: if the xorb already exists in CAS, the call is content-addressed-idempotent and skipped — re-pushes never reject. Otherwise we conservatively check `stored_bytes_for_owner + body.len() ≤ quota` and 429 on miss. This blocks the obvious "upload terabytes" failure mode at the door.
2. **At `POST /shards`**: after xorb metadata is registered but *before* `register_files` (the atomic batch), we compute the projected post-commit stored bytes — current stored plus the on-disk sizes of xorbs the owner doesn't already reference (`unaccounted_xorb_bytes_for_owner`). 429 on miss, and `register_files` never runs, so no file rows are left behind.

The second check is load-bearing because the first one's "skip if exists" shortcut would otherwise let an owner gain attributable bytes by referencing someone else's xorb without paying.

### Configuration

`BALE_DEFAULT_QUOTA_BYTES` sets the fallback limit applied when no per-owner override exists. Per-owner overrides (set via `PUT /v1/quotas/{owner}`) take precedence; `null` clears the override and falls back to the default. If neither is set, the owner is unlimited.

Over-quota uploads reject with **429 Too Many Requests** (not 413): a 413 reads to clients as "this one request's body is too big", but over-quota is an account-state condition, so 429 with a `quota exceeded` message names it explicitly. Caveat: xet treats 429 as transient and retries it to exhaustion before surfacing the error, so an over-quota push takes a while to fail and the error chain is long — `git-bale`'s `explain_quota_exceeded` collapses it to a single user-facing line.

The admin endpoint is gated by `BALE_ADMIN_TOKEN_HEX` (a 64-char hex string decoding to 32 bytes). When unset, the route returns 404 — the wire surface advertises that admin is disabled rather than 401-ing. Comparison is constant-time. The admin bearer is **not** a Bale JWT and the endpoint sits outside the JWT middleware.

`GET /v1/usage/{owner}` accepts either a Bale JWT scoped to the owner (the token's `repo.owner()` slice must equal the URL segment, so an `alice/x` token can't enumerate bob's usage) or the admin bearer (which bypasses the scope check so an operator dashboard can read every owner). The handler does this auth inline rather than going through the JWT middleware, so the admin bearer doesn't have to be a valid JWT.

## Signed transfer URLs

The reconstruction handler embeds URLs of the form

```
{public_base_url}/xorb/default/{xorb_hex}?s={start}&e={end_inclusive}&x={unix_exp}&sig={hmac_sha256_hex}
```

The signature covers `xorb_hex | start | end_inclusive | exp` (concatenated with `|`). The transfer handler enforces:

- the signature is valid (constant-time compare),
- the expiry hasn't passed,
- the `Range:` header is present and matches the signed range exactly.

Missing or non-matching `Range:` returns 401 — per the spec, this is required ("Not specifying this header will result in an authorization failure") so the URL grants access to a specific byte range, not the whole xorb.

## Observability

The server's instrumentation is OpenTelemetry-based and **gated on `OTEL_EXPORTER_OTLP_ENDPOINT`** (or per-signal sibling). With the env unset, `telemetry::init` skips the SDK entirely — no provider is registered against `opentelemetry::global`, so every `meter(...).u64_counter(...).build().add(...)` in the request path resolves to the global no-op. That's how the "do nothing when no collector is running" contract is honoured: no background threads, no socket open, no per-request cost beyond a function call.

When set, the bin installs:

- An OTLP HTTP/protobuf **`SdkTracerProvider`** with a `BatchSpanProcessor`. The tracing-opentelemetry layer is wired into the `tracing_subscriber` registry, so the existing `tower_http::trace` access-log span (and any `tracing::info_span!` inside handlers) flow through as OTel spans.
- An OTLP HTTP/protobuf **`SdkMeterProvider`** with a `PeriodicReader`. The HTTP crate defines its instruments lazily via `LazyLock<Counter<_>>` so they're constructed against whichever provider was installed at init time.

Per-request metering lives in `crates/bale-server-http/src/metrics.rs` and is wired via an axum `middleware::from_fn` layer. It reads the matched route pattern out of `MatchedPath` (NOT the raw URI) before labelling — without that bound, a label like `/v1/xorbs/default/{hash}` would explode into one series per xorb hash and bury the metric backend.

Both processors export from their own dedicated OS thread (`OpenTelemetry.Traces.BatchProcessor` / `…Metrics.PeriodicReader`), *not* from a Tokio worker. Those threads have no async reactor, so `opentelemetry-otlp` is built with the **blocking** reqwest client (`reqwest-blocking-client`); the async client panics there with "no reactor running" and silently drops all telemetry. Blocking I/O on those threads is fine — export is off the request path, so it can't stall request handling. (The `rt-tokio` feature on `opentelemetry_sdk` is currently unused; switching to the async client would mean adopting the `experimental_async_runtime` span-processor/reader variants and accepting their shutdown-in-`Drop` fragility — not worth it.)

A `Guard` returned from `telemetry::init` flushes both providers on drop, so a SIGINT-triggered graceful shutdown still ships the trailing spans/metrics to the collector before the process exits.

See [`SERVER.md` § "Observability"](SERVER.md#observability) for the operator-facing env vars and the instrument-name list.

## Tricky bits

These are the easy-to-get-wrong parts of the protocol. Calling them out explicitly so they don't get re-broken.

- **Xet hash hex encoding** (spec §"Converting Hashes to Strings"). Not plain hex. Bytes are reordered as four little-endian u64s before stringifying. The spec text shows a doc-typo example missing one byte; the actual algorithm produces 64 hex chars from 32 input bytes. See `bale_server_wire::{encode_hash, decode_hash}`.
- **Shard upload validation** — every xorb referenced by an uploaded shard MUST already be in the `xorbs` table (we return 400 otherwise). Per-term `FileVerificationEntry` MUST be present (spec says "MUST be set for shard uploads"). Per-term `chunk_idx_start < chunk_idx_end` is checked at the trust boundary — an empty/inverted range used to underflow `chunk_idx_end - 1` at reconstruction time and crash the request task; now rejected with 400 before any metadata write, plus a defensive `start >= end` guard at both reconstruction sites. We can additionally re-verify by recomputing the term verification hash against the chunk hashes we already indexed — *not done yet*; tracked as a hardening TODO.
- **Write ordering across the two stores** — both upload handlers commit metadata-first, then blob-store:
    - **`POST /v1/xorbs/...`** writes `register_xorb_layout` BEFORE `put_xorb`. A layout row with no backing blob is harmless: the next shard upload's `blobs.xorb_exists` check rejects with 400 (`missing xorb`), the same "metadata says yes, blob says no" shape the global-dedup path already tolerates. The inverse — blob with no layout — used to wedge every file referencing that xorb permanently (reconstruction returns 500 "xorb on-disk layout missing"), so that direction is now explicitly forbidden.
    - **`POST /shards`** writes `put_shard` first (content-addressed archive, inert without metadata pointing at it — orphan archive is GC-able and recoverable on retry), then registers all xorb metadata, then commits every file in a SINGLE atomic batch via `register_files`. A partial fault inside the batch rolls back the whole shard; the client's "500 ⇒ nothing happened" mental model holds. The earlier per-file loop could leave the first N-1 file rows committed while the client believed the upload failed — those orphans were then reachable to anyone who knew the file hash.
- **`url_range.end` is inclusive** in the wire format (matches HTTP `Range:` semantics). The chunk-index `range.end` is **exclusive**. We translate carefully in `get_reconstruction`.
- **Idempotency** — `POST /v1/xorbs/{prefix}/{hash}` and `POST /shards` are content-addressed; re-uploading the same content MUST return 200, not error. `was_inserted: false` on the xorb side; `result: 0` on the shard side (we currently always return `1`; both are spec-defined "success — value is informational").
- **The server does decompress on `POST /v1/xorbs/...` (and only there).** Every chunk frame is decompressed via xet-core's `CompressionScheme` (None / LZ4-frame / BG4-LZ4) so the server can recompute each chunk's `compute_data_hash`, aggregate via `xorb_hash`, and compare to the URL hash. Mismatch → 400 before anything is persisted. This is the load-bearing integrity check that keeps a writer from corrupting the CAS by uploading bytes that don't match the content hash. Implemented in `bale_server_shard::xorb::verify_xorb_body`. Outside of this verification step, payload bytes are still treated as opaque: reconstruction streams raw xorb bytes through signed transfer URLs without touching the compressed payload.
- **Shard `byte_start` / `unpacked_segment_bytes` live in *uncompressed* coordinate space**, NOT on-disk bytes. The CAS Info section in an MDB shard records each chunk's offset within a *conceptual* uncompressed xorb (xet-core's `XorbChunkSequenceEntry::chunk_byte_range_start` accumulates `c.data.len()` pre-compression). On-disk byte ranges live separately in the `xorb_frames` table, populated by walking the chunk frame headers when a xorb is POSTed (`bale_server_shard::xorb::parse_xorb_frames`). Reconstruction MUST build `url_range` from `xorb_frames`, not from the shard-derived `chunks` table — using shard offsets gives wrong byte ranges for any real LZ4-compressed xorb.
- **A file's term list is NOT canonical, and `file_terms` is global — so term registration is write-once per `file_hash`.** `file_hash` is the merkle hash of the file's *content*, but how those chunks are grouped into xorb-referencing terms depends on global dedup: a later clean that matches different pre-existing xorbs produces a different *number* of terms for byte-identical content. `file_terms` is keyed `(file_hash, term_index)` with no repo column (it's shared across repos), so a naive per-term `INSERT OR IGNORE`/`ON CONFLICT DO NOTHING` *merges* two differently-segmented registrations: it keeps the old terms where indices collide and appends the longer list's tail, leaving `Σ unpacked_bytes > file_size`. That over-describing list is silently fatal — on reconstruction with a cold client cache, xet's "trim the last term to the query range" step computes `last_term_shrinkage = Σterms − file_size`, subtracts it from the final term's byte range, underflows `u64`, and `slice`-panics the client (`FileTerm::extract_bytes`, seen as `range end out of bounds: ~2^64`). The fix: register the term set **write-once** — if any term row exists for the hash, leave it (the first complete list fully describes the content). SQLite relies on its single-writer transaction; Postgres (READ COMMITTED) takes a `pg_advisory_xact_lock` on the hash so two concurrent first-registrations can't both insert. Defense in depth: `lookup_file` re-checks `Σ terms == files.total_bytes` and returns 500 rather than serve an inconsistent reconstruction (this also fails closed for legacy merged rows written before the fix — re-register the file to repair). See `write_file_in_tx` in both meta stores.
- **`FileMetadataExt.sha256` is stored in xet-core's byte-reversed-within-u64-groups order**, not natural sha256 byte order. xet-core treats every `Hash32`-shaped field uniformly as `[u64; 4]` and writes LE u64s, even for sha256 (which has no semantic reason to be reordered). The shard parser un-swaps with `swap_u64_groups` so `ParsedFile.sha256` matches the standard byte order; the serializer applies the inverse swap on the way out.
- **Chunk frame format** (8-byte `XorbChunkHeader`): `version(u8) | compressed_length(u24 LE) | compression_scheme(u8) | uncompressed_length(u24 LE)`. Schemes: 0=None, 1=LZ4 frame, 2=BG4-LZ4 (byte-group-of-4 deinterleave then LZ4 frame). Scheme 99 (Auto) is a sentinel and must never appear on the wire. baleforgit-server only parses the header (for byte-range layout) and never touches payloads.
- **64 MiB limits** on both xorbs and shards — enforced via `DefaultBodyLimit`.
- **Shard magic tag** — the 32-byte `MDB_SHARD_HEADER_TAG` is `b"HFRepoMetaData" + [0, 85, 105, 103, 69, 106, 123, 129, 87, 131, 165, 189, 217, 92, 205, 209, 74, 169]`, lifted verbatim from xet-core's `mdb_shard::shard_format::MDB_SHARD_HEADER_TAG` at the `git-xet-v0.2.1` tag. Our parser still accepts any 32-byte tag (so shards from older toolchains round-trip), but the serializer emits this canonical value so xet-core's strict header check accepts what we produce.
- **Token `exp` is UTC unix seconds and is compared against the *local* clock — client and server clocks must agree (NTP).** Tokens are short-lived (`DEFAULT_TOKEN_TTL_SECS` = 5 min, UTC, in `bale-server-authz-{mem,http}`). xet's `TokenProvider` checks `expiration <= local_now + 30s` and, when true, calls the token refresher. git-bale supplies `resolver::ForgeTokenRefresher`, which re-runs the full forge resolution (`resolve`) to re-mint — wired into **every** CAS client (`push-pending`, the cold smudge path, `mount`, and `fetch_manifest`) via `resolver::forge_refresher(raw, scope)`. This is what lets a single operation outlive one token's TTL, and why a 5-minute TTL is safe. The failure mode it does **not** paper over is clock skew: the server mints `exp` on *its* clock, so if the client's clock runs more than the TTL ahead of the server's, a freshly minted, server-valid token looks already-expired on arrival and re-minting just yields another equally-"expired" one. To avoid storming the forge forever, `ForgeTokenRefresher` counts consecutive re-mints that come back already-expired (within xet's 30 s `REFRESH_BUFFER_SEC`) and, after `MAX_EXPIRED_REFRESHES` (3), fails with an explicit "clocks differ by more than the TTL — sync clocks (NTP)" error instead. This bit hard under podman on macOS, whose VM clock lags the host after sleep — keep the server's clock NTP-synced. The old `ErrTokenRefresher` (no refresher wired up) turned the very first tripped check into a hard `RefreshFunctionNotCallable` error with no recovery.
- **A per-repo local store (`.git/bale/store`) is NOT carried by `git clone`.** `git clone` copies the object database and refs, not `.git/bale/`. A clone of a repo with a per-repo store cannot reconstruct its Bale-tracked files: the store is on the original machine only. Use `--shared` (store at `~/bale-local`) when you need multiple working copies on one machine.
- **The clean store lock is per-file (brief), and gc skips on `index.lock` — do NOT "fix" this by holding the clean lock longer.** Two windows must both be closed: object-vs-marker (clean writes objects then marker) and marker-vs-index (git updates its on-disk index *after* the filter returns, so a marker can exist before git references it). A tempting fix is to hold the clean lock across the whole filter-process lifetime so gc stays blocked until git finishes the add — but that **deadlocks**: a git porcelain op (`git stash`, `git commit -a`) keeps the long-running filter alive holding the lock, then nests another `git` that invokes clean, which blocks on the lock the outer filter holds while the outer op waits for the inner one. (Confirmed: it hung the `offline-no-network` e2e phase.) The correct split is a *brief per-file* lock (object-vs-marker) plus gc *deferring while a git index/ref update is in flight* (marker-vs-index, `crate::gc::git_op_in_flight` — checked after taking the store lock). Don't narrow `git_op_in_flight` back to just the main `index.lock`: `git stash` cleans against a *temporary* index, so the main `index.lock` is absent and the stash window would reopen (it must also see `index.<temp>.lock` / `refs/stash.lock`). The `local-clean-gc-race` and `local-cache-hit-gc-race` e2e phases (using `BALE_TEST_CLEAN_MARKER_DELAY_MS` / `BALE_TEST_CLEAN_CACHE_HIT_DELAY_MS` to widen the windows) prove both, and `local-concurrent-stress` checks no deadlock. See `crate::store::StoreLock`, `crate::gc::git_op_in_flight`, and the store-lock paragraph in the Fully-local mode section.
- **Dedup-shard footer lookup offsets must be non-zero even with no lookup tables.** `get_dedup_chunk`'s shard omits the file/xorb/chunk lookup tables (`*_num_entry = 0`), but `serialize` must still write each lookup *offset* as `footer_offset` (the section end), not 0. The client runs `read_all_truncated_hashes` on every dedup shard it ingests into its `ShardFileManager`; for a table-less shard it computes the xorb-info byte range as `(xorb_info_offset, file_lookup_offset)` and a 0 there underflows `file_lookup_offset - xorb_info_offset` → panic (debug) / multi-exabyte alloc → OOM (release), killing the push. xet's own serializer sets the offset even when the table is absent; we match it. Guarded by the `global-dedup-shard` e2e phase.

## Where to look in the code

Server side:

| Concern | File |
|---------|------|
| Trait definitions | `crates/bale-server-core/src/lib.rs` |
| Hex encoding + JSON wire types | `crates/bale-server-wire/src/lib.rs` |
| MDB shard binary parser/serializer | `crates/bale-server-shard/src/lib.rs` |
| Xorb chunk-frame parser (on-disk layout) | `crates/bale-server-shard/src/xorb.rs` |
| Filesystem blob store | `crates/bale-server-storage-fs/src/lib.rs` |
| In-memory blob store (pluggability) | `crates/bale-server-storage-mem/src/lib.rs` |
| S3-compatible blob store | `crates/bale-server-storage-s3/src/lib.rs` |
| SQLite metadata store | `crates/bale-server-meta-sqlite/src/lib.rs` |
| Postgres metadata store | `crates/bale-server-meta-postgres/src/lib.rs` |
| Static authz (`AlwaysAllow`, `ConfigAuthz`) | `crates/bale-server-authz-mem/src/lib.rs` |
| HTTP-delegating authz (`HttpAuthz`) | `crates/bale-server-authz-http/src/lib.rs` |
| JWT mint/verify | `crates/bale-server-tokens/src/lib.rs` |
| Router, handlers, middleware, signed URLs | `crates/bale-server-http/src/lib.rs` |
| HTTP metrics middleware + handler counters | `crates/bale-server-http/src/metrics.rs` |
| OTLP traces + metrics init (gated on env) | `crates/bale-server-bin/src/telemetry.rs` |
| Binary launcher | `crates/bale-server-bin/src/main.rs` |
| End-to-end test harness | `tests/e2e/` |

Client side (`crates/git-bale/`):

| Concern | File |
|---------|------|
| `git-bale` CLI entry point | `crates/git-bale/src/main.rs` |
| Long-running filter-process loop | `crates/git-bale/src/filter_process.rs` |
| Pkt-line framing | `crates/git-bale/src/pktline.rs` |
| JSON pointer encode/decode | `crates/git-bale/src/pointer.rs` |
| Per-repo manifest cache (`.git/bale/manifests/`) | `crates/git-bale/src/manifest_cache.rs` |
| Pointer cache for `clean` (`.git/bale/clean-cache/`) | `crates/git-bale/src/clean_cache.rs` |
| Cache-only smudge fast path | `crates/git-bale/src/local_reconstruct.rs` |
| Cold-path manifest fetch | `crates/git-bale/src/remote_manifest.rs` |
| Config loader (env + `git config`) | `crates/git-bale/src/config.rs` |
| Remote URL parsing (http/https/ssh) | `crates/git-bale/src/remote.rs` |
| Forge auth resolver | `crates/git-bale/src/resolver.rs` |
| `git-bale install` / `git-bale uninstall` (+ pre-push / post-checkout / post-commit / post-merge hooks) | `crates/git-bale/src/install.rs` |
| `git-bale push-pending` (drain `.git/bale/staging/`) | `crates/git-bale/src/push_pending.rs` |
| `git-bale gc` (reconcile staging / local store against git reachability) | `crates/git-bale/src/gc.rs` |
| `git-bale prune --shared` (compact shared local store) | `crates/git-bale/src/prune.rs` |
| Object store root resolution + shared-store registry | `crates/git-bale/src/store.rs` |
| `git-bale init-local` (no-server setup) | `crates/git-bale/src/install.rs`, `src/store.rs` |
| Local staging-dir path + cleanup helpers | `crates/git-bale/src/staging.rs` |
| `git-bale track` (`.gitattributes` writer) | `crates/git-bale/src/track.rs` |
| `git-bale mount-diff` (read-only FUSE diff view) | `crates/git-bale/src/mount/` |
