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
   │   │ Azure (later) │    │ (later)   │      │ HttpAuthz (upstream)│  │
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

`Range:` request-side support on `/v1/reconstructions/*` is **not yet implemented** — the prototype always returns the full file's terms. Range support on the transfer URL itself is fully implemented (and mandatory, since signatures cover the byte range). The native `git-bale` smudge handler works around the missing range support by passing `0..file_size` to `xet-data` (see "Native filter" below).

### Global dedup

- Server stores `chunk_hash → xorb_hash` and a notion of "neighborhood" (the other chunks in the same xorb).
- On hit, server builds a synthetic shard whose CAS Info section lists that xorb (and up to `DEDUP_NEIGHBORHOOD` other xorbs) with each chunk hash wrapped as `HMAC-SHA256(per_response_key, chunk_hash)`.
- The per-response random key is written into the shard footer's `chunk_hash_hmac_key`. The client wraps its own candidate chunk hashes with the same key and looks for matches in the response.
- This is what makes Xet's dedup secure: clients can confirm "I have chunk X" without the server ever revealing the full set of chunk hashes it knows about.
- Handler lives at `get_dedup_chunk` in `bale-server-http`. Returns 404 if the chunk hash isn't indexed.

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
    // M12 scope check: true iff `file_hash` is registered in `repo_id`.
    async fn file_in_repo(&self, file_hash: &FileHash, repo_id: &str) -> CoreResult<bool>;
    async fn lookup_chunk(&self, chunk_hash: &ChunkHash) -> CoreResult<Option<ChunkLocation>>;
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
| `BlobStore` | `bale-server-storage-mem` | `MemBlobStore` — `RwLock<HashMap>`, used for tests and the M8 pluggability check |
| `BlobStore` | `bale-server-storage-s3` | `S3BlobStore` — AWS SDK against any S3-compatible API (AWS S3, MinIO, R2, B2); real presigned `GET` URLs returned from `presign_xorb_range`, so reconstruction bytes never flow through the server's HTTP layer |
| `MetadataStore` | `bale-server-meta-sqlite` | `SqliteMetadataStore` — runtime `sqlx` queries (no compile-time DB) |
| `RepoAuthz` | `bale-server-authz-mem` | `AlwaysAllow` (tests) and `ConfigAuthz` (static map of hub bearers → users → repo scopes) |
| `RepoAuthz` | `bale-server-authz-http` | `HttpAuthz` — delegates `check_repo_access` to a small `POST /check_access` upstream contract. The contract is intentionally generic: any service that knows about users and repos (a git forge, an identity provider, a custom proxy) can implement it. Bale token mint/verify stays local. |

### Planned implementations

- `MetadataStore` on Postgres (only required when we outgrow SQLite — the schema is portable).
- `RepoAuthz` that talks directly to a specific upstream's APIs (e.g. `/api/v4/user` + project-member lookups for a particular git forge), as an alternative to going through the generic `HttpAuthz` shim. Useful when bringing the access-decision logic in-process saves a hop, or when richer upstream concepts (groups, scopes, OAuth) don't fit cleanly behind the minimal `/check_access` contract.

## Wire surface

CAS API (all behind `RepoAuthz::verify_bale_token`):

| Method | Path | Scope | Purpose |
|--------|------|-------|---------|
| GET | `/v1/reconstructions/{file_id}` | read | File reconstruction metadata |
| GET | `/v1/chunks/{prefix}/{chunk_hash}` | read | Global dedup query |
| POST | `/v1/xorbs/default/{xorb_hash}` | write | Xorb upload (rejects with 413 if over the owner's quota) |
| POST | `/shards` | write | Shard upload + indexing (rejects with 413 if over the owner's quota) |
| GET | `/v1/usage/{owner}` | read or admin | Per-owner accounting — accepts either a Bale JWT scoped to the owner OR `BALE_ADMIN_TOKEN_HEX`. See "Owner accounting and quotas". |
| GET | `/v1/usage/repo/{owner}/{repo}` | read or admin | Per-repo accounting — same auth as `/v1/usage/{owner}` (token's `repo.owner()` must match `{owner}`, or admin bearer). Returns `{repo_id, raw_bytes, stored_bytes, dedup_savings_bytes}`. Unknown repos return zeros, not 404. |

Transfer URL (referenced from `fetch_info`, signed query string, no bearer required):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/xorb/default/{xorb_hash}?s=...&e=...&x=...&sig=...` | Byte-range fetch of a xorb |

Browser file download (outside the JWT middleware — bearer rides in the query string because browsers can't carry `Authorization` on a 302 follow):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/files/{file_id}?token=<forge-jwt>&repo=<owner/name>&filename=<name>` | Streams the reconstructed file. Forge (e.g. gitea) calls `check_repo_access` to validate the JWT against `repo`, then the M12 `file_in_repo` scope check runs locally (404 on miss). `filename` is honored for `Content-Disposition: attachment` only when its SHA-256 matches the `FilenameSHA256` claim in the JWT payload — caller-rewritten filenames on leaked URLs get 400. |

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
- **Deferred upload**: `git add` chunks and stages locally; `git push` (via a pre-push hook) is what actually moves bytes to the server.

Layout on disk:

```
<repo>/big.bin                          # worktree (one copy)
<repo>/.git/bale/manifests/<file_id>.json # per-file reconstruction terms
<repo>/.git/bale/staging/                 # pending xorbs+shards, drained by push-pending
<repo>/.git/bale/clean-cache/<blake3(path)> # path-keyed, chunked-verified pointer cache
~/.cache/bale/chunks/                     # shared chunk pool across repos
```

### Pointer cache (clean short-circuit)

`git status` and `git diff` invalidate git's stat cache for any worktree file whose mtime/size differs from the index entry, then re-run the configured filter to recompute the worktree's hash. For our filter that's full CDC + xorb building + shard write — ~1–2 s for a 30 MiB file. With `git status` invoked routinely by shells, IDEs, and prompts, this gets painful fast.

The clean filter keeps a per-repo pointer cache at `<git_dir>/bale/clean-cache/<blake3(pathname)>`. Each entry is JSON shaped:

```json
{ "v": 2, "size": 30000000, "chunks": [{ "start": 0, "end": 1048576, "hash": "..." }, ...], "pointer": "{...}\n" }
```

Verification order on every clean call:

1. **Drain pkt-line into a temp file.** No hashing during the read — the chunk index is the verification mechanism.
2. **Size check.** If `tmp.metadata().size` ≠ `entry.size`, the cache *can't* match — skip straight to the full clean. This is the cheapest possible negative signal.
3. **Chunked verify.** A small thread pool hashes file regions in 1 MiB chunks and compares to `entry.chunks`. The order is `[first, last, 3 random middle samples, rest]` — edits cluster at file head/tail in practice (headers, appended log lines), so this catches the majority of mismatches in the first two reads. All workers share an `AtomicBool` and exit early as soon as any chunk diverges.
4. **All chunks match** → write `entry.pointer` back to git and return.

On miss, the full clean runs as before, then a fresh chunk index is computed from the temp file and saved. Cache hits stay side-effect-free (no staging touch, no marker touch), so a stale cache after `push-pending` drained staging just means future smudges fall to the cold path, which is correct.

**Smudge populates the cache too.** Every successful smudge already has both inputs to the `clean(content) → pointer` mapping in hand: the pointer git just sent us as input, and the reconstructed bytes we just wrote to the temp file. We compute a chunk index against the temp file and save it under the smudge's pathname before responding to git. That makes `git checkout -- foo.bin` fast on the *next* `git status`: the worktree gets back to HEAD's content and the clean cache simultaneously learns its fingerprint, so the subsequent stat-cache-invalidated clean call hits instead of full-cleaning HEAD's content from scratch.

Entries are ~70 bytes per chunk; a 30 MiB file is ~30 chunks = ~2 KiB on disk. No eviction; manual reset is `rm -rf .git/bale/clean-cache/`.

Two filter-process startup optimisations matter specifically because `git diff` pays them on every invocation (one filter-process per command):

- `RawConfig::load` issues a single `git config --null --get-regexp '^bale\\.'` to fetch every `bale.*` key in one fork+exec, instead of four `git config --get` calls. Saves ~15–60 ms.
- `XetRuntime::new()` is lazy. Its worker-thread stack allocations (8 MiB × n threads) aren't needed on a cache hit, so we hold an `Option<Arc<XetRuntime>>` and only fill it when the clean miss path or any smudge actually calls `bridge_sync`. Saves another ~20–50 ms on the cache-hit path.

### Deferred upload and `push-pending`

`clean` (driven by `git add` / `git commit`) does not touch the network. It builds a `FileUploadSession` via `TranslatorConfig::local_config(<git_dir>/bale/staging/)`, which routes xet-data through `LocalClient` — xorbs land at `…/xet/xorbs/xorbs/default.<hex>` and shards at `…/xet/xorbs/shards/<hex>.mdb`. The pointer Git stores is identical to the synchronous-upload flow; only the upload is deferred. Authentication is **not** resolved during clean (no `git credential fill`, no forge auth roundtrip), so `git add` works on a fully offline laptop.

`git-bale push-pending` is the drain step. It:

1. Walks the staging tree for `default.<hex>` (xorbs) and `<hex>.mdb` (shards).
2. Resolves write-scoped auth via the standard forge protocol.
3. POSTs each xorb to `/v1/xorbs/default/{hash}` and each shard to `/shards`. Xorbs go first because `/shards` rejects shards referencing unknown xorbs.
4. Strips the lookup tables + footer from each shard before upload by truncating to `MDBShardFile.shard.metadata.file_lookup_offset` and rewriting the header's `footer_size` field to 0 — same algorithm as xet-data's private `read_shard_to_bytes_remove_footer`. Without this step the bale shard parser sees lookup bytes where it expects either the cas-info bookend or the footer, and 400s.
5. Deletes each local file on 2xx and best-effort `rmdir`s now-empty directories. Re-running after a partial failure is safe because both endpoints are content-addressed and idempotent (`was_inserted: false` on a repeat xorb, `result: 0` on a repeat shard).

`git-bale install --local` writes a `.git/hooks/pre-push` that just `exec`s `git-bale push-pending`. The hook carries a `bale-marker:` line so `git-bale uninstall --local` removes it without clobbering a hand-written hook. Global / system-scope installs don't touch the hook — hooks are inherently per-repo. The hook path comes from `git rev-parse --git-path hooks/pre-push` so worktrees and `core.hooksPath` overrides resolve correctly.

### Hot vs lukewarm vs cold smudge

On `command=smudge` (filter sees a pointer, must reconstruct), git-bale tries three paths in order, falling through on failure:

1. **Hot path** — cache-only reconstruction:
   1. Load `.git/bale/manifests/<file_id>.json`. Returns `None` for missing / malformed / unknown-version manifests — all three trigger the next path.
   2. For each cached term, ask the local chunk cache (`xet-client::chunk_cache`) for the chunk range. Any miss → fall through.
   3. Concatenate the chunk bytes into a temp file. Length checks guard against stale manifests corrupting the worktree.
2. **Lukewarm path** — staging-dir reconstruction. After `git add` but before `git-bale push-pending`, the xorbs/shards are still under `.git/bale/staging/`. We open a `FileDownloadSession` against `TranslatorConfig::local_config(<git_dir>/bale/staging/)` and call `download_to_writer(info, 0..file_size, dest)`. Any error (missing xorb, missing shard, post-push-pending empty tree) is logged at `debug` and we fall through. This keeps `git add big.bin && rm big.bin && git checkout -- big.bin` working before the user has pushed. Gated on a per-file marker `<staging>/file-index/<file_hex>` written by `clean` — without it, smudges for file hashes we never staged (e.g. `git stash`'s HEAD-restore phase) drop into xet-data's `ReconstructionTermManager`, return zero terms, and trip a `debug_assert_eq!` in its progress tracker that calls `update_item_size(0, true)` after a previous `update_item_size(file_size, true)` already finalized the size. Release builds drop the assert; dev builds panic. `push-pending` clears the markers after a successful drain so they don't outlive the staged bytes.
3. **Cold path** — `FileDownloadSession::download_to_writer` against the remote bale server, same code path xet-core uses for HF-Hub-hosted Xet content. As a side effect, it also writes the manifest to `.git/bale/manifests/` so subsequent checkouts go through the hot path. The manifest stores only content-addressed `terms` (xorb hash + chunk-index range), **not** `fetch_info` URLs — those signed URLs expire after `SIGNATURE_TTL_SECS` (10 min) and aren't safe to persist.

Critical detail: the cold path passes `0..file_size` (not `FileRange::full()`, which xet-core defaults to) to `download_to_writer`. baleforgit-server has no Range support on `/v1/reconstructions/*`, and xet-data's prefetcher fans out to up to 256 MiB beyond EOF when given an unbounded range — every prefetched block then re-fetches the full file terms and trips xet-data's `SequentialWriter` contiguity check. The cap keeps the prefetcher quiet. Drives `m11_native_filter`.

### Auth resolution

`git-bale` deliberately holds no baleforgit-server secret of its own. Auth is resolved on first-use per scope (one resolution for write/clean, one for read/smudge, cached in the filter-process lifetime). The resolver lives in `crates/git-bale/src/resolver.rs`:

1. **Fast path**: if both `bale.serverUrl` and `bale.token` are set in local git config (or `BALE_SERVER_URL` / `BALE_TOKEN` env), use them as-is. This is the `m11` test path and the "I'm running my own forge and just want a static service token" mode.
2. **Remote parse**: `git remote get-url origin` → HTTP(S) or SSH `RemoteUrl` (scp-style `git@host:owner/repo.git` also supported).
3. **Forge authenticate**:
   - HTTPS → `POST {forge}/<owner>/<repo>.git/info/bale/authenticate?op=<download|upload>` with HTTPS Basic auth pulled from `git credential fill`. The user's password / PAT is verified inside the forge and never travels beyond it.
   - SSH → `ssh git@host git-bale-authenticate <owner>/<repo> <op>`. Identity-based; the SSH key already proved who the user is.
   - Both return `{href: <baleforgit-server URL>, header.Authorization: "Bearer <forge-minted JWT>"}`.
4. **Token exchange**: `GET <baleforgit-server>/api/models/<owner>/<repo>/bale-{rw}-token/<rev>` with `Authorization: Bearer <forge-jwt>` → final bale token via the existing HF-Hub-shaped endpoint.

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
- `backend/mod.rs` — `MountBackend` trait. Today there is one impl; fuse-t (macFUSE-free macOS), WinFsp (Windows), or NFS could slot in without touching the VFS.
- `backend/libfuse.rs` — hand-rolled FFI to libfuse **2.x**'s high-level API (`fuse_main_real` + `struct fuse_operations`). libfuse is loaded with `libloading` at runtime, *not* linked at build time — workspaces without libfuse still build. On Linux that's `libfuse.so.2` (`libfuse2` / `fuse-libs` / `fuse2` depending on distro); on macOS that's `libfuse-t.dylib` (fuse-t's userspace shim, no kext). Picking 2.x for both platforms is what lets one binding work everywhere: fuse-t reports itself as `FUSE library version: 2.9.9`, and a libfuse-3-shaped `fuse_operations` shifts every slot after `readlink` because 2.x has `getdir` (slot 2) and `utime` (slot 13) that 3 dropped — fuse-t then reads our `op_open` as `truncate`, finds NULL where `open`/`read` should be, and silently returns EIO from its default handler. Cache hints that 3.x would set via `fuse_config` in `init` are passed as `-o` options instead (`use_ino,kernel_cache,attr_timeout=30,entry_timeout=30`). Mounts foreground (`-f`), read-only (`-o ro`), and lets libfuse run callbacks on multiple threads. `fuse_main_real` installs its own SIGINT/SIGTERM handlers, so Ctrl-C cleanly unmounts. The `ensure_available` probe runs first thing in `run`/`run_rev`; if libfuse fails to load the user gets a multi-line install hint and the process exits without doing any other work.

Tricky bits:

- **`getattr` never reconstructs.** Bale pointers carry `file_size` in their JSON, so a `stat` just reads the pointer blob from the ODB and parses the few hundred bytes — no chunks expanded, no network. Plain blobs report ODB blob length. Reconstruction (cache + possibly network) is deferred until the first actual `read`.
- **Path-based libfuse API.** The high-level API hands callbacks paths, not inodes. We walk slash components against the in-memory dir tree on every call. Fine for diffs in the low-thousands of entries; bigger trees should move to `fuse_lowlevel_ops` (inode-native).
- **Lazy single-rev mounts hold the repo handle for the life of the mount.** Each first-touch of a directory issues one `find_object(tree_oid)` against the ODB and populates that directory's children. The commit (and therefore every reachable tree) is immutable, so there is no invalidation — the populated children just stay cached until the FUSE process exits. `mount-diff` is still eager because the diff result is already bounded by the changeset.
- **Active-VFS singleton.** libfuse's path callbacks don't get user-data, so we stash `Arc<DiffVfs>` in a `OnceLock`. One mount per process — a second mount in the same process is rejected.
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

`<aa>` / `<bb>` are bytes 0 / 1 of the hash in plain (not Xet) lowercase hex — just for sane directory fan-out, not exposed on the wire. Writes go through `tmp/<uuid>` then `rename(2)` for atomicity.

### S3 `BlobStore`

Same key layout under an optional bucket-relative prefix:

```
<prefix>xorbs/<aa>/<bb>/<full-hex>
<prefix>shards/<aa>/<bb>/<full-hex>
```

Idempotency uses `HEAD`-before-`PUT` (a concurrent racer writing the same content-addressed bytes is benign). Reconstruction handlers call `presign_xorb_range` first — when `Some(url)` comes back the URL goes straight into `fetch_info` and the server is no longer in the data path. The S3 presigned URL signs the `Range:` header, so the client must send the exact range advertised in `url_range`.

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

`files` has a composite primary key on `(file_hash, repo_id)`. The same content can be registered in multiple repos (cross-repo dedup at the file level), and each registration independently grants read access via the M12 scope check.

`files.owner` is the slice of `repo_id` before the first `/`, denormalised so quota and usage aggregations can hit the `files_by_owner` index instead of `LIKE 'alice/%'`. Populated at `register_file` time from `RepoRef::owner()` — there is no separate backfill or migration path, so existing dev DBs from before owner accounting will fail to open and should be deleted.

This is the minimum needed to answer reconstruction queries, global-dedup queries, and per-owner accounting. Migrations run automatically on connection open (idempotent `CREATE TABLE IF NOT EXISTS ...`).

## Auth flow

Two layers:

1. **HF-Hub-shaped token endpoint** — accepts a hub-style bearer, calls `RepoAuthz::check_repo_access` + `RepoAuthz::mint_bale_token`, returns `{accessToken, exp, casUrl}`. The `casUrl` is the server's own `public_base_url`, so the client sends subsequent CAS calls right back to us.

2. **Bale token middleware** — wraps every `/v1/*` route. Verifies the `Authorization: Bearer <jwt>` via `RepoAuthz::verify_bale_token`, attaches `TokenClaims` to request extensions, and enforces scope by HTTP method (POST requires write; GET tolerates read). The transfer route `/xorb/default/...` and the token-issuance route `/api/...` are explicitly **outside** the middleware — the former uses signed URLs, the latter uses the hub bearer.

The binary (`bale-server-bin`) picks which `RepoAuthz` impl to wire in at startup:

- `BALE_AUTHZ_HTTP_URL` set → `HttpAuthz` from `bale-server-authz-http`. Token mint/verify stays local; only `check_repo_access` is delegated.
- Otherwise → `ConfigAuthz` from `bale-server-authz-mem`, populated from the `BALE_GRANTS` env var. Intended for dev and integration tests only — `AlwaysAllow` is the test-only variant.

The `Service` struct is generic over the trait impls (`Arc<B>`/`Arc<M>`/`Arc<A>`, not `Arc<dyn ...>`) so the chosen impls get monomorphised at link time. The binary builds a separate `Service` per branch for that reason.

### Why JWTs (HS256) and not opaque tokens?

The verifier needs the user/repo/scope tuple on every request, and the issuer is the same process today, so a self-contained signed token saves us a DB round-trip per request. If/when a `RepoAuthz` impl needs to mint tokens out-of-process (issuer ≠ verifier), switching to RS256 is a one-line change in `bale-server-tokens`.

## Owner accounting and quotas

The server accounts storage usage per **owner** — the namespace before `/` in a `repo_id` (`alice/big-model` → `alice`). Forges that don't allow user/org name collisions can treat users and orgs uniformly; nothing in the server distinguishes them.

Two numbers, both queryable by `GET /v1/usage/{owner}` (which returns JSON `{owner, raw_bytes, stored_bytes, dedup_savings_bytes, quota_bytes}`):

- **`raw_bytes`** — `SUM(files.total_bytes)` for the owner. Each file's `total_bytes` is the sum of its terms' `unpacked_segment_bytes`, recorded at `register_file` time. This is the "no-dedup baseline" the UI shows when illustrating savings.
- **`stored_bytes`** — `SUM(num_bytes_on_disk)` over the distinct xorbs that any of the owner's files reference. **No cross-owner accounting**: a xorb that two owners both reference is counted once for each of them, so an owner's stored-bytes never depends on what another owner does or doesn't push. This matches the demo story ("here's what's actually on disk for me") and keeps quota enforcement stable under cross-owner activity.

`dedup_savings_bytes = raw_bytes - stored_bytes`.

`GET /v1/usage/repo/{owner}/{repo}` returns the same shape (minus the quota field) keyed by full `repo_id`. The intended consumer is a per-repo settings page in a forge: `raw_bytes` is the "this repo's total size" to surface to the user, ignoring chunk-level dedup with sibling repos. Stored-bytes is also returned but is generally less useful at the per-repo level — sibling repos under the same owner can share xorbs, so a repo's "stored" cost in isolation is somewhat fictional. Same auth rule as the owner endpoint.

### Quota enforcement

Quotas are **soft** — under concurrent uploads two writers can both pass the check then both succeed, slightly overshooting. That tradeoff buys us no extra locking on the hot path. Two enforcement points:

1. **At `POST /v1/xorbs/{prefix}/{hash}`**: if the xorb already exists in CAS, the call is content-addressed-idempotent and skipped — re-pushes never reject. Otherwise we conservatively check `stored_bytes_for_owner + body.len() ≤ quota` and 413 on miss. This blocks the obvious "upload terabytes" failure mode at the door.
2. **At `POST /shards`**: after xorb metadata is registered but *before* `register_files` (the atomic batch), we compute the projected post-commit stored bytes — current stored plus the on-disk sizes of xorbs the owner doesn't already reference (`unaccounted_xorb_bytes_for_owner`). 413 on miss, and `register_files` never runs, so no file rows are left behind.

The second check is load-bearing because the first one's "skip if exists" shortcut would otherwise let an owner gain attributable bytes by referencing someone else's xorb without paying. Drives `m13_quotas_and_usage::quota_blocks_at_shard_upload_for_cross_owner_dedup`.

### Configuration

`BALE_DEFAULT_QUOTA_BYTES` sets the fallback limit applied when no per-owner override exists. Per-owner overrides (set via `PUT /v1/quotas/{owner}`) take precedence; `null` clears the override and falls back to the default. If neither is set, the owner is unlimited.

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

A `Guard` returned from `telemetry::init` flushes both providers on drop, so a SIGINT-triggered graceful shutdown still ships the trailing spans/metrics to the collector before the process exits.

See [`SERVER.md` § "Observability"](SERVER.md#observability) for the operator-facing env vars and the instrument-name list.

## Tricky bits

These are the easy-to-get-wrong parts of the protocol. Calling them out explicitly so they don't get re-broken.

- **Xet hash hex encoding** (spec §"Converting Hashes to Strings"). Not plain hex. Bytes are reordered as four little-endian u64s before stringifying. The spec text shows a doc-typo example missing one byte; the actual algorithm produces 64 hex chars from 32 input bytes. See `bale_server_wire::{encode_hash, decode_hash}` and its `hash_hex_spec_vector` test.
- **Shard upload validation** — every xorb referenced by an uploaded shard MUST already be in the `xorbs` table (we return 400 otherwise). Per-term `FileVerificationEntry` MUST be present (spec says "MUST be set for shard uploads"). Per-term `chunk_idx_start < chunk_idx_end` is checked at the trust boundary — an empty/inverted range used to underflow `chunk_idx_end - 1` at reconstruction time and crash the request task; now rejected with 400 before any metadata write, plus a defensive `start >= end` guard at both reconstruction sites. We can additionally re-verify by recomputing the term verification hash against the chunk hashes we already indexed — *not done yet*; tracked as a hardening TODO.
- **Write ordering across the two stores** — both upload handlers commit metadata-first, then blob-store:
    - **`POST /v1/xorbs/...`** writes `register_xorb_layout` BEFORE `put_xorb`. A layout row with no backing blob is harmless: the next shard upload's `blobs.xorb_exists` check rejects with 400 (`missing xorb`), and the M6 ghost-xorb dedup tests already cover the "metadata says yes, blob says no" shape. The inverse — blob with no layout — used to wedge every file referencing that xorb permanently (reconstruction returns 500 "xorb on-disk layout missing"), so that direction is now explicitly forbidden.
    - **`POST /shards`** writes `put_shard` first (content-addressed archive, inert without metadata pointing at it — orphan archive is GC-able and recoverable on retry), then registers all xorb metadata, then commits every file in a SINGLE atomic batch via `register_files`. A partial fault inside the batch rolls back the whole shard; the client's "500 ⇒ nothing happened" mental model holds. The earlier per-file loop could leave the first N-1 file rows committed while the client believed the upload failed — those orphans were then reachable to anyone who knew the file hash.
- **`url_range.end` is inclusive** in the wire format (matches HTTP `Range:` semantics). The chunk-index `range.end` is **exclusive**. We translate carefully in `get_reconstruction`.
- **Idempotency** — `POST /v1/xorbs/{prefix}/{hash}` and `POST /shards` are content-addressed; re-uploading the same content MUST return 200, not error. `was_inserted: false` on the xorb side; `result: 0` on the shard side (we currently always return `1`; both are spec-defined "success — value is informational").
- **The server does decompress on `POST /v1/xorbs/...` (and only there).** Every chunk frame is decompressed via xet-core's `CompressionScheme` (None / LZ4-frame / BG4-LZ4) so the server can recompute each chunk's `compute_data_hash`, aggregate via `xorb_hash`, and compare to the URL hash. Mismatch → 400 before anything is persisted. This is the load-bearing integrity check that keeps a writer from corrupting the CAS by uploading bytes that don't match the content hash. Implemented in `bale_server_shard::xorb::verify_xorb_body`. Outside of this verification step, payload bytes are still treated as opaque: reconstruction streams raw xorb bytes through signed transfer URLs without touching the compressed payload.
- **Shard `byte_start` / `unpacked_segment_bytes` live in *uncompressed* coordinate space**, NOT on-disk bytes. The CAS Info section in an MDB shard records each chunk's offset within a *conceptual* uncompressed xorb (xet-core's `XorbChunkSequenceEntry::chunk_byte_range_start` accumulates `c.data.len()` pre-compression). On-disk byte ranges live separately in the `xorb_frames` table, populated by walking the chunk frame headers when a xorb is POSTed (`bale_server_shard::xorb::parse_xorb_frames`). Reconstruction MUST build `url_range` from `xorb_frames`, not from the shard-derived `chunks` table — using shard offsets gives wrong byte ranges for any real LZ4-compressed xorb.
- **`FileMetadataExt.sha256` is stored in xet-core's byte-reversed-within-u64-groups order**, not natural sha256 byte order. xet-core treats every `Hash32`-shaped field uniformly as `[u64; 4]` and writes LE u64s, even for sha256 (which has no semantic reason to be reordered). The shard parser un-swaps with `swap_u64_groups` so `ParsedFile.sha256` matches the standard byte order; the serializer applies the inverse swap on the way out.
- **Chunk frame format** (8-byte `XorbChunkHeader`): `version(u8) | compressed_length(u24 LE) | compression_scheme(u8) | uncompressed_length(u24 LE)`. Schemes: 0=None, 1=LZ4 frame, 2=BG4-LZ4 (byte-group-of-4 deinterleave then LZ4 frame). Scheme 99 (Auto) is a sentinel and must never appear on the wire. baleforgit-server only parses the header (for byte-range layout) and never touches payloads.
- **64 MiB limits** on both xorbs and shards — enforced via `DefaultBodyLimit`.
- **Shard magic tag** — the 32-byte `MDB_SHARD_HEADER_TAG` is `b"HFRepoMetaData" + [0, 85, 105, 103, 69, 106, 123, 129, 87, 131, 165, 189, 217, 92, 205, 209, 74, 169]`, lifted verbatim from xet-core's `mdb_shard::shard_format::MDB_SHARD_HEADER_TAG` at the `git-xet-v0.2.1` tag. Our parser still accepts any 32-byte tag (so shards from older toolchains round-trip), but the serializer emits this canonical value so xet-core's strict header check accepts what we produce.

## Where to look in the code

Server side:

| Concern | File |
|---------|------|
| Trait definitions | `crates/bale-server-core/src/lib.rs` |
| Hex encoding + JSON wire types | `crates/bale-server-wire/src/lib.rs` |
| MDB shard binary parser/serializer | `crates/bale-server-shard/src/lib.rs` |
| Xorb chunk-frame parser (on-disk layout) | `crates/bale-server-shard/src/xorb.rs` |
| Filesystem blob store | `crates/bale-server-storage-fs/src/lib.rs` |
| In-memory blob store (M8 pluggability) | `crates/bale-server-storage-mem/src/lib.rs` |
| S3-compatible blob store | `crates/bale-server-storage-s3/src/lib.rs` |
| SQLite metadata store | `crates/bale-server-meta-sqlite/src/lib.rs` |
| Static authz (`AlwaysAllow`, `ConfigAuthz`) | `crates/bale-server-authz-mem/src/lib.rs` |
| HTTP-delegating authz (`HttpAuthz`) | `crates/bale-server-authz-http/src/lib.rs` |
| JWT mint/verify | `crates/bale-server-tokens/src/lib.rs` |
| Router, handlers, middleware, signed URLs | `crates/bale-server-http/src/lib.rs` |
| HTTP metrics middleware + handler counters | `crates/bale-server-http/src/metrics.rs` |
| OTLP traces + metrics init (gated on env) | `crates/bale-server-bin/src/telemetry.rs` |
| Binary launcher | `crates/bale-server-bin/src/main.rs` |
| Cross-crate integration tests | `crates/bale-server-tests/tests/m*.rs` |

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
| `git-bale install` / `git-bale uninstall` (+ pre-push hook) | `crates/git-bale/src/install.rs` |
| `git-bale push-pending` (drain `.git/bale/staging/`) | `crates/git-bale/src/push_pending.rs` |
| Local staging-dir path helper | `crates/git-bale/src/staging.rs` |
| `git-bale track` (`.gitattributes` writer) | `crates/git-bale/src/track.rs` |
| `git-bale mount-diff` (read-only FUSE diff view) | `crates/git-bale/src/mount/` |
