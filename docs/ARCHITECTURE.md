# Architecture

This document describes the internals of `baleforgit-server`: how the protocol pieces map to code, what each pluggable trait is for, and the gotchas of the on-disk format inherited from xet-core.

The repo also ships two client paths that sit *in front of* baleforgit-server: the native `git-bale` filter in `crates/git-bale/` (replaces `git-lfs` entirely with a long-running Git filter, talks to baleforgit-server directly via the Bale wire protocol) and the legacy `lfs-adapter/` Go bridge (drives `git-lfs` users into baleforgit-server). Both are covered below.

## Goals

1. Define a clean Bale wire protocol for chunked CAS upload/download/dedup, served by `baleforgit-server` and consumed by `git-bale`.
2. Keep everything that touches storage, persistence, or authorization behind a **trait** so the same server can run on top of S3, Postgres, or any external repo authority.
3. Reuse xet-core's well-tested hashing, chunking, and shard format semantics (we link `xet-data`/`xet-client`/`xet-runtime`/`xet-core-structures` as library deps); own the wire surface and the server-side state.
4. Make it possible to drop the server in front of an existing git forge without sharing secrets: the forge owns the user model, mints short-lived JWTs, and answers a single `/check_access` callback (see [`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md)).

## Component view

```
                ┌──────────────────────────────────────────────────────┐
                │      git-bale client (or legacy lfs-adapter)         │
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
   │   │ S3 (later)    │    │ Postgres  │      │ ConfigAuthz         │  │
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

1. Client calls one of:
   - `GET /v1/reconstructions/{file_id}` — file_id is the Xet merkle file hash (in Xet hex encoding).
   - `GET /v1/reconstructions/by-sha256/{oid}` — `oid` is a standard 64-char lowercase-hex LFS sha256 OID; the server first resolves it to a file_id via the `files.sha256` index.
2. Server **scope-checks the file against the caller's repo**: there must be a row in `files` matching `(file_hash, repo_id = claims.repo.repo_id)`. If not, returns **404** (not 403 — so an attacker can't probe for existence in other repos). The `files` table uses `(file_hash, repo_id)` as a composite primary key, so the same content can be registered in multiple repos and each registration independently grants read access (cross-repo dedup at the chunk layer is unchanged).
3. Server looks up the file's terms. For each term it reads the xorb's on-disk frame layout from `xorb_frames` (NOT the `chunks` table — that one stores uncompressed offsets) and computes the on-disk byte range covering `[chunk_idx_start, chunk_idx_end)`. It builds `fetch_info` with one **signed transfer URL** per term and the `url_range` bytes covered.
4. Server returns JSON `QueryReconstructionResponse`.
5. Client fetches each `url` with the prescribed `Range` header. The server (transfer layer) verifies the HMAC signature, verifies the Range header matches the signed range (otherwise 401), and streams the bytes from `BlobStore::get_xorb_range`. Client deserializes chunks, strips `offset_into_first_range` from the first one, concatenates.

`Range:` request-side support on `/v1/reconstructions/*` is **not yet implemented** — the prototype always returns the full file's terms. Range support on the transfer URL itself is fully implemented (and mandatory, since signatures cover the byte range). The native `git-bale` smudge handler works around the missing range support by passing `0..file_size` to `xet-data` (see "Native filter" below); the LFS-adapter download path doesn't need it because it streams term-by-term itself.

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
                           sha256: Option<&Hash32>, terms: &[FileTerm]) -> CoreResult<()>;

    // On-disk frame layout — populated at xorb upload time by parsing the
    // chunk frame headers; required to translate shard chunk-index ranges
    // into HTTP byte ranges (the chunks table only has uncompressed offsets).
    async fn register_xorb_layout(&self, xorb: &XorbHash, frames: &[XorbFrameRow]) -> CoreResult<()>;
    async fn xorb_frame_layout(&self, xorb: &XorbHash) -> CoreResult<Vec<XorbFrameRow>>;

    async fn xorb_exists(&self, xorb: &XorbHash) -> CoreResult<bool>;
    async fn lookup_file(&self, file_hash: &FileHash) -> CoreResult<Option<Vec<FileTerm>>>;
    // M12 scope check: true iff `file_hash` is registered in `repo_id`.
    async fn file_in_repo(&self, file_hash: &FileHash, repo_id: &str) -> CoreResult<bool>;
    // LFS-keyed lookup for the by-sha256 reconstruction endpoint.
    async fn lookup_file_by_sha256(&self, sha256: &Hash32) -> CoreResult<Option<FileHash>>;
    async fn lookup_chunk(&self, chunk_hash: &ChunkHash) -> CoreResult<Option<ChunkLocation>>;
    async fn xorbs_near_chunk(&self, chunk_hash: &ChunkHash, limit: usize)
        -> CoreResult<Vec<XorbInfo>>;
    async fn xorb_chunk_offsets(&self, xorb: &XorbHash) -> CoreResult<Vec<ChunkOffsetRow>>;
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
| GET | `/v1/reconstructions/by-sha256/{sha256}` | read | Same, but keyed by LFS sha256 OID |
| GET | `/v1/chunks/{prefix}/{chunk_hash}` | read | Global dedup query |
| POST | `/v1/xorbs/default/{xorb_hash}` | write | Xorb upload |
| POST | `/shards` | write | Shard upload + indexing |

Transfer URL (referenced from `fetch_info`, signed query string, no bearer required):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/xorb/default/{xorb_hash}?s=...&e=...&x=...&sig=...` | Byte-range fetch of a xorb |

Mock HF Hub token endpoint:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/{models\|datasets\|spaces}/{ns}/{name}/bale-{read\|write}-token/{rev}` | Returns `{accessToken, exp, casUrl}` |

The token endpoint accepts the client's upstream hub bearer in `Authorization: Bearer ...`, calls `RepoAuthz::check_repo_access`, then `RepoAuthz::mint_bale_token`.

Operational endpoints (no bearer, no scope check, no access log):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/healthz` | Liveness probe. Returns `200 ok` while the process is running. Sits outside the auth middleware *and* the `TraceLayer`, so a probe firing every few seconds doesn't drown out real request logs. |

The binary registers a `SIGINT`/`SIGTERM` handler and hands it to `axum::serve(...).with_graceful_shutdown(...)`: on signal the listener stops accepting new connections and the server returns once in-flight handlers complete. Useful for container orchestrators that send `SIGTERM` and a grace period.

## LFS adapter (the git-forge integration seam)

baleforgit-server speaks the **Hugging Face Hub** flavor of the Bale protocol — token endpoint at `/api/{type}s/.../bale-{rw}-token/{rev}`, CAS API at `/v1/...`. Git-LFS doesn't know about this surface; it speaks the [git-lfs Batch API](https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md) and dispatches to a custom transfer agent (`git-xet`) when the batch response declares `transfer="xet"`. Something in the middle has to bridge the two protocols.

`lfs-adapter/` (Go) is that bridge:

```
git lfs push ─▶ POST /repos/{o}/{n}/objects/batch (Basic auth, URL-embedded PAT)
                       │
                       ▼
                lfs-adapter (Go, stateless)
                   │ forwards bearer to
                   ▼
                GET /api/models/{o}/{n}/bale-{rw}-token/main  ─▶ baleforgit-server
                                                                   │
                                                                   ▼ check_repo_access
                                                            upstream PAT verifier
                                                            (mock here; real git forge in prod)
                       ◀── {accessToken, exp, casUrl}
                       │
                       ▼ wraps as standard LFS Batch response
                { "transfer": "xet",
                  "objects": [ { "actions": { "upload": {
                      "href": "<casUrl>",
                      "header": { "X-Xet-Cas-Url", "X-Xet-Access-Token", "X-Xet-Token-Expiration" }
                  } } } ] }
                       │
                       ▼ git-lfs spawns git-xet
                git-xet transfer ─▶ POST /v1/xorbs/..., POST /shards (to baleforgit-server, with Bale token)
```

The **download** path is asymmetric. git-xet's custom-transfer agent is upload-only — it errors out on `download` with "Operation not supported". For pulls the adapter advertises `transfer="basic"` (standard LFS Batch transfer) and serves bytes itself:

```
git lfs pull ─▶ POST /repos/{o}/{n}/objects/batch  (operation=download)
                       │
                       ▼  transfer="basic", action.download.href = adapter's own URL
                git-lfs GET /repos/{o}/{n}/objects/{sha256}  ─▶ lfs-adapter
                                                                  │ mint read token
                                                                  ▼
                                                       baleforgit-server: GET /v1/reconstructions/by-sha256/{sha256}
                                                                  │
                                                       ◀── {terms, fetch_info (signed xorb URLs)}
                                                                  │ per term
                                                                  ▼  GET signed URL with Range
                                                       streams xorb frames, decodes 8-byte header,
                                                       LZ4/BG4-LZ4/raw decompress per scheme,
                                                       writes raw bytes to the LFS response.
```

Key properties:

- The adapter is **stateless and credential-free**. It holds no JWT secret. It doesn't decode the user's PAT — it just forwards it to baleforgit-server, where `RepoAuthz` is authoritative. This is the property that makes it cheap to drop in front of an existing git forge (no shared secrets to manage).
- The adapter is intentionally written in **Go** so engineers maintaining the existing LFS code in upstream forges can read it without learning Rust.
- For integration into a specific forge: stand up a `/check_access` endpoint that authorizes the user/repo pair against that forge's own data, and point baleforgit-server's `BALE_AUTHZ_HTTP_URL` at it. Adapter and baleforgit-server are unchanged.
- The remote URL **must** be http(s)/ssh — git-xet rejects `file://` during credential helper setup. `lfs.url` only redirects LFS traffic; the remote URL still has to parse. The push integration test (`m9_real_lfs_push`) uses `git lfs push` directly so the unreachable `origin` doesn't actually need to accept a ref push. The pull test (`m10_real_lfs_pull`) wipes `.git/lfs/objects/` and the worktree file after the push, then runs `git lfs pull` so the bytes have to come from the server.
- Download streaming in the adapter is **per-chunk** — schemes 0 (raw) and 1 (LZ4 frame) flow through `io.Copy`; scheme 2 (BG4-LZ4) needs the full uncompressed chunk in memory before the byte-group regroup, but chunks are ≤16 MiB by the xorb header's u24 length and typically ~64 KiB. No full-file buffering anywhere.

## Native filter: `git-bale` (the LFS-bypass path)

`crates/git-bale/` is a native Rust replacement for the LFS adapter, installed as a `filter.bale.process` driver in git config. It speaks Git's long-running filter protocol directly, and calls into `xet-core`'s `FileUploadSession` / `FileDownloadSession` for chunking and reconstruction — bypassing `git-lfs` entirely. The forge protocol it speaks to authenticate is documented in [`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md).

Why a second client path?

- **No `.git/lfs/objects/`**: git-lfs's design keeps a whole-file copy of every tracked blob in the per-repo store *in addition to* the worktree. That defeats Xet's chunk-level dedup locally and roughly doubles disk usage. git-bale keeps only the worktree file plus a deduplicated per-user chunk cache.
- **Pretty-printed JSON pointer** with stable key order (`hash`, `file_size`, `sha256`) instead of the git-lfs `version/oid/size` line format. Tracked as a normal blob, parseable without xet-core.
- **Long-running process**: one filter-process subprocess per `git add` / `git checkout` fan-out, not one subprocess per file.

Layout on disk:

```
<repo>/big.bin                          # worktree (one copy)
<repo>/.git/bale/manifests/<file_id>.json # per-file reconstruction terms
~/.cache/bale/chunks/                     # shared chunk pool across repos
```

### Hot vs cold smudge

On `command=smudge` (filter sees a pointer, must reconstruct), git-bale first tries a **cache-only** path:

1. Load `.git/bale/manifests/<file_id>.json`. Returns `None` for missing / malformed / unknown-version manifests — all three trigger the cold path.
2. For each cached term, ask the local chunk cache (`xet-client::chunk_cache`) for the chunk range. Any miss → fall back to the cold path.
3. Concatenate the chunk bytes into a temp file. Length checks guard against stale manifests corrupting the worktree.

If the cache path fails or doesn't run, git-bale falls back to the standard `FileDownloadSession::download_to_writer` — same code path xet-core uses for HF-Hub-hosted Xet content. It additionally writes the manifest to `.git/bale/manifests/` as a side effect so subsequent checkouts go through the hot path. The manifest stores only content-addressed `terms` (xorb hash + chunk-index range), **not** `fetch_info` URLs — those signed URLs expire after `SIGNATURE_TTL_SECS` (10 min) and aren't safe to persist.

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
files       (file_hash, repo_type, repo_id, revision, sha256, total_bytes, created_at)
              PK (file_hash, repo_id)   -- composite: same content in N repos
              INDEX (sha256) WHERE sha256 IS NOT NULL
              INDEX (repo_id)
file_terms  (file_hash, term_index, xorb_hash, chunk_idx_start, chunk_idx_end,
             unpacked_bytes, verification)
              PK (file_hash, term_index)
```

`xorb_frames` is populated at upload time by `parse_xorb_frames` in `bale-server-shard`. It is the *only* source of truth for HTTP byte ranges — the `chunks` table records uncompressed offsets from the shard's CAS Info section, which don't match on-disk positions for any real LZ4-compressed xorb. See the "Tricky bits" note below.

`files` has a composite primary key on `(file_hash, repo_id)`. The same content can be registered in multiple repos (cross-repo dedup at the file level), and each registration independently grants read access via the M12 scope check.

This is the minimum needed to answer reconstruction queries and global-dedup queries. Migrations run automatically on connection open (idempotent `CREATE TABLE IF NOT EXISTS ...`).

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

## Tricky bits

These are the easy-to-get-wrong parts of the protocol. Calling them out explicitly so they don't get re-broken.

- **Xet hash hex encoding** (spec §"Converting Hashes to Strings"). Not plain hex. Bytes are reordered as four little-endian u64s before stringifying. The spec text shows a doc-typo example missing one byte; the actual algorithm produces 64 hex chars from 32 input bytes. See `bale_server_wire::{encode_hash, decode_hash}` and its `hash_hex_spec_vector` test.
- **Shard upload validation** — every xorb referenced by an uploaded shard MUST already be in the `xorbs` table (we return 400 otherwise). Per-term `FileVerificationEntry` MUST be present (spec says "MUST be set for shard uploads"). We can additionally re-verify by recomputing the term verification hash against the chunk hashes we already indexed — *not done yet*; tracked as a hardening TODO.
- **`url_range.end` is inclusive** in the wire format (matches HTTP `Range:` semantics). The chunk-index `range.end` is **exclusive**. We translate carefully in `get_reconstruction`.
- **Idempotency** — `POST /v1/xorbs/{prefix}/{hash}` and `POST /shards` are content-addressed; re-uploading the same content MUST return 200, not error. `was_inserted: false` on the xorb side; `result: 0` on the shard side (we currently always return `1`; both are spec-defined "success — value is informational").
- **The server does decompress on `POST /v1/xorbs/...` (and only there).** Every chunk frame is decompressed via xet-core's `CompressionScheme` (None / LZ4-frame / BG4-LZ4) so the server can recompute each chunk's `compute_data_hash`, aggregate via `xorb_hash`, and compare to the URL hash. Mismatch → 400 before anything is persisted. This is the load-bearing integrity check that keeps a writer from corrupting the CAS by uploading bytes that don't match the content hash. Implemented in `bale_server_shard::xorb::verify_xorb_body`. Outside of this verification step, payload bytes are still treated as opaque: reconstruction streams raw xorb bytes through signed transfer URLs without touching the compressed payload.
- **Shard `byte_start` / `unpacked_segment_bytes` live in *uncompressed* coordinate space**, NOT on-disk bytes. The CAS Info section in an MDB shard records each chunk's offset within a *conceptual* uncompressed xorb (xet-core's `XorbChunkSequenceEntry::chunk_byte_range_start` accumulates `c.data.len()` pre-compression). On-disk byte ranges live separately in the `xorb_frames` table, populated by walking the chunk frame headers when a xorb is POSTed (`bale_server_shard::xorb::parse_xorb_frames`). Reconstruction MUST build `url_range` from `xorb_frames`, not from the shard-derived `chunks` table — using shard offsets gives wrong byte ranges for any real LZ4-compressed xorb.
- **`FileMetadataExt.sha256` is stored in xet-core's byte-reversed-within-u64-groups order**, not natural sha256 byte order. xet-core treats every `Hash32`-shaped field uniformly as `[u64; 4]` and writes LE u64s, even for sha256 (which has no semantic reason to be reordered). The shard parser un-swaps with `swap_u64_groups` so that downstream code — and the `/v1/reconstructions/by-sha256/{oid}` endpoint, which accepts standard hex LFS OIDs — sees natural bytes.
- **Chunk frame format** (8-byte `XorbChunkHeader`): `version(u8) | compressed_length(u24 LE) | compression_scheme(u8) | uncompressed_length(u24 LE)`. Schemes: 0=None, 1=LZ4 frame, 2=BG4-LZ4 (byte-group-of-4 deinterleave then LZ4 frame). Scheme 99 (Auto) is a sentinel and must never appear on the wire. The Go adapter decodes all three for the LFS download path; baleforgit-server only parses the header (for byte-range layout) and never touches payloads.
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
| Cache-only smudge fast path | `crates/git-bale/src/local_reconstruct.rs` |
| Cold-path manifest fetch | `crates/git-bale/src/remote_manifest.rs` |
| Config loader (env + `git config`) | `crates/git-bale/src/config.rs` |
| Remote URL parsing (http/https/ssh) | `crates/git-bale/src/remote.rs` |
| Forge auth resolver | `crates/git-bale/src/resolver.rs` |
| `git-bale install` / `git-bale uninstall` | `crates/git-bale/src/install.rs` |
| `git-bale track` (`.gitattributes` writer) | `crates/git-bale/src/track.rs` |
