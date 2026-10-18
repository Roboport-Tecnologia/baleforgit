# Architecture

Internals of `baleforgit-server` (how the protocol maps to code, the pluggable traits, the on-disk format gotchas inherited from xet-core) and of its one client, the native `git-bale` Git filter in `crates/git-bale/`.

## Goals

1. A Bale wire protocol for chunked CAS upload/download/dedup, served by `baleforgit-server` and consumed by `git-bale`.
2. Everything that touches storage, persistence, or authorization sits behind a **trait**, so the same server runs on S3, Postgres, or any external repo authority.
3. Reuse xet-core's hashing, chunking, and shard format (the server links `xet-core-structures`; `git-bale` also links `xet-data`/`xet-client`/`xet-runtime`, all pinned `=1.5.2`); own the wire surface and the server-side state.
4. Drop in front of an existing git forge without sharing secrets: the forge owns the user model, mints short-lived JWTs, and answers a single `/check_access` callback (see [`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md)).

## Component view

```
                ┌──────────────────────────────────────────────────────┐
                │                  git-bale client                     │
                │ (forge JWT → token exchange → CAS URL + Bale token)  │
                └────────────────────┬─────────────────────────────────┘
                                     │ HTTPS
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
              ▼                      ▼                      ▼
   ┌─────────────────────┐   ┌──────────────────┐   ┌──────────────────┐
   │  Token exchange     │   │   CAS API        │   │  Transfer URL    │
   │  /api/models/...    │   │   /v1/..,/shards │   │  /xorb/...       │
   │  /bale-{read,write} │   │   uploads/dl     │   │  (signed range   │
   │  -token/{rev}       │   │   recon/dedup    │   │   GET)           │
   └──────────┬──────────┘   └────────┬─────────┘   └────────┬─────────┘
              │                       │                      │
              ▼                       ▼                      ▼
   ┌────────────────────────────────────────────────────────────────────┐
   │               baleforgit-server (single Rust binary)               │
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
   │   │ in-memory     │    │           │      │ HttpAuthz (upstream)│  │
   │   └───────────────┘    └───────────┘      └─────────────────────┘  │
   └────────────────────────────────────────────────────────────────────┘
```

## Request flows

### Upload (write-token scope required)

1. Client splits the file via gearhash CDC into chunks (~64 KiB target, 8 KiB min, 128 KiB max).
2. Client may query `GET /v1/chunks/{prefix}/{hash}` (`prefix` is `default` in current xet-core) for any chunk whose hash matches the eligibility rule (last 8 bytes mod 1024 == 0); server replies with a shard whose CAS Info section lists nearby xorbs that contain that chunk (chunk hashes HMAC-wrapped — see *Global dedup* below).
3. Client groups new chunks into xorbs (≤ 64 MiB *unpacked*, ≤ 8192 chunks; serialized size can slightly exceed 64 MiB since incompressible chunks are stored raw plus an 8-byte header each) and uploads them with `POST /v1/xorbs/default/{xorb_hash}`. Server decompresses every frame (output capped at each frame's declared length), recomputes every chunk hash and the xorb merkle hash, and rejects a mismatch (400). It charges the owner's quota (see *Quota enforcement*), persists the blob first-writer-wins, records the frame layout **with the server-computed chunk hashes** for the bytes actually stored, registers the xorb's `xorbs`/`chunks` rows from those verified hashes, and returns `{was_inserted: bool}`. At most 16 xorb uploads run concurrently per server; the rest queue.
4. Client builds a shard with **File Info** (each file → list of terms `(xorb_hash, chunk_index_range, unpacked_segment_bytes)` plus one verification hash per term, required) and **CAS Info** (per new xorb: the chunk hashes and their byte offsets inside that xorb). Client POSTs the shard (≤ 64 MiB, ≤ 256 Mi chunks referenced in total) to `/shards`.
5. Server, all verification before any state change:
   - verifies every referenced xorb blob exists (otherwise 400),
   - **verifies every file against content** (proof of possession, see *Tricky bits*): each term's range is in bounds, its `unpacked_segment_bytes` equals its chunks' sizes, its verification range hash matches, and the whole-file merkle hash equals `file_hash`,
   - **ignores the CAS Info chunk lists** entirely (client claims; the server already holds the verified chunk sequence),
   - re-derives any missing `xorbs` row from the stored blob (crash between layout and row writes), then runs the shard-time quota check,
   - persists the shard blob keyed by BLAKE3 over its bytes (internal-only — the Bale protocol doesn't define a shard hash), *before* file rows: an orphan shard is harmless, a file row without one is not,
   - writes `files` rows and ordered `file_terms` rows (write-once per `file_hash`) in one transaction, so a 500 means nothing was registered.

### Download (read-token scope sufficient)

1. Client calls `GET /v1/reconstructions/{file_id}` (file_id is the Xet merkle file hash, in Xet hex encoding).
2. Server **scope-checks the file against the caller's repo**: there must be a `files` row `(file_hash, repo_id = claims.repo.repo_id)`, else **404** (not 403, so other repos can't be probed). `files` is keyed `(file_hash, repo_id)`, so the same content can be registered in many repos and each registration independently grants read.
3. Server looks up the file's terms (only those overlapping the request's `Range`, see below). For each xorb it reads the on-disk frame layout from `xorb_frames` (NOT the `chunks` table, which stores uncompressed offsets). It merges the terms' chunk ranges per xorb into **disjoint** ranges and builds `fetch_info` with one transfer URL per merged range (an S3 presigned URL when `presign_xorb_range` returns one, else a self-signed `/xorb/...` URL) plus the `url_range` bytes covered. Disjointness matters: xet binds each term to the first entry containing it and dedups blocks by `(xorb, range start)`, so overlapping per-term entries (`[0,5)` then `[0,10)`) made it slice a short block and panic.
4. Server returns JSON `QueryReconstructionResponse`.
5. Client fetches each `url` with exactly the `url_range` as its `Range` header (see *Signed transfer URLs*), deserializes chunks, strips `offset_into_first_range` from the first one, and concatenates.

`/v1/reconstructions/*` **honors `Range: bytes=S-E`**: it returns only the terms overlapping the range, sets `offset_into_first_range` to skip the first term's leading bytes (the client trims the last term), and answers 416 at or past EOF. This is mandatory, not an optimization. xet-data fetches any file larger than 2 × `min_reconstruction_fetch_size` (256 MiB) in byte-range blocks even when asked for `0..file_size`. Answering every block with the whole file's terms made the client lay the file out at the block's offset and underflow its last-term trim, so no file over ~512 MiB could be cloned (`large-file` e2e phase).

### Global dedup

- `GET /v1/chunks/{prefix}/{hash}` (`get_dedup_chunk` in `bale-server-http`) looks the chunk up in the `chunks` table (`chunk_hash → xorb_hash`). Today only the containing xorb is returned (`xorbs_near_chunk` ignores its `DEDUP_NEIGHBORHOOD` = 8 limit beyond that; neighborhood expansion is unimplemented). A xorb whose blob is gone is dropped (advertising it would make the client skip the upload and `/shards` then reject); 404 if nothing remains.
- The response is a synthetic shard whose CAS Info lists that xorb with each chunk hash wrapped as `blake3::keyed_hash(per_response_key, chunk_hash)`, which is xet's `MerkleHash::hmac` (an HMAC-SHA256 wrap never matches, so global dedup would silently never hit). The key goes into the footer's `chunk_hash_hmac_key` (expiry 24 h); the client wraps its own candidate hashes with it and looks for matches, so it can confirm "I have chunk X" without the server revealing the chunk hashes it knows.
- The chunk list comes from the server-verified per-frame chunk hashes in `xorb_frames`, re-checked against the xorb hash, never from `chunks` rows: clients dedup by chunk *position*, and the `chunks` PK `(chunk_hash, xorb_hash)` collapses a chunk that repeats within one xorb, shifting every later index. A xorb whose sequence can't be verified is left out.
- **Footer offsets are load-bearing even though the shard carries no lookup tables.** `serialize` (`bale-server-shard`) omits the file/xorb/chunk lookup tables (counts 0), but each lookup *offset* must still equal `footer_offset`, **not** 0, as xet's own serializer does. The client ingests every dedup shard and calls `read_all_truncated_hashes`, which for a table-less shard scans `(xorb_info_offset, file_lookup_offset)`; a zero `file_lookup_offset` underflows that range (debug panic; release a multi-exabyte `Vec::with_capacity` → OOM), killing the pre-push hook. Guarded by the `global-dedup-shard` e2e phase.

## Pluggable traits

The traits live in `bale-server-core`. Handlers never touch storage or auth directly; they go through the `Service<B, M, A>` struct in `bale-server-http`, which holds `Arc<B>` / `Arc<M>` / `Arc<A>` (generic, not `dyn`, so the chosen impls are monomorphised; the binary builds one `Service` per backend/authz combination).

```rust
#[async_trait]
pub trait BlobStore: Send + Sync {
    // First writer wins; never replaces (equal-hash bodies can differ in compression,
    // and the recorded frame layout describes whichever body was kept).
    async fn put_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<bool /* was_inserted */>;
    // Heals a stored blob that failed re-verification.
    async fn replace_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<()>;
    async fn xorb_exists(&self, hash: &XorbHash) -> CoreResult<bool>;
    async fn get_xorb_range(&self, hash: &XorbHash, byte_range: Range<u64> /* [start, end) */)
        -> CoreResult<Bytes>;
    async fn get_xorb(&self, hash: &XorbHash) -> CoreResult<Bytes> { /* full range */ }
    async fn put_shard(&self, hash: &ShardHash, body: Bytes) -> CoreResult<()>;
    async fn get_shard(&self, hash: &ShardHash) -> CoreResult<Bytes>;
    async fn presign_xorb_range(&self, hash: &XorbHash, byte_range: Range<u64>, ttl: Duration)
        -> CoreResult<Option<String>> { Ok(None) }
}

#[async_trait]
pub trait MetadataStore: Send + Sync {
    async fn register_xorb(&self, xorb: &XorbInfo, chunks: &[ChunkRow]) -> CoreResult<()>;
    // One transaction per shard, so a fault can't leave file rows the client thinks
    // didn't upload. With `quota`, usage is rechecked inside it (serialized per owner).
    async fn register_files(&self, repo: &RepoRef, files: &[FileRegistration],
                            quota: Option<u64>) -> CoreResult<()>;

    // Charge a new xorb to its uploader before the blob is written (atomic with the
    // quota check); settle to the stored size afterwards, or release on write failure.
    async fn reserve_xorb_upload(&self, xorb: &XorbHash, owner: &str, bytes: u64,
                                 quota: Option<u64>) -> CoreResult<bool>;
    async fn settle_xorb_upload(&self, xorb: &XorbHash, owner: &str, bytes_on_disk: u64)
        -> CoreResult<()>;
    async fn release_xorb_upload(&self, xorb: &XorbHash, owner: &str) -> CoreResult<()>;

    // On-disk frame layout + server-computed chunk hash per frame, from the verified
    // body: the only source for HTTP byte ranges and the trusted chunk sequence.
    // Upsert, so it can be re-derived from whichever encoding the blob store kept.
    async fn register_xorb_layout(&self, xorb: &XorbHash, frames: &[XorbFrameRow]) -> CoreResult<()>;
    async fn xorb_frame_layout(&self, xorb: &XorbHash) -> CoreResult<Vec<XorbFrameRow>>;
    async fn xorb_frame_layouts(&self, xorbs: &[XorbHash])
        -> CoreResult<HashMap<XorbHash, Vec<XorbFrameRow>>>; // default: loops
    // Frames [start, end) per span, for shard verification without loading whole layouts.
    async fn xorb_frame_spans(&self, spans: &[(XorbHash, u32, u32)])
        -> CoreResult<Vec<Vec<XorbFrameRow>>>;

    async fn xorb_exists(&self, xorb: &XorbHash) -> CoreResult<bool>;
    async fn missing_xorb_rows(&self, xorbs: &[XorbHash]) -> CoreResult<Vec<XorbHash>>;
    async fn lookup_file(&self, file_hash: &FileHash) -> CoreResult<Option<Vec<FileTerm>>>;
    // Scope check: true iff `file_hash` is registered in `repo_id`.
    async fn file_in_repo(&self, file_hash: &FileHash, repo_id: &str) -> CoreResult<bool>;
    async fn xorbs_near_chunk(&self, chunk_hash: &ChunkHash, limit: usize)
        -> CoreResult<Vec<XorbInfo>>;
    async fn xorb_chunk_offsets(&self, xorb: &XorbHash) -> CoreResult<Vec<ChunkOffsetRow>>;

    // Accounting + quotas (see "Owner accounting and quotas").
    async fn raw_bytes_for_owner(&self, owner: &str) -> CoreResult<u64>;
    async fn stored_bytes_for_owner(&self, owner: &str) -> CoreResult<u64>;
    async fn get_owner_quota(&self, owner: &str) -> CoreResult<Option<u64>>;
    async fn set_owner_quota(&self, owner: &str, limit_bytes: Option<u64>) -> CoreResult<()>;
    // On-disk bytes of `candidates` the owner doesn't already pay for.
    async fn unaccounted_xorb_bytes_for_owner(&self, owner: &str, candidates: &[XorbHash])
        -> CoreResult<u64>;
    async fn raw_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64>;
    async fn stored_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64>;
    async fn exclusive_stored_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64>;
}

#[async_trait]
pub trait RepoAuthz: Send + Sync {
    async fn verify_xet_token(&self, bearer: &str) -> CoreResult<TokenClaims>;
    // `purpose` (TokenExchange | FileDownload { file_id }) lets the authority refuse a
    // download-scoped credential for token exchange; the grant may carry a canonical
    // scope key and accounting owner.
    async fn check_repo_access(&self, hub_bearer: &str, repo: &RepoRef, scope: Scope,
                               purpose: AccessPurpose<'_>) -> CoreResult<AccessGrant>;
    // Returns (token, absolute expiry in unix seconds).
    async fn mint_xet_token(&self, user: &UserId, repo: &RepoRef, scope: Scope)
        -> CoreResult<(String, u64)>;
}
```

`xorb_chunk_offsets` is implemented by both stores but no handler calls it.

### Shipped implementations

| Trait | Crate | Impl |
|-------|-------|------|
| `BlobStore` | `bale-server-storage-fs` | `FsBlobStore` — fsynced temp → `link(2)` (no-replace) writes with durable parent dirs, byte-range reads. Default. |
| `BlobStore` | `bale-server-storage-s3` | `S3BlobStore` — any S3-compatible API with conditional writes (AWS S3, MinIO, R2, B2); selected by `BALE_S3_BUCKET`. `presign_xorb_range` returns real presigned `GET` URLs, so reconstruction bytes bypass the server. |
| `BlobStore` | `bale-server-storage-mem` | `MemBlobStore` — `RwLock<HashMap>`; not wired into the binary |
| `MetadataStore` | `bale-server-meta-sqlite` | `SqliteMetadataStore` — runtime `sqlx` queries (no compile-time DB). Default. |
| `MetadataStore` | `bale-server-meta-postgres` | `PostgresMetadataStore` — same schema/queries in the Postgres dialect; selected by `BALE_POSTGRES_URL` |
| `RepoAuthz` | `bale-server-authz-mem` | `ConfigAuthz` (static map of hub bearers → users → repo scopes, from `BALE_GRANTS`) and `AlwaysAllow` (grants everything; not wired into the binary) |
| `RepoAuthz` | `bale-server-authz-http` | `HttpAuthz` — delegates `check_repo_access` to a generic `POST /check_access` upstream (a forge, an identity provider, a proxy); Bale token mint/verify stays local. Selected by `BALE_AUTHZ_HTTP_URL`. |

A forge-specific `RepoAuthz` that calls the forge's own APIs in-process (saving the `/check_access` hop, or for concepts that don't fit that contract) is a possible future impl.

## Wire surface

All routes are built in `router()` in `bale-server-http`.

CAS API (behind the Bale JWT middleware; POST needs a write-scope token, a read token gets 403):

| Method | Path | Scope | Purpose |
|--------|------|-------|---------|
| GET | `/v1/reconstructions/{file_id}` | read | File reconstruction metadata (honors `Range`) |
| GET | `/v1/chunks/{prefix}/{chunk_hash}` | read | Global dedup query (`prefix` is always `default` today) |
| POST | `/v1/xorbs/{prefix}/{xorb_hash}` | write | Xorb upload; 413 over quota, 408 past the 110 s deadline |
| POST | `/shards` | write | Shard upload + file registration; 413 over quota, 408 past the 300 s deadline |

Token exchange (outside the JWT middleware; authenticated by the upstream bearer):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/{models\|datasets\|spaces}/{ns}/{name}/bale-{read\|write}-token/{rev}` | Takes `Authorization: Bearer <upstream bearer>` (e.g. the forge JWT), calls `check_repo_access` (purpose `TokenExchange`) then `mint_xet_token`, returns `{accessToken, exp, casUrl}`. The path shape is inherited from HF Hub; `git-bale` always requests `models`. |

Transfer URL (referenced from `fetch_info`; signed query string, no bearer — see *Signed transfer URLs*):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/xorb/default/{xorb_hash}?s=...&e=...&x=...&sig=...` | Byte-range fetch of a xorb (206) |

Browser file download (outside the JWT middleware: browsers can't carry `Authorization` on a 302 follow, so the bearer rides in the query string):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/files/{file_id}?token=<forge-jwt>&repo=<owner/name>&filename=<name>` | Streams the reconstructed file term by term. The server calls `check_repo_access` (purpose `FileDownload { file_id }`, read scope) against the forge, then runs the `file_in_repo` scope check on the canonical repo id (404 on miss). `filename` sets `Content-Disposition: attachment` only when its SHA-256 matches the JWT payload's `FilenameSHA256` claim; a mismatch is 400 (see [`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md)). A mid-stream error truncates the body. |

Usage and admin (outside the JWT middleware because they also accept the static admin bearer, which isn't a JWT; bodies capped at 4 KiB):

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/v1/usage/{owner}` | write-scope Bale JWT whose `repo.owner()` is `{owner}`, or admin | Per-owner accounting. Write scope because owner totals span private repos a read-only collaborator can't see. |
| GET | `/v1/usage/repo/{owner}/{repo}` | Bale JWT (any scope) for exactly `{owner}/{repo}`, or admin | Per-repo accounting. Unknown repos return zeros, not 404. |
| PUT | `/v1/quotas/{owner}` | admin only | Set (`{"limit_bytes": <u64>}`) or clear (`{"limit_bytes": null}`) the owner's quota; 204. 404 when `BALE_ADMIN_TOKEN_HEX` is unset. The body is parsed only after the bearer check. |

The admin bearer is `Authorization: Bearer <hex of BALE_ADMIN_TOKEN_HEX>`, constant-time compared. Response shapes are in *Owner accounting and quotas*.

`GET /healthz` returns `200 ok`; it sits outside auth, the access log, and metrics, so frequent probes don't drown real request logs.

## Native filter: `git-bale`

`crates/git-bale/` is the client: a native Rust long-running filter (`filter.bale.process`, with `filter.bale.required=true`) that speaks Git's filter protocol directly and calls `xet-data`'s `FileUploadSession` / `FileDownloadSession` for chunking and reconstruction. Its forge auth protocol is in [`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md).

- **Pretty-printed JSON pointer** with stable key order (`hash`, `file_size`, `sha256`), tracked as a normal blob, parseable without xet-core.
- **One filter process per git command**, not one subprocess per file.
- **Deduplicated per-user chunk cache** instead of a whole-file local store — the worktree file is the only full copy on disk.
- **Deferred upload**: `git add` chunks and stages locally; the pre-push hook moves bytes to the server; `git-bale gc` (post-checkout/commit/merge hooks) reclaims staging for changes abandoned before a push.

Git access is pure Rust via `gix`. Only four things shell out: `git credential fill` and `ssh` for forge auth (no library equivalent), the `git config --local/--global/--system` writes in `install.rs`, and `git cat-file --batch-check` in push-pending to lazily fetch missing blobs in a partial clone. The `xet-*` crates are pinned to `=1.5.2` — load-bearing for the on-disk shard format.

Layout on disk:

```
<repo>/big.bin                              # worktree (one copy)
<repo>/.git/bale/manifests/<file_id>.json   # per-file reconstruction terms (hot smudge path)
<repo>/.git/bale/staging/                   # server mode: pending xorbs+shards, drained by push-pending, reconciled by gc
<repo>/.git/bale/staging/file-index/<hash>  # per-file markers (both modes): the inventory gc/prune/push-pending trust
<repo>/.git/bale/store/                     # local mode: default per-repo durable store
<repo>/.git/bale/clean-cache/<blake3(path)> # path-keyed pointer cache
~/.cache/bale/chunks/                       # per-user chunk cache (BALE_CACHE_DIR / bale.cacheDir / $XDG_CACHE_HOME)
~/.cache/bale/xet/                          # xet's own cache root (BALE_XET_CACHE)
```

`.git` here is always the repo's **common** git dir (`store::common_git_dir`, canonicalized with `dunce` so Windows never gets `\\?\` paths), so every linked worktree shares one staging area, marker inventory, clean-cache and manifest cache. Keying on `.git/worktrees/<id>` would give each worktree an inventory the others' gc can't see — main's gc would sweep a linked worktree's staged-only content.

**Durability.** Staging and the local store are the only copy of content until pushed (forever, in local mode), and xet's local client doesn't fsync. So clean snapshots the `xet/xorbs/{xorbs,shards}` listings first, afterwards fsyncs exactly the newly created files and their directories (`store::ObjectSnapshot`), and only then writes the marker. For every new shard it also validates and fsyncs each xorb the shard's files reference (`XorbObject::validate_xorb_object`): a re-add can dedup against an xorb from an earlier session that a power loss tore or lost while the redb index and shard naming it survived; a missing/corrupt one fails the clean (`status=error`) instead of getting a marker. Markers, clean-cache entries, manifests and registry entries are written tmp → fsync → rename → fsync dir (`fs_util::write_durable` or equivalent).

**Store creation.** Only `init-local` creates a local store (claiming it, or registering it as shared). `store::object_store_root` refuses a store path holding neither `.bale-owner` nor `repos/`: a repo moved away from a recorded store path, or a store on an unmounted disk, would otherwise get a fresh empty store there, hiding every committed file. The per-repo default (`<common>/bale/store`) is therefore never written to `bale.localStore` — it's derived from the git dir, so it moves with the repo.

**Store ownership.** gc sweeps a non-shared store whole once its repo's markers are gone, which would destroy another repo's content in it. So a non-shared store records its owner's canonical common git dir in `<store>/.bale-owner` (`store::claim_store`, by `init-local` or the first clean). init-local, clean and gc refuse a non-shared store owned by another repo or registered as shared (pointing at `--shared`); registering an owned store as shared is refused; gc never sweeps a store it doesn't own. A store under the repo's own `<common>/bale/` (not merely `<common>`, which also holds submodules' git dirs) records the sentinel `@containing-git-dir`, so the claim survives moving or copying the repo, while a foreign repo pointed into it with `--store` is refused — and if the foreign repo claimed it first, the containing repo is refused rather than sweeping its content. The owner may convert its own store to `--shared` (`.bale-owner` is removed only after the registry entry is durable).

### Pointer cache (clean short-circuit)

`git status` / `git diff` re-run the clean filter for any worktree file whose stat data differs from the index; for us that's full CDC + xorb + shard building (~1–2 s for 30 MiB), on every prompt/IDE refresh.

So clean keeps a pointer cache at `<git_dir>/bale/clean-cache/<blake3(pathname)>`:

```json
{ "v": 4, "size": 30000000, "chunks": [{ "start": 0, "end": 1048576, "hash": "<xxh3-64 hex>" }, ...],
  "pointer": "{...}\n", "store": "<canonical object store>", "store_id": "<store .bale-id, null for staging>" }
```

On every clean:

1. **Drain the pkt-line payload** into memory, spilling to a temp file past `MAX_INLINE_CLEAN` (4 GiB; `BALE_MAX_INLINE_CLEAN` overrides, the e2e harness uses 1 MiB to exercise the spill path). No hashing during the read.
2. **Size check** against `entry.size` — a mismatch goes straight to a full clean.
3. **Chunked verify** against `entry.chunks` (1 MiB chunks) in the order first, last, 3 random middles, rest — edits cluster at head/tail. Spilled payloads verify on a small thread pool that stops at the first divergence.
4. **Store check under the store lock**: the entry must still be present and name the current store path and `.bale-id`; otherwise switching stores (`init-local --store`) or a store wiped and re-created at the same path would emit pointers the current store can't back. (`.bale-id` is copied through `prune --shared`'s swap, except when `--force` skipped a missing repo: its clean-cache wasn't retired, so the compacted store gets a fresh id and that repo's entries miss and re-stage.)
5. **Hit** → emit `entry.pointer`. A hit writes no objects; it only bumps an existing marker's mtime (gc's reclaim grace) and never creates one. In server mode a hit with no marker is normal after `push-pending` drained staging (the content is on the server). In **local mode** a hit with no marker falls through to a full clean: the store is the only copy and nothing vouches for it.

On a miss the full clean runs, then a fresh chunk index is saved. The marker write is mandatory (failure → `status=error`); the cache write is best-effort. gc invalidates entries for every hash it drops — see [Staging reconciliation](#staging-reconciliation-git-bale-gc).

**Smudge seeds the cache** with the pointer it was given and the bytes it just verified, so the `git status` after a `git checkout -- foo.bin` hits. Seeding is best-effort (non-blocking `try_exclusive` on the store lock, skipped on any error) and happens only while something guarantees the bytes stay retrievable: the server (server mode, hot or cold path — manifests are only saved from a server fetch) or, re-checked under the lock, a marker for bytes reconstructed from this repo's own staging/store. Otherwise a seed racing gc's `forget_hashes` could let a later `git add` emit a pointer whose bytes gc already swept.

Entries are ~60 bytes per chunk (~2 KiB for 30 MiB). No eviction; reset with `rm -rf .git/bale/clean-cache/`. Because `git diff` spawns a filter process per command, startup is kept cheap: config comes from one gix config snapshot (no `git config` subprocess), and `XetRuntime` (8 MiB worker stacks) is created lazily, so a cache hit never starts it.

### Deferred upload and `push-pending`

`clean` never touches the network or resolves auth (no `git credential fill`, no forge round-trip), so `git add` works offline. It writes through `TranslatorConfig::local_config(<object store>)`, i.e. xet-data's `LocalClient` (`…/xet/xorbs/xorbs/default.<hex>`, `…/xet/xorbs/shards/<hex>.mdb`); the pointer is identical to a synchronous upload's.

`git-bale push-pending` ensures every bale file the push *advertises* is present on — and registered under — the push target's repo, and uploads **nothing else**: staging also holds bytes a `git status` re-clean of an uncommitted edit staged, which must not leave the machine. Candidates are the files reachable from the pushed ref delta, plus staged content the **target already references** (reachable from the remote shas on stdin or `refs/remotes/<target>/*`): a commit pushed earlier with `--no-verify`, or where the hook couldn't run, leaves the remote advertising a pointer whose bytes exist only in local staging. That second walk runs only for markers the delta didn't cover (early exit), and leaks nothing the user didn't already push. Everything else stays staged for gc. Two classes qualify:

1. **Freshly staged** files, sourced from `.git/bale/staging/`.
2. **Already-pushed-elsewhere** files: drained by a prior push to a *different* remote, so unknown to the target's repo (the server's `files` scope check is per-repo — see [Pluggable traits](#pluggable-traits)) and a clone of the target would 404. They're found by walking the pushed ref delta for pointers (the same gix rev-walk + tree diff gc uses) and re-sourced from whichever configured remote still holds them (`origin` first). The walk hides only the remote shas git reports on stdin — a **new** ref (zero sha) reconsiders all history — and deliberately **not** `refs/remotes/<name>/*`: git refs on a remote say nothing about whether the bale objects were registered there. To keep the over-walk cheap each candidate is probed first (`GET /v1/reconstructions/{hash}` with the target write token: 200 = registered → skip). (To register objects on a remote that has the history but not the objects, push to a *new* branch; re-pushing a ref it already has is a git no-op.)

Neither class POSTs staged xorbs/shards verbatim — that would bypass global dedup. Each file is reconstructed to a temp file (from staging or a source server) and re-cleaned through one online `FileUploadSession` against the target, which uploads only server-unknown xorbs but *always* POSTs its shard — and that `/shards` POST is what calls `register_files(<target repo>, …)`. So even the "two remotes, one server" case registers the file under the target cheaply. CDC is deterministic, so the re-cleaned hash must equal the sourced hash; a mismatch aborts the push. If no remote can supply an already-committed file, the push **fails** rather than advertise a pointer the target can't reconstruct.

Auth is minted against the **push target** (`resolver::resolve_for_remote` with the hook's `$2` URL), not `origin` — the write token sets the server-side repo scope of every upload. After the session finalizes, the uploaded files' markers are drained under the store lock; the objects are swept once no marker remains, unless a git op is in flight (gc finishes it later).

`progress.rs` draws a git-styled stderr line (`Uploading bales: 47% (4/8), 14.5 MiB | 3.0 MiB/s`; `n` derives from the byte fraction since xet only reports bytes). The live line appears only on a terminal and only after 200 ms. On success a summary always prints (terminal or not), finalized in place and `\n`-terminated so it stays above git's `Enumerating objects…`: `<bytes transferred> | <rate>, done.`, with ` (+ <size> deduped)` for a partial dedup, or `<size> already on server, done.` when nothing was transferred (from xet's `DeduplicationMetrics`). On failure it only erases the live line — no misleading "done".

`git-bale install --local` writes managed hooks, each tagged with a `bale-marker:` line so `uninstall --local` never removes a hand-written hook. `pre-push` runs `exec git-bale push-pending "$@"` (remote name + URL as `$1`/`$2`, ref updates on stdin); run by hand with no args, push-pending authenticates against `origin`, treats HEAD as the push (whole history) and uploads only the staged content HEAD reaches, re-sourcing nothing. `post-checkout`/`post-commit`/`post-merge` run `git-bale gc || true`. A foreign pre-push hook makes install **fail** (it gates upload correctness); a foreign gc hook is **skipped with a warning**. `--global`/`--system` installs write no hooks and warn that `install --local` is needed per repo — without the pre-push hook `git push` uploads nothing. Hooks go where git looks: `core.hooksPath` (tilde-expanded; relative to the worktree root, or the git dir when bare), else the **common** git dir's `hooks/`.

### Fully-local mode

`git-bale init-local [--store <path>] [--shared]` (unrelated to `install --local`, whose `--local` is the git-config scope) puts a repo into fully-local (no-server) mode: it claims the store (or, with `--shared`, registers the repo in `<store>/repos/`) before touching config, then installs the filter and the gc hooks (no pre-push hook — nothing to drain) and sets `bale.local=true`, `bale.localShared=true` with `--shared`, and `bale.localStore=<canonical path>` for any non-default store — including `--shared` without `--store`, which defaults to `~/bale-local`. Keys and env overrides are listed in the [README](../README.md#configuration).

The mode is always explicit — no auto-fallback when a server is unreachable, so a misconfigured server never silently lands load-bearing data elsewhere — and a repo is either local or server-backed, never both. The store is staging's `LocalClient` layout made durable; object data never lives in the chunk cache, which stays a pure perf layer.

**Limitations.** A per-repo store is not carried by `git clone` (even a same-machine clone), so the clone can't reconstruct its large files; use `--shared` for several working copies on one machine. No cross-repo refcounting: a shared store is append-only, reclaimed only by `git-bale prune --shared`.

**Object store resolution** (`store::object_store_root`, canonicalized): server mode → `.git/bale/staging/`; local mode → `bale.localStore` (tilde-expanded) if set, else `.git/bale/store`.

**Markers stay per-repo.** `file-index/` markers, the clean-cache and the manifest cache always live under the common `.git/bale/` — only xorbs/shards relocate to the store. A shared store never holds one repo's markers.

**Smudge:** hot path → store reconstruct → **hard error**. No lukewarm path, no network. A store that can't fully reconstruct the file, or bytes failing sha256, is an error rather than a partial, corrupt or empty file.

**push-pending** is a no-op: `git push` moves only pointer commits; large-file data stays machine-local.

**gc** uses server mode's liveness (see [Staging reconciliation](#staging-reconciliation-git-bale-gc)). Unlike server-mode staging, "no marker left" does not mean "nothing live": a repo deleted and re-cloned at the same path re-claims its old external store with zero markers, and that store is the only copy of every committed file. So before a whole-store sweep (zero markers, or the last dead marker just dropped) gc reads the files the store holds from its shards and sweeps only if none of them is reachable (same liveness scan); a partial clone never sweeps. Tested by `local-reclone-same-path`. Shared store: gc is append-only — it never deletes objects or markers from the shared store, because another registered repo may reference the same objects. `git-bale prune --shared` reclaims.

**Interrupted prune.** If a `prune` swap crashed between its two renames, the store path is missing while `<store>.old.<pid>` (or `<store>.compact.<pid>`) exists. `object_store_root` then refuses — clean, smudge, gc, and prune all error, naming the directory to rename back — instead of silently recreating an empty store that would orphan every committed pointer.

**Store lock (`store::StoreLock`).** Every store mutation takes an exclusive advisory lock (`fs4`: `flock`/`LockFileEx`) on `<store-parent>/.<storename>.lock` — outside the store so prune's rename can't move it, and derived from the **canonicalized** path (nearest existing ancestor for a not-yet-created store) so two spellings share one lock. `clean` holds it **briefly, per file**, across {write objects → write marker} (a cache hit, just long enough to touch the marker); `gc` takes it non-blocking (`try_exclusive`, skipping if held) across {read markers → drop dead → sweep}; `push-pending` across its drain; `prune` for its whole run; registry writes while writing. Smudge never blocks on it. The OS releases it on process death, so no stale locks.

Two windows must both be closed:
- **object-vs-marker** — a sweep between clean's object write and its marker write would delete an object nothing protects yet. The per-file lock closes it.
- **marker-vs-index** — git writes its index (or the ref) *after* the filter returns, so a marker can exist before git references the file, and a gc reading the stale index would sweep its only copy. clean has released the lock by then, so instead **gc defers while any git index/ref `*.lock` exists** (`gc::git_op_in_flight`): `index.lock` for `add`/`commit`; for `git stash`, a temporary `index.<temp>.lock` and then `refs/stash.lock` (stash cleans against a temp index whose `GIT_INDEX_FILE` gc can't see); ref locks generally; and stopped rebase/am/sequencer/autostash state. It's checked *after* taking the store lock, so a clean can't slip between the check and the marker read. The one lock-free residual — a stash's commit-object write between releasing its temp index lock and taking `refs/stash.lock` — is closed by the **reclaim grace**: gc never drops or sweeps a marker cleaned within `BALE_GC_GRACE_SECS` (default **2 weeks**, git's `gc.pruneExpire`: a dropped stash or orphaned commit stays recoverable that long, so its bytes must too). Every clean writes or touches the marker, so its mtime is "last cleaned". Abandoned content lingers up to the grace (and in server mode a push-pending in that window might upload it — wasteful, not incorrect).

Why the lock must stay per-file is in [Tricky bits](#tricky-bits).

**Registration.** In shared mode, clean and gc (re)register the repo under its current canonical common git dir on every run (`store::register_repo_locked`, idempotent, under the store lock), so a moved or copied repo is registered before prune could mistake its content for unreferenced. A registry entry whose path no longer exists is a moved or deleted repo: prune refuses unless `--force`, which skips it and so **deletes content only that repo referenced** — run a gc in the moved repo first.

**`git-bale prune --shared`** compacts a shared store:

1. Takes the store lock at a moment no registered repo has a git index/ref `*.lock` (a clean may have written a marker git hasn't recorded yet). It never waits *while holding* the lock — that op's next clean may be blocked on it — but releases, sleeps, and retries (up to ~2 min).
2. **Aborts if any registered repo path is missing** — its objects may be the only copy. Pass `--force` to skip missing repos. Any unreadable repo, ref, reflog, index, or object aborts (fail closed).
3. Liveness is gc's liveness (`gc::reachable_hashes`: every pointer reachable from refs, reflogs, indexes, worktree HEADs, rebase/merge state) **unioned over every present registered repo**, plus markers younger than the gc reclaim grace. It never depends on which repo holds a marker: content cleaned by repo B can be referenced only by repo A (A fetched B's commit), and B may since have been deleted. `--force` skips a missing repo (content only it referenced is deleted) — content a present repo reaches is always kept. Which files the store actually holds, and their sizes, come from the store's own shards (`MDBShardFile::read_all_file_info_sections`); live hashes the store doesn't hold are ignored.
4. Retires bookkeeping for everything reclaimed (and stale markers) **before** the swap: forgets those hashes from every present repo's clean-cache and drops their markers. A later failure then only leaves unreferenced objects behind; the reverse order could leave a marker or cache entry vouching for deleted bytes.
5. Reconstructs each live file from the old store and re-cleans it into a fresh `<store>.compact.<pid>` (deterministic CDC re-dedups), asserting the round-trip hash, copies the registry, **fsyncs the whole compacted tree**, then renames the old store to `<store>.old.<pid>` and the compacted one into place and fsyncs the parent dir. A failed second rename rolls back; a crash between them is caught by the interrupted-prune refusal above.

Concurrent `git add` just blocks on the store lock; prunes serialize against each other.

### Staging reconciliation (`git-bale gc`)

`clean` only ever *adds* to staging and only a successful `push-pending` drains it, so content `git add`ed and then abandoned (`git reset`, `git checkout`, a branch switch) would otherwise linger forever. `git-bale gc` reconciles staging (or a non-shared local store) against git reachability.

**Only markers older than the reclaim grace are candidates**, filtered before any scanning: every `git status` re-clean refreshes a marker, so without this the full-history walk would run on every hook (tens of seconds on a large repo).

Liveness mirrors git's own gc. A candidate is live if a pointer to it is reachable from:

1. **every worktree's index** — the main `index`, each `.git/worktrees/<id>/index`, and an explicit `GIT_INDEX_FILE` (split indexes are dissolved; sparse-index directory entries are scanned as whole trees; intent-to-add entries are skipped since their empty blob may not exist), and
2. **every tip**: all refs — local *and* remote-tracking — plus **every reflog entry** of every ref (`logs/**` in the common dir and each worktree, so `stash@{1..n}`, reset-away commits and deleted-branch history in HEAD's reflog all count), every worktree's `HEAD`, per-worktree refs, `ORIG_HEAD`/`MERGE_HEAD`/`CHERRY_PICK_HEAD`/`REVERT_HEAD`/`REBASE_HEAD`/`BISECT_HEAD`/`AUTO_MERGE`, and stopped-operation state: `MERGE_AUTOSTASH`, `rebase-merge/{autostash,orig-head,onto,stopped-sha,amend}`, `rebase-apply/{autostash,orig-head,onto}`, `sequencer/{head,abort-safety}`. A `rebase --autostash` (or `pull --rebase` with `rebase.autoStash`, `merge --autostash`) that stops on a conflict records the user's uncommitted changes **only** in its autostash file — no ref, no reflog, no `*.lock` — so without this gc would sweep them. Belt and braces: the existence of `rebase-merge/`, `rebase-apply/`, `sequencer/` or `MERGE_AUTOSTASH` in any worktree git dir also counts as an op in flight, and gc skips. Tags are peeled; a tag of a tree or blob is scanned directly. Commit tips are walked with `rev_walk(...).all()` (nothing hidden), diffing each commit against its first parent so only changed blobs are read (an unreadable parent diffs against the empty tree — a superset). The scan early-outs once every staged hash is found.

**Remote-tracking reachability is not proof of upload**: `git push --no-verify` and pushes to plain-git remotes advance `refs/remotes/*` without running push-pending. In server mode the *only* thing that releases committed staged content is push-pending's drain after a successful upload; gc only reclaims content nothing references at all.

**Fail closed.** Every error while computing liveness — config load, an unreadable index, ref, reflog or worktree dir, a rev-walk or tree-diff failure, a missing object named by a ref/reflog/tree, reftable ref storage (unsupported) — aborts gc with everything kept, and `git-bale gc` prints a one-line `warning: git-bale gc refused to reclaim anything: …` to stderr and exits 1, so the refusal is visible even through the hooks' `|| true`. An unreadable ref must never read as "unreferenced". An unreadable git dir while sniffing for `*.lock` files counts as "op in flight". **Partial clones** (`extensions.partialClone`, a `remote.*.promisor`, or `*.promisor` packs): missing blobs are indistinguishable from corruption, so gc never reclaims there — quietly (debug log; every hook would otherwise repeat a warning) — and prune refuses. push-pending collects the blobs its walk needs that aren't local, has git fetch exactly those (`git cat-file --batch-check` lazily fetches from the promisor), retries once, and only fails — with an explicit partial-clone message — if they're still missing.

Xorbs are shared across files by xet's local dedup, so gc never deletes an individual xorb. Objects are swept only once **no** marker remains (the same all-or-nothing wipe push-pending's drain does); the mixed case drops dead markers and leaves the objects for a later sweep. The sweep is crash-safe: `staging::sweep_objects` renames the whole `<store>/xet` dir (xorbs, shards, the `global_dedup_lookup.redb` index, shard cache) aside to `.xet-sweep-*` before deleting it, so a crash never leaves the dedup index or shards alive while xorbs are gone (a later clean would dedup against chunks that no longer exist); leftovers are finished by the next sweep. Blob reads are header-gated (`find_header`) so non-pointer blobs are never inflated. Phases: `gc-abandon-checkout`, `gc-keeps-unpushed`, `gc-mixed` (`tests/e2e/baleharness/phases/gc.py`).

**gc invalidates the clean-cache for every hash it drops** (`clean_cache::forget_hashes`, *before* removing any marker; a failure aborts with nothing removed). post-checkout also fires on file-level checkouts: `git add f` then `git restore --staged f` leaves `f`'s bytes unreferenced, so gc reclaims them — but the path-keyed cache entry still maps those exact worktree bytes to the now-unbacked pointer, and a re-`git add` would emit a pointer reconstructable from neither staging nor the server (this broke add → unstage → re-add → `stash` → `pop`). Already-pushed content is never dropped by gc (push-pending's drain releases it), so it keeps its cache entry. Guarded by the `basic` phase's stash/pop round-trip and `local-stash-reflog`.

### Hot vs lukewarm vs cold smudge

On `command=smudge` git-bale tries, in order (local mode: hot → store → hard error, see above):

1. **Hot path** — load `.git/bale/manifests/<file_id>.json` (missing/malformed/unknown-version → next path) and assemble the file purely from the local chunk cache; any chunk miss falls through.
2. **Lukewarm path** (server mode) — reconstruct from `.git/bale/staging/` via `TranslatorConfig::local_config`, so `git add big.bin && rm big.bin && git checkout -- big.bin` works before a push. Errors fall through (logged at `debug`). Gated on the file's marker: without it, smudging a hash we never staged (e.g. `git stash`'s HEAD-restore) yields zero terms in xet's `ReconstructionTermManager` and trips a `debug_assert` in its progress tracker (dev builds panic).
3. **Cold path** — `FileDownloadSession::download_to_writer` against the server, then a best-effort manifest fetch into `.git/bale/manifests/` so the next checkout is hot. Manifests store only content-addressed terms (xorb hash + chunk range), never `fetch_info` URLs, which expire after `SIGNATURE_TTL_SECS` (10 min).

**Every path is content-verified before git sees a byte.** xet reconstructs from xorb chunks without re-hashing them, so a corrupt chunk cache, staging dir, local store or server object would otherwise land silently in the worktree. The temp file is truncated before each path and checked against the pointer's `file_size` + `sha256` after (`content_matches`; a pointer without `sha256` is refused as unverifiable). A hot-path mismatch drops the cached manifest and falls through; a lukewarm mismatch falls through to the cold path; a cold-path mismatch through the chunk cache is retried once without it, then fails; a local-store mismatch fails. Failure returns `status=error` (git aborts the checkout) and never seeds the clean-cache. `git-bale mount` verifies the same way, with the same cache-less retry.

**Protocol hygiene.** Each request's payload is drained to its flush *before* any reply, so a per-request failure goes out as `status=error` without desyncing the stream (a failed drain is fatal). Smudge input that isn't a pointer — including anything over the pointer size cap, spilled to disk — passes through unchanged, like git-lfs. Clean input that already *is* a canonical pointer (byte-identical to what git-bale writes, with `file_size` + `sha256`) passes through too, so a worktree checked out before the filter was installed isn't committed as a pointer-to-a-pointer (`local-pointer-passthrough`); a user JSON that merely has a `"hash"` key is cleaned normally. The smudge output file is opened and size-checked before `status=success`; a read error after content streaming has begun follows git's mid-content error form (flush, then a `status=error` list) so error text can never become file content, and a failed write to git tears the filter down.

The cold path passes `0..file_size` (not `FileRange::full()`), which spares a past-EOF block request but does **not** disable block fetching: files over 2 × 256 MiB are always fetched in Range blocks, which is why the server must honor `Range` on `/v1/reconstructions`.

The cold download runs under a **no-progress watchdog** (`download_cold` in `filter_process.rs`, shared with `git-bale mount`). Bytes come from presigned blob-store URLs the *client* fetches directly, so a blob store reachable by the server but not the client (a bundled MinIO presigned as `minio:9000`, a wrong public endpoint) fails only on the client — and xet retries even a DNS "host not found" as a connect error, with a base-squared exponential backoff. xet's default 3 s base parks the second retry for up to ~2.5 h; `main.rs` lowers the default to 10 ms (`HF_XET_CLIENT_RETRY_BASE_DELAY`, an explicit setting wins), but a permanent failure still retries silently. The watchdog counts bytes actually written and aborts once none arrive for `BALE_DOWNLOAD_STALL_SECS` (default 30; `0` disables), dropping the future (cancelling the request and any backoff sleep) and naming the file in a user-facing error. A slow-but-progressing transfer is never killed.

### Auth resolution

`git-bale` holds no baleforgit-server secret of its own. Auth is resolved lazily (`resolver.rs`) and never by clean: once per filter process for the smudge cold path and once per `mount` (read scope), and by push-pending (write scope):

1. **Static pair**: if both `bale.serverUrl` and `bale.token` are set (env `BALE_SERVER_URL` / `BALE_TOKEN` first, else git config), use them as-is. A lone one is ignored with a warning and the forge flow runs — a lone token would otherwise be sent to whatever server some forge advertises, and a lone URL would receive another setup's token.
2. **Remote**: `origin` (HTTP(S), SSH, or scp-style `git@host:owner/repo.git`), or for push-pending the push target's URL (`resolve_for_remote`), so the token's repo scope matches where git is pushing.
3. **Forge authenticate**:
   - HTTPS → `POST {forge}/<owner>/<repo>.git/info/bale/authenticate?op=<download|upload>`. `op=download` tries **anonymously first** so a public-repo checkout never prompts, falling back to Basic auth from `git credential fill` only on `401`/`403`; `op=upload` always sends Basic auth. The password/PAT never travels beyond the forge (`authenticate_http_with_fallback`).
   - SSH → `ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new [-p port] -- <user>@<host> git-bale-authenticate <owner>/<repo> <op>`. User/host starting with `-`, containing whitespace/control chars, or (host) `@` are rejected (`remote::validate_ssh_target`) and `--` ends option parsing, so a hostile URL can't inject `-oProxyCommand=…`. No anonymous path. On unix the subprocess honors `GIT_SSH_COMMAND`, else `core.sshCommand` (git's precedence; run through `/bin/sh` with our args appended, so the user's options win), so a custom key/port/jump host applies to the handshake as to git's transport. This also keeps the e2e harness's isolated `UserKnownHostsFile` in force: ssh finds `~/.ssh/known_hosts` via `getpwuid`, not `$HOME`, so bare `ssh` would write test host keys into the developer's real file.
   - Both return `{href: <baleforgit-server URL>, header.Authorization: "Bearer <forge JWT>"}`; an anonymous download's JWT just carries an anonymous subject, so **baleforgit-server needs no notion of repo visibility** — the forge decides. For an https/ssh remote, a cleartext `http://` `href` or token-exchange `casUrl` is refused unless loopback (`require_tls`) — the JWT / bale token would otherwise cross the network unencrypted.
4. **Token exchange**: `GET <href>/api/models/<owner>/<repo>/bale-{read,write}-token/main` with the forge JWT → bale token (HF-Hub-shaped endpoint). Bale tokens live `DEFAULT_TOKEN_TTL_SECS` (5 min); every CAS client carries a `ForgeTokenRefresher` that re-runs this resolution before expiry — see *Tricky bits*.

Step 3 plus the server's `POST /check_access` callback is the whole forge-integration surface ([`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md)) — no shared secrets.

### `git-bale mount-diff` and `git-bale mount`

Two read-only FUSE mounts sharing one VFS, reader and backend: `mount-diff` shows both sides of a `git diff` with the label folded into each basename (`foo__<labelA>.txt`, `foo__<labelB>.txt`); `mount` shows the tree at one revision with original names. Usage and runtime driver requirements are in the [README](../README.md#mounting-a-diff-or-a-single-rev).

Neither checks anything out: plain blobs are read from the ODB, Bale files reconstructed through the same verified paths as smudge (`try_smudge_from_staging` / `smudge_from_local_store` are shared): hot, then lukewarm in server mode or the local store in local mode (a miss or mismatch is a hard read error, never a network fallback), then cold, which also backfills `.git/bale/manifests/`. `mount-local` guards the local-mode path.

Layout (`crates/git-bale/src/mount/`):

- `mod.rs` — CLI entry, label sanitisation, lifecycle (`run` = diff mode, `run_rev` = single rev). `run_rev` resolves the rev to a tree OID and hands it to the lazy VFS (no tree walk at mount time); one eager root `readdir` makes an empty/mis-targeted mount fail loudly instead of mounting empty.
- `diff.rs` — pure-gix diff (`tree.changes().for_each_to_obtain_tree`) with rename tracking **off** (`track_rewrites(None)`; see the limitation below). The pathspec is applied inside the callback so non-matching changes allocate nothing.
- `vfs.rs` — inode tree (inode 1 = root) behind a single `Mutex`. `build` (diff mode) is fully populated up front; `build_single_lazy` populates each directory from its tree object on first `lookup_child`/`readdir`, and pathspec prefixes prune untouched subtrees. Inodes are stable for the mount's life.
- `reader.rs` — plain blobs cached whole (over 16 MiB is an error telling the user to track the file); Bale files in a 1 GiB byte-budgeted LRU.
- `backend/mod.rs` — `MountBackend` trait and shared path→node helpers; exactly one backend compiles per target (`PlatformBackend` / `ensure_available`: libfuse on unix, WinFsp on Windows).
- `backend/libfuse.rs` (unix) — hand-rolled FFI to libfuse **2.x**'s high-level API (`fuse_main_real`), `dlopen`ed via `libloading` (`libfuse.so.2` on Linux, `libfuse-t.dylib` from fuse-t on macOS) so the workspace builds without it. 2.x is what makes one binding work everywhere: fuse-t reports `2.9.9`, and a libfuse-3-shaped `fuse_operations` shifts every slot after `readlink` (2.x has `getdir` and `utime`), so fuse-t would read our `open` as `truncate` and silently EIO. 3.x's `fuse_config` cache hints become `-o ro,default_permissions,use_ino,kernel_cache,attr_timeout=30,entry_timeout=30,fsname=git-bale`; foreground (`-f`), multi-threaded; libfuse's own SIGINT/SIGTERM handlers unmount on Ctrl-C. `ensure_available` runs first and exits with an install hint if libfuse won't load.
- `backend/winfsp.rs` (Windows) — the same against WinFsp's FUSE-compat layer (`winfsp-{x64,a64,x86}.dll`, `dlopen`ed from PATH or `%ProgramFiles*%\WinFsp\bin`, no SDK at build time). Entry is `fsp_fuse_main_real(env, …)` with a hand-built `fsp_fuse_env` (CRT `malloc`/`free`, no-op `daemonize`/`set_signal_handlers`) and `opsize = size_of::<fuse_operations>()`. argv `-f -o uid=-1,gid=-1 <mountpoint>`, where the mountpoint is a free drive letter or a non-existent directory (so no `exists`/`is_dir` precheck). Files are `0444`/dirs `0555`; WinFsp maps "other" bits to an Everyone ACE. `ensure_available` only proves the DLL loads — a missing kernel driver surfaces as a non-zero `fsp_fuse_main_real` return. Ctrl-C terminates the process and the driver tears the volume down.

Tricky bits:

- **`getattr` never reconstructs.** A Bale `stat` parses `file_size` from the pointer blob; reconstruction waits for the first `read`.
- **Path-based API.** Callbacks get paths, walked component by component on every call — fine for low-thousands of entries; bigger trees want `fuse_lowlevel_ops`.
- **Lazy mounts hold the repo handle** for the mount's life. Commits are immutable, so populated directories are never invalidated. `mount-diff` stays eager — the changeset already bounds it.
- **Active-VFS singleton.** Path callbacks get no user data, so each backend stashes `Arc<DiffVfs>` in a `OnceLock`: one mount per process.
- **WinFsp's `fuse_operations` is not libfuse 2.x's** — don't cross-paste. One version-independent layout (`getdir` slot 1, `readlink` slot 2), i64 `fuse_off_t` everywhere, and its own `fuse_stat` / `fuse_file_info` (32-bit `fh_old`, so `fh` at offset 16 vs libfuse 2.x's 24), transcribed from WinFsp's `inc/fuse/*.h` with `#[repr(C)]`. A wrong width or slot silently corrupts reads or the handle round-trip. CI only proves it compiles and lints for `x86_64-pc-windows-gnu`.
- **Per-open handles.** `op_open` reconstructs once into a `NamedTempFile`; if it fits the LRU it's slurped and cached, otherwise the tempfile lives for the open and `op_read` `pread`s it (handle id in `fi.fh`, dropped on `op_release`). Without this, files over the LRU budget would re-reconstruct on every 128 KiB read.
- **Committed revisions only** — no worktree view (it would need rebuilding the VFS as the index moves).

Limitation: **`mount-diff` does not pair renames.** A rename shows as a deletion on side A and an addition on side B, not a labelled pair under one basename — the price of skipping gix's O(N²) post-walk similarity pass, which dominates on diffs with thousands of changes. For rename-aware viewing of a small diff, use `git difftool`.

## Storage layout

### Filesystem `BlobStore`

```
<data_root>/
├── xorbs/<aa>/<bb>/<full-hex>     # immutable xorb blobs, ≤ 64 MiB each
├── shards/<aa>/<bb>/<full-hex>    # archived shards (BLAKE3-keyed)
└── tmp/<uuid>                     # staging for atomic link
```

`<data_root>` is `BALE_DATA_ROOT` (default `./xet-data`). `<aa>` / `<bb>` are bytes 0 / 1 of the hash in plain (not Xet) lowercase hex, for directory fan-out only. Writes go through an fsynced `tmp/<uuid>` (mode 0600), then `link(2)` to the addressed path, then the tmp is unlinked; a write/fsync failure removes the tmp and errors, so a half-written blob is never visible. `link(2)` fails with `EEXIST` instead of replacing, so of two concurrent writers of one hash exactly one body is ever visible. That matters because equal-hash xorbs can differ in compression, and the recorded frame layout must describe the stored bytes (see *Tricky bits*). Every write, including the "already exists" return, fsyncs the leaf dir and every ancestor up to the data root (errors propagated), so a racing writer's link or fresh fanout dir is durable before metadata depends on it. The data root must support hard links. `replace_xorb` (healing a blob that fails re-verification) uses `rename(2)`. `upload_xorb` runs put/register/settle in a detached task, so a request deadline or client disconnect can't interrupt a write midway. `tmp/` entries older than an hour (crash leftovers) are removed when the store opens. Test-only: `BALE_TEST_FS_WRITE_FAIL` forces `write_atomic`'s failure-cleanup arm on every write (ENOSPC can't be injected without putting `tmp/` on another filesystem, which breaks `link(2)`); the `failure-fs-writefail` e2e phase uses it.

### S3 `BlobStore`

Same key layout under an optional bucket-relative prefix:

```
<prefix>xorbs/<aa>/<bb>/<full-hex>
<prefix>shards/<aa>/<bb>/<full-hex>
```

Idempotency uses `HEAD`-before-`PUT`, and the PUT itself is conditional (`If-None-Match: *`): a 412 means another writer's bytes won, and a 409 (a concurrent conditional PUT in flight) is retried up to 5 times with a re-`HEAD`. So an equal-hash body in a different compression can never overwrite the one whose layout was recorded (`replace_xorb` is the only unconditional PUT). At startup the server writes a probe object twice under `<prefix>.bale-probe/` and **refuses to start** if the second conditional write succeeds, i.e. the endpoint silently ignores `If-None-Match`. If the bucket isn't reachable at startup, the probe is retried before the first xorb put, and puts fail until conditional-write support is proven. Puts request SSE-S3 (AES256) unless `BALE_S3_DISABLE_SSE` is set.

Reconstruction calls `presign_xorb_range` first; a `Some(url)` goes straight into `fetch_info`, taking the server out of the data path. The presigned URL signs the `Range:` header, so the client must send exactly `url_range`, and its host must be reachable by the **client**. When that differs from the server's endpoint (a bundled MinIO at `minio:9000` vs `localhost:9000` for clients), set `BALE_S3_PUBLIC_ENDPOINT_URL`: a second `presign_client` signs download URLs against it while reads/writes stay on `BALE_S3_ENDPOINT_URL`. A mismatch is invisible on push and only surfaces as a client hang on checkout (connect failures to the unreachable host, retried per term).

### SQLite `MetadataStore` schema

```sql
xorbs       (hash BLOB PK, num_chunks, num_bytes_in_cas, num_bytes_on_disk, created_at)
chunks      (chunk_hash, xorb_hash, chunk_index, byte_start, unpacked_bytes)
              PK (chunk_hash, xorb_hash)
              INDEX (xorb_hash, chunk_index)
xorb_frames (xorb_hash, frame_index, on_disk_start, on_disk_len, uncompressed_len,
             chunk_hash)   -- server-computed from the verified body
              PK (xorb_hash, frame_index)
files       (file_hash, repo_type, repo_id, revision, total_bytes, created_at, owner)
              PK (file_hash, repo_id)   -- composite: same content in N repos
              INDEX (repo_id), INDEX (owner)
file_terms  (file_hash, term_index, xorb_hash, chunk_idx_start, chunk_idx_end,
             unpacked_bytes, verification)
              PK (file_hash, term_index)
              INDEX (xorb_hash)
xorb_uploads (xorb_hash PK, owner, num_bytes_on_disk, created_at)
              INDEX (owner)
owner_quotas (owner PK, limit_bytes)
```

`xorb_frames` is populated at upload time from the verified body (`parse_xorb_frames` + `verify_xorb_body` in `bale-server-shard`). It is the *only* source of truth for HTTP byte ranges, and its `chunk_hash` column is the only trusted chunk sequence for a xorb (it feeds dedup responses and file-term verification). The `chunks` table records uncompressed offsets and serves only `chunk_hash → xorb` lookups.

`files.owner` is `RepoRef::owner()`: the authority's accounting owner when `/check_access` returned one, else the part of `repo_id` before `/`. It is denormalised so quota and usage aggregations hit the `files_by_owner` index. `xorb_uploads` charges each uploaded xorb to its first uploader until some file references it (see *Quota enforcement*).

Migrations run on open (idempotent `CREATE TABLE/INDEX IF NOT EXISTS`). There is no backfill path: a database from an incompatible older version (detected by a missing `xorb_frames.chunk_hash`, or a failing `CREATE INDEX` on a missing column) refuses to open and must be recreated. The SQLite file is `BALE_DB_PATH` (default `<data_root>/meta.db`), in WAL mode with a 30 s busy timeout because quota'd uploads serialize on `BEGIN IMMEDIATE`.

### Postgres `MetadataStore`

`bale-server-meta-postgres` is the same schema and queries in the Postgres dialect, selected when `BALE_POSTGRES_URL` is set. Dialect-free helpers and row decoders are shared in `bale-server-meta-common`. The differences that matter:

- **Column types.** `BLOB` → `BYTEA`, `INTEGER` → `BIGINT` (every integer column binds an `i64`; Postgres `INTEGER` is 32-bit).
- **Upserts.** `INSERT OR IGNORE` → `ON CONFLICT DO NOTHING`; `INSERT OR REPLACE INTO files` → `ON CONFLICT (file_hash, repo_id) DO UPDATE`. `file_terms` is **write-once per `file_hash`** (term lists are not canonical, see *Tricky bits*): SQLite relies on its `BEGIN IMMEDIATE` write lock around the `SELECT 1 FROM file_terms` probe, while READ COMMITTED can't serialize two concurrent first registrations, so Postgres takes a `pg_advisory_xact_lock` on the file hash first. The per-term conflict clause is only a backstop.
- **Quota serialization.** SQLite's `BEGIN IMMEDIATE` serializes all writers; Postgres takes a per-owner `pg_advisory_xact_lock(1, hashtext(owner))` in `reserve_xorb_upload` and, when a quota applies, in `register_files` (before any per-file lock, so lock order can't deadlock).
- **Placeholders.** `?` → `$n` in hand-written queries (`QueryBuilder` handles both).
- **Aggregates.** Postgres widens `SUM` over `bigint` to `numeric`, which `try_get::<i64>` can't decode, so every `SUM(...)` is `COALESCE(SUM(...), 0)::BIGINT`. The cast also turns an overflow into a hard error rather than the wrap `nonneg_i64_to_u64` catches on SQLite.
- **Migration concurrency.** Concurrent `CREATE ... IF NOT EXISTS` can collide in `pg_catalog`, so the schema runs in one transaction under a fixed-key `pg_advisory_xact_lock`. Same no-backfill rule as SQLite.

## Auth flow

Two layers:

1. **Token exchange** (`/api/.../bale-{read,write}-token/{rev}`) — takes the upstream bearer, calls `check_repo_access` (purpose `TokenExchange`, sent upstream as `"token"`) then `mint_xet_token`, returns `{accessToken, exp, casUrl}`. `casUrl` is the server's own `BALE_PUBLIC_URL`, so subsequent CAS calls come back here. When the authority returns a canonical `repo_id` and `owner`, the token is minted for **that** scope key and accounting owner rather than the client-typed name, so case variants (`Alice/Repo` vs `alice/repo` on a case-insensitive forge) can't split one repo's files or dodge an owner quota; see [`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md) for choosing the key. Bale tokens are HS256 JWTs signed with `BALE_JWT_SECRET_HEX`, live 5 minutes (the client refreshes via the forge), and carry `iss: "baleforgit"` / `aud: "baleforgit-cas"`, both required on verify (zero leeway), so a JWT from another issuer sharing the key never verifies.

2. **Bale token middleware** — wraps the CAS routes (`/v1/reconstructions`, `/v1/chunks`, `/v1/xorbs`, `/shards`). Verifies `Authorization: Bearer <jwt>` via `verify_xet_token` (401 on failure), attaches `TokenClaims` to the request, and enforces scope by method: POST with a read token is 403. Everything else is outside it: token exchange (upstream bearer), `/xorb/...` (signed URL), `/v1/files` (forge JWT in the query), and the usage/quota routes (Bale JWT or admin bearer, checked inline).

The binary (`bale-server-bin`) picks the `RepoAuthz` impl at startup:

- `BALE_AUTHZ_HTTP_URL` set → `HttpAuthz`, which POSTs to `{url}/check_access` (5 s connect / 10 s total timeout, 64 KiB response cap). Only `check_repo_access` is delegated. It never follows redirects: a 3xx would re-POST the body, which carries the user's bearer, to whatever `Location` names, so point the URL at the final endpoint.
- Otherwise → `ConfigAuthz`, populated from `BALE_GRANTS` (`hub_token:user:repo_id:scope,...`; exact `repo_id` match, constant-time bearer compare). Dev use; with neither set, every request is refused.

### Why JWTs (HS256) and not opaque tokens?

The verifier needs the user/repo/scope tuple on every request and is the same process as the issuer, so a self-contained signed token saves a DB round-trip per request. If a `RepoAuthz` impl ever needs to mint out-of-process, switching to RS256 is local to `bale-server-tokens`.

## Owner accounting and quotas

Usage is accounted per **owner**: `RepoRef::owner()`, i.e. the authority's accounting owner when `/check_access` returns one, else the namespace before `/` (`alice/big-model` → `alice`). Nothing distinguishes users from orgs.

`GET /v1/usage/{owner}` returns `{owner, raw_bytes, stored_bytes, dedup_savings_bytes, quota_bytes}`:

- **`raw_bytes`** — `SUM(files.total_bytes)` for the owner, each file's `total_bytes` being the sum of its terms' `unpacked_segment_bytes`. The no-dedup baseline, for display only.
- **`stored_bytes`** — `SUM(num_bytes_on_disk)` over the distinct xorbs the owner's files reference, **plus** the owner's own uploaded xorbs no file references yet (see below). **No cross-owner accounting**: a xorb two owners reference counts in full for each, so an owner's usage never depends on what another owner pushes or deletes, and quota enforcement stays stable.
- **`dedup_savings_bytes`** — `raw_bytes - stored_bytes`, saturating at 0 (orphan uploads can make stored exceed raw).
- **`quota_bytes`** — the effective quota, or `null` for unlimited.

`GET /v1/usage/repo/{owner}/{repo}` returns `{repo_id, raw_bytes, stored_bytes, dedup_savings_bytes, exclusive_bytes}` for the full `repo_id` (no quota field; quotas are owner-scoped). It's meant for a forge's repo settings page. `raw_bytes` is the repo's total size. `stored_bytes` counts every xorb the repo references, so sibling repos sharing xorbs double-count. **`exclusive_bytes`** is the genuinely per-repo number: on-disk bytes of xorbs this repo references that no other repo **of the same owner** references, i.e. how much the owner's `stored_bytes` would drop if the repo were deleted. Cross-owner sharing is ignored, as above. Always `<= stored_bytes`.

### Quota enforcement

The effective quota is the per-owner override (`PUT /v1/quotas/{owner}`), else `BALE_DEFAULT_QUOTA_BYTES`, else unlimited. Two enforcement points:

1. **`POST /v1/xorbs`**: a xorb whose blob already exists is content-addressed-idempotent and never charged or rejected. Otherwise `reserve_xorb_upload` checks `stored + body size ≤ quota` and records the charge in one per-owner-serialized transaction (`xorb_uploads`), *before* the blob is written, so concurrent uploads can't jointly overshoot. The charge is settled to the stored body's on-disk size afterwards, or released if the write fails; a reservation whose blob never landed (crash) stops counting after an hour. Charging unreferenced uploads closes the "POST xorbs, never send a shard" bypass.
2. **`POST /shards`**: before `register_files`, the handler projects current stored bytes plus `unaccounted_xorb_bytes_for_owner` (on-disk sizes of referenced xorbs the owner neither references through its files nor already pays for as its own uploads, so a push isn't charged twice). `register_files` then rechecks the same thing inside its transaction (SQLite `BEGIN IMMEDIATE`; Postgres a per-owner advisory lock), so concurrent shards can't each pass a separate pre-check. Either failure is 413 with no file rows written. This check is load-bearing: without it, the xorb-time "skip if exists" would let an owner reference someone else's xorbs for free.

Only a registration that *grows* usage is refused, so an idempotent re-push still succeeds after a quota is lowered.

Over-quota uploads get **413** (`storage quota exceeded ...`), not 429: xet retries 429 and 5xx with a backoff that squares each step (3 s, then up to ~2.5 h), so an over-quota push hung for hours. 413 is fatal to xet and otherwise unused by legitimate xet traffic. xet discards response bodies, so `git-bale`'s `explain_quota_exceeded` keys on the status to print a single user-facing line. git-bale also defaults `HF_XET_CLIENT_RETRY_BASE_DELAY` to 10 ms (retries at 10 ms, 100 ms, 1 s, 10 s, 100 s), so transient 5xx don't stall a push for hours either.

Usage-endpoint auth (see *Wire surface*): an owner token must match `repo.owner()` exactly, so an `alice/x` token can't read bob's totals; the repo endpoint requires a token for exactly that repo, so it can't probe sibling private repos; the admin bearer bypasses both for operator dashboards. `BALE_ADMIN_TOKEN_HEX` must decode to exactly 32 bytes; when unset, `PUT /v1/quotas` answers 404.

### No server-side GC

Nothing is ever deleted. A blob GC can race a client that just learned the blob from a dedup response and is registering a shard against it, which would leave a registered file pointing at a deleted blob, i.e. data loss. Making that safe needs tombstones checked inside `register_files` plus a long grace, and isn't implemented. Disk growth is bounded by quotas (orphans included), so set `BALE_DEFAULT_QUOTA_BYTES`.

## Connection and request limits

Connection-level limits live in `serve_http` in `bale-server-bin`, which serves over hyper-util because `axum::serve` exposes none of them:

- At most 4096 open connections, and `BALE_MAX_CONNECTIONS_PER_IP` (default 512, `0` = unlimited) per client IP, an IPv6 client counting per /64 since it usually controls the whole prefix. Per-IP rejections are logged at most every 10 s. Slots are released by a drop guard, so a panicking handler can't leak them.
- 30 s header-read timeout. HTTP/2 allows 32 concurrent streams per connection (each unauthenticated stream can cost a forge round-trip).
- Connections are closed gracefully after 10 minutes, so an idle HTTP/2 connection kept alive by pings can't hold a slot forever; in-flight requests then get 15 more minutes before the connection is dropped, so a peer that never reads its responses can't pin it.
- Shutdown (`SIGINT`/`SIGTERM`) closes the listener, gives connections up to 25 s to drain, then waits up to 2 min for detached xorb commits (a `TaskTracker`).

Request-level limits live in `router()` in `bale-server-http`: a 60 s **idle** (per-frame) body timeout, so slow-but-steady uploads pass but stalled ones are dropped; per-request deadlines of 110 s on `/v1/xorbs` (xet gives up after 120 s anyway) and 300 s on `/shards`, answered with 408; at most 16 concurrent xorb uploads (each holds up to ~64 MiB plus decode buffers, and one xet client ramps to 64 parallel uploads); 64 MiB shard bodies and 4 KiB usage/admin bodies. A reverse proxy in front is still recommended for TLS and per-client rate limits.

## Signed transfer URLs

When the blob store doesn't presign, the reconstruction handler embeds URLs of the form

```
{BALE_PUBLIC_URL}/xorb/default/{xorb_hex}?s={start}&e={end_inclusive}&x={unix_exp}&sig={hmac_sha256_hex}
```

`sig` is HMAC-SHA256 under `BALE_TRANSFER_SECRET_HEX` over `xorb_hex|start|end_inclusive|exp`; URLs (and S3 presigns) live 600 s. The transfer handler checks, in order:

- the signature (constant-time compare) — 401 on mismatch;
- the expiry — **403**, not 401, because xet refreshes the reconstruction (new URLs) only on 403, so a 401 would fail any download that outlives the TTL;
- a `Range:` header matching the signed range exactly — 401 if missing or different, so the URL grants one byte range, not the whole xorb (the spec requires this).

It answers 206 with `Content-Range: bytes S-E/*` and the bytes from `BlobStore::get_xorb_range`.

## Observability

Operator-facing env vars and the instrument list are in [`SERVER.md` § Observability](SERVER.md#observability). Implementation notes:

- **Off unless configured.** `telemetry::init` (`bale-server-bin/src/telemetry.rs`) installs an exporter per signal only when `OTEL_EXPORTER_OTLP_ENDPOINT` or that signal's `OTEL_EXPORTER_OTLP_{TRACES,METRICS}_ENDPOINT` is set. Otherwise no provider is registered on `opentelemetry::global`, every instrument resolves to the global no-op, and there are no background threads or sockets.
- **Traces**: an OTLP HTTP/protobuf `SdkTracerProvider` with a batch processor, bridged from `tracing` via tracing-opentelemetry, so the `tower_http::trace` access-log span and any handler spans become OTel spans. The access-log span records method + URI **path only**: `/v1/files?token=` carries a forge bearer and `/xorb/...&sig=` a reusable transfer signature.
- **Metrics**: an OTLP HTTP/protobuf `SdkMeterProvider` with a `PeriodicReader`. Instruments in `bale-server-http/src/metrics.rs` are `LazyLock`s, so they bind to whichever provider init installed. The per-request middleware labels by the `MatchedPath` route pattern, never the raw URI, which would create one series per hash.
- **Blocking exporter.** Both processors export from a dedicated OS thread with no Tokio reactor, so `opentelemetry-otlp` uses `reqwest-blocking-client`; the async client panics there ("no reactor running") and silently drops all telemetry. Export is off the request path, so blocking is harmless. (`opentelemetry_sdk`'s `rt-tokio` feature is enabled but unused; moving to the async client would mean the `experimental_async_runtime` processor variants and their shutdown-in-`Drop` fragility.)
- The `Guard` from `telemetry::init` flushes both providers on drop, so trailing spans/metrics ship on graceful shutdown.

## Tricky bits

Easy-to-get-wrong parts, called out so they don't get re-broken.

- **Xet hash hex encoding** (spec §"Converting Hashes to Strings"). Not plain hex. Bytes are reordered as four little-endian u64s before stringifying. The spec text shows a doc-typo example missing one byte; the actual algorithm produces 64 hex chars from 32 input bytes. See `bale_server_wire::{encode_hash, decode_hash}`.
- **Shard registration is a proof of possession — never trust a shard's claims.** `file_terms` is global and `files` grants read per repo, so an unverified `/shards` lets any writer (a) register a known file hash (it's in every git pointer) into their own repo and read another repo's private bytes, (b) bind a not-yet-uploaded hash to arbitrary bytes for every repo, and (c) inject chunk→xorb mappings via CAS Info that make *other* clients dedup against the wrong bytes. `upload_shard` therefore requires every term xorb to exist with a verifiable chunk sequence (the server-computed `xorb_frames.chunk_hash`). For each file it checks `start < end ≤ num_chunks`, `unpacked_segment_bytes ==` the chunks' sizes, and a **mandatory** per-term verification hash `== term_verification_hash(chunks)`, then recomputes the whole-file merkle hash and compares it to `file_hash`. The verification hashes are what need plaintext chunk hashes. The server never serves those (dedup HMAC-wraps them), so replaying terms seen in a reconstruction response (xorb + chunk ranges) is not enough. The checks run before any write, and every term xorb gets a `xorbs` row derived from its verified layout, so accounting can't be dodged by omitting CAS blocks. Empty/inverted ranges are rejected here too, and both reconstruction sites keep a defensive `start >= end` guard. Guarded by the `shard-guards` e2e phase.
- **The recorded frame layout must describe the exact xorb bytes stored.** The xorb hash covers *decompressed* chunks, so one hash has many valid encodings (per-frame None / LZ4 / BG4, different LZ4 output), each with different frame offsets. `put_xorb` is first-writer-wins on every backend (fs `link(2)`, S3 `If-None-Match: *`). The layout is **only ever derived from the stored body, after the put**: an insert means the stored body is ours, and otherwise `upload_xorb` reads the stored body and derives the layout from it. If the stored body no longer verifies, the upload heals it with `replace_xorb` and loops until the registered layout still describes the landed body. Every writer therefore writes the same layout for an immutable blob. A layout is never registered ahead of the put, because a delayed or cancelled request could then pin offsets for bytes that lost the race; that once silently broke every mid-xorb term of every file using the xorb. A crash between put and register leaves a blob with no layout, and `ensure_layout` derives it from the blob on first use (reconstruction, download, shard, dedup). Residual: two *concurrent* heals of an already-corrupt blob, plus a crash inside the loop, can leave a mismatch. `/v1/files` re-derives the layout from the blob when a term fails chunk verification, and clients reject mismatched bytes by sha256, so it surfaces as a failed download, never as wrong bytes. Guarded by the `xorb-layout-heal` e2e phase.
- **Write ordering across the two stores** — both upload handlers write the blob store first and metadata last, so metadata never names a missing blob:
    - **`POST /v1/xorbs/...`** puts the blob, then registers the layout derived from the stored body (previous bullet), then the `xorbs`/`chunks` rows from the verified chunk hashes, so dedup only advertises xorbs whose blob exists. A crash in between leaves a blob with no layout, which `ensure_layout` re-derives.
    - **`POST /shards`** verifies and registers term-xorb metadata, checks quota, then `put_shard` (content-addressed archive; an orphan is harmless and a retry rewrites the same key), then commits every file in ONE atomic `register_files` batch. A fault rolls back the whole shard, so "500 ⇒ nothing happened" holds; the old per-file loop could leave N-1 file rows committed — readable by anyone who knew the hash — while the client believed the upload failed.
- **`url_range.end` is inclusive** in the wire format (matches HTTP `Range:` semantics). The chunk-index `range.end` is **exclusive**. We translate carefully in `get_reconstruction`.
- **Idempotency** — `POST /v1/xorbs/{prefix}/{hash}` and `POST /shards` are content-addressed; re-uploading the same content MUST return 200, not error. `was_inserted: false` on the xorb side; `result: 0` on the shard side (we currently always return `1`; both are spec-defined "success — value is informational").
- **The server does decompress on `POST /v1/xorbs/...` (and only there).** Every chunk frame is decompressed (None / LZ4-frame / BG4-LZ4, `bale_server_shard::xorb::decompress_frame`) **with output capped at the frame's declared `uncompressed_length` + 1**, after rejecting bodies past xet's own limits (> 8192 chunks or > 64 MiB uncompressed) before any decoding. LZ4 expands ~255×, so an unbounded decode of one 16 MiB frame is a multi-GiB allocation — one write token could OOM-kill the server. On `spawn_blocking`, the server recomputes each chunk's hash, aggregates the xorb hash and compares it to the URL hash; a mismatch is a 400 before anything is persisted (`verify_xorb_body`). This is the load-bearing check that stops a writer corrupting the CAS. Elsewhere payloads stay opaque: reconstruction streams raw xorb bytes through signed URLs.
- **Shard `byte_start` / `unpacked_segment_bytes` live in *uncompressed* coordinate space**, NOT on-disk bytes. The CAS Info section in an MDB shard records each chunk's offset within a *conceptual* uncompressed xorb (xet-core's `XorbChunkSequenceEntry::chunk_byte_range_start` accumulates `c.data.len()` pre-compression). On-disk byte ranges live separately in the `xorb_frames` table, populated by walking the chunk frame headers when a xorb is POSTed (`bale_server_shard::xorb::parse_xorb_frames`). Reconstruction MUST build `url_range` from `xorb_frames`, not from the `chunks` table — using uncompressed offsets gives wrong byte ranges for any real LZ4-compressed xorb.
- **A file's term list is NOT canonical, and `file_terms` is global — so term registration is write-once per `file_hash`.** `file_hash` is the merkle hash of the file's *content*, but how those chunks are grouped into xorb-referencing terms depends on global dedup: a later clean that matches different pre-existing xorbs produces a different *number* of terms for byte-identical content. `file_terms` is keyed `(file_hash, term_index)` with no repo column (it's shared across repos), so a naive per-term `INSERT OR IGNORE`/`ON CONFLICT DO NOTHING` *merges* two differently-segmented registrations: it keeps the old terms where indices collide and appends the longer list's tail, leaving `Σ unpacked_bytes > file_size`. That over-describing list is silently fatal — on reconstruction with a cold client cache, xet's "trim the last term to the query range" step computes `last_term_shrinkage = Σterms − file_size`, subtracts it from the final term's byte range, underflows `u64`, and `slice`-panics the client (`FileTerm::extract_bytes`, seen as `range end out of bounds: ~2^64`). The fix: register the term set **write-once** — if any term row exists for the hash, leave it (the first complete list fully describes the content). SQLite relies on its single-writer transaction; Postgres (READ COMMITTED) takes a `pg_advisory_xact_lock` on the hash so two concurrent first-registrations can't both insert. Defense in depth: `lookup_file` re-checks `Σ terms` against `files.total_bytes` and returns 500 rather than serve an inconsistent reconstruction. It requires *some* registration to record that size, not an arbitrary `LIMIT 1` row, so one repo's bad row can't 500 every repo. Postgres takes the per-hash advisory lock before the `files` upsert and registers a shard's files in hash order, so two overlapping shards can't deadlock. See `write_file_in_tx` in both meta stores.
- **`FileMetadataExt.sha256` is stored in xet-core's byte-reversed-within-u64-groups order**, not natural sha256 byte order. xet-core treats every `Hash32`-shaped field uniformly as `[u64; 4]` and writes LE u64s, even for sha256 (which has no semantic reason to be reordered). The shard parser un-swaps with `swap_u64_groups` so `ParsedFile.sha256` matches the standard byte order; the serializer applies the inverse swap on the way out.
- **Chunk frame format** (8-byte `XorbChunkHeader`): `version(u8) | compressed_length(u24 LE) | compression_scheme(u8) | uncompressed_length(u24 LE)`. Schemes: 0=None, 1=LZ4 frame, 2=BG4-LZ4 (byte-group-of-4 deinterleave then LZ4 frame). Scheme 99 (Auto) is a sentinel and must never appear on the wire. baleforgit-server parses the headers for the byte-range layout and decompresses payloads only to verify uploads (see above).
- **Body limits.** Shards are capped at 64 MiB. Xorbs are capped at 64 MiB + 8 B × 8192 + slack, **not** 64 MiB: xet cuts on *unpacked* bytes and stores incompressible chunks raw plus an 8-byte header, so a legit serialized xorb can exceed 64 MiB, and a flat 64 MiB cap failed ~1 in 8 xorbs of video/zip data. The real caps (≤ 64 MiB unpacked, ≤ 8192 chunks, and frames must consume the body exactly: xet uploads no footer, so trailing bytes would be stored unverified and unaccounted) are enforced in `verify_xorb_body`. Guarded by the `oversize-xorb` e2e phase. At most 16 xorb uploads are processed at once (`ConcurrencyLimitLayer` on the route, which also covers body buffering), each with a 110 s deadline. Further uploads queue rather than let one aggressive push run the server out of memory, and a trickling client can't pin a slot (xet abandons a xorb POST after 120 s anyway). Shard verification loads only the frame spans the terms name (`MetadataStore::xorb_frame_spans`), never whole 8192-frame layouts, and verifies file by file in batches of at most 64K frames as they arrive. The first mismatch rejects, frames are fed straight into an incremental merkle hasher (`bale_server_shard::FileHasher`, equal to xet's `file_hash`; `bale-e2e-tools selfcheck` cross-checks it on random sequences), and hashing runs on `spawn_blocking`. Memory per file is therefore constant, whatever the file size. A shard may span at most 256 Mi chunks in total (≈ 16 TiB of file content at xet's 64 KiB average chunk; 400 above that) to bound CPU, and at most 4 file verifications run at once. Empty or inverted term ranges are rejected at parse time, and blob-existence probing stops at the first missing xorb. A short span heals from the blob only when the xorb has no layout at all, so a term running past an existing xorb's end can't force full-layout loads.
- **Shard magic tag** — the 32-byte `MDB_SHARD_HEADER_TAG` is `b"HFRepoMetaData" + [0, 85, 105, 103, 69, 106, 123, 129, 87, 131, 165, 189, 217, 92, 205, 209, 74, 169]`, lifted verbatim from xet-core's `mdb_shard::shard_format::MDB_SHARD_HEADER_TAG` at the `git-xet-v0.2.1` tag. Our parser still accepts any 32-byte tag (so shards from older toolchains round-trip), but the serializer emits this canonical value so xet-core's strict header check accepts what we produce.
- **Token `exp` is UTC unix seconds and is compared against the *local* clock — client and server clocks must agree (NTP).** Tokens live `DEFAULT_TOKEN_TTL_SECS` (5 min, in `bale-server-authz-{mem,http}`). xet's `TokenProvider` calls the refresher once `expiration <= local_now + 30s`; git-bale's `resolver::ForgeTokenRefresher` re-runs the full forge resolution and is wired into **every** CAS client (push-pending, cold smudge, `mount`, `fetch_manifest`), which is what lets one operation outlive a token and makes a 5-minute TTL safe (without a refresher, xet fails hard with `RefreshFunctionNotCallable`). It can't fix clock skew: `exp` is minted on the *server's* clock, so a client running more than the TTL ahead sees every fresh token as already expired. `ForgeTokenRefresher` counts consecutive already-expired re-mints and after `MAX_EXPIRED_REFRESHES` (3) fails with an explicit "sync clocks (NTP)" error instead of storming the forge. This bites podman on macOS, whose VM clock lags the host after sleep.
- **The clean store lock is per-file (brief), and gc skips while a git op is in flight — do NOT "fix" this by holding the clean lock longer** (windows explained under *Store lock* in [Fully-local mode](#fully-local-mode)). Holding it for the filter-process lifetime **deadlocks**: a porcelain op (`git stash`, `git commit -a`) keeps the filter alive holding the lock, then nests another `git` whose clean blocks on it while the outer op waits for the inner one (it hung the `offline-no-network` phase). Don't narrow `git_op_in_flight` back to the main `index.lock` either: `git stash` cleans against a *temporary* index, so it must also see `index.<temp>.lock` / `refs/stash.lock`. `local-clean-gc-race` and `local-cache-hit-gc-race` (widened with `BALE_TEST_CLEAN_MARKER_DELAY_MS` / `BALE_TEST_CLEAN_CACHE_HIT_DELAY_MS`) prove both windows closed; `local-concurrent-stress` checks no deadlock.
- **Dedup-shard footer lookup offsets must be non-zero even with no lookup tables.** `get_dedup_chunk`'s shard omits the file/xorb/chunk lookup tables (`*_num_entry = 0`), but `serialize` must still write each lookup *offset* as `footer_offset` (the section end), not 0. The client runs `read_all_truncated_hashes` on every dedup shard it ingests into its `ShardFileManager`; for a table-less shard it computes the xorb-info byte range as `(xorb_info_offset, file_lookup_offset)` and a 0 there underflows `file_lookup_offset - xorb_info_offset` → panic (debug) / multi-exabyte alloc → OOM (release), killing the push. xet's own serializer sets the offset even when the table is absent; we match it. Guarded by the `global-dedup-shard` e2e phase.

## Known gaps

Open items from the 2026-05 data-loss audit, kept here so they aren't lost:

- **No S3 PUT checksum.** S3 `put_xorb`/`put_shard` send no `Content-MD5`/`x-amz-checksum-*`; integrity rests on the server re-verifying xorb hashes before the put and clients verifying sha256 on read.
- **`BALE_AUTHZ_HTTP_URL` accepts `http://` for any host** (the client refuses cleartext to non-loopback forges; the server doesn't). Redirects are disabled.
- **`BALE_DATA_ROOT` defaults to `./xet-data`** (relative to the server's cwd).
- **Tokens carry no `nbf`/`jti`**; `iss`/`aud` are required.
- **`RangeJson` serves both chunk-index (exclusive end) and byte (inclusive end) ranges** — see *`url_range.end` is inclusive* above.
- **Startup only warns** when the S3 `head_bucket` probe fails or `BALE_PUBLIC_URL` is unset on a non-loopback bind.
- **Clean-cache chunk fingerprints are xxh3-64** — change detection, not integrity; every smudge still verifies sha256.
- **Test gaps:** no ENOSPC or S3 5xx injection (`failure-s3-conndrop` and the fs write-fail hook in `xorb-layout-heal` cover drops and fs write errors).

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
| Config loader (env + gix config snapshot) | `crates/git-bale/src/config.rs` |
| Remote URL parsing (http/https/ssh) | `crates/git-bale/src/remote.rs` |
| Forge auth resolver | `crates/git-bale/src/resolver.rs` |
| `git-bale install` / `git-bale uninstall` (+ pre-push / post-checkout / post-commit / post-merge hooks) | `crates/git-bale/src/install.rs` |
| `git-bale push-pending` (drain `.git/bale/staging/`) | `crates/git-bale/src/push_pending.rs` |
| Upload progress line | `crates/git-bale/src/progress.rs` |
| `git-bale gc` (reconcile staging / local store against git reachability) | `crates/git-bale/src/gc.rs` |
| `git-bale prune --shared` (compact shared local store) | `crates/git-bale/src/prune.rs` |
| Object store resolution, store lock, ownership, shared-store registry | `crates/git-bale/src/store.rs` |
| `git-bale init-local` (no-server setup) | `crates/git-bale/src/main.rs`, `install.rs`, `store.rs` |
| Staging paths, markers, crash-safe object sweep | `crates/git-bale/src/staging.rs` |
| Durable writes (tmp → fsync → rename → fsync dir) | `crates/git-bale/src/fs_util.rs` |
| `git-bale track` (`.gitattributes` writer) | `crates/git-bale/src/track.rs` |
| `git-bale mount-diff` / `git-bale mount` (read-only FUSE views) | `crates/git-bale/src/mount/` |
