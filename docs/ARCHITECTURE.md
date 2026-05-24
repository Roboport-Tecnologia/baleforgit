# Architecture

This document describes the internals of `xet-server`: how the protocol pieces map to code, what each pluggable trait is for, and the gotchas of the Xet wire format.

## Goals

1. Speak the [Xet protocol](https://huggingface.co/docs/xet/index) well enough that an unmodified `git-xet` client can push and pull through us.
2. Keep everything that touches storage, persistence, or authorization behind a **trait** so the same server can later run on top of S3 / Postgres / GitLab / Gitea.
3. Don't reimplement what xet-core (the client crates) already does well; reuse hashing/chunking semantics, but write our own server-side state.

## Component view

```
                ┌──────────────────────────────────────────────────────┐
                │                 git-xet client                       │
                │  (unmodified — uses HF API to fetch CAS URL+token)   │
                └────────────────────┬─────────────────────────────────┘
                                     │ HTTPS
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
              ▼                      ▼                      ▼
   ┌─────────────────────┐   ┌──────────────────┐   ┌──────────────────┐
   │  Token endpoint     │   │   CAS API        │   │  Transfer URL    │
   │  (mock HF Hub)      │   │   /v1/...        │   │  /xorb/...       │
   │  /api/{type}s/...   │   │   uploads/dl     │   │  (signed range   │
   │  /xet-{rw}-token/.. │   │   recon/dedup    │   │   GET)           │
   └──────────┬──────────┘   └────────┬─────────┘   └────────┬─────────┘
              │                       │                      │
              ▼                       ▼                      ▼
   ┌────────────────────────────────────────────────────────────────────┐
   │                       xet-server (single Rust binary)              │
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
   │   │ Azure (later) │    │ (later)   │      │ GitLab/Gitea (later)│  │
   │   └───────────────┘    └───────────┘      └─────────────────────┘  │
   └────────────────────────────────────────────────────────────────────┘
```

## Request flows

### Upload (write-token scope required)

1. Client splits the file via gearhash CDC into chunks (~64 KiB target, 8 KiB min, 128 KiB max).
2. Client may query `GET /v1/chunks/default-merkledb/{hash}` for any chunk whose hash matches the eligibility rule (last 8 bytes mod 1024 == 0); server replies with a shard whose CAS Info section lists nearby xorbs that contain that chunk (chunk hashes HMAC-wrapped — see *Global dedup* below). *Endpoint pending — M6.*
3. Client groups new chunks into xorbs (≤ 64 MiB serialized, ~1024 chunks each) and uploads them with `POST /v1/xorbs/default/{xorb_hash}`. Server verifies the URL hash is well-formed, persists the xorb blob, returns `{was_inserted: bool}`.
4. Client builds a shard with **File Info** (each file → list of terms `(xorb_hash, chunk_index_range, unpacked_segment_bytes)` plus per-term verification hashes) and **CAS Info** (per new xorb: the chunk hashes and their byte offsets inside that xorb). Client POSTs the shard to `/v1/shards`.
5. Server:
   - verifies every referenced xorb already exists (otherwise 400),
   - parses CAS Info and writes one `chunks` row per `(chunk_hash, xorb_hash, chunk_index, byte_start, unpacked_bytes)`,
   - parses File Info and writes ordered `file_terms` rows,
   - persists the shard blob keyed by BLAKE3 over its bytes (internal-only — the Xet protocol doesn't define a shard hash).

### Download (read-token scope sufficient)

1. Client calls `GET /v1/reconstructions/{file_id}` (optionally with `Range: bytes=..`).
2. Server looks up the file's terms; for each term it joins against the chunk-offset index to compute the xorb byte range covering `[chunk_idx_start, chunk_idx_end)`. It builds `fetch_info` with one **signed transfer URL** per term and the `url_range` bytes covered.
3. Server returns JSON `QueryReconstructionResponse`.
4. Client fetches each `url` with the prescribed `Range` header. The server (transfer layer) verifies the HMAC signature, verifies the Range header matches the signed range (otherwise 401), and streams the bytes from `BlobStore::get_xorb_range`. Client deserializes chunks, strips `offset_into_first_range` from the first one, concatenates.

`Range:` request-side support on `/v1/reconstructions/*` is **not yet implemented** — the prototype always returns the full file's terms. Range support on the transfer URL itself is fully implemented (and mandatory, since signatures cover the byte range).

### Global dedup (M6 — pending)

- Server stores `chunk_hash → xorb_hash` and a notion of "neighborhood" (the other chunks in the same xorb).
- On hit, server builds a synthetic shard whose CAS Info section lists that xorb (and optionally nearby xorbs) with chunk hashes wrapped with a per-shard HMAC key.
- The HMAC key is written into the shard footer. Client matches by HMAC-ing its own chunk hashes against the listing.
- This is what makes Xet's dedup secure: clients can confirm "I have chunk X" without the server ever revealing the full set of chunk hashes it knows about.

## Pluggable traits

All three live in `xet-server-core`. No HTTP handler accesses storage or auth directly — handlers go through these traits via the `Service` struct, which holds `Arc<dyn ...>` (well, `Arc<B>` etc. — kept generic so the binary picks a concrete impl at link time).

```rust
#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn put_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<bool /* was_inserted */>;
    async fn xorb_exists(&self, hash: &XorbHash) -> CoreResult<bool>;
    async fn get_xorb_range(&self, hash: &XorbHash, byte_range: Range<u64>) -> CoreResult<Bytes>;
    async fn put_shard(&self, hash: &ShardHash, body: Bytes) -> CoreResult<()>;
    async fn get_shard(&self, hash: &ShardHash) -> CoreResult<Bytes>;
    async fn presign_xorb_range(&self, hash: &XorbHash, byte_range: Range<u64>, ttl: Duration)
        -> CoreResult<Option<String>>;
}

#[async_trait]
pub trait MetadataStore: Send + Sync {
    async fn register_xorb(&self, xorb: &XorbInfo, chunks: &[ChunkRow]) -> CoreResult<()>;
    async fn register_file(&self, file_hash: &FileHash, repo: &RepoRef,
                           sha256: Option<&Hash32>, terms: &[FileTerm]) -> CoreResult<()>;
    async fn xorb_exists(&self, xorb: &XorbHash) -> CoreResult<bool>;
    async fn lookup_file(&self, file_hash: &FileHash) -> CoreResult<Option<Vec<FileTerm>>>;
    async fn lookup_chunk(&self, chunk_hash: &ChunkHash) -> CoreResult<Option<ChunkLocation>>;
    async fn xorbs_near_chunk(&self, chunk_hash: &ChunkHash, limit: usize)
        -> CoreResult<Vec<XorbInfo>>;
    async fn xorb_chunk_offsets(&self, xorb: &XorbHash) -> CoreResult<Vec<ChunkOffsetRow>>;
}

#[async_trait]
pub trait RepoAuthz: Send + Sync {
    async fn verify_xet_token(&self, bearer: &str) -> CoreResult<TokenClaims>;
    async fn check_repo_access(&self, hub_bearer: &str, repo: &RepoRef, scope: Scope)
        -> CoreResult<UserId>;
    async fn mint_xet_token(&self, user: &UserId, repo: &RepoRef, scope: Scope)
        -> CoreResult<(String, u64)>;
}
```

### Shipped implementations

| Trait | Crate | Impl |
|-------|-------|------|
| `BlobStore` | `xet-server-storage-fs` | `FsBlobStore` — atomic temp→rename writes, byte-range reads |
| `MetadataStore` | `xet-server-meta-sqlite` | `SqliteMetadataStore` — runtime `sqlx` queries (no compile-time DB) |
| `RepoAuthz` | `xet-server-authz-mem` | `AlwaysAllow` (tests) and `ConfigAuthz` (static map of hub bearers → users → repo scopes) |

### Planned implementations

- `BlobStore` on S3-compatible object storage, with real presigned URLs returned from `presign_xorb_range` so the HTTP layer can hand them out directly in `fetch_info`.
- `MetadataStore` on Postgres (only required when we outgrow SQLite — the schema is portable).
- `RepoAuthz` proxying to GitLab or Gitea: verify the hub bearer by calling `/api/v4/user` (or Gitea equivalent), check repo membership via their API, mint Xet tokens with the same `xet-server-tokens` crate.

## Wire surface

CAS API (all behind `RepoAuthz::verify_xet_token`):

| Method | Path | Scope | Purpose |
|--------|------|-------|---------|
| GET | `/v1/reconstructions/{file_id}` | read | File reconstruction metadata |
| GET | `/v1/chunks/default-merkledb/{chunk_hash}` | read | Global dedup query (M6) |
| POST | `/v1/xorbs/default/{xorb_hash}` | write | Xorb upload |
| POST | `/v1/shards` | write | Shard upload + indexing |

Transfer URL (referenced from `fetch_info`, signed query string, no bearer required):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/xorb/default/{xorb_hash}?s=...&e=...&x=...&sig=...` | Byte-range fetch of a xorb |

Mock HF Hub token endpoint:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/{models\|datasets\|spaces}/{ns}/{name}/xet-{read\|write}-token/{rev}` | Returns `{accessToken, exp, casUrl}` |

The token endpoint accepts the client's upstream hub bearer in `Authorization: Bearer ...`, calls `RepoAuthz::check_repo_access`, then `RepoAuthz::mint_xet_token`.

## Storage layout

### Filesystem `BlobStore`

```
<data_root>/
├── xorbs/<aa>/<bb>/<full-hex>     # immutable xorb blobs, ≤ 64 MiB each
├── shards/<aa>/<bb>/<full-hex>    # archived shards (BLAKE3-keyed)
└── tmp/<uuid>                     # staging for atomic rename
```

`<aa>` / `<bb>` are bytes 0 / 1 of the hash in plain (not Xet) lowercase hex — just for sane directory fan-out, not exposed on the wire. Writes go through `tmp/<uuid>` then `rename(2)` for atomicity.

### SQLite `MetadataStore` schema

```sql
xorbs       (hash BLOB PK, num_chunks, num_bytes_in_cas, num_bytes_on_disk, created_at)
chunks      (chunk_hash, xorb_hash, chunk_index, byte_start, unpacked_bytes)
              PK (chunk_hash, xorb_hash)
              INDEX (xorb_hash, chunk_index)
files       (file_hash PK, repo_type, repo_id, revision, sha256, total_bytes, created_at)
file_terms  (file_hash, term_index, xorb_hash, chunk_idx_start, chunk_idx_end,
             unpacked_bytes, verification)
              PK (file_hash, term_index)
```

This is the minimum needed to answer reconstruction queries and global-dedup queries. Migrations run automatically on connection open (idempotent `CREATE TABLE IF NOT EXISTS ...`).

## Auth flow

Two layers:

1. **Mock HF Hub token endpoint** — accepts a hub-style bearer, calls `RepoAuthz::check_repo_access` + `RepoAuthz::mint_xet_token`, returns `{accessToken, exp, casUrl}`. The `casUrl` is the server's own `public_base_url`, so the client sends subsequent CAS calls right back to us.

2. **Xet token middleware** — wraps every `/v1/*` route. Verifies the `Authorization: Bearer <jwt>` via `RepoAuthz::verify_xet_token`, attaches `TokenClaims` to request extensions, and enforces scope by HTTP method (POST requires write; GET tolerates read). The transfer route `/xorb/default/...` and the token-issuance route `/api/...` are explicitly **outside** the middleware — the former uses signed URLs, the latter uses the hub bearer.

### Why JWTs (HS256) and not opaque tokens?

The verifier needs the user/repo/scope tuple on every request, and the issuer is the same process today, so a self-contained signed token saves us a DB round-trip per request. If/when the GitLab/Gitea `RepoAuthz` lives out-of-process, switching to RS256 (issuer ≠ verifier) is a one-line change in `xet-server-tokens`.

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

- **Xet hash hex encoding** (spec §"Converting Hashes to Strings"). Not plain hex. Bytes are reordered as four little-endian u64s before stringifying. The spec text shows a doc-typo example missing one byte; the actual algorithm produces 64 hex chars from 32 input bytes. See `xet_server_wire::{encode_hash, decode_hash}` and its `hash_hex_spec_vector` test.
- **Shard upload validation** — every xorb referenced by an uploaded shard MUST already be in the `xorbs` table (we return 400 otherwise). Per-term `FileVerificationEntry` MUST be present (spec says "MUST be set for shard uploads"). We can additionally re-verify by recomputing the term verification hash against the chunk hashes we already indexed — *not done yet*; tracked as a hardening TODO.
- **`url_range.end` is inclusive** in the wire format (matches HTTP `Range:` semantics). The chunk-index `range.end` is **exclusive**. We translate carefully in `get_reconstruction`.
- **Idempotency** — `POST /v1/xorbs/default/{hash}` and `POST /v1/shards` are content-addressed; re-uploading the same content MUST return 200, not error. `was_inserted: false` on the xorb side; `result: 0` on the shard side (we currently always return `1`; both are spec-defined "success — value is informational").
- **The server never compresses or decompresses chunks.** Xorbs are opaque bytes on the wire. We verify the URL hash is well-formed on upload; the *content* hash of the xorb is part of the future hardening pass — it requires walking the chunk-hash merkle structure which is reconstructable from the shard CAS Info section, so the server *can* eventually re-verify, but the prototype doesn't.
- **64 MiB limits** on both xorbs and shards — enforced via `DefaultBodyLimit`.
- **Shard magic tag** — the 32-byte `MDB_SHARD_HEADER_TAG` magic isn't in the public spec text; the parser currently tolerates any 32-byte tag. The real value will be pinned in M7 when we test against a published reference shard from `xet-team/xet-spec-reference-files`.

## Where to look in the code

| Concern | File |
|---------|------|
| Trait definitions | `crates/xet-server-core/src/lib.rs` |
| Hex encoding + JSON wire types | `crates/xet-server-wire/src/lib.rs` |
| MDB shard binary parser/serializer | `crates/xet-server-shard/src/lib.rs` |
| Filesystem blob store | `crates/xet-server-storage-fs/src/lib.rs` |
| SQLite metadata store | `crates/xet-server-meta-sqlite/src/lib.rs` |
| Static authz + JWT verify wiring | `crates/xet-server-authz-mem/src/lib.rs` |
| JWT mint/verify | `crates/xet-server-tokens/src/lib.rs` |
| Router, handlers, middleware, signed URLs | `crates/xet-server-http/src/lib.rs` |
| Binary launcher | `crates/xet-server-bin/src/main.rs` |
| Cross-crate integration tests | `crates/xet-server-tests/tests/*.rs` |
