# Status

All milestones below are shipped and verified end-to-end by the [`tests/e2e/`](../tests/e2e/README.md) harness (there are no Rust unit tests). Details live in [`ARCHITECTURE.md`](ARCHITECTURE.md).

| Milestone | What it provides |
|-----------|------------------|
| Wire types + shard parser | Hex encoding, JSON shapes, MDB shard binary format |
| Filesystem + SQLite stores | `BlobStore` on disk, `MetadataStore` on SQLite |
| Upload endpoints | `POST /v1/xorbs/{prefix}/{hash}`, `POST /shards` |
| Download endpoints | `GET /v1/reconstructions/...`, signed `/xorb/default/...` transfer |
| Auth + token endpoint | HS256 Bale tokens, scope enforcement, `GET /api/{models,datasets,spaces}/{ns}/{name}/bale-{read,write}-token/{rev}`; forge delegation via `POST /check_access` |
| Global dedup endpoint | `GET /v1/chunks/{prefix}/{hash}` (per-response HMAC-wrapped shard) |
| Pluggable trait impls | `bale-server-storage-mem` (in-memory `BlobStore`) + `bale-server-authz-http` (HTTP-backed `RepoAuthz`) show the traits are swappable |
| Native filter (`git-bale`) | Implements Git's long-running filter protocol directly. A shared chunk cache (`~/.cache/bale/chunks` by default) plus a per-repo manifest cache (`.git/bale/manifests/`, in the common git dir) let a warm checkout make **zero** calls to `/v1/reconstructions/`; a clean-cache short-circuits re-cleaning unchanged files. Every smudge verifies size + sha256. |
| Per-repo scope check on reconstruction | `/v1/reconstructions/*` requires a `(file_hash, repo_id=claims.repo)` row in the `files` table — returns 404 on miss (no existence leak); `GET /v1/files/{file_id}` browser downloads get the same check. The `files` PK is `(file_hash, repo_id)`, so the same content registered in multiple repos grants independent read access (cross-repo dedup). |
| Owner accounting + quotas | Per-owner + per-repo storage accounting, atomic quotas, and the `/v1/usage/{owner}`, `/v1/usage/repo/{owner}/{repo}`, `/v1/quotas/{owner}` endpoints. |
| S3 + Postgres backends | `bale-server-storage-s3` (any S3-compatible store, real presigned download URLs) and `bale-server-meta-postgres` (`BALE_POSTGRES_URL`); the whole e2e suite runs against each |
| Deferred upload + gc | `git add` stages offline; the pre-push hook (`git-bale push-pending`) uploads only what the push references, to the push target's repo scope; `git-bale gc` reclaims abandoned staging using git's own liveness rules |
| Fully-local mode | `git-bale init-local [--store] [--shared]` keeps objects in a durable on-disk store with no server; `git-bale prune --shared` compacts a shared store |
| Read-only mounts | `git-bale mount <rev>` and `git-bale mount-diff <a> <b>` via a runtime-loaded FUSE driver (libfuse 2 / fuse-t / WinFsp) |
