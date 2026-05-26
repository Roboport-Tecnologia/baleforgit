# Status

All milestones (M1–M12) are done. M1–M6 build out the server itself; M7–M12 prove it end-to-end against real clients and exercise alternate trait impls, real LFS push/pull through the Go adapter, the native `git-bale` filter, and the per-repo scope check on reconstruction. Each milestone has a matching integration test under `crates/bale-server-tests/tests/m<N>_*.rs`.

| Milestone | Status | What it provides |
|-----------|--------|------------------|
| M1 — Wire types + shard parser | done | Hex encoding, JSON shapes, MDB shard binary format |
| M2 — Filesystem + SQLite stores | done | `BlobStore` on disk, `MetadataStore` on SQLite |
| M3 — Upload endpoints | done | `POST /v1/xorbs/{prefix}/{hash}`, `POST /shards` |
| M4 — Download endpoints | done | `GET /v1/reconstructions/...`, signed `/xorb/default/...` transfer |
| M5 — Auth + mock HF Hub token endpoint | done | HS256 JWTs, scope enforcement, `GET /api/{type}s/.../bale-{rw}-token/{rev}` |
| M6 — Global dedup endpoint | done | `GET /v1/chunks/{prefix}/{hash}` (per-response HMAC-wrapped shard) |
| M7 — End-to-end against `git-xet` | done | `m7_git_xet` drives the real `git-xet transfer` binary over the LFS custom-transfer JSON protocol; skips if the binary isn't on PATH |
| M8 — Pluggability sanity (alternate impls) | done | `bale-server-storage-mem` (in-memory `BlobStore`) + `bale-server-authz-http` (HTTP-backed `RepoAuthz` skeleton), exercised end-to-end by `m8_pluggability` |
| M9 — Real LFS push via Go adapter | done | `lfs-adapter/` (Go) bridges the standard git-lfs Batch API to baleforgit-server; `m9_real_lfs_push` drives a real `git lfs push --all` through the full chain (git-lfs → adapter → baleforgit-server → git-xet → CAS upload). Skips when `{go, git, git-lfs, git-xet}` aren't all on PATH. |
| M10 — Real LFS pull via Go adapter | done | Symmetric `git lfs pull` path: adapter advertises `transfer="basic"` for downloads, serves bytes itself by querying baleforgit-server's `/v1/reconstructions/by-sha256/{oid}` endpoint, then streams xorb frames (LZ4 / raw / BG4-LZ4) chunk-by-chunk back to git-lfs. `m10_real_lfs_pull` round-trips a 300 KiB payload through push then pull and byte-compares. |
| M11 — Native filter (`git-bale`) | done | `crates/git-bale` implements Git's long-running filter protocol directly. No `.git/lfs/objects/` whole-file cache — content lives only as the worktree file, a shared chunk cache (`~/.cache/bale/chunks` by default), and a per-repo manifest cache (`.git/bale/manifests/`). `m11_native_filter` drives `git add` + `git checkout` round-trips and asserts the hot path (cached manifest + cached chunks) makes **zero** calls to `/v1/reconstructions/`. |
| M12 — Per-repo scope check on reconstruction | done | `/v1/reconstructions/*` requires a `(file_hash, repo_id=claims.repo)` row in the `files` table — returns 404 on miss (no existence leak). The `files` PK is `(file_hash, repo_id)`, so the same content registered in multiple repos grants independent read access (cross-repo dedup). `m12_repo_scope` covers isolation, dedup, and the 404-vs-403 distinction. |
