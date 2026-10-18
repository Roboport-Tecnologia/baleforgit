# Bale for Git

[![CI](https://github.com/Roboport-Tecnologia/baleforgit/actions/workflows/ci.yml/badge.svg)](https://github.com/Roboport-Tecnologia/baleforgit/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/Roboport-Tecnologia/baleforgit?sort=semver)](https://github.com/Roboport-Tecnologia/baleforgit/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

A replacement for `git-lfs` that stores large files as deduplicated **content-defined chunks**. Use a Bale server (run your own, or get your favourite git forge to support it) or run fully offline.

This repo ships two binaries:

- **`git-bale`** — the client: a native Git filter driver (`filter.bale.process`) installed per-user or per-repo.
- **`baleforgit-server`** — the content-addressed storage server, with pluggable storage (filesystem or S3), metadata (SQLite or Postgres) and authz (static, or delegated to your git forge). See [`docs/SERVER.md`](docs/SERVER.md) to run it and [`docs/BALE_FORGE_PROTOCOL.md`](docs/BALE_FORGE_PROTOCOL.md) to integrate a forge.

## Install

Grab the `bale-client-<version>-<target>` artifact for your platform from the [releases page](https://github.com/Roboport-Tecnologia/baleforgit/releases): a `.tar.gz` on Linux (put `git-bale` on your `PATH`), a signed `.pkg` on macOS (installs to `/usr/local/bin`), or a `.zip` on Windows. The server ships separately as `bale-server-<version>-<target>` (Linux/macOS); see [`docs/SERVER.md`](docs/SERVER.md).

## Usage

### Against a Bale-enabled forge

Inside a fresh clone of a repo whose forge supports the Bale forge protocol:

```bash
git-bale install --local
git-bale track '*.bin'  # or any extension you want to track
git add .gitattributes && git commit -m 'enable bale'

git add some-binary-file.bin && git commit -m 'add binary file'
git push
```

`git add` chunks the file and stages xorbs/shards under `.git/bale/staging/`, with no network access. The upload happens at `git push`, via the pre-push hook that `git-bale install --local` installs, and covers only content the pushed commits reference: an uncommitted edit that `git status` happened to re-chunk never leaves your machine. Run `git-bale push-pending` by hand to upload the staged content reachable from `HEAD` to `origin`.

Staged content you abandon (`git reset`, `git checkout`) is reclaimed by `git-bale gc`, which keeps everything git itself would keep (every ref including remote-tracking, every reflog entry, every worktree's HEAD and index), anything cleaned within the last two weeks, and committed content until `git push` has uploaded it. `install --local` runs gc from post-checkout/commit/merge hooks; it's safe to run by hand anytime. Plain `git-bale install` (global; `--system` for system-wide) registers only the filter, not the hooks: run `install --local` in each repo, or pushes won't upload.

Auth comes from the remote: over HTTPS `git-bale` uses your git credentials (`git credential fill`), over SSH your key (honoring `GIT_SSH_COMMAND` / `core.sshCommand`). Public repos clone without credentials: downloads ask the forge anonymously first and only fall back to `git credential fill` for a private repo. Uploads always authenticate.

### Without a forge (manual config)

If you're running your own `baleforgit-server` and don't have a forge integration, pin the server URL and a token in git config:

```bash
git config --local bale.serverUrl http://127.0.0.1:8080
git config --local bale.token "<a Bale JWT minted out-of-band>"
```

`BALE_SERVER_URL` / `BALE_TOKEN` do the same from the environment. Set both or neither: a lone one is ignored (with a warning) and the forge flow runs, so a static token is never sent to a server some forge advertises. Without `bale.tokenExpiration` the token is treated as never expiring.

### Fully local (no server)

If you don't have (or want) a `baleforgit-server`, `git-bale init-local` puts a repo into fully-local mode: large-file objects are stored on disk and never uploaded. A non-shared store (`--store <dir>` without `--shared`) belongs to the repo that created it; other repos are refused — use `--shared` for a store several repos use.

```bash
git init myrepo && cd myrepo
git-bale init-local            # per-repo store at .git/bale/store, no server needed
git-bale init-local --shared   # shared store at ~/bale-local, usable by all local repos
git-bale track '*.bin'
git add big.bin && git commit -m "add"   # data stays local, no upload
git push                                 # only pointer commits move; large-file data doesn't
git-bale prune --shared        # compact a shared store (per-repo stores are managed by gc)
```

`git add` writes straight to the durable store; checkout reads from it and fails hard if objects are missing (there is no network fallback). `git-bale gc` reclaims objects for abandoned changes in a per-repo store.

**Limitation:** `git clone` doesn't carry a per-repo store (`.git/bale/store`), so a clone elsewhere has no large-file data. Use `--shared` for several working copies on one machine.

### Mounting a diff or a single rev

`git-bale mount-diff` exposes both sides of `git diff <revA> <revB>` as a read-only filesystem, with the revision label folded into each filename, so directory-diff tools (Beyond Compare, Meld, …) work without checking out either side.

```bash
mkdir /tmp/diff
git-bale mount-diff main feature-x --mount /tmp/diff
# In another shell:
ls /tmp/diff/src/
#   foo__main.rs   foo__feature-x.rs   bar__feature-x.rs (added)
# Ctrl-C the mount-diff process to unmount.
```

Arguments follow `git diff`: `<revA> <revB> [-- <paths>...]`; `--label-a` / `--label-b` override the labels.

`git-bale mount <rev> --mount <dir> [-- <paths>...]` exposes a *single* revision with normal filenames, for browsing a tag, an older commit or another branch without `git checkout`.

```bash
mkdir /tmp/v1
git-bale mount v1.0.0 --mount /tmp/v1
# In another shell:
ls /tmp/v1/        # files at v1.0.0, as they were committed
```

Nothing is checked out: plain files are read from git's object DB, and Bale-tracked files are rebuilt per open into a temp file, verified like a checkout — from the chunk cache, then your unpushed staging (or, in fully-local mode, the local store, never the network), then the server, which repopulates the cache.

Requires a userspace filesystem driver at runtime (not at build time): `libfuse2` on Linux (Debian/Ubuntu) — `fuse-libs` on Fedora/RHEL, `fuse2` on Arch — [fuse-t](https://www.fuse-t.org/) on macOS, and [WinFsp](https://winfsp.dev/) on Windows (`winget install WinFsp.WinFsp`). On Windows pass a free drive letter or a non-existent directory as `--mount` (e.g. `git-bale mount v1.0.0 --mount X:`). Everything else in `git-bale` (clean/smudge, `push-pending`, `gc`, `install`, `track`) works on Windows without it.

## Configuration

Environment variables override git config.

| Env | Git config | Purpose |
|-----|------------|---------|
| `BALE_SERVER_URL` | `bale.serverUrl` | Server base URL; together with the token, skips forge auto-resolve |
| `BALE_TOKEN` | `bale.token` | Pre-minted Bale JWT; together with the URL, skips forge auto-resolve |
| `BALE_TOKEN_EXPIRATION` | `bale.tokenExpiration` | Unix timestamp when that token expires (default: never) |
| `BALE_CACHE_DIR` | `bale.cacheDir` | Chunk cache directory |
| `BALE_XET_CACHE` | | xet's own cache directory (default `<cache-base>/bale/xet`; also honors `HF_XET_CACHE`) |
| `BALE_DOWNLOAD_STALL_SECS` | | Abort a checkout download after this many seconds with no bytes (default 30, `0` disables) |
| `BALE_GC_GRACE_SECS` | | `git-bale gc` never reclaims content cleaned more recently than this (default 2 weeks) |
| `BALE_LOCAL` | `bale.local` | Fully-local (no-server) mode; set by `init-local` |
| `BALE_LOCAL_STORE` | `bale.localStore` | Local object store directory; set by `init-local` |
| `BALE_LOCAL_SHARED` | `bale.localShared` | The local store is shared across repos; set by `init-local --shared` |
| `GIT_SSH_COMMAND` | `core.sshCommand` | ssh command for the forge auth handshake, as for git itself |
| `RUST_LOG` | | Log filter (default `git_bale=info`; `-v` / `-vv` for debug / trace when unset) |

Booleans accept `1`/`true`/`yes`/`on`. `<cache-base>` is `$XDG_CACHE_HOME`, else `~/.cache` (`%LOCALAPPDATA%` on Windows); the chunk cache defaults to `<cache-base>/bale/chunks`. There is no default server URL or token: without them the forge flow is used.

## Try it locally with Docker

[`demo-docker/`](demo-docker/) is a self-contained compose stack — [gitea](https://gitea.io/) patched with the Bale forge endpoints, `baleforgit-server` (built from your working tree) and [MinIO](https://min.io/) — that lets a `git-bale` client on your host push and pull against a real forge.

```bash
cd demo-docker
podman compose up -d    # or: docker compose up -d
# first run writes .env with fresh secrets and exits; run it once more to start the stack
```

Then open <http://localhost:3000>, register a user, create a repo, and use `git-bale` against it as in [Usage](#against-a-bale-enabled-forge). [`demo-docker/README.md`](demo-docker/README.md) has the full walkthrough, port overrides and teardown. It's for trying Bale out, not for production.

## What this is, in context

Bale for Git does content-defined chunking with chunk-level deduplication, in the lineage of Git-LFS. The on-disk format and dedup algorithm come from Hugging Face's open-source [Xet](https://huggingface.co/docs/xet/index) project (the client links its `xet-*` crates). `baleforgit-server` and `git-bale` are independent implementations that wrap that format with their own wire protocol, auth and forge integration.

## More docs

- [`docs/SERVER.md`](docs/SERVER.md) — running `baleforgit-server`: install, configuration, quotas, container, observability, artifact verification.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — request flows, trait surface, storage layout, protocol notes, and the "Tricky bits" section.
- [`docs/BALE_FORGE_PROTOCOL.md`](docs/BALE_FORGE_PROTOCOL.md) — what a git forge has to implement to support `git-bale`.
- [`docs/STATUS.md`](docs/STATUS.md) — what's shipped.
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — building from source, tests, CI and releases.
- [`tests/e2e/README.md`](tests/e2e/README.md) — the end-to-end harness and its phase list.
- Design notes: [`docs/CLEAN_FILTER_PERF.md`](docs/CLEAN_FILTER_PERF.md) (clean-path profiling and why the pointer cache looks the way it does), [`docs/SMART_DEDUP.md`](docs/SMART_DEDUP.md) (unimplemented proposal: decompress gzip containers before chunking).

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
