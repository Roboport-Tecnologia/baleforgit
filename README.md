# Bale for Git

A Git filter driver that stores large files as **content-defined chunks** on a Bale CAS server. It's meant to be a replacement for `git-lfs`. It needs a backend server to work, you can run your own or pester your favourite git forge to implement it.

This repo ships two binaries:

- **`git-bale`** — the client. A native Git filter driver (`filter.bale.process`) you install per-user or per-repo. Speaks Git's long-running filter protocol and talks to the server directly.
- **`baleforgit-server`** — a content-addressed storage server for chunked large files. Pluggable storage (filesystem or S3) and authz (static, or delegated to your git forge). See [`docs/SERVER.md`](docs/SERVER.md) for ops; [`docs/BALE_FORGE_PROTOCOL.md`](docs/BALE_FORGE_PROTOCOL.md) for integrating it with a forge.

## Install

Grab the `bale-client-<version>-<target>` artifact for your platform from the [releases page](https://github.com/davidrios/baleforgit/releases): a `.tar.gz` on Linux (unpack it and put `git-bale` on your `PATH`), a signed `.pkg` on macOS (run it — installs `git-bale` to `/usr/local/bin`), or a `.zip` on Windows. (The server ships separately as `bale-server-<version>-<target>`, Linux/macOS only.)

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

`git add` chunks the file and stages xorbs/shards under `.git/bale/staging/` — no network. The actual upload happens at `git push`, via the pre-push hook installed by `git-bale install --local`. If you want to push the staged content explicitly (e.g. before a clone to verify, or after editing then reverting), run `git-bale push-pending`.

If you stage a change and then abandon it (`git reset`, `git checkout`) before pushing, the staged bytes are no longer needed. `git-bale gc` reclaims that orphaned staging by reconciling it against what the index and your unpushed commits still reference; `install --local` runs it automatically via post-checkout/commit/merge hooks, and it's safe to run by hand anytime.

**Public repos clone without credentials.** When the forge marks a repo public and grants anonymous read (see [`docs/BALE_FORGE_PROTOCOL.md`](docs/BALE_FORGE_PROTOCOL.md)), cloning or checking out its Bale-tracked files over HTTPS needs no login: `git-bale` asks the forge anonymously first and only falls back to `git credential fill` for a private repo, so a public clone never prompts. Uploads (`git push`) always authenticate.

### Without a forge (manual config)

If you're running your own `baleforgit-server` and don't have a forge integration, pin the server URL and a token in git config:

```bash
git config --local bale.serverUrl http://127.0.0.1:8080
git config --local bale.token "<a Bale JWT minted out-of-band>"
```

Same env-var equivalents exist for ephemeral overrides: `BALE_SERVER_URL`, `BALE_TOKEN`.

### Fully local (no server)

If you don't have (or want) a `baleforgit-server`, `git-bale init-local` puts a repo into fully-local mode: large-file objects are stored on disk and never uploaded.

```bash
git init myrepo && cd myrepo
git-bale init-local            # per-repo store at .git/bale/store, no server needed
git-bale init-local --shared   # shared store at ~/bale-local, usable by all local repos
git-bale track '*.bin'
git add big.bin && git commit -m "add"   # data stays local, no upload
git push                                 # only pointer commits move; large-file data doesn't
git-bale prune --shared        # compact a shared store (per-repo stores are managed by gc)
```

`git add` writes xorbs/shards to the durable store (no staging, no drain step). Checkout reconstructs from the store with a hard error if objects are missing — there is no network fallback. `git-bale gc` reclaims objects for abandoned changes, same as in server mode.

**Limitation:** a per-repo store (`.git/bale/store`) is not carried by `git clone`. Cloning the repo elsewhere leaves the large-file data behind. Use `--shared` (store at `~/bale-local`) when you need multiple working copies on the same machine.

### Mounting a diff or a single rev

`git-bale mount-diff` exposes both sides of `git diff <revA> <revB>` as a read-only filesystem, with the revision label folded into each filename. Useful for piping a diff through external tools (Beyond Compare, Meld, vimdiff over directories, etc.) without checking out either side.

```bash
mkdir /tmp/diff
git-bale mount-diff main feature-x --mount /tmp/diff
# In another shell:
ls /tmp/diff/src/
#   foo__main.rs   foo__feature-x.rs   bar__feature-x.rs (added)
# Ctrl-C the mount-diff process to unmount.
```

Supports the same arg shape as `git diff`: `<revA> <revB> [-- <paths>...]`. Custom labels via `--label-a` / `--label-b`.

`git-bale mount` does the same for a *single* revision — every file from the tree appears under the mount point with its normal name. Useful for browsing a tag, an older commit, or another branch without `git checkout`.

```bash
mkdir /tmp/v1
git-bale mount v1.0.0 --mount /tmp/v1
# In another shell:
ls /tmp/v1/        # files at v1.0.0, as they were committed
```

Both modes: no bytes are copied to disk — each `read` streams from git's object DB or, for Bale-tracked files, the chunk cache (with a network fallback that also repopulates the cache).

Requires a userspace filesystem driver at runtime (not at build time): `libfuse2` on Linux (Debian/Ubuntu) — `fuse-libs` on Fedora/RHEL, `fuse2` on Arch — [fuse-t](https://www.fuse-t.org/) on macOS, and [WinFsp](https://winfsp.dev/) on Windows (`winget install WinFsp.WinFsp`). On Windows pass a free drive letter or a non-existent directory as `--mount` (e.g. `git-bale mount v1.0.0 --mount X:`). Everything else in `git-bale` (clean/smudge, `push-pending`, `gc`, `install`, `track`) works on Windows without it.

## Configuration

| Source     | Key                     | Purpose                                                       |
|------------|-------------------------|---------------------------------------------------------------|
| env        | `BALE_SERVER_URL`       | baleforgit-server base URL — skips forge auto-resolve         |
| env        | `BALE_TOKEN`            | Pre-minted Bale JWT — skips forge auto-resolve                |
| env        | `BALE_TOKEN_EXPIRATION` | Unix timestamp when `BALE_TOKEN` expires                      |
| env        | `BALE_CACHE_DIR`        | Override the shared chunk cache location                      |
| env        | `XDG_CACHE_HOME`        | Used to derive the default cache dir                          |
| git config | `bale.serverUrl`        | Same as `BALE_SERVER_URL`                                     |
| git config | `bale.token`            | Same as `BALE_TOKEN`                                          |
| git config | `bale.tokenExpiration`  | Same as `BALE_TOKEN_EXPIRATION`                               |
| git config | `bale.cacheDir`         | Same as `BALE_CACHE_DIR`                                      |
| env        | `BALE_LOCAL`            | Enable fully-local (no-server) mode                           |
| env        | `BALE_LOCAL_STORE`      | Object store directory (overrides `init-local` default)       |
| env        | `BALE_LOCAL_SHARED`     | Mark the store as shared across repos                         |
| git config | `bale.local`            | Same as `BALE_LOCAL`                                          |
| git config | `bale.localStore`       | Same as `BALE_LOCAL_STORE`                                    |
| git config | `bale.localShared`      | Same as `BALE_LOCAL_SHARED`                                   |

Defaults: cache directory is `$XDG_CACHE_HOME/bale/chunks` if set, otherwise `~/.cache/bale/chunks`. No default server URL or token — without forge auto-resolve, one of the env/config settings above is required.

## Self-hosting the server

If you want to run your own CAS server (rather than point `git-bale` at someone else's), grab the `bale-server-<version>-<target>.tar.gz` artifact from the [releases page](https://github.com/davidrios/baleforgit/releases). See [`docs/SERVER.md`](docs/SERVER.md) for the quick start, env vars, and container instructions; [`docs/BALE_FORGE_PROTOCOL.md`](docs/BALE_FORGE_PROTOCOL.md) for what your forge needs to expose so clients can auto-resolve.

## What this is, in context

Bale for Git is a Git large-file system that does content-defined chunking + chunk-level deduplication, in the lineage of Git-LFS. The on-disk format and the chunk-dedup algorithm are derived from Hugging Face's open-source [Xet](https://huggingface.co/docs/xet/index) project (the `xet-core`/`xet-data` crates this client links against). `baleforgit-server` and `git-bale` are independent implementations of the server and client that wrap that format with their own wire protocol, auth, and forge-integration story.

## More docs

- [`docs/SERVER.md`](docs/SERVER.md) — running `baleforgit-server`: install, configuration (incl. `BALE_DEFAULT_QUOTA_BYTES` and `BALE_ADMIN_TOKEN_HEX` for per-owner quotas), container, artifact verification.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — request flows, trait surface, storage layout, protocol notes, and the "Tricky bits" section.
- [`docs/BALE_FORGE_PROTOCOL.md`](docs/BALE_FORGE_PROTOCOL.md) — what a git forge has to implement to support `git-bale`.
- [`docs/STATUS.md`](docs/STATUS.md) — feature breakdown with what each piece provides.
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — building from source, the test matrix, CI workflows, and how releases are cut.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
