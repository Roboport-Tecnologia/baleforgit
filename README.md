# Bale for Git

A Git filter driver that stores large files as **content-defined chunks** on a Bale CAS server. It's meant to be a replacement for `git-lfs`. It needs a backend server to work, you can run your own or pester your favourite git forge to implement it.

This repo ships two binaries:

- **`git-bale`** — the client. A native Git filter driver (`filter.bale.process`) you install per-user or per-repo. Speaks Git's long-running filter protocol and talks to the server directly.
- **`baleforgit-server`** — a content-addressed storage server for chunked large files. Pluggable storage (filesystem or S3) and authz (static, or delegated to your git forge). See [`docs/SERVER.md`](docs/SERVER.md) for ops; [`docs/BALE_FORGE_PROTOCOL.md`](docs/BALE_FORGE_PROTOCOL.md) for integrating it with a forge.

## Install

Proprietary distribution: see your release channel for the `git-bale-<version>-<target>.tar.gz` artifact for your platform, unpack, and put `git-bale` somewhere on your `PATH`.

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

### Without a forge (manual config)

If you're running your own `baleforgit-server` and don't have a forge integration, pin the server URL and a token in git config:

```bash
git config --local bale.serverUrl http://127.0.0.1:8080
git config --local bale.token "<a Bale JWT minted out-of-band>"
```

Same env-var equivalents exist for ephemeral overrides: `BALE_SERVER_URL`, `BALE_TOKEN`.

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

Defaults: cache directory is `$XDG_CACHE_HOME/bale/chunks` if set, otherwise `~/.cache/bale/chunks`. No default server URL or token — without forge auto-resolve, one of the env/config settings above is required.

## Self-hosting the server

If you want to run your own CAS server (rather than point `git-bale` at someone else's), grab the `baleforgit-server-<version>-<target>.tar.gz` artifact from your distribution channel, or pull the container image. See [`docs/SERVER.md`](docs/SERVER.md) for the quick start, env vars, and container instructions; [`docs/BALE_FORGE_PROTOCOL.md`](docs/BALE_FORGE_PROTOCOL.md) for what your forge needs to expose so clients can auto-resolve.

## What this is, in context

Bale for Git is a Git large-file system that does content-defined chunking + chunk-level deduplication, in the lineage of Git-LFS. The on-disk format and the chunk-dedup algorithm are derived from Hugging Face's open-source [Xet](https://huggingface.co/docs/xet/index) project (the `xet-core`/`xet-data` crates this client links against). `baleforgit-server` and `git-bale` are proprietary implementations of the server and client that wrap that format with our own wire protocol, auth, and forge-integration story.

## More docs

- [`docs/SERVER.md`](docs/SERVER.md) — running `baleforgit-server`: install, configuration (incl. `BALE_DEFAULT_QUOTA_BYTES` and `BALE_ADMIN_TOKEN_HEX` for per-owner quotas), container, artifact verification.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — request flows, trait surface, storage layout, protocol notes, and the "Tricky bits" section.
- [`docs/BALE_FORGE_PROTOCOL.md`](docs/BALE_FORGE_PROTOCOL.md) — what a git forge has to implement to support `git-bale`.
- [`docs/STATUS.md`](docs/STATUS.md) — feature breakdown with what each piece provides.
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — building from source, the test matrix, CI workflows, and how releases are cut.

## License

Proprietary and confidential. See [`LICENSE`](LICENSE).
