# git-dfs

A Git filter driver that stores large files as **content-defined chunks** on a Xet-protocol CAS server. It's meant to be a replacement for `git-lfs`. It needs a backend server to work, you can run your own or pester your favourite git forge to implement it.

This repo ships two binaries:

- **`git-dfs`** — the client. A native Git filter driver (`filter.dfs.process`) you install per-user or per-repo. Speaks Git's long-running filter protocol and talks to the server directly.
- **`xet-server`** — a Xet-protocol-compatible CAS server. Pluggable storage (filesystem or S3) and authz (static, or delegated to your git forge). See [`docs/SERVER.md`](docs/SERVER.md) for ops; [`docs/DFS_FORGE_PROTOCOL.md`](docs/DFS_FORGE_PROTOCOL.md) for integrating it with a forge.

## Install

Download `git-dfs-<version>-<target>.tar.gz` for your platform from the [releases page](https://github.com/davidrios/git-xet-server/releases), unpack, and put `git-dfs` somewhere on your `PATH`.

### Verify the download (optional but recommended)

Each release tarball is covered by a [SLSA Build Provenance](https://slsa.dev/spec/v1.0/provenance) attestation tying it back to the exact workflow run and commit that produced it. Easily verify with the GitHub CLI:

```bash
gh attestation verify git-dfs-<version>-<target>.tar.gz --repo davidrios/git-xet-server
```

A passing verify means the tarball came from this repo's CI at a specific commit and nothing in transit has tampered with it.

## Usage

### Against a DFS-enabled forge

Inside a fresh clone of a repo whose forge supports the DFS protocol:

```bash
git-dfs install --local
git-dfs track '*.bin'  # or any extension you want to track
git add .gitattributes && git commit -m 'enable dfs'

git add some-binary-file.bin && git commit -m 'add binary file'
git push
```

### Without a forge (manual config)

If you're running your own `xet-server` and don't have a forge integration, pin the server URL and a token in git config:

```bash
git config --local dfs.serverUrl http://127.0.0.1:8080
git config --local dfs.token "<a Xet JWT minted out-of-band>"
```

Same env-var equivalents exist for ephemeral overrides: `DFS_SERVER_URL`, `DFS_TOKEN`.

## Configuration

| Source | Key | Purpose |
|--------|-----|---------|
| env | `DFS_SERVER_URL` (alias `XET_SERVER_URL`) | xet-server base URL — skips forge auto-resolve |
| env | `DFS_TOKEN` (alias `XET_TOKEN`) | Pre-minted Xet JWT — skips forge auto-resolve |
| env | `DFS_TOKEN_EXPIRATION` (alias `XET_TOKEN_EXPIRATION`) | Unix timestamp when `DFS_TOKEN` expires |
| env | `DFS_CACHE_DIR` (alias `XET_CACHE_DIR`) | Override the shared chunk cache location |
| env | `XDG_CACHE_HOME` | Used to derive the default cache dir |
| git config | `dfs.serverUrl` | Same as `DFS_SERVER_URL` |
| git config | `dfs.token` | Same as `DFS_TOKEN` |
| git config | `dfs.tokenExpiration` | Same as `DFS_TOKEN_EXPIRATION` |
| git config | `dfs.cacheDir` | Same as `DFS_CACHE_DIR` |

Defaults: cache directory is `$XDG_CACHE_HOME/dfs/chunks` if set, otherwise `~/.cache/dfs/chunks`. No default server URL or token — without forge auto-resolve, one of the env/config settings above is required.

## Self-hosting the server

If you want to run your own CAS server (rather than point `git-dfs` at someone else's), grab `xet-server-<version>-<target>.tar.gz` from the same releases page, or pull `ghcr.io/davidrios/git-xet-server`. See [`docs/SERVER.md`](docs/SERVER.md) for the quick start, env vars, and container instructions; [`docs/DFS_FORGE_PROTOCOL.md`](docs/DFS_FORGE_PROTOCOL.md) for what your forge needs to expose so clients can auto-resolve.

## What this is, in context

[Xet](https://huggingface.co/docs/xet/index) is Hugging Face's storage backend: a Git-LFS-style large-file system that does content-defined chunking + chunk-level deduplication. The official client (`git-xet`, `hf-xet`) is open source — the server is not.

- `xet-server` here is a from-scratch Rust implementation of the server side of the Xet protocol, so unmodified Xet clients can push to and pull from your own infrastructure.
- `git-dfs` is a native client that goes one step further: it implements Git's filter protocol directly and avoids `git-lfs` entirely.

## More docs

- [`docs/SERVER.md`](docs/SERVER.md) — running `xet-server`: install, configuration, container, artifact verification.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — request flows, trait surface, storage layout, protocol notes, and the "Tricky bits" section.
- [`docs/DFS_FORGE_PROTOCOL.md`](docs/DFS_FORGE_PROTOCOL.md) — what a git forge has to implement to support `git-dfs`.
- [`docs/STATUS.md`](docs/STATUS.md) — milestone breakdown (M1–M12) with what each one provides.
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — building from source, the test matrix, CI workflows, and how releases are cut.
- [`lfs-adapter/README.md`](lfs-adapter/README.md) — the legacy Go LFS bridge.

## License

Apache-2.0.
