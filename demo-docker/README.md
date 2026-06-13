# Bale for Git demo stack

A self-contained docker/podman compose stack — gitea + baleforgit-server +
MinIO — wired so a `git-bale` client on the host can push and pull large files
end-to-end. Meant for trying Bale out locally, not for production.

| Service             | Image                                        | Host ports | Role                                              |
|---------------------|----------------------------------------------|------------|---------------------------------------------------|
| `bootstrap`         | `python:3-alpine`                            | —          | First-run job that writes `.env` with secrets     |
| `gitea`             | `ghcr.io/davidrios/gitea:bale-support-v1.26` | 3000, 2222 | Forge with the Bale forge-auth endpoints (SQLite) |
| `baleforgit-server` | built from `../Dockerfile`                   | 8080       | Bale CAS server (SQLite metadata + S3 blobs)      |
| `minio`             | `minio/minio:latest`                         | 9000, 9001 | Bundled S3-compatible blob backend                |
| `minio-init`        | `minio/mc:latest`                            | —          | One-shot job that creates the `bale` bucket       |

The server is **built from the repo root `Dockerfile`**, so the demo always runs
the code in your working tree — rebuild after changes with `compose build
baleforgit-server`. Blobs go to the bundled MinIO, so there's nothing external
to configure. Named volumes (`gitea-data`, `bale-server-data`, `minio-data`)
keep all state across restarts.

Requires `podman` (rootless) or `docker` (rootful) with compose v2. The host
ports default to 3000 / 2222 / 8080 / 9000 / 9001 (none privileged) and are all
overridable in the **Host ports** block `bootstrap` writes to `.env`; the URLs
and examples below assume the defaults.

## 1. Bring it up

```bash
cd demo-docker
podman compose up -d         # or: docker compose up -d
```

The first run finds no `.env`, writes one with fresh random secrets, and **exits
non-zero on purpose** so nothing starts with empty values:

```
[bootstrap] wrote /work/.env with fresh secrets.
[bootstrap] re-run `compose up -d` to start the demo stack.
```

Run the same command again. This time `.env` exists, `bootstrap` exits 0, and
the stack comes up. `compose ps` shows `gitea` healthy and `minio-init` exited
once the bucket is made; `compose logs -f baleforgit-server` shows it listening.

Open <http://localhost:3000>, register a user (sign-ups are open in the demo),
and create a repository.

## 2. Use git-bale against it

From a fresh clone of that repository on the host:

```bash
git-bale install --local
git-bale track '*.bin'
git add .gitattributes && git commit -m 'enable bale'

dd if=/dev/urandom of=blob.bin bs=1M count=8
git add blob.bin && git commit -m 'add blob'
git push
```

git-bale auto-discovers the server URL via gitea's forge endpoints, mints a
short-lived JWT, and uploads chunks to baleforgit-server, which streams them to
MinIO. A checkout in a new clone gets back a presigned MinIO URL the client
fetches directly.

The server reaches MinIO in-network at `minio:9000`, but the client on the host
can't resolve that name — so the presigned URLs it hands clients are signed
against `BALE_S3_PUBLIC_ENDPOINT_URL` (default `http://localhost:9000`, the
published port) instead. If you run the client from another machine, override it
in `.env` with a LAN IP or domain those clients can reach:

```bash
echo 'BALE_S3_PUBLIC_ENDPOINT_URL=http://192.168.1.50:9000' >> .env
podman compose up -d --force-recreate baleforgit-server
```

The MinIO console at <http://localhost:9001> takes the `MINIO_ROOT_USER` /
`MINIO_ROOT_PASSWORD` values from `.env` (the password is random per bootstrap);
there you can watch xorbs and shards land in the `bale` bucket.

## Teardown

```bash
podman compose down            # stop, keep data
podman compose down -v         # stop and wipe all volumes
```

## Rotating the secrets

`bootstrap` only writes `.env` when it's missing, so to regenerate every secret:

```bash
rm .env
podman compose up -d --force-recreate
```

## Why the JWT secrets are paired

`BALE_JWT_SECRET_HEX` (baleforgit-server) and `LFS_JWT_SECRET_BASE64URL` (gitea)
must decode to the **same 32 bytes**: gitea mints the JWT the client presents to
baleforgit-server, which verifies it against its own copy of the HS256 key
before delegating the repo-access check back to gitea over
`POST /-/bale/check_access`. `bootstrap.py` keeps the two encodings in sync — if
you edit `.env` by hand, keep them paired.
