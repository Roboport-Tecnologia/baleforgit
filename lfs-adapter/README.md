# xet-lfs-adapter

A small Go HTTP server that bridges the standard **git-lfs Batch API** to a
**xet-server** CAS backend by way of the `git-xet` custom transfer agent.

It exists as a reference shape for what a GitLab/Gitea Xet integration would
look like: a thin protocol adapter that holds no secrets, knows nothing about
users, and delegates all authorization to the upstream xet-server.

## What it does

For every `POST /repos/{owner}/{name}/objects/batch` request from git-lfs:

1. Reads the caller's `Authorization` header (Bearer or Basic — git-lfs uses
   Basic when credentials are URL-embedded; the adapter normalizes Basic to
   Bearer using the password part).
2. Forwards that bearer to xet-server's HF-Hub-compatible token endpoint:
   `GET {xet-server}/api/models/{owner}/{name}/xet-{read|write}-token/main`
3. Repackages xet-server's `{accessToken, exp, casUrl}` response into a
   standard LFS Batch response with `transfer="xet"` and per-object
   `action.header` carrying:
   - `X-Xet-Cas-Url`
   - `X-Xet-Access-Token`
   - `X-Xet-Token-Expiration`
4. Returns the batch response. git-lfs then dispatches to the `git-xet` custom
   transfer agent, which reads those headers and uploads/downloads bytes
   directly to/from xet-server.

The adapter never touches blob bytes. It is pure protocol glue.

## Where authorization actually happens

The adapter is **stateless and credential-free**. The PAT verification +
mint-token logic lives in xet-server's `RepoAuthz` impl (typically
`xet-server-authz-http`, which calls out to the platform). To integrate with
GitLab or Gitea, you'd write a small `/check_access` shim in front of their
API (verify the PAT via `/api/v4/user`, check project access, return
`{user_id}`) — the adapter and xet-server remain unchanged.

## Build

```bash
cd lfs-adapter
go build ./...
```

## Run

```bash
./xet-lfs-adapter --listen 127.0.0.1:9090 --xet-server http://127.0.0.1:8080
```

## Configure a git repo to use it

```bash
# Remote URL must be http(s)/ssh — git-xet rejects file:// for credential
# derivation. The URL doesn't have to be reachable: we only invoke `git lfs
# push`, which sends to lfs.url (the adapter), not the remote itself.
git remote add origin http://token:${PAT}@127.0.0.1:9090/repos/alice/demo
git config --local lfs.url http://token:${PAT}@127.0.0.1:9090/repos/alice/demo

# Register git-xet as the "xet" custom transfer agent (matches the
# `transfer` field the adapter sets in batch responses).
git config --local lfs.customtransfer.xet.path git-xet
git config --local lfs.customtransfer.xet.args transfer
git config --local lfs.customtransfer.xet.concurrent true
git config --local lfs.locksverify false

git lfs install --local
git lfs track "*.bin"
git add .gitattributes
git commit -m 'track .bin via lfs'

echo "hello" > big.bin
git add big.bin
git commit -m 'add big.bin'

git lfs push --all origin
```

## Wire shape

Batch request (from git-lfs):

```json
POST /repos/alice/demo/objects/batch
Authorization: Basic dG9rZW46cGxhdGZvcm0tcGF0
Content-Type: application/vnd.git-lfs+json

{ "operation": "upload",
  "transfers": ["xet", "basic"],
  "objects": [{"oid": "<sha256>", "size": 307200}] }
```

Batch response (from adapter):

```json
{ "transfer": "xet",
  "objects": [
    { "oid": "<sha256>",
      "size": 307200,
      "authenticated": true,
      "actions": {
        "upload": {
          "href": "http://xet-server:8080",
          "header": {
            "X-Xet-Cas-Url":          "http://xet-server:8080",
            "X-Xet-Access-Token":     "<jwt>",
            "X-Xet-Token-Expiration": "1716580000"
          }
        }
      } } ] }
```
