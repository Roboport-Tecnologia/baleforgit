# bale-lfs-adapter

A small Go HTTP server that bridges the standard **git-lfs Batch API** to a
**baleforgit-server** CAS backend by way of the `git-xet` custom transfer agent.

It exists as a reference shape for what a GitLab/Gitea Bale integration would
look like: a thin protocol adapter that holds no secrets, knows nothing about
users, and delegates all authorization to the upstream baleforgit-server.

## What it does

### Uploads (`operation: upload`)

For every `POST /repos/{owner}/{name}/objects/batch` from git-lfs:

1. Reads the caller's `Authorization` header (Bearer or Basic — git-lfs uses
   Basic when credentials are URL-embedded; the adapter normalizes Basic to
   Bearer using the password part).
2. Forwards that bearer to baleforgit-server's HF-Hub-compatible token endpoint:
   `GET {baleforgit-server}/api/models/{owner}/{name}/bale-write-token/main`
3. Repackages baleforgit-server's `{accessToken, exp, casUrl}` response into a
   standard LFS Batch response with `transfer="xet"` and per-object
   `action.header` carrying `X-Xet-Cas-Url`, `X-Xet-Access-Token`,
   `X-Xet-Token-Expiration`.
4. Returns the batch response. git-lfs dispatches to the `git-xet` custom
   transfer agent, which reads those headers and uploads bytes directly to
   baleforgit-server. The adapter never touches blob bytes.

### Downloads (`operation: download`)

git-xet's custom-transfer agent is **upload-only**, so for pulls the adapter
takes over byte serving:

1. Batch response advertises `transfer="basic"` with each object's
   `action.download.href` pointing back at the adapter
   (`/repos/{owner}/{name}/objects/{sha256}`), `header.Authorization`
   echoing the caller's bearer.
2. git-lfs follows that URL; the adapter mints a Bale **read** token,
   queries baleforgit-server's `GET /v1/reconstructions/by-sha256/{sha256}` to
   get the file's terms and signed xorb byte ranges, then **streams**:
   - For each term, GET the signed URL with the prescribed `Range` header.
   - Parse 8-byte chunk frame headers in flight, decompress per scheme
     (0 = raw, 1 = LZ4 frame, 2 = ByteGrouping4-LZ4), drain any decoder
     leftovers to stay aligned with the next frame.
   - Write raw bytes straight into the LFS response.
3. The only per-file buffering is per-chunk (≤ 16 MiB by xorb spec,
   typically ~64 KiB) when scheme 2 forces a full decode before regroup.
   Schemes 0 and 1 are end-to-end streaming.

The adapter never persists blob bytes. It is pure protocol glue with a
small lz4 dependency for download decoding.

## Where authorization actually happens

The adapter is **stateless and credential-free**. The PAT verification +
mint-token logic lives in baleforgit-server's `RepoAuthz` impl (typically
`bale-server-authz-http`, which calls out to the platform). To integrate with
GitLab or Gitea, you'd write a small `/check_access` shim in front of their
API (verify the PAT via `/api/v4/user`, check project access, return
`{user_id}`) — the adapter and baleforgit-server remain unchanged.

## Build

```bash
cd lfs-adapter
go build ./...
```

## Run

```bash
./bale-lfs-adapter --listen 127.0.0.1:9090 --bale-server http://127.0.0.1:8080
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

# Wipe and re-pull to exercise the download path:
rm -rf .git/lfs/objects big.bin
git lfs pull origin
diff <(echo hello) big.bin   # should be empty
```

## Wire shape

### Upload batch

```json
POST /repos/alice/demo/objects/batch
Authorization: Basic dG9rZW46cGxhdGZvcm0tcGF0
Content-Type: application/vnd.git-lfs+json

{ "operation": "upload",
  "transfers": ["xet", "basic"],
  "objects": [{"oid": "<sha256>", "size": 307200}] }
```

Response:

```json
{ "transfer": "xet",
  "objects": [
    { "oid": "<sha256>", "size": 307200, "authenticated": true,
      "actions": {
        "upload": {
          "href": "http://baleforgit-server:8080",
          "header": {
            "X-Xet-Cas-Url":          "http://baleforgit-server:8080",
            "X-Xet-Access-Token":     "<jwt>",
            "X-Xet-Token-Expiration": "1716580000"
          } } } } ] }
```

### Download batch

```json
POST /repos/alice/demo/objects/batch  ... { "operation": "download", "objects": [...] }
```

Response (note: `transfer="basic"` and the action `href` points back at the adapter):

```json
{ "transfer": "basic",
  "objects": [
    { "oid": "<sha256>", "size": 307200, "authenticated": true,
      "actions": {
        "download": {
          "href": "http://adapter:9090/repos/alice/demo/objects/<sha256>",
          "header": { "Authorization": "Bearer <PAT>" }
        } } } ] }
```

git-lfs then issues `GET http://adapter:9090/repos/alice/demo/objects/<sha256>` with the supplied Authorization, and the adapter streams the raw file bytes.
