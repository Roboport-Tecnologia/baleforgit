# git-bale forge protocol

This document describes what a **git forge** (gitea, gitlab, sourcehut, a custom git host, …) must implement to support `git-bale` as a content-addressed alternative to git-lfs.

The protocol is deliberately shaped to mirror git-lfs's authentication flow, so a forge that already speaks LFS will have most of the wire surface in place.

## Components

```
   ┌──────────────┐   1. authenticate (HTTPS Basic / SSH)
   │  git-bale     │ ───────────────────────────▶ ┌────────────┐
   │  (client)    │ ◀────────────────────────────│   forge    │
   └──────┬───────┘   {href, Bearer <jwt>, exp}  └─────┬──────┘
          │                                            │
          │ 2. exchange JWT for bale token              │ 3. /check_access
          ▼                                            ▼  (verify jwt, return user_id)
   ┌──────────────┐                              ┌────────────┐
   │  baleforgit-server  │ ────────────────────────────▶│   forge    │
   └──────────────┘                              └────────────┘
```

Three things the forge owns:

1. **Authenticate endpoints** (this document) — turn the user's long-lived credential into a short-lived JWT.
2. **`POST /check_access`** — the upstream-authz hook baleforgit-server calls to verify the JWT and check repo access. See `crates/bale-server-authz-http` for the wire contract.
3. **A discovery endpoint** for clients that haven't been pre-configured (optional but recommended).

This document covers #1 and #3.

## 1. HTTPS authenticate

```
POST  {forge}/<owner>/<repo>.git/info/bale/authenticate?op=<op>
Authorization: Basic <base64("<user>:<secret>")>
```

Where:

- `<op>` is `download` (returns a read-scoped JWT) or `upload` (write-scoped).
- The forge authenticates the user against its own user database (password, PAT, OAuth token — whatever it normally accepts on Basic auth). The credential **never leaves the forge**.
- The `Authorization` header is **optional for `op=download`**. A request with no credentials is an *anonymous* read: if the repo is **public**, return a read-scoped JWT whose subject identifies the anonymous principal (e.g. `anonymous`); if the repo is **private**, return `401 Unauthorized`. `op=upload` **must** require credentials — anonymous writes are never granted (return `401`).
- If a credential is presented but unrecognized → `401 Unauthorized`.
- If the user is known but lacks the requested scope on the repo → `403 Forbidden`.

> **Client behaviour.** `git-bale` resolves a `download` token by calling this endpoint **anonymously first** (no `Authorization` header) and only retries with Basic auth — sourced from `git credential fill`, which may prompt — if the anonymous attempt returns `401`/`403`. So a clone or checkout of a public repo never prompts for credentials, while a private repo still falls back to the user's stored credentials. `upload` always authenticates.

On success: `200 OK` with JSON body

```json
{
  "href": "https://baleforgit-server.example.com",
  "header": { "Authorization": "Bearer <jwt>" },
  "expires_at": "2026-05-25T12:00:00Z"
}
```

- `href` is the base URL of the baleforgit-server the client should talk to next. Required.
- `header.Authorization` carries the JWT the client will present to baleforgit-server. The full `Bearer <jwt>` prefix is included so the forge can rotate auth schemes later without a client change.
- `expires_at` is informational (RFC 3339); the JWT's own `exp` is authoritative.

## 2. SSH authenticate

```
ssh <user>@<host> git-bale-authenticate <owner>/<repo> <op>
```

The forge's SSH server recognises `git-bale-authenticate` as a built-in command (alongside `git-receive-pack` / `git-upload-pack`). On success, write the same JSON body shown above to **stdout** and exit 0. On failure, exit non-zero with a human-readable message on stderr.

SSH auth is identity-based (the user has already proven who they are by presenting their SSH key), so no additional credential is needed in the command line. Anonymous access does not apply over SSH — the transport itself requires a key, so there is no credential-less path to special-case; the anonymous-download flow above is HTTPS-only.

## 3. Discovery (optional)

```
GET  {forge}/<owner>/<repo>.git/info/bale
```

`200 OK` with

```json
{ "server_url": "https://baleforgit-server.example.com" }
```

Lets a client confirm a repo has Bale enabled before attempting to authenticate. `git-bale install` and CI scripts can use it as a feature probe. If the repo has Bale disabled, return `404`.

## The JWT

git-bale treats the JWT as opaque — it just forwards it to baleforgit-server as the `hub_bearer` (see `crates/bale-server-authz-http`). The **recommended** shape is:

- HS256 (or RS256) signed by the forge, with a secret known only to the forge.
- Short TTL (5–15 minutes). Long enough to cover a single push/pull, short enough that revocation isn't a concern.
- Claims: at minimum a user identifier; optionally repo / scope to let baleforgit-server cross-check.

The forge then implements `POST /check_access` (see `bale-server-authz-http`) to verify the JWT it issued and return the user identity to baleforgit-server. Serve it directly at the configured URL: baleforgit-server does not follow redirects on this call (the request body carries the user's bearer). Because verification and issuance live in the same process, the forge can pick whatever JWT scheme it likes — baleforgit-server never tries to parse the bearer itself.

**Anonymous reads need no special handling on baleforgit-server.** An anonymous read token is just an ordinary JWT with an anonymous subject; the client still presents `Authorization: Bearer <jwt>` to the token endpoint, and `/check_access` validates it and returns the anonymous identity (read scope) for the public repo exactly as for a logged-in user. The public-vs-private decision lives entirely in the forge — baleforgit-server has no concept of repo visibility.

### Browser file download (`GET /v1/files/{file_id}`)

The forge can also use this JWT to 302 a browser straight into baleforgit-server's `GET /v1/files/{file_id}?token=&repo=&filename=` endpoint, so "view raw" / "download" links don't proxy file bytes through the forge. baleforgit-server delegates the JWT validation back to the forge via `check_access` exactly like the `git-bale` flow does — but with one extra invariant the forge participates in:

- If the JWT is going to be used in a redirect URL, include a `FilenameSHA256` claim — hex SHA-256 of the filename the forge wants the browser to download as. baleforgit-server reads this claim out of the JWT payload (signature is irrelevant — `check_access` is the source of truth) and rejects any `?filename=` query that doesn't hash to it (HTTP 400). Without this binding, anyone with the redirect URL could rewrite the `Content-Disposition` filename and trick a browser into a different file type.

## `POST /check_access` request/response

```text
POST {authz_base}/check_access
{ "hub_bearer": "<jwt>", "repo": { "repo_type": "model", "repo_id": "owner/name", "revision": "main" },
  "scope": "read" | "write",
  "purpose": "token" | "file-download",
  "file_id": "<64-hex xet file hash>"            // only for purpose = file-download }

200 OK  { "user_id": "alice", "repo_id": "id/42", "owner": "7" }   // repo_id optional; owner required with repo_id
401     unknown/invalid bearer        403  valid user, insufficient access
```

What a forge implementation should do with the fields:

- **Return a stable canonical `repo_id` and the accounting `owner`.** `repo_id` in the request is whatever the client typed into its remote URL. baleforgit-server scopes tokens, file registrations and downloads to the `repo_id` you return, and per-owner quota and accounting to the `owner` you return. `owner` is required whenever you return `repo_id` (a response with `repo_id` but no `owner` is rejected as an upstream error); with neither, the owner is the part of the typed `repo_id` before `/`. Return a key that survives renames *and* transfers, ideally derived from the repo's immutable ID (the bundled gitea fork returns `id/<repoID>` with `owner` = `<ownerID>`). A name-based key splits one repo's files across case variants (`Alice/Repo` vs `alice/repo`), lets case variants dodge owner quotas, and strands every registered file on rename or transfer. With an ID-based key, a transfer only leaves historical accounting with the previous owner; files stay reachable. The owner must contain no `/` or whitespace.
- **Never reveal existence.** Verify the bearer before looking anything up, and answer every failure (bad token, unknown repo, mismatch, no permission) with the same 401, so the endpoint can't be used to enumerate private repos. The same goes for `/info/bale/authenticate`: an anonymous request for a missing repo gets the same 401 challenge as one for a private repo. Honor the forge's sign-in-required setting on every anonymous path (authenticate, discovery, and anonymous tokens at `check_access`, so tokens minted before the setting was turned on stop working).
- **Enforce `purpose`.** A JWT minted for a browser download link (`/v1/files?token=`) should be accepted only for `purpose: "file-download"`, bound to the `file_id` named in it, and should expire in minutes, not hours. Such links end up in browser history, proxy logs and shared URLs, so a download link must not double as a repo-wide token-exchange credential (`purpose: "token"`).
- **Honor credential scopes and keep tokens short-lived.** A personal access / OAuth token presented to `/info/bale/authenticate` must be held to its scopes (repository read for `download`, write for `upload`, public-only tokens only for public repos), exactly as the forge's git HTTP does. Mint the JWT for ~15 minutes (the client re-authenticates on refresh) and in its own token family: if it shares a signing key with LFS, tag it so an LFS token is never accepted by `check_access` and a Bale token never by LFS.
- **Serve it directly at the configured URL.** baleforgit-server doesn't follow redirects on this call.

## Why this shape

- **Mirrors `git-lfs-authenticate`.** A forge that supports LFS already has SSH `git-lfs-authenticate`, an HTTPS LFS Batch endpoint, and Basic-auth credential handling. The Bale endpoints follow the same patterns under a different name.
- **No shared secret between forge and baleforgit-server.** The forge mints JWTs against its own key. baleforgit-server verifies them by calling back to the forge (`/check_access`) rather than holding a copy of the signing key.
- **Forge owns the user model.** baleforgit-server has no concept of users, organisations, teams, branches, or branch protection. The forge is the single source of truth for "who can read/write this repo".
