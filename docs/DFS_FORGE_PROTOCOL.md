# git-dfs forge protocol

This document describes what a **git forge** (gitea, gitlab, sourcehut, a custom git host, …) must implement to support `git-dfs` as a content-addressed alternative to git-lfs.

The protocol is deliberately shaped to mirror git-lfs's authentication flow, so a forge that already speaks LFS will have most of the wire surface in place.

## Components

```
   ┌──────────────┐   1. authenticate (HTTPS Basic / SSH)
   │  git-dfs     │ ────────────────────────────▶ ┌────────────┐
   │  (client)    │ ◀────────────────────────────│   forge    │
   └──────┬───────┘   {href, Bearer <jwt>, exp}  └─────┬──────┘
          │                                             │
          │ 2. exchange JWT for xet token               │ 3. /check_access
          ▼                                             ▼  (verify jwt, return user_id)
   ┌──────────────┐                              ┌────────────┐
   │  xet-server  │ ────────────────────────────▶│   forge    │
   └──────────────┘                              └────────────┘
```

Three things the forge owns:

1. **Authenticate endpoints** (this document) — turn the user's long-lived credential into a short-lived JWT.
2. **`POST /check_access`** — the upstream-authz hook xet-server calls to verify the JWT and check repo access. See `crates/xet-server-authz-http` for the wire contract.
3. **A discovery endpoint** for clients that haven't been pre-configured (optional but recommended).

This document covers #1 and #3.

## 1. HTTPS authenticate

```
POST  {forge}/<owner>/<repo>.git/info/dfs/authenticate?op=<op>
Authorization: Basic <base64("<user>:<secret>")>
```

Where:

- `<op>` is `download` (returns a read-scoped JWT) or `upload` (write-scoped).
- The forge authenticates the user against its own user database (password, PAT, OAuth token — whatever it normally accepts on Basic auth). The credential **never leaves the forge**.
- If the credential is unrecognized → `401 Unauthorized`.
- If the user is known but lacks the requested scope on the repo → `403 Forbidden`.

On success: `200 OK` with JSON body

```json
{
  "href": "https://xet-server.example.com",
  "header": { "Authorization": "Bearer <jwt>" },
  "expires_at": "2026-05-25T12:00:00Z"
}
```

- `href` is the base URL of the xet-server the client should talk to next. Required.
- `header.Authorization` carries the JWT the client will present to xet-server. The full `Bearer <jwt>` prefix is included so the forge can rotate auth schemes later without a client change.
- `expires_at` is informational (RFC 3339); the JWT's own `exp` is authoritative.

## 2. SSH authenticate

```
ssh <user>@<host> git-dfs-authenticate <owner>/<repo> <op>
```

The forge's SSH server recognises `git-dfs-authenticate` as a built-in command (alongside `git-receive-pack` / `git-upload-pack`). On success, write the same JSON body shown above to **stdout** and exit 0. On failure, exit non-zero with a human-readable message on stderr.

SSH auth is identity-based (the user has already proven who they are by presenting their SSH key), so no additional credential is needed in the command line.

## 3. Discovery (optional)

```
GET  {forge}/<owner>/<repo>.git/info/dfs
```

`200 OK` with

```json
{ "server_url": "https://xet-server.example.com" }
```

Lets a client confirm a repo has DFS enabled before attempting to authenticate. `git-dfs install` and CI scripts can use it as a feature probe. If the repo has DFS disabled, return `404`.

## The JWT

git-dfs treats the JWT as opaque — it just forwards it to xet-server as the `hub_bearer` (see `crates/xet-server-authz-http`). The **recommended** shape is:

- HS256 (or RS256) signed by the forge, with a secret known only to the forge.
- Short TTL (5–15 minutes). Long enough to cover a single push/pull, short enough that revocation isn't a concern.
- Claims: at minimum a user identifier; optionally repo / scope to let xet-server cross-check.

The forge then implements `POST /check_access` (see `xet-server-authz-http`) to verify the JWT it issued and return the user identity to xet-server. Because verification and issuance live in the same process, the forge can pick whatever JWT scheme it likes — xet-server never tries to parse the bearer itself.

## Why this shape

- **Mirrors `git-lfs-authenticate`.** A forge that supports LFS already has SSH `git-lfs-authenticate`, an HTTPS LFS Batch endpoint, and Basic-auth credential handling. The DFS endpoints follow the same patterns under a different name.
- **No shared secret between forge and xet-server.** The forge mints JWTs against its own key. xet-server verifies them by calling back to the forge (`/check_access`) rather than holding a copy of the signing key.
- **No long-lived credential reaches xet-server.** The user's password / PAT stays inside the forge. xet-server only sees short-lived JWTs.
- **Forge owns the user model.** xet-server has no concept of users, organisations, teams, branches, or branch protection. The forge is the single source of truth for "who can read/write this repo".
