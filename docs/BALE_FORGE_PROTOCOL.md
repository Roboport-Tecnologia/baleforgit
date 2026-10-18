# git-bale forge protocol

What a **git forge** (gitea, gitlab, sourcehut, a custom git host, …) implements so `git-bale` clients can use a `baleforgit-server` without any per-user configuration. It mirrors git-lfs's authentication flow, so a forge that already speaks LFS has most of the pieces.

## Components

```
   ┌───────────────────┐  1. authenticate (HTTPS Basic / SSH)  ┌────────────┐
   │     git-bale      │ ────────────────────────────────────▶ │            │
   │     (client)      │ ◀──────────────────────────────────── │   forge    │
   └─────────┬─────────┘     {href, Bearer <forge jwt>}        │            │
             │                                                 └─────▲──────┘
             │ 2. exchange forge JWT for a Bale token                │ 3. POST /check_access
             ▼                                                       │ (verify jwt, return user)
   ┌───────────────────┐                                             │
   │ baleforgit-server │ ────────────────────────────────────────────┘
   └───────────────────┘
```

The forge owns:

1. **Authenticate endpoints** (HTTPS and SSH) — turn the user's long-lived credential into a short-lived forge JWT plus the server URL.
2. **`POST /check_access`** — called by baleforgit-server (configured with `BALE_AUTHZ_HTTP_URL`) to verify that JWT and the user's access to the repo.
3. Optionally, a **discovery endpoint**.

In between, the client exchanges the forge JWT for a short-lived (5-minute) Bale token at baleforgit-server's `GET {href}/api/models/<owner>/<repo>/bale-{read,write}-token/main` (`Authorization: Bearer <forge jwt>` → `{accessToken, exp, casUrl}`), which is what triggers `/check_access`. The client re-runs the whole flow to refresh before the Bale token lapses. That endpoint is the server's; the forge doesn't implement it.

**Repo paths.** The client derives `<owner>/<repo>` from the `origin` remote (or the push target) by stripping a trailing `.git`. It must be exactly two segments, each `[A-Za-z0-9._-]` with no leading dot, so nested groups and forges served under a URL subpath aren't supported.

## 1. HTTPS authenticate

```
POST  {forge}/<owner>/<repo>.git/info/bale/authenticate?op=<op>
Authorization: Basic <base64("<user>:<secret>")>
```

Where:

- `{forge}` is `http(s)://host[:port]` from the remote URL (an SSH remote uses the SSH flow below instead).
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

- `href` (required) is the base URL of the baleforgit-server. For an `https://` or SSH remote the client refuses an `http://` href unless its host is loopback, so serve it over TLS.
- `header.Authorization` (required) must be `Bearer <jwt>`; anything else is rejected.
- `expires_at` is informational (RFC 3339) and ignored by the client.

## 2. SSH authenticate

```
ssh <user>@<host> git-bale-authenticate <owner>/<repo> <op>
```

The forge's SSH server recognises `git-bale-authenticate` as a built-in command (alongside `git-receive-pack` / `git-upload-pack`). On success, write the same JSON body to **stdout** and exit 0 (a top-level `"Authorization"` key is accepted in place of `header.Authorization`). On failure, exit non-zero with a message on stderr. The client runs ssh with `BatchMode=yes`, honoring `GIT_SSH_COMMAND` / `core.sshCommand`.

The SSH key already identifies the user, so there is no credential argument and no anonymous path.

## 3. Discovery (optional)

```
GET  {forge}/<owner>/<repo>.git/info/bale
```

`200 OK` with

```json
{ "server_url": "https://baleforgit-server.example.com" }
```

A feature probe for scripts and tooling: return `404` if the repo has Bale disabled. `git-bale` itself doesn't call it.

## The JWT

The JWT is opaque to both git-bale and baleforgit-server: the client presents it to the token endpoint, and the server passes it back to the forge's `/check_access` as `hub_bearer`. Since the forge both issues and verifies it, any scheme works. Recommended:

- Signed by the forge with a key only it holds.
- Short TTL (~15 minutes; the client re-authenticates on every refresh).
- Claims: at least the user, plus repo and scope so `/check_access` can check them.

**Anonymous reads need no server-side support.** An anonymous token is an ordinary JWT with an anonymous subject; `/check_access` returns that identity with read access for a public repo exactly as for a logged-in user. Repo visibility is entirely the forge's decision.

### Browser file download (`GET /v1/files/{file_id}`)

A forge can 302 a browser to `GET {href}/v1/files/{file_id}?token=<jwt>&repo=<owner>/<name>&filename=<name>` so "raw" / "download" links don't proxy bytes through the forge. baleforgit-server validates `token` via `/check_access` with `purpose: "file-download"` and the `file_id`, then applies the same per-repo file check as reconstructions (404 on miss).

To set the download name, put a `FilenameSHA256` claim (hex SHA-256 of the filename) in the JWT. The server reads it from the payload without checking the signature (`/check_access` is the authority) and answers 400 to a `filename` that doesn't hash to it; without the claim, `filename` is ignored and no `Content-Disposition` is sent. This stops anyone holding the URL from rewriting the filename to trick a browser into a different file type.

## `POST /check_access` request/response

```text
POST {BALE_AUTHZ_HTTP_URL}/check_access
{ "hub_bearer": "<jwt>", "repo": { "repo_type": "model", "repo_id": "owner/name", "revision": "main" },
  "scope": "read" | "write",
  "purpose": "token" | "file-download",
  "file_id": "<64-hex xet file hash>"            // only for purpose = file-download }

200 OK  { "user_id": "alice", "repo_id": "id/42", "owner": "7" }   // repo_id optional; owner required with repo_id
401/403 denied (both refuse the request; see below for why 401 is preferred)
```

`repo_type` is always `model` and `revision` always `main` from `git-bale`. Any other status, a body over 64 KiB, a returned `repo_id` that isn't exactly `<a>/<b>`, or an `owner` containing `/`, whitespace or control characters is treated as an upstream error (5xx to the client). The call times out after 10 s and redirects are not followed (the body carries the user's bearer), so serve it directly at the configured URL.

What a forge implementation should do with the fields:

- **Return a stable canonical `repo_id` and the accounting `owner`.** `repo_id` in the request is whatever the client typed into its remote URL (or the `repo` query of a file download). baleforgit-server scopes tokens, file registrations and downloads to the `repo_id` you return, and per-owner quota and accounting to the `owner` you return. `owner` is required whenever you return `repo_id` (a response with `repo_id` but no `owner` is rejected as an upstream error); with neither, the owner is the part of the typed `repo_id` before `/`. Return a key that survives renames *and* transfers, ideally derived from the repo's immutable ID (the bundled gitea fork returns `id/<repoID>` with `owner` = `<ownerID>`). A name-based key splits one repo's files across case variants (`Alice/Repo` vs `alice/repo`), lets case variants dodge owner quotas, and strands every registered file on rename or transfer. With an ID-based key, a transfer only leaves historical accounting with the previous owner; files stay reachable.
- **Never reveal existence.** Verify the bearer before looking anything up, and answer every failure (bad token, unknown repo, mismatch, no permission) with the same 401, so the endpoint can't be used to enumerate private repos. The same goes for `/info/bale/authenticate`: an anonymous request for a missing repo gets the same 401 challenge as one for a private repo. Honor the forge's sign-in-required setting on every anonymous path (authenticate, discovery, and anonymous tokens at `check_access`, so tokens minted before the setting was turned on stop working).
- **Enforce `purpose`.** A JWT minted for a browser download link (`/v1/files?token=`) should be accepted only for `purpose: "file-download"`, bound to the `file_id` named in it, and should expire in minutes, not hours. Such links end up in browser history, proxy logs and shared URLs, so a download link must not double as a repo-wide token-exchange credential (`purpose: "token"`).
- **Honor credential scopes and keep tokens short-lived.** A personal access / OAuth token presented to `/info/bale/authenticate` must be held to its scopes (repository read for `download`, write for `upload`, public-only tokens only for public repos), exactly as the forge's git HTTP does. Mint the JWT in its own token family: if it shares a signing key with LFS, tag it so an LFS token is never accepted by `check_access` and a Bale token never by LFS.

## Why this shape

- **Mirrors `git-lfs-authenticate`.** A forge that supports LFS already has SSH `git-lfs-authenticate`, an HTTPS LFS Batch endpoint, and Basic-auth credential handling. The Bale endpoints follow the same patterns under a different name.
- **No shared secret between forge and baleforgit-server.** The forge mints JWTs against its own key. baleforgit-server verifies them by calling back to the forge (`/check_access`) rather than holding a copy of the signing key.
- **Forge owns the user model.** baleforgit-server has no concept of users, organisations, teams, branches, or branch protection. The forge is the single source of truth for "who can read/write this repo".
