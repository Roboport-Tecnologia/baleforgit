"""Usage API + browser-style file download over HTTP."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from baleharness.server import ServerHandle


def fetch_usage(handle: ServerHandle, *, token: str, owner: str) -> dict:
    req = urllib.request.Request(
        f"{handle.public_host_url}/v1/usage/{owner}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_repo_usage(
    handle: ServerHandle, *, token: str, owner: str, repo: str
) -> dict:
    req = urllib.request.Request(
        f"{handle.public_host_url}/v1/usage/repo/{owner}/{repo}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def usage_status(handle: ServerHandle, *, token: str, owner: str) -> int:
    """HTTP status of GET /v1/usage/{owner}, 4xx included (authz negative tests)."""
    req = urllib.request.Request(
        f"{handle.public_host_url}/v1/usage/{owner}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def http_get_file(
    handle: ServerHandle,
    *,
    file_id: str,
    token: str,
    repo: str,
    filename: str | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    """GET /v1/files/{id}; returns (status, body, headers) for 4xx too.

    The bearer rides in `?token=` because the forge 302s here without an
    Authorization header."""
    params = {"token": token, "repo": repo}
    if filename is not None:
        params["filename"] = filename
    url = (
        f"{handle.public_host_url}/v1/files/{file_id}?{urllib.parse.urlencode(params)}"
    )
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return (
                resp.status,
                resp.read(),
                {k.lower(): v for k, v in resp.headers.items()},
            )
    except urllib.error.HTTPError as e:
        return e.code, e.read(), {k.lower(): v for k, v in e.headers.items()}
