"""Hand-rolled HS256 JWT + forge-style JWT helpers (no pip deps)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def forge_jwt_with_filename(filename: str) -> str:
    """A forge-style JWT carrying gitea's `FilenameSHA256` claim. bale-server
    base64url-decodes the payload to gate the download's `Content-Disposition`
    but never verifies the signature (the forge does), so a dummy sig is fine.
    No `:` in the base64url alphabet, so it slots into a BALE_GRANTS tuple."""
    header = _b64url_no_pad(b'{"alg":"HS256","typ":"JWT"}')
    claim = hashlib.sha256(filename.encode("utf-8")).hexdigest()
    payload = _b64url_no_pad(
        json.dumps({"FilenameSHA256": claim}, separators=(",", ":")).encode("utf-8")
    )
    return f"{header}.{payload}.{_b64url_no_pad(b'e2e-unverified-sig')}"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint_bale_jwt(
    *,
    secret: bytes,
    sub: str,
    repo_type: str,
    repo_id: str,
    revision: str,
    scope: str,
    ttl_secs: int,
) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": sub,
        "repo_type": repo_type,
        "repo_id": repo_id,
        "revision": revision,
        "scope": scope,
        "exp": int(time.time()) + ttl_secs,
    }
    h_b = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b}.{p_b}".encode("ascii")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h_b}.{p_b}.{_b64url(sig)}"
