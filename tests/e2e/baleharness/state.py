"""Multi-run state stash for --state-dir / --reuse-from."""

from __future__ import annotations

import json
from pathlib import Path


STATE_FILE = ".e2e_state.json"


def save_state(
    state_dir: Path,
    *,
    jwt_secret_hex: str,
    transfer_secret_hex: str,
    admin_token_hex: str,
    rev_state: dict,
) -> None:
    """Persist the bits a follow-up --reuse-from run needs: server-side
    secrets so JWT/transfer signatures stay valid against the same data
    dir, and rev_state's shas/commits so read-only phases know what to
    expect from the already-pushed history."""
    payload = {
        "jwt_secret_hex": jwt_secret_hex,
        "transfer_secret_hex": transfer_secret_hex,
        "admin_token_hex": admin_token_hex,
        # rev_state contains Paths and a dict env; strip to the JSON-friendly
        # subset the read-only phases actually consume.
        "rev_state": {
            "shas": list(rev_state.get("shas", [])),
            "commits": list(rev_state.get("commits", [])),
            "disk_after": list(rev_state.get("disk_after", [])),
            "raw_after": list(rev_state.get("raw_after", [])),
        },
    }
    (state_dir / STATE_FILE).write_text(json.dumps(payload, indent=2))


def load_state(state_dir: Path) -> dict:
    return json.loads((state_dir / STATE_FILE).read_text())
