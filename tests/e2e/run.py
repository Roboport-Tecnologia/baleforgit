#!/usr/bin/env python3
"""End-to-end harness entry point for git-bale + baleforgit-server.

The harness lives in the `baleharness` package; this module runs it and
re-exports the names `s3lib.py` imports via `from run import ...`.

    python3 tests/e2e/run.py              # filesystem blob store
    python3 tests/e2e/run.py --backend s3 # the whole suite against MinIO

See `tests/e2e/README.md` for prereqs and flags.
"""

from __future__ import annotations

import sys

from baleharness.cli import main

# `s3lib.py` does `from run import …`; keep these names resolvable here.
from baleharness.client import ClientEnv, setup_client  # noqa: F401
from baleharness.config import (  # noqa: F401
    BIG_FILE_BYTES,
    DEFAULT_IMAGE_TAG,
    E2E_HUB_TOKEN,
    E2E_OWNER,
    E2E_REPO,
    E2E_REPO_2,
    E2E_USER,
    JWT_TTL_YEARS,
    REPO_ROOT,
    SIZE_TOLERANCE_BYTES,
)
from baleharness.gitutil import git, verify_pointer_at, verify_worktree  # noqa: F401
from baleharness.jwtutil import mint_bale_jwt  # noqa: F401
from baleharness.logutil import (  # noqa: F401
    TestFailure,
    die,
    fmt_bytes,
    info,
    skip,
    warn,
)
from baleharness.mocks import TcpProxy  # noqa: F401
from baleharness.payloads import deterministic_payload  # noqa: F401
from baleharness.phases.failure import (  # noqa: F401
    _start_push_background,
    _wait_push,
    fail_fast_xet_env,
)
from baleharness.proc import (  # noqa: F401
    host_primary_ip,
    pick_free_port,
    sha256_bytes,
    tool_on_path,
)
from baleharness.repo import init_repo_for_clone, init_repo_for_push  # noqa: F401
from baleharness.runtime import (  # noqa: F401
    Runtime,
    build_image,
    detect_runtime,
    image_exists,
)
from baleharness.server import ServerHandle, start_container  # noqa: F401
from baleharness.storage import staging_files  # noqa: F401
from baleharness.timing import Timings  # noqa: F401
from baleharness.usage import fetch_repo_usage  # noqa: F401

if __name__ == "__main__":
    sys.exit(main())
