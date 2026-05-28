"""`git-bale track` .gitattributes editing."""

from __future__ import annotations

from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.logutil import TestFailure
from baleharness.proc import run
from baleharness.timing import Timings


def _count_tracked(attrs: bytes, pattern: str) -> int:
    """How many active lines filter `pattern` through bale (mirrors the Rust
    `pattern_already_tracked`: skip blank/`#` lines, first token == pattern,
    `filter=bale` among the rest)."""
    n = 0
    for line in attrs.decode("utf-8", "replace").splitlines():
        t = line.strip()
        if not t or t.startswith("#"):
            continue
        parts = t.split()
        if parts and parts[0] == pattern and "filter=bale" in parts[1:]:
            n += 1
    return n


def phase_track(
    *,
    timings: Timings,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """`git-bale track <pattern>...` appends `<pattern> filter=bale -text` to
    `.gitattributes` in the cwd (no git repo required): it creates the file
    when absent, normalizes a missing trailing newline so a new pattern lands
    on its own line, preserves the file's CRLF/LF convention for that inserted
    separator, skips empty patterns, and never duplicates an already-tracked
    one."""
    env = client.make_env()
    bale = str(client.git_bale_bin)
    root = work_root / "track"
    root.mkdir()

    def track(cwd: Path, *patterns: str, expect_fail: bool = False):
        return run(
            [bale, "track", *patterns], cwd=cwd, env=env, expect_fail=expect_fail
        )

    def attrs(cwd: Path) -> bytes:
        p = cwd / ".gitattributes"
        return p.read_bytes() if p.exists() else b""

    with timings.measure("track: create / dedup / append / newline-fixups"):
        # No .gitattributes yet: created with the single line (NotFound read).
        fresh = root / "fresh"
        fresh.mkdir()
        out = track(fresh, "*.bin").stdout.decode("utf-8", "replace")
        if _count_tracked(attrs(fresh), "*.bin") != 1:
            raise TestFailure(f"track: *.bin not written once: {attrs(fresh)!r}")
        if 'Tracking "*.bin"' not in out:
            raise TestFailure(f"track: no 'Tracking' line in stdout: {out!r}")

        # Re-track the same pattern: reported already-tracked, no duplicate
        # (the `appended == 0` early return).
        out = track(fresh, "*.bin").stdout.decode("utf-8", "replace")
        if _count_tracked(attrs(fresh), "*.bin") != 1:
            raise TestFailure(f"track: *.bin duplicated on re-track: {attrs(fresh)!r}")
        if "already tracked" not in out:
            raise TestFailure(f"track: expected 'already tracked', got: {out!r}")

        # New patterns appended to a file that already ends in a newline.
        track(fresh, "*.png", "*.jpg")
        a = attrs(fresh)
        for pat in ("*.bin", "*.png", "*.jpg"):
            if _count_tracked(a, pat) != 1:
                raise TestFailure(f"track: {pat} count != 1 after append: {a!r}")

        # Existing file with NO trailing newline, plus a comment and a blank
        # line: the new pattern must not be concatenated onto the last line,
        # and the already-tracked one must be found across the skipped lines.
        no_eol = root / "no-eol"
        no_eol.mkdir()
        (no_eol / ".gitattributes").write_bytes(
            b"# bale patterns\n\n*.bin filter=bale -text"
        )
        out = track(no_eol, "*.bin", "*.png").stdout.decode("utf-8", "replace")
        a = attrs(no_eol)
        if _count_tracked(a, "*.bin") != 1:
            raise TestFailure(f"track: *.bin mangled in no-eol file: {a!r}")
        if _count_tracked(a, "*.png") != 1:
            raise TestFailure(f"track: *.png not appended in no-eol file: {a!r}")
        if b"-text*.png" in a:
            raise TestFailure(f"track: new pattern fused to newline-less line: {a!r}")
        if "already tracked" not in out:
            raise TestFailure(f"track: *.bin should be already-tracked: {out!r}")

        # An empty/whitespace pattern is skipped; the real one still lands.
        out = track(no_eol, "   ", "*.log").stdout.decode("utf-8", "replace")
        if _count_tracked(attrs(no_eol), "*.log") != 1:
            raise TestFailure(f"track: *.log not appended: {attrs(no_eol)!r}")
        if 'Tracking "   "' in out:
            raise TestFailure(f"track: blank pattern should be skipped: {out!r}")

        # CRLF file with no trailing newline: the inserted separator must be
        # CRLF, matching the file's convention.
        crlf = root / "crlf"
        crlf.mkdir()
        (crlf / ".gitattributes").write_bytes(
            b"*.bin filter=bale -text\r\n*.old filter=bale -text"
        )
        track(crlf, "*.new")
        a = attrs(crlf)
        if _count_tracked(a, "*.new") != 1:
            raise TestFailure(f"track: *.new not appended in CRLF file: {a!r}")
        if b"*.old filter=bale -text\r\n" not in a:
            raise TestFailure(f"track: separator before new pattern wasn't CRLF: {a!r}")

        # `.gitattributes` that is a directory: the read fails with a non-
        # NotFound error and track surfaces it instead of clobbering.
        baddir = root / "baddir"
        baddir.mkdir()
        (baddir / ".gitattributes").mkdir()
        c = track(baddir, "*.bin", expect_fail=True)
        if c.returncode == 0:
            raise TestFailure("track: a directory .gitattributes should fail the read")
        if b"reading .gitattributes" not in c.stderr:
            raise TestFailure(
                f"track: expected a read error, got: {c.stderr.decode('utf-8', 'replace')!r}"
            )

        # No patterns: the CLI rejects the invocation.
        c = track(fresh, expect_fail=True)
        if c.returncode == 0:
            raise TestFailure("track: no patterns should be rejected")
