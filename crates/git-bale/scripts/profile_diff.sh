#!/usr/bin/env bash
# Repro harness for slow `git diff` on a modified bale-tracked binary.
#
# Builds release `git-bale`, sets up an offline-only bale repo in a tempdir,
# writes a random binary of $SIZE_MIB MiB, commits it, appends $APPEND_BYTES
# bytes, then times `git diff` (which re-invokes the clean filter).
#
# Env knobs:
#   SIZE_MIB=35        payload size in MiB
#   APPEND_BYTES=16    bytes to append before diffing
#   ITERS=3            number of timed diff iterations
#   PROFILE=samply     wrap the *second* git diff with a profiler ("samply" or "")
#   KEEP=1             keep the tempdir for poking around
#   BUILD=0            skip cargo build (use stale binary)
#
# Profiling tips after a run:
#   cd $WORK && samply record git diff --quiet
#   cargo flamegraph --release --bin git-bale -- filter-process < fixture
# The clean filter speaks git's pkt-line protocol on stdin, so the easiest
# end-to-end profile target is `git diff` itself with samply.

set -euo pipefail

SIZE_MIB=${SIZE_MIB:-35}
APPEND_BYTES=${APPEND_BYTES:-16}
ITERS=${ITERS:-3}
PROFILE=${PROFILE:-}
KEEP=${KEEP:-0}
BUILD=${BUILD:-1}

here=$(cd "$(dirname "$0")" && pwd)
root=$(git -C "$here" rev-parse --show-toplevel)

if [ "$BUILD" = "1" ]; then
    echo ">> cargo build --release -p git-bale"
    (cd "$root" && cargo build --release -p git-bale)
fi
git_bale="$root/target/release/git-bale"
if [ ! -x "$git_bale" ]; then
    echo "missing $git_bale; set BUILD=1" >&2
    exit 1
fi

work=$(mktemp -d -t bale-profile.XXXXXX)
cleanup() { [ "$KEEP" = "1" ] || rm -rf "$work"; }
trap cleanup EXIT
echo ">> workdir: $work"

cd "$work"
git init -q -b main
git config user.email harness@bale.invalid
git config user.name harness
git config --local filter.bale.process "$git_bale filter-process"
git config --local filter.bale.required true
# Clean is offline (writes to .git/bale/staging/) so the URL is never dialed.
git config --local bale.serverUrl http://127.0.0.1:1
git config --local bale.token harness

printf '*.bin filter=bale -text\n' > .gitattributes
git add .gitattributes
git commit -q -m "enable bale filter"

echo ">> writing $SIZE_MIB MiB random payload to big.bin"
# bs=1048576 works on both macOS and Linux (macOS dd uses 1m, Linux uses 1M).
dd if=/dev/urandom of=big.bin bs=1048576 count="$SIZE_MIB" status=none

echo
echo "=== initial git add (cold clean — full CDC + xorb) ==="
/usr/bin/time -p git add big.bin

echo
echo "=== git commit ==="
/usr/bin/time -p git commit -q -m "add big.bin"

echo
echo ">> staging dir contents after add+commit:"
find .git/bale -maxdepth 3 -type f | head -20
echo ">> clean-cache entries:"
ls -la .git/bale/clean-cache 2>/dev/null || echo "  (none)"

echo
echo ">> appending $APPEND_BYTES bytes to big.bin"
dd if=/dev/urandom bs="$APPEND_BYTES" count=1 status=none >> big.bin
ls -la big.bin

echo
echo "=== git diff after append — expect SLOW (size mismatch defeats clean-cache) ==="
for i in $(seq 1 "$ITERS"); do
    echo "  -- iter $i --"
    if [ "$i" = "2" ] && [ "$PROFILE" = "samply" ] && command -v samply >/dev/null 2>&1; then
        samply record -- git diff --quiet || true
    else
        /usr/bin/time -p git diff --quiet || true
    fi
done

echo
echo "=== control: git diff with NO modification (clean-cache hit, expected fast) ==="
# Truncate the appended bytes off so size matches the cache entry; clean-cache
# should now verify by chunks and short-circuit before the xet-data pipeline.
truncate -s "$((SIZE_MIB * 1048576))" big.bin
/usr/bin/time -p git diff --quiet || true
/usr/bin/time -p git diff --quiet || true

echo
echo ">> done. workdir: $work  (KEEP=1 to retain)"
