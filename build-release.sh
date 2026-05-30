#!/usr/bin/env bash
# Build the release binaries (baleforgit-server + git-bale) for every
# distributed target and package one tarball per target under dist/, plus a
# SHA256SUMS file — ready to drop on a download list.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

BINS=(baleforgit-server git-bale)
LINUX_TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
MAC_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)

DIST="$ROOT/dist"
STAGING="$DIST/staging"

usage() {
  cat <<'EOF'
Build + package the bale release binaries for every distributed target.

  ./build-release.sh              build + package all targets
  ./build-release.sh --mac-only   skip the Linux (podman) builds
  ./build-release.sh --linux-only only the Linux musl builds

Targets:
  x86_64-unknown-linux-musl    static, podman in an emulated linux/amd64 container
  aarch64-unknown-linux-musl   static, podman native linux/arm64 (no emulation)
  aarch64-apple-darwin         native cargo build (Apple Silicon)
  x86_64-apple-darwin          cross cargo build (Intel Mac; Apple SDK ships both arches)

Linux targets need podman + a running podman machine (amd64 emulation for x86_64).
EOF
}

DO_LINUX=1
DO_MAC=1
for arg in "$@"; do
  case "$arg" in
    --mac-only|--no-linux) DO_LINUX=0 ;;
    --linux-only|--no-mac) DO_MAC=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $arg (try --help)" >&2; exit 2 ;;
  esac
done

VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -1)"
[ -n "${VERSION:-}" ] || { echo "could not read version from Cargo.toml" >&2; exit 1; }
GITSHA="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
BUILT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
pkgname() { echo "bale-${VERSION}-$1"; }
stagedir() { echo "$STAGING/$(pkgname "$1")"; }

# These functions use explicit `|| return 1` instead of relying on `set -e`:
# bash suspends errexit inside a function whose result is tested with `if`/`||`,
# which is exactly how the dispatch loop calls them.
platform_for() {
  case "$1" in
    x86_64-unknown-linux-musl)  echo linux/amd64 ;;
    aarch64-unknown-linux-musl) echo linux/arm64 ;;
    *) return 1 ;;
  esac
}

build_linux() {
  local t="$1" plat img cid sd b
  command -v podman >/dev/null 2>&1 || { echo "podman not found" >&2; return 1; }
  plat="$(platform_for "$t")" || { echo "no platform for $t" >&2; return 1; }
  img="localhost/bale-${t}:latest"
  log "Linux $t (podman, $plat)"
  podman build --platform "$plat" -f Dockerfile.musl \
      --build-arg RUST_TARGET="$t" --target export -t "$img" . || return 1
  # podman on macOS runs in remote mode where `--output type=local` is rejected,
  # so extract via a throwaway container instead.
  cid="$(podman create "$img")" || return 1
  sd="$(stagedir "$t")"; rm -rf "$sd"; mkdir -p "$sd"
  for b in "${BINS[@]}"; do
    podman cp "$cid:/$b" "$sd/$b" || { podman rm "$cid" >/dev/null 2>&1; return 1; }
  done
  podman rm "$cid" >/dev/null 2>&1 || true
}

build_mac() {
  local t="$1" sd b
  log "macOS $t (cargo)"
  rustup target add "$t" >/dev/null || return 1
  # Strip at link time via the profile, NOT a post-link `strip`: modifying the
  # binary after linking invalidates the ad-hoc code signature the linker adds
  # on Apple Silicon, and the result is killed on launch.
  cargo build --release --target "$t" \
      --config 'profile.release.strip="symbols"' \
      -p bale-server-bin -p git-bale || return 1
  sd="$(stagedir "$t")"; rm -rf "$sd"; mkdir -p "$sd"
  for b in "${BINS[@]}"; do
    cp "target/$t/release/$b" "$sd/$b" || return 1
    chmod 755 "$sd/$b"
  done
}

package() {
  local t="$1" name sd
  name="$(pkgname "$t")"
  sd="$(stagedir "$t")"
  printf 'bale %s\ncommit: %s\ntarget: %s\nbuilt:  %s\n' \
      "$VERSION" "$GITSHA" "$t" "$BUILT" > "$sd/VERSION.txt"
  tar -C "$STAGING" -czf "$DIST/${name}.tar.gz" "$name" || return 1
}

mkdir -p "$STAGING"
targets=()
[ "$DO_LINUX" = 1 ] && targets+=("${LINUX_TARGETS[@]}")
[ "$DO_MAC" = 1 ] && targets+=("${MAC_TARGETS[@]}")

built=()
failed=()
for t in "${targets[@]}"; do
  case "$t" in
    *-linux-musl)   builder=build_linux ;;
    *-apple-darwin) builder=build_mac ;;
    *) failed+=("$t (no builder)"); continue ;;
  esac
  if "$builder" "$t"; then
    if package "$t"; then built+=("$t"); else failed+=("$t (packaging)"); fi
  else
    failed+=("$t")
  fi
done

if [ ${#built[@]} -gt 0 ]; then
  log "checksums"
  ( cd "$DIST"
    if command -v shasum >/dev/null 2>&1; then shasum -a 256 bale-*.tar.gz
    else sha256sum bale-*.tar.gz; fi > SHA256SUMS )
  rm -rf "$STAGING"
  log "artifacts in dist/"
  ( cd "$DIST" && ls -lh bale-*.tar.gz SHA256SUMS )
fi

if [ ${#failed[@]} -gt 0 ]; then
  printf '\n\033[1;31m==> FAILED: %s\033[0m\n' "${failed[*]}" >&2
  exit 1
fi
log "done — ${#built[@]} target(s) built"
