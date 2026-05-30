#!/usr/bin/env bash
# Build the release binaries for every distributed target and package one
# archive per target under dist/, plus a SHA256SUMS file — ready to drop on a
# download list. Linux/macOS ship both binaries; Windows ships git-bale only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

BINS=(baleforgit-server git-bale)
LINUX_TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
MAC_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
WINDOWS_TARGETS=(x86_64-pc-windows-gnu)

DIST="$ROOT/dist"
STAGING="$DIST/staging"

usage() {
  cat <<'EOF'
Build + package the bale release binaries for every distributed target.

  ./build-release.sh                 build + package all targets
  ./build-release.sh --linux-only    only the Linux musl builds
  ./build-release.sh --mac-only      only the macOS builds
  ./build-release.sh --windows-only  only the Windows build
  ./build-release.sh --no-windows    everything except Windows  (also --no-linux / --no-mac)

Targets:
  x86_64-unknown-linux-musl    static, podman in an emulated linux/amd64 container
  aarch64-unknown-linux-musl   static, podman native linux/arm64 (no emulation)
  aarch64-apple-darwin         native cargo build (Apple Silicon)
  x86_64-apple-darwin          cross cargo build (Intel Mac; Apple SDK ships both arches)
  x86_64-pc-windows-gnu        git-bale.exe only, podman + mingw-w64 (no emulation)

Linux/Windows targets need podman + a running podman machine (amd64 emulation
for the x86_64 Linux target; the Windows build cross-compiles, no emulation).
EOF
}

DO_LINUX=1
DO_MAC=1
DO_WIN=1
only() { DO_LINUX=0; DO_MAC=0; DO_WIN=0; }
for arg in "$@"; do
  case "$arg" in
    --linux-only)   only; DO_LINUX=1 ;;
    --mac-only)     only; DO_MAC=1 ;;
    --windows-only) only; DO_WIN=1 ;;
    --no-linux)     DO_LINUX=0 ;;
    --no-mac)       DO_MAC=0 ;;
    --no-windows)   DO_WIN=0 ;;
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

build_windows() {
  local t="$1" img cid sd
  command -v podman >/dev/null 2>&1 || { echo "podman not found" >&2; return 1; }
  img="localhost/bale-${t}:latest"
  # No --platform: cargo-xwin cross-compiles to Windows, so build native (no
  # emulation). Only git-bale ships for Windows.
  log "Windows $t (podman, mingw-w64, git-bale only)"
  podman build -f Dockerfile.windows \
      --build-arg RUST_TARGET="$t" --target export -t "$img" . || return 1
  cid="$(podman create "$img")" || return 1
  sd="$(stagedir "$t")"; rm -rf "$sd"; mkdir -p "$sd"
  podman cp "$cid:/git-bale.exe" "$sd/git-bale.exe" \
      || { podman rm "$cid" >/dev/null 2>&1; return 1; }
  podman rm "$cid" >/dev/null 2>&1 || true
}

package() {
  local t="$1" name sd
  name="$(pkgname "$t")"
  sd="$(stagedir "$t")"
  printf 'bale %s\ncommit: %s\ntarget: %s\nbuilt:  %s\n' \
      "$VERSION" "$GITSHA" "$t" "$BUILT" > "$sd/VERSION.txt"
  # zip for Windows (what its users expect), tar.gz elsewhere.
  case "$t" in
    *-windows-*)
      rm -f "$DIST/${name}.zip"
      ( cd "$STAGING" && zip -qr "$DIST/${name}.zip" "$name" ) || return 1
      ;;
    *)
      tar -C "$STAGING" -czf "$DIST/${name}.tar.gz" "$name" || return 1
      ;;
  esac
}

mkdir -p "$STAGING"
targets=()
[ "$DO_LINUX" = 1 ] && targets+=("${LINUX_TARGETS[@]}")
[ "$DO_MAC" = 1 ] && targets+=("${MAC_TARGETS[@]}")
[ "$DO_WIN" = 1 ] && targets+=("${WINDOWS_TARGETS[@]}")

built=()
failed=()
for t in "${targets[@]}"; do
  case "$t" in
    *-linux-musl)   builder=build_linux ;;
    *-apple-darwin) builder=build_mac ;;
    *-windows-*)    builder=build_windows ;;
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
    shopt -s nullglob
    files=(bale-*.tar.gz bale-*.zip)
    if command -v shasum >/dev/null 2>&1; then shasum -a 256 "${files[@]}"
    else sha256sum "${files[@]}"; fi > SHA256SUMS )
  rm -rf "$STAGING"
  log "artifacts in dist/"
  ( cd "$DIST" && ls -lh bale-*.tar.gz bale-*.zip SHA256SUMS 2>/dev/null )
fi

if [ ${#failed[@]} -gt 0 ]; then
  printf '\n\033[1;31m==> FAILED: %s\033[0m\n' "${failed[*]}" >&2
  exit 1
fi
log "done — ${#built[@]} target(s) built"
