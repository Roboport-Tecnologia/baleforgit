#!/usr/bin/env bash
# Build the release binaries for every distributed target and package them under
# dist/, plus a SHA256SUMS file — ready to drop on a download list. The server
# and client ship as separate archives per target (bale-server-* and
# bale-client-*); Linux/macOS ship both, Windows ships the client (git-bale) only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

SERVER_BIN=baleforgit-server
CLIENT_BIN=git-bale
LINUX_TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
MAC_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
WINDOWS_TARGETS=(x86_64-pc-windows-gnu)

DIST="$ROOT/dist"
STAGING="$DIST/staging"

usage() {
  cat <<'EOF'
Build + package the bale release binaries for every distributed target.

The server and client are packaged as separate archives per target:
bale-server-<version>-<target> and bale-client-<version>-<target>.

  ./build-release.sh                 build + package all targets
  ./build-release.sh --linux-only    only the Linux musl builds
  ./build-release.sh --mac-only      only the macOS builds
  ./build-release.sh --windows-only  only the Windows build
  ./build-release.sh --no-windows    everything except Windows  (also --no-linux / --no-mac)
  ./build-release.sh --no-sign       don't sign macOS binaries (ship plain .tar.gz)
  ./build-release.sh --no-notarize   sign + build .pkg but skip notarization/stapling
  ./build-release.sh --component server|client  build only that component
  ./build-release.sh --arch x86_64|aarch64      build only that architecture

--component and --arch narrow what gets built across all selected platforms;
they compose with each other and with the platform flags. A combination that
selects nothing (e.g. --component server with --windows-only, since Windows is
client-only) is an error.

Targets:
  x86_64-unknown-linux-musl    static, podman in an emulated linux/amd64 container
  aarch64-unknown-linux-musl   static, podman native linux/arm64 (no emulation)
  aarch64-apple-darwin         native cargo build (Apple Silicon)
  x86_64-apple-darwin          cross cargo build (Intel Mac; Apple SDK ships both arches)
  x86_64-pc-windows-gnu        git-bale.exe only, podman + mingw-w64 (no emulation)

Linux/Windows targets need podman + a running podman machine (amd64 emulation
for the x86_64 Linux target; the Windows build cross-compiles, no emulation).

macOS signing (when a "Developer ID Application" identity is in the keychain):
each binary is signed with hardened runtime, then — if a "Developer ID
Installer" identity is also present — packaged as a signed .pkg, notarized via
the BALE_NOTARY_PROFILE keychain profile (default "bale-notary"), and stapled.
Without those certs the macOS targets fall back to a plain .tar.gz.
EOF
}

DO_LINUX=1
DO_MAC=1
DO_WIN=1
MAC_SIGN=1
MAC_NOTARIZE=1
COMPONENT=""   # empty = both server and client
ARCH=""        # empty = all architectures
only() { DO_LINUX=0; DO_MAC=0; DO_WIN=0; }
# while/shift (not `for arg`) so --component/--arch can consume the next token.
while [ $# -gt 0 ]; do
  case "$1" in
    --linux-only)   only; DO_LINUX=1 ;;
    --mac-only)     only; DO_MAC=1 ;;
    --windows-only) only; DO_WIN=1 ;;
    --no-linux)     DO_LINUX=0 ;;
    --no-mac)       DO_MAC=0 ;;
    --no-windows)   DO_WIN=0 ;;
    --no-sign)      MAC_SIGN=0 ;;
    --no-notarize)  MAC_NOTARIZE=0 ;;
    --component)    shift; COMPONENT="${1:-}" ;;
    --component=*)  COMPONENT="${1#*=}" ;;
    --arch)         shift; ARCH="${1:-}" ;;
    --arch=*)       ARCH="${1#*=}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

case "$COMPONENT" in
  ""|server|client) ;;
  *) echo "--component must be server or client (got: '$COMPONENT')" >&2; exit 2 ;;
esac
case "$ARCH" in
  ""|x86_64|aarch64) ;;
  arm64) ARCH=aarch64 ;;
  amd64) ARCH=x86_64 ;;
  *) echo "--arch must be x86_64 or aarch64 (got: '$ARCH')" >&2; exit 2 ;;
esac

# macOS signing config, auto-detected once below. An empty identity means "not
# available — skip that step": no Developer ID Application -> unsigned .tar.gz;
# Application but no Installer -> signed binary in a .tar.gz (no .pkg).
APP_IDENTITY=""
INSTALLER_IDENTITY=""
NOTARY_PROFILE="${BALE_NOTARY_PROFILE:-bale-notary}"
ENTITLEMENTS="$ROOT/packaging/macos/git-bale.entitlements"

VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -1)"
[ -n "${VERSION:-}" ] || { echo "could not read version from Cargo.toml" >&2; exit 1; }
GITSHA="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
BUILT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# macOS stamps com.apple.provenance (and quarantine) xattrs on the binaries, and
# Apple's bsdtar stores them as LIBARCHIVE.xattr/SCHILY.xattr pax headers by
# default — which makes GNU tar warn ("Ignoring unknown extended header keyword")
# and materialize ._<name> AppleDouble sidecars on extract. Strip them so the
# Linux/Windows archives carry no Mac metadata. GNU tar (a Linux host running
# --linux-only) neither adds those xattrs nor knows --no-mac-metadata, so the
# flags are bsdtar-only. Unquoted expansion below is intentional word-splitting.
case "$(tar --version 2>&1)" in
  *bsdtar*|*libarchive*) TAR_MAC_OPTS="--no-mac-metadata --no-xattrs" ;;
  *)                     TAR_MAC_OPTS="" ;;
esac

log() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
# Raw build outputs (both binaries) land here per target; package() splits them
# into one archive per component.
rawdir() { echo "$STAGING/raw/$1"; }
pkgname() { echo "bale-$1-${VERSION}-$2"; }       # component, target

# Populate APP_IDENTITY / INSTALLER_IDENTITY from the keychain. -p codesigning
# only lists code-signing identities (the Application cert); Installer certs
# aren't in that policy, so they need a plain `find-identity -v`.
detect_mac_signing() {
  [ "$MAC_SIGN" = 1 ] || { log "macOS signing disabled (--no-sign)"; return; }
  command -v codesign >/dev/null 2>&1 || return
  APP_IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
      | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | head -1)"
  INSTALLER_IDENTITY="$(security find-identity -v 2>/dev/null \
      | sed -n 's/.*"\(Developer ID Installer: [^"]*\)".*/\1/p' | head -1)"
  if [ -n "$APP_IDENTITY" ]; then log "signing as: $APP_IDENTITY"
  else log "no 'Developer ID Application' identity — macOS binaries unsigned"; fi
  [ -z "$APP_IDENTITY" ] || [ -n "$INSTALLER_IDENTITY" ] \
      || log "no 'Developer ID Installer' identity — shipping signed .tar.gz, no .pkg"
}

# Sign one Mach-O with hardened runtime + secure timestamp. git-bale gets the
# library-validation opt-out so its dlopened FUSE dylib can load.
sign_mac_binary() {
  local bin="$1" ent=()
  [ "$(basename "$bin")" = "$CLIENT_BIN" ] && ent=(--entitlements "$ENTITLEMENTS")
  codesign --force --timestamp --options runtime "${ent[@]}" \
      --sign "$APP_IDENTITY" "$bin" || return 1
  codesign --verify --strict "$bin" || return 1
}

# Which components ship for a target, and the on-disk binary name for each.
components_for() {
  case "$1" in
    *-windows-*) echo client ;;
    *)           echo server client ;;
  esac
}
# components_for intersected with the --component filter — what we actually
# build/package for this target. May be empty (target contributes nothing).
effective_components() {
  local c out=""
  for c in $(components_for "$1"); do
    { [ -z "$COMPONENT" ] || [ "$c" = "$COMPONENT" ]; } && out="$out $c"
  done
  printf '%s' "$out"
}
cargo_pkg() {
  case "$1" in
    server) echo bale-server-bin ;;
    client) echo git-bale ;;
    *) return 1 ;;
  esac
}
binname() {
  local bin
  case "$1" in
    server) bin="$SERVER_BIN" ;;
    client) bin="$CLIENT_BIN" ;;
    *) return 1 ;;
  esac
  case "$2" in
    *-windows-*) echo "${bin}.exe" ;;
    *)           echo "$bin" ;;
  esac
}

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
  local t="$1" plat img cid raw b comp
  command -v podman >/dev/null 2>&1 || { echo "podman not found" >&2; return 1; }
  plat="$(platform_for "$t")" || { echo "no platform for $t" >&2; return 1; }
  img="localhost/bale-${t}:latest"
  log "Linux $t (podman, $plat)"
  podman build --platform "$plat" -f Dockerfile.musl \
      --build-arg RUST_TARGET="$t" --target export -t "$img" . || return 1
  # podman on macOS runs in remote mode where `--output type=local` is rejected,
  # so extract via a throwaway container instead.
  cid="$(podman create "$img")" || return 1
  raw="$(rawdir "$t")"; rm -rf "$raw"; mkdir -p "$raw"
  # The image builds both binaries; copy out only the requested component(s).
  for comp in $(effective_components "$t"); do
    b="$(binname "$comp" "$t")"
    podman cp "$cid:/$b" "$raw/$b" || { podman rm "$cid" >/dev/null 2>&1; return 1; }
  done
  podman rm "$cid" >/dev/null 2>&1 || true
}

build_mac() {
  local t="$1" raw comp b pkgs=()
  log "macOS $t (cargo)"
  for comp in $(effective_components "$t"); do pkgs+=(-p "$(cargo_pkg "$comp")"); done
  rustup target add "$t" >/dev/null || return 1
  # Strip at link time via the profile, NOT a post-link `strip`: modifying the
  # binary after linking invalidates the ad-hoc code signature the linker adds
  # on Apple Silicon, and the result is killed on launch.
  cargo build --release --target "$t" \
      --config 'profile.release.strip="symbols"' \
      "${pkgs[@]}" || return 1
  raw="$(rawdir "$t")"; rm -rf "$raw"; mkdir -p "$raw"
  for comp in $(effective_components "$t"); do
    b="$(binname "$comp" "$t")"
    cp "target/$t/release/$b" "$raw/$b" || return 1
    chmod 755 "$raw/$b"
    # Sign last — codesign is the binary's final mutation (it replaces the
    # linker's ad-hoc signature); anything after it invalidates the signature.
    [ -n "$APP_IDENTITY" ] && { sign_mac_binary "$raw/$b" || return 1; }
  done
  return 0
}

build_windows() {
  local t="$1" img cid raw
  command -v podman >/dev/null 2>&1 || { echo "podman not found" >&2; return 1; }
  img="localhost/bale-${t}:latest"
  # No --platform: cargo-xwin cross-compiles to Windows, so build native (no
  # emulation). Only git-bale ships for Windows.
  log "Windows $t (podman, mingw-w64, git-bale only)"
  podman build -f Dockerfile.windows \
      --build-arg RUST_TARGET="$t" --target export -t "$img" . || return 1
  cid="$(podman create "$img")" || return 1
  raw="$(rawdir "$t")"; rm -rf "$raw"; mkdir -p "$raw"
  podman cp "$cid:/${CLIENT_BIN}.exe" "$raw/${CLIENT_BIN}.exe" \
      || { podman rm "$cid" >/dev/null 2>&1; return 1; }
  podman rm "$cid" >/dev/null 2>&1 || true
}

# Build a signed .pkg that installs one (already-signed) binary to
# /usr/local/bin, then notarize + staple it. Unlike a bare Mach-O, a .pkg can
# carry a stapled notarization ticket, so Gatekeeper verifies it offline.
build_pkg() {
  local t="$1" comp="$2" bin="$3" name="$4"
  local raw root pkg
  raw="$(rawdir "$t")"
  root="$STAGING/pkgroot-$name"; rm -rf "$root"; mkdir -p "$root/usr/local/bin"
  cp "$raw/$bin" "$root/usr/local/bin/$bin" || return 1
  pkg="$DIST/${name}.pkg"; rm -f "$pkg"
  pkgbuild --root "$root" --identifier "com.davidriosgomes.baleforgit.$comp" \
      --version "$VERSION" --install-location / \
      --sign "$INSTALLER_IDENTITY" "$pkg" || return 1
  rm -rf "$root"
  if [ "$MAC_NOTARIZE" = 1 ]; then
    log "notarize ${name}.pkg (profile: $NOTARY_PROFILE)"
    xcrun notarytool submit "$pkg" --keychain-profile "$NOTARY_PROFILE" --wait \
        || return 1
    xcrun stapler staple "$pkg" || return 1
  fi
}

# One artifact per component for this target. Signed macOS targets -> stapled
# .pkg; Windows -> .zip; everything else (and unsigned macOS) -> .tar.gz, each
# holding a single binary + VERSION.txt.
package() {
  local t="$1" comp name sd raw bin
  raw="$(rawdir "$t")"
  for comp in $(effective_components "$t"); do
    name="$(pkgname "$comp" "$t")"
    bin="$(binname "$comp" "$t")" || return 1
    if [ -n "$APP_IDENTITY" ] && [ -n "$INSTALLER_IDENTITY" ] \
        && [[ "$t" == *-apple-darwin ]]; then
      build_pkg "$t" "$comp" "$bin" "$name" || return 1
      continue
    fi
    sd="$STAGING/$name"; rm -rf "$sd"; mkdir -p "$sd"
    cp "$raw/$bin" "$sd/$bin" || return 1
    printf 'bale %s\ncomponent: %s\ncommit: %s\ntarget: %s\nbuilt:  %s\n' \
        "$VERSION" "$comp" "$GITSHA" "$t" "$BUILT" > "$sd/VERSION.txt"
    case "$t" in
      *-windows-*)
        rm -f "$DIST/${name}.zip"
        # -X: don't store Mac extra attributes (xattrs/AppleDouble) in the zip.
        ( cd "$STAGING" && zip -Xqr "$DIST/${name}.zip" "$name" ) || return 1
        ;;
      *)
        tar $TAR_MAC_OPTS -C "$STAGING" -czf "$DIST/${name}.tar.gz" "$name" || return 1
        ;;
    esac
  done
}

mkdir -p "$STAGING"
[ "$DO_MAC" = 1 ] && detect_mac_signing
targets=()
[ "$DO_LINUX" = 1 ] && targets+=("${LINUX_TARGETS[@]}")
[ "$DO_MAC" = 1 ] && targets+=("${MAC_TARGETS[@]}")
[ "$DO_WIN" = 1 ] && targets+=("${WINDOWS_TARGETS[@]}")

# Apply --arch (target prefix is the arch) and --component (drop targets that
# ship none of the requested component). The ${arr[@]+...} guards keep this safe
# under `set -u` with macOS's bash 3.2, which errors on an empty-array expansion.
if [ -n "$ARCH" ] || [ -n "$COMPONENT" ]; then
  sel=()
  for t in ${targets[@]+"${targets[@]}"}; do
    [ -z "$ARCH" ] || [[ "$t" == "$ARCH"-* ]] || continue
    [ -n "$(effective_components "$t")" ] || continue
    sel+=("$t")
  done
  targets=(${sel[@]+"${sel[@]}"})
fi
[ ${#targets[@]} -gt 0 ] || { echo "no targets match the given filters" >&2; exit 1; }

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
    files=(bale-*.tar.gz bale-*.zip bale-*.pkg)
    if command -v shasum >/dev/null 2>&1; then shasum -a 256 "${files[@]}"
    else sha256sum "${files[@]}"; fi > SHA256SUMS )
  rm -rf "$STAGING"
  log "artifacts in dist/"
  ( cd "$DIST" && ls -lh bale-*.tar.gz bale-*.zip bale-*.pkg SHA256SUMS 2>/dev/null )
fi

if [ ${#failed[@]} -gt 0 ]; then
  printf '\n\033[1;31m==> FAILED: %s\033[0m\n' "${failed[*]}" >&2
  exit 1
fi
log "done — ${#built[@]} target(s) built"
