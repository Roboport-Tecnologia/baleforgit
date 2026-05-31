#!/usr/bin/env bash
# Xcode "Run Script" build phase: compile the Rust C-ABI staticlib and stage it
# where the extension target links it. Add as a build phase ORDERED BEFORE
# "Link Binary With Libraries" on the BaleFSExtension target.
#
# Link setup in Xcode (extension target):
#   - Build Phases ▸ Link Binary With Libraries ▸ add ${BUILT_PRODUCTS_DIR}/libbale_mount_ffi.a
#   - Build Settings ▸ Library Search Paths ▸ add ${BUILT_PRODUCTS_DIR}
#   - Build Settings ▸ Objective-C Bridging Header ▸ path to include/bale_mount.h
set -euo pipefail

# Derive the ffi crate from THIS script's location (robust to where the .xcodeproj
# is saved), not from SRCROOT. This script lives at fskit-prototype/xcode/.
FFI_DIR="$(cd "$(dirname "$0")/../ffi" && pwd)"
OUT="${BUILT_PRODUCTS_DIR:-/tmp}/libbale_mount_ffi.a"

# Map Xcode's arch(s) to Rust triples. Dev builds are single-arch (arm64);
# a Developer-ID/universal build sets ARCHS="arm64 x86_64" and needs `lipo`.
build_one() {
	case "$1" in
		arm64)  echo "aarch64-apple-darwin" ;;
		x86_64) echo "x86_64-apple-darwin" ;;
		*) echo "unsupported arch $1" >&2; exit 1 ;;
	esac
}

libs=()
for arch in ${ARCHS:-arm64}; do
	triple=$(build_one "$arch")
	rustup target add "$triple" >/dev/null 2>&1 || true
	( cd "$FFI_DIR" && cargo build --release --target "$triple" )
	libs+=("${FFI_DIR}/target/${triple}/release/libbale_mount_ffi.a")
done

if [ "${#libs[@]}" -gt 1 ]; then
	lipo -create "${libs[@]}" -output "$OUT"
else
	cp "${libs[0]}" "$OUT"
fi
echo "staged staticlib -> $OUT"
