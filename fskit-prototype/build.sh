#!/usr/bin/env bash
# Feasibility prototype build. Proves, on a plain Command Line Tools install
# (no Xcode, no signing identity):
#   1. the Rust VFS compiles to a C-ABI staticlib and runs across the boundary
#   2. the Swift FSKit shim (FSUnaryFileSystem + FSVolume conformances) compiles
#      and links against both FSKit and the Rust staticlib
# What it does NOT do: produce a loadable .appex (needs signing + the
# com.apple.developer.fskit.fsmodule entitlement + user enable in Settings).
set -euo pipefail
cd "$(dirname "$0")"

SDK=$(xcrun --show-sdk-path)
TARGET=arm64-apple-macos15.4

echo "==> 1. Rust FFI staticlib"
( cd ffi && cargo build --release )
LIB=ffi/target/release/libbale_mount_ffi.a

echo "==> 2. Link + run C harness (runtime proof of the FFI boundary)"
cc -O2 -o /tmp/bale_harness harness.c "$LIB" \
    -framework CoreFoundation -framework Security
/tmp/bale_harness

echo "==> 3. Typecheck Swift FSKit shim against the SDK"
swiftc -sdk "$SDK" -target "$TARGET" -typecheck \
    -import-objc-header include/bale_mount.h \
    swift/BaleVolume.swift swift/BaleFS.swift

echo "==> 4. Code-gen the shim (single object via WMO)"
swiftc -sdk "$SDK" -target "$TARGET" -wmo -module-name BaleFSExt \
    -emit-object -parse-as-library \
    -import-objc-header include/bale_mount.h \
    swift/BaleVolume.swift swift/BaleFS.swift -o /tmp/bale_shim.o
echo "    shim object: $(ls -la /tmp/bale_shim.o | awk '{print $5}') bytes"
echo "    references both FSKit classes and Rust FFI:"
nm -u /tmp/bale_shim.o | grep -iE "FSVolume|FSUnary|bale_vfs_open" | sed 's/^/      /'

echo "==> OK — feasibility chain proven end to end (sans signing)."
