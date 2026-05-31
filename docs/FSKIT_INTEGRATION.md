# FSKit-native macOS mount — integration notes (paused)

Status: **feasibility proven, integration paused before first signed build.** This
doc is the resume point. The work lives in `fskit-prototype/` (a standalone,
workspace-excluded prototype). Nothing here is wired into the shipping `git-bale`
yet.

## Goal

Make `git-bale mount` / `mount-diff` *native* on macOS via **FSKit** (Apple's
post-kext userspace filesystem framework, macOS 15.4+), as an alternative to the
current dlopened **fuse-t** backend (`crates/git-bale/src/mount/backend/libfuse.rs`).

### Why FSKit, not File Provider
- **FSKit** mounts a real volume and exposes lookup/getattr/readdir/read callbacks
  — a near 1:1 match for the existing backend-agnostic VFS (`mount/vfs.rs`,
  `mount/reader.rs`). Right paradigm.
- **File Provider** is a cloud-*sync* paradigm (domains, working sets, sync
  anchors, files under `~/Library/CloudStorage/`). Wrong shape for ephemeral,
  read-only, mount-at-path views. Rejected.
- We're already kext-free via fuse-t; the lowest-effort "more native, no kext"
  alternative is the **macFUSE 5.2 FSKit backend** (no protocol change) — but
  that requires users install macFUSE, and we bind fuse-t today.

## Distribution model (decided)

- Ship one **signed + notarized `.pkg`** with two payloads:
  - `/usr/local/bin/git-bale` — the Rust CLI (App ID "Bale for Git Client").
  - `/Applications/Bale for Git Mount.app` — host app embedding the FSKit
    **`.appex`** (App ID "Bale for Git Mount").
- **Two certs**: *Developer ID Application* signs the binaries/bundles;
  *Developer ID Installer* signs the `.pkg`. Notarize the pkg (covers contents),
  then `stapler staple`.
- The FSKit module **must** be an App Extension embedded in a host app — it cannot
  be a standalone app. The host app is "Bale for Git Mount".
- Local-dev iteration uses **Apple Development** cert + a Development provisioning
  profile instead (no notarization needed to run on your own Mac).

## What the prototype proved (run `fskit-prototype/build.sh`)

On macOS 15.7 with **Command Line Tools only** (no Xcode, no signing):

1. FSKit is present; `import FSKit` compiles under CLT; a full Swift overlay
   (`.swiftinterface`) ships in the CLT SDK.
2. The Rust VFS maps onto a small **C ABI** (`fskit-prototype/include/bale_mount.h`):
   `open / lookup / getattr / readdir / open_file / read / close` — shaped 1:1
   with `DiffVfs` + `Reader`.
3. That boundary **runs** (`fskit-prototype/harness.c` links the staticlib and
   drives it: readdir, partial read at offset, EOF, negative lookup — all green).
4. Panics can't cross into Swift — every FFI entry is `catch_unwind`-wrapped,
   message via `bale_vfs_last_error` (`fskit-prototype/ffi/src/lib.rs`).
5. The Swift FSKit shim **typechecks AND code-generates**
   (`fskit-prototype/swift/`): `BaleVolume` conforms to `FSVolume.Operations` +
   `PathConfOperations` + `OpenCloseOperations` + `ReadWriteOperations`; `BaleFS`
   is the `FSUnaryFileSystem` delegate + `@main UnaryFileSystemExtension`.
6. The emitted object references both the FSKit ObjC classes and the `_bale_vfs_*`
   symbols — Swift→FSKit and Swift→Rust both wire up.

The prototype's Rust side is a **hardcoded fake tree** (`/hello.txt`,
`/sub/world.bin`). Wiring the real `DiffVfs`/`Reader` is deferred (mechanical —
the methods already line up) until a signed mount actually runs.

## FSKit API findings (carry into the real impl)

- **No read-only conformance.** `FSVolume.Operations` makes the mutators
  (`createItem`, `removeItem`, `renameItem`, `setAttributes`, `write`, …)
  *required*. We implement them as `EROFS` throws. (Matches the known quirk that
  Finder doesn't fully grasp read-only FSKit volumes and lets users "create"
  things that silently vanish.)
- **Mountpoints restricted to `/Volumes`** — a UX change from today's
  arbitrary-path `git-bale mount <rev> <path>`.
- **Read buffer API** is `FSMutableFileDataBuffer.withUnsafeMutableBytes { … }`
  (the header's `withMutableBytes` is absent from this SDK's overlay).
- **Async forms are first-class.** Quirks: the async `getAttributes` is named
  `attributes(_:of:)`; the async `createSymbolicLink` returns `(FSItem, FSFileName)`.
- ObjC names map to nested Swift names: `FSVolumeOperations` → `FSVolume.Operations`,
  `FSItemAttributes` → `FSItem.Attributes`, `FSVolumeIdentifier` →
  `FSVolume.Identifier`, etc.
- The appex `@main` entry is `UnaryFileSystemExtension` (ExtensionFoundation).

## Signing reality

- **`com.apple.developer.fskit.fsmodule` is a *restricted* entitlement.** It must
  be authorized by a **provisioning profile** on a **paid team**, and the portal
  routes it through "do you need additional entitlements?" — i.e. likely a
  **request + wait for Apple's approval email**. The capability lives on the
  **extension's** App ID, not the host app's.
- **Xcode is required** — CLT can't author/sign an appex with a restricted
  entitlement (no template, and you can't codesign a restricted entitlement
  without a profile). Start from the *File System Extension* target template.
- Entitlements (scaffolded in `fskit-prototype/xcode/config/`):
  - extension: `fsmodule` + `app-sandbox` + `network.client` +
    `files.user-selected.read-only`
  - host app: `app-sandbox` + `files.user-selected.read-write` + `network.client`

## THE open risk to settle first (cheap test, expensive to discover late)

An FSKit appex runs **App-Sandboxed**. The real `Reader` needs to (a) open network
connections (cold-path reconstruction) and (b) read `~/.cache/bale/chunks`,
`.git/bale/staging`, and the repo ODB. **Before** wiring the real VFS, get a mount
running on the *fake* VFS and drop a throwaway probe in `BaleFS.loadResource` that
tries a network socket + a read under `~`. If the sandbox blocks the cache/repo
paths, context must arrive as **security-scoped bookmarks via the mount's
`FSTaskOptions`** — the compile-level work can't answer this.

## Context channel (design open question)

The FS "resource" / mount options is how repo+rev reach the out-of-process
extension. `mount-diff`'s two-revs-plus-labels argues for an **XPC handshake**
(host app ↔ extension) over cramming everything into a single `mount` resource
string. agent-harbor's FSKit setup uses an XPC control service in the appex
Info.plist as precedent.

## Machine state at pause (2026-05-31)

- Xcode installed and active (`/Applications/Xcode.app`).
- Keychain: one **Developer ID Application: David Rios Gomes (33H52KGYNU)** cert.
  Account has all cert types available to generate via Xcode.
- **No provisioning profiles yet.**
- Portal: App IDs created for **"Bale for Git Client"** (= the CLI) and
  **"Bale for Git Mount"** (= host app). **No extension App ID yet**, and the
  FSKit capability / `fsmodule` entitlement **not yet enabled/approved**.
- **No Xcode project created yet.**
- `fskit-prototype/signing/bale_dev.csr` generated (+ gitignored `bale_dev.key`).

## Prototype layout

```
fskit-prototype/
├── README.md                 feasibility verdict + what each piece proves
├── build.sh                  builds staticlib, runs C harness, typechecks+codegens shim
├── ffi/                      Rust C-ABI staticlib (fake VFS; real DiffVfs wiring deferred)
│   └── src/lib.rs
├── include/bale_mount.h      the C ABI / Swift bridging header
├── harness.c                 runtime proof of the FFI boundary
├── swift/                    BaleVolume.swift, BaleFS.swift — the FSKit shim (compiles)
├── signing/                  bale_dev.csr (+ gitignored key)
└── xcode/
    ├── SETUP.md              Apple-Development local-signing checklist
    ├── build-rust-staticlib.sh   Xcode Run-Script build phase (arch→triple, lipo)
    └── config/
        ├── BaleFSExtension.entitlements
        ├── BaleMountApp.entitlements
        └── BaleFSExtension-Info.reference.plist
```

## Resume here — Xcode build steps

Use your real bundle IDs where these say `com.you.…`. Save the project at
`fskit-prototype/xcode/` so the build-script + bridging-header paths resolve.

1. **Host project**: Xcode → New → Project → macOS → App, name "Bale for Git
   Mount", Swift/SwiftUI. Signing & Capabilities → Automatically manage signing →
   team; set Bundle ID to the "Bale for Git Mount" App ID. Save in
   `fskit-prototype/xcode/`.
2. **Extension target**: New → Target → macOS → **File System Extension**, name
   `BaleFSExtension`, bundle id = host + `.fsext` (this carries `fsmodule`).
3. **Swap sources**: delete the template's sample FS Swift files; add
   `../swift/BaleVolume.swift` + `../swift/BaleFS.swift` to the extension target
   (don't copy — reference in place). Build Settings → Objective-C Bridging Header
   = `$(SRCROOT)/../include/bale_mount.h`. Confirm `FSShortName=balefs`,
   `FSSupportsBlockResources=false` in the template Info.plist.
4. **Link staticlib** (extension → Build Phases): add Run Script
   `"${SRCROOT}/../build-rust-staticlib.sh"`, ordered before "Link Binary With
   Libraries"; link `${BUILT_PRODUCTS_DIR}/libbale_mount_ffi.a`; Library Search
   Paths += `$(BUILT_PRODUCTS_DIR)`.
5. **Entitlements** (Build Settings → Code Signing Entitlements): extension →
   `$(SRCROOT)/../config/BaleFSExtension.entitlements`; host →
   `$(SRCROOT)/../config/BaleMountApp.entitlements`. Deployment target 15.4 both.
6. **Build the host app.** If it fails on the `fsmodule` entitlement: portal →
   extension's App ID → enable **FSKit** capability (request + await approval if
   prompted) → Xcode regenerates the profile → rebuild.
7. **Enable + mount the fake VFS**: run the host app once; System Settings →
   General → Login Items & Extensions → File System Extensions → enable Bale;
   then `mkdir -p /Volumes/bale && mount -F -t balefs x /Volumes/bale && ls
   /Volumes/bale` (expect `hello.txt`, `sub/`). Debug via
   `log stream --predicate 'subsystem CONTAINS "fskit"' --info`.

Then: run the **sandbox probe** (above), and once green, wire the real
`DiffVfs`/`Reader` behind the C ABI so it reconstructs actual Bale-tracked content.
