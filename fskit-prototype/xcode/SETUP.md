# FSKit prototype — signing + Xcode setup (Apple Development, local)

Goal: build, sign, enable, and **mount** the FSKit extension on *this* Mac for
development. Distribution (Developer ID + notarized `.pkg`) comes later.

The account-bound / GUI steps are yours; everything else is scaffolded in this
repo. Steps marked ⏳ may block on an Apple approval email.

## 0. Prereqs
- [ ] **Install full Xcode** (App Store or developer.apple.com). CLT alone can't
      author an appex with a restricted entitlement. After install:
      `sudo xcode-select -s /Applications/Xcode.app` then `sudo xcodebuild -license accept`.
- [ ] macOS ≥ 15.4 (this machine is 15.7 ✓).

## 1. Apple Developer portal
- [ ] **App IDs** — create two explicit bundle IDs, e.g.
      `com.<you>.balemount` (host app) and `com.<you>.balemount.fsext` (extension).
- [ ] ⏳ **Request the FSKit entitlement.** On the extension's App ID, enable the
      FSKit capability. If the portal routes you through "do you need additional
      entitlements?", request `com.apple.developer.fskit.fsmodule` and wait for
      Apple's approval email before the profile will carry it.
- [ ] **Certificate** — easiest is Xcode automatic signing (step 2). Manual
      fallback: upload `signing/bale_dev.csr` (already generated) as an *Apple
      Development* cert, download the `.cer`, then:
      ```
      security import signing/bale_dev.key  -k ~/Library/Keychains/login.keychain-db
      security import ~/Downloads/development.cer -k ~/Library/Keychains/login.keychain-db
      security find-identity -v -p codesigning   # should now list 1 identity
      ```
- [ ] **Provisioning profiles** — one per App ID, Development type, including the
      approved fsmodule entitlement on the extension's profile.

## 2. Xcode project
- [ ] New **macOS App** "BaleMount" (the host). Set its bundle ID + team; turn on
      *Automatically manage signing* (creates the dev cert if you skipped the CSR).
- [ ] Add target → **File System Extension** ("BaleFSExtension"). This generates
      the correct `Info.plist` + a sample `FSUnaryFileSystem`.
- [ ] **Swap in our sources:** delete the template's sample filesystem files; add
      `swift/BaleVolume.swift` and `swift/BaleFS.swift` to the extension target.
- [ ] **Bridging header:** Build Settings ▸ *Objective-C Bridging Header* →
      `include/bale_mount.h` (so Swift sees the `bale_vfs_*` C ABI).
- [ ] **Info.plist:** diff the template's plist against
      `config/BaleFSExtension-Info.reference.plist`; ensure `FSShortName=balefs`
      and `FSSupportsBlockResources=false`.
- [ ] **Entitlements:** set each target's *Code Signing Entitlements* build setting
      to `config/BaleFSExtension.entitlements` and `config/BaleMountApp.entitlements`.
- [ ] **Deployment target:** 15.4 on both.

## 3. Link the Rust staticlib (extension target)
- [ ] Build Phases → **New Run Script Phase**, body: `"${SRCROOT}/../xcode/build-rust-staticlib.sh"`.
      Drag it **above** "Link Binary With Libraries".
- [ ] Build Phases → *Link Binary With Libraries* → add
      `${BUILT_PRODUCTS_DIR}/libbale_mount_ffi.a`.
- [ ] Build Settings → *Library Search Paths* → `${BUILT_PRODUCTS_DIR}`.

## 4. Build, enable, mount
- [ ] **Build** the host app (builds + embeds the appex). Run it once so the
      extension registers.
- [ ] **Enable:** System Settings → General → Login Items & Extensions →
      *File System Extensions* → toggle Bale on.
- [ ] **Mount** (FSKit restricts mountpoints to `/Volumes`):
      ```
      mkdir -p /Volumes/bale
      mount -F -t balefs <resource> /Volumes/bale      # resource carries repo+rev
      ls /Volumes/bale            # expect hello.txt + sub/ from the fake VFS
      umount /Volumes/bale
      ```
      Watch `log stream --predicate 'subsystem CONTAINS "fskit"'` for the daemon side.

## 5. Verify the open risk early (do this on the *fake* VFS first)
Before wiring the real `DiffVfs`/`Reader`, confirm the **sandboxed** extension can
actually (a) make a network connection and (b) read a path under `~` — using a
throwaway probe in `loadResource`. If the sandbox blocks the cache/repo paths,
that decides whether context must arrive as security-scoped bookmarks via the
mount options. This is the one thing the compile-level prototype can't answer.

## What's already done in the repo
- `signing/bale_dev.csr` (+ gitignored `.key`) — the CSR for step 1.
- `swift/BaleVolume.swift`, `swift/BaleFS.swift` — the FSKit shim (compiles).
- `include/bale_mount.h` — the C ABI bridging header.
- `ffi/` — the Rust staticlib (fake VFS; real `DiffVfs` wiring is the next phase,
  intentionally deferred until a mount runs).
- `config/*.entitlements`, `build-rust-staticlib.sh` — this scaffold.
