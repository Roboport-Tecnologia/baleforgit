# FSKit mount — feasibility prototype

Question: can `git-bale mount` be made native on macOS via **FSKit** (the
post-kext userspace filesystem framework, macOS 15.4+), instead of the dlopened
fuse-t backend?

**Verdict: feasible.** Every part we can settle without an Apple signing identity
checks out, on a plain Command Line Tools install (no Xcode). Run `./build.sh`.

## What this proves

| # | Claim | How |
|---|-------|-----|
| 1 | FSKit is present & usable on this OS | macOS 15.7; `import FSKit` compiles; full Swift overlay (`.swiftinterface`) ships in the CLT SDK |
| 2 | The Rust VFS maps onto a small C ABI | `ffi/` staticlib — `open/lookup/getattr/readdir/open_file/read/close`, shaped 1:1 with `mount::vfs::DiffVfs` + `mount::reader::Reader` |
| 3 | The boundary works at runtime | `harness.c` links the staticlib and drives it (readdir, partial read at offset, EOF, negative lookup) — **runs green** |
| 4 | Panics can't cross into Swift | every entry point wrapped in `catch_unwind`, message surfaced via `bale_vfs_last_error` |
| 5 | The Swift FSKit shim compiles | `swift/BaleVolume.swift` conforms to `FSVolume.Operations` + `PathConfOperations` + `OpenCloseOperations` + `ReadWriteOperations`; `BaleFS.swift` is the `FSUnaryFileSystem` delegate + `@main UnaryFileSystemExtension` — clean typecheck **and** codegen |
| 6 | The shim links to both worlds | the emitted object references `_OBJC_CLASS_$_FSVolume`/`_FSUnaryFileSystem` **and** `_bale_vfs_*` |

## What stays gated (needs your Developer cert + an Xcode box)

- **Signing**: the appex carries the *managed* `com.apple.developer.fskit.fsmodule`
  entitlement — needs a provisioning profile + real signature. This machine has
  0 signing identities, so the extension can't load here.
- **Packaging**: embed the `.appex` in a host `.app`, ship via a signed+notarized
  `.pkg` (also installs the `git-bale` CLI). See the chat notes on the two certs
  (Developer ID Application for the bundles, Developer ID Installer for the pkg).
- **User enable**: System Settings → General → Login Items & Extensions → File
  System Extensions. Not bypassable.
- **The sandbox question** (the real risk to de-risk next): an FSKit appex runs
  App-Sandboxed. The real `Reader` needs the network + `~/.cache/bale/chunks` +
  `.git/bale/staging`. Prove a sandboxed extension can reach those before
  committing — this is the one unknown a compile can't answer.

## Findings worth carrying into the design

- **No read-only conformance.** `FSVolume.Operations` makes the mutators
  (`createItem`, `removeItem`, `renameItem`, `setAttributes`, write…) *required*.
  We implement them as `EROFS` throws. Matches the known FSKit quirk that Finder
  doesn't fully understand read-only volumes.
- **Mountpoints restricted to `/Volumes`** (FSKit limitation) — a UX change from
  today's arbitrary-path `git-bale mount <rev> <path>`.
- **Context channel.** The FS "resource" is how repo+rev reach the out-of-process
  extension. `mount-diff`'s two-revs-plus-labels argues for an XPC handshake over
  cramming it into a single `mount` resource string.
- **Read buffer API** is `FSMutableFileDataBuffer.withUnsafeMutableBytes { … }`
  (not the header's `withMutableBytes`, which isn't in this SDK's overlay).

## Next step to a *running* mount

On a machine with Xcode + your Developer account: drop the staticlib into an
Xcode FSModule extension target (this `BaleVolume`/`BaleFS` is the body), wire the
real `DiffVfs`/`Reader` behind the C ABI (mechanical — the methods already line
up), sign with the fsmodule entitlement, enable, and `mount -F -t balefs`.

## Layout

```
ffi/         Rust staticlib exposing the C ABI (excluded from the cargo workspace)
include/     bale_mount.h — the C ABI, imported into Swift via bridging header
harness.c    runtime proof of the FFI boundary
swift/       BaleVolume.swift, BaleFS.swift — the FSKit shim
build.sh     runs all of the above
```
