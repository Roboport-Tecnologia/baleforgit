//! Backend abstraction for the mount-diff VFS.
//!
//! The VFS layer (`mount/vfs.rs`) and the byte source (`mount/reader.rs`) are
//! backend-agnostic. A `MountBackend` is responsible for binding the chosen
//! kernel/userspace interface (libfuse today; fuse-t, WinFsp, etc. later) to
//! that VFS, blocking until the user unmounts, then returning.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;

use crate::mount::vfs::{DiffVfs, Node, ROOT_INODE};

// libfuse (Linux/macOS) and WinFsp (Windows) bind the same backend-agnostic VFS
// to their respective kernel/userspace interface. Exactly one compiles per
// target; `mount/mod.rs` reaches both through the `PlatformBackend` /
// `ensure_available` aliases below.
#[cfg(unix)]
pub mod libfuse;
#[cfg(windows)]
pub mod winfsp;

#[cfg(unix)]
pub use libfuse::{ensure_available, LibfuseBackend as PlatformBackend};
#[cfg(windows)]
pub use winfsp::{ensure_available, WinfspBackend as PlatformBackend};

pub trait MountBackend {
    /// Mount the VFS read-only at `mount_point` and block in the foreground
    /// until the filesystem is unmounted (e.g. via Ctrl-C, `fusermount -u`, or
    /// `net use <drive> /delete` on Windows).
    fn mount(&self, mount_point: &Path, vfs: Arc<DiffVfs>) -> Result<()>;
}

/// Both backends speak the path-based FUSE high-level API, so they share the
/// `const char *path` → UTF-8 decode and the slash-walk to a VFS node.
pub(crate) fn cstr_to_path(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: FUSE/WinFsp hand us a NUL-terminated C string from kernel input.
    let s = unsafe { CStr::from_ptr(p) };
    s.to_str().ok().map(|s| s.to_string())
}

/// Walk a slash-delimited path from the root; `""` and `/` resolve to the root.
pub(crate) fn lookup_path(vfs: &DiffVfs, path: &str) -> Option<Node> {
    let mut current = vfs.lookup_by_inode(ROOT_INODE)?.clone();
    for component in path.split('/').filter(|c| !c.is_empty()) {
        let child = vfs.lookup_child(current.inode, component)?;
        current = child.clone();
    }
    Some(current)
}
