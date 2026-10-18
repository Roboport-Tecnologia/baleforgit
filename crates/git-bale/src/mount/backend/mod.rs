//! Binds the backend-agnostic VFS (`mount/vfs.rs`, bytes via `mount/reader.rs`)
//! to the platform filesystem interface: libfuse/fuse-t on Unix, WinFsp on
//! Windows. Exactly one compiles per target; `mount/mod.rs` reaches it through
//! the `PlatformBackend` / `ensure_available` re-exports.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;

use crate::mount::vfs::{DiffVfs, Node, ROOT_INODE};

#[cfg(unix)]
pub mod libfuse;
#[cfg(windows)]
pub mod winfsp;

#[cfg(unix)]
pub use libfuse::{ensure_available, LibfuseBackend as PlatformBackend};
#[cfg(windows)]
pub use winfsp::{ensure_available, WinfspBackend as PlatformBackend};

pub trait MountBackend {
    /// Mounts read-only and blocks until unmounted (Ctrl-C, `fusermount -u`,
    /// `net use <drive> /delete` on Windows).
    fn mount(&self, mount_point: &Path, vfs: Arc<DiffVfs>) -> Result<()>;
}

/// Both backends speak the path-based FUSE high-level API; non-UTF-8 paths map to `None`.
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
