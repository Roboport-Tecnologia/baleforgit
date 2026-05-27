//! Backend abstraction for the mount-diff VFS.
//!
//! The VFS layer (`mount/vfs.rs`) and the byte source (`mount/reader.rs`) are
//! backend-agnostic. A `MountBackend` is responsible for binding the chosen
//! kernel/userspace interface (libfuse today; fuse-t, WinFsp, etc. later) to
//! that VFS, blocking until the user unmounts, then returning.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;

use crate::mount::vfs::DiffVfs;

pub mod libfuse;

pub trait MountBackend {
    /// Mount the VFS read-only at `mount_point` and block in the foreground
    /// until the filesystem is unmounted (e.g. via Ctrl-C or `fusermount -u`).
    fn mount(&self, mount_point: &Path, vfs: Arc<DiffVfs>) -> Result<()>;
}
