//! libfuse high-level (`fuse_main_real`) backend.
//!
//! libfuse is loaded dynamically via `libloading`, not linked at build time —
//! so the workspace still builds on machines without libfuse installed; only
//! `mount-diff` at runtime needs it. On Linux that's `libfuse3.so.3`; on
//! macOS that's `libfuse-t.dylib` (the fuse-t userspace shim).
//!
//! ABI notes:
//! - We target libfuse 3.x's `fuse_main_real` signature. fuse-t advertises
//!   API+ABI compatibility with libfuse 3.x, so the same struct layouts apply.
//! - The high-level API uses *path-based* callbacks: each request gives us a
//!   `const char *path`, and we have to walk it to an inode ourselves. That's
//!   slightly slower than the low-level (inode) API for deep trees, but the
//!   API is far simpler to bind to and the diff trees we mount are usually
//!   tiny anyway.
//! - We don't get user-data on every callback. Instead we stash an
//!   `Arc<DiffVfs>` in a process-wide `OnceLock` set right before `fuse_main`.

#![allow(non_camel_case_types, non_snake_case)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_double, c_int, c_uint, c_void};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Context, Result};
use libc::{mode_t, off_t, size_t, stat as libc_stat};

use crate::mount::backend::MountBackend;
use crate::mount::vfs::{DiffVfs, Node, NodeKind, ROOT_INODE};

/// Holds the live VFS for the running mount. The high-level libfuse API
/// doesn't thread user-data through path callbacks, so we keep one
/// process-wide reference. Set right before `fuse_main_real`, never cleared.
static ACTIVE_VFS: OnceLock<Arc<DiffVfs>> = OnceLock::new();

fn vfs() -> Option<&'static Arc<DiffVfs>> {
    ACTIVE_VFS.get()
}

pub struct LibfuseBackend;

impl LibfuseBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LibfuseBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MountBackend for LibfuseBackend {
    fn mount(&self, mount_point: &Path, vfs_arc: Arc<DiffVfs>) -> Result<()> {
        if !mount_point.exists() {
            return Err(anyhow!(
                "mount point {} does not exist; create it first (mkdir)",
                mount_point.display()
            ));
        }
        if !mount_point.is_dir() {
            return Err(anyhow!(
                "mount point {} is not a directory",
                mount_point.display()
            ));
        }

        ACTIVE_VFS
            .set(vfs_arc)
            .map_err(|_| anyhow!("mount: another mount is already active in this process"))?;

        let lib = load_libfuse().context("loading libfuse / fuse-t")?;
        // SAFETY: signature matches libfuse 3.x's `fuse_main_real` exactly.
        let fuse_main_real: libloading::Symbol<FuseMainRealFn> = unsafe {
            lib.get(b"fuse_main_real\0")
                .context("looking up fuse_main_real in libfuse")?
        };

        let mount_str = mount_point
            .to_str()
            .ok_or_else(|| anyhow!("mount point path is not UTF-8: {}", mount_point.display()))?;

        // Argv we pass to libfuse: it parses these like a CLI tool. `-f`
        // keeps the daemon in the foreground (we want to block until ^C),
        // `-s` runs single-threaded (simpler concurrency story for the
        // reader's caches), and `-o ro` enforces read-only at the kernel.
        let argv_strings = [
            CString::new("git-bale-mount").unwrap(),
            CString::new(mount_str).context("CString for mount point")?,
            CString::new("-f").unwrap(),
            CString::new("-s").unwrap(),
            CString::new("-o").unwrap(),
            CString::new("ro,default_permissions,fsname=git-bale").unwrap(),
        ];
        let mut argv_ptrs: Vec<*mut c_char> = argv_strings
            .iter()
            .map(|c| c.as_ptr() as *mut c_char)
            .collect();

        let ops = build_operations();

        eprintln!(
            "git-bale: filesystem ready at {} (Ctrl-C to unmount)",
            mount_point.display()
        );

        // SAFETY: argv outlives the call; ops is stack-allocated and read by
        // libfuse synchronously during fuse_main_real. fuse_main_real blocks
        // until the FS is unmounted.
        let rc = unsafe {
            fuse_main_real(
                argv_ptrs.len() as c_int,
                argv_ptrs.as_mut_ptr(),
                &ops,
                std::mem::size_of::<fuse_operations>(),
                std::ptr::null_mut(),
            )
        };

        // Drop the library handle only after fuse has unwound — otherwise
        // we'd unload the dylib while it still holds frames.
        drop(lib);

        if rc != 0 {
            return Err(anyhow!(
                "fuse_main_real returned non-zero status {rc}; check stderr"
            ));
        }
        Ok(())
    }
}

type FuseMainRealFn = unsafe extern "C" fn(
    argc: c_int,
    argv: *mut *mut c_char,
    op: *const fuse_operations,
    op_size: usize,
    private_data: *mut c_void,
) -> c_int;

fn libfuse_candidates() -> &'static [&'static str] {
    #[cfg(target_os = "macos")]
    {
        &[
            "libfuse-t.dylib",
            "/usr/local/lib/libfuse-t.dylib",
            "/opt/homebrew/lib/libfuse-t.dylib",
        ]
    }
    #[cfg(target_os = "linux")]
    {
        &[
            "libfuse3.so.3",
            "libfuse3.so",
            "/usr/lib/x86_64-linux-gnu/libfuse3.so.3",
            "/usr/lib64/libfuse3.so.3",
        ]
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        &[]
    }
}

/// Returned by [`ensure_available`] when libfuse can't be loaded. `Display`
/// formats a multi-line, user-friendly message — `mount::run` prints it as-is
/// and exits, so the user sees install hints rather than an anyhow chain.
#[derive(Debug)]
pub struct LibfuseUnavailable {
    tried: Vec<(String, String)>,
}

impl std::fmt::Display for LibfuseUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "git-bale mount-diff needs libfuse at runtime, but it couldn't be loaded.\n"
        )?;
        writeln!(f, "Install one of:")?;
        if cfg!(target_os = "linux") {
            writeln!(f, "  • Debian/Ubuntu:  sudo apt install libfuse3-3")?;
            writeln!(f, "  • Fedora/RHEL:    sudo dnf install fuse3")?;
            writeln!(f, "  • Arch:           sudo pacman -S fuse3")?;
        } else if cfg!(target_os = "macos") {
            writeln!(
                f,
                "  • fuse-t (recommended, no kext):  brew install macos-fuse-t/cask/fuse-t"
            )?;
            writeln!(f, "    or grab the installer from https://www.fuse-t.org/")?;
        } else {
            writeln!(f, "  • mount-diff is not yet supported on this platform.")?;
        }
        writeln!(f)?;
        writeln!(f, "Tried these library names:")?;
        for (name, err) in &self.tried {
            writeln!(f, "  - {name}: {err}")?;
        }
        Ok(())
    }
}

impl std::error::Error for LibfuseUnavailable {}

/// Probe for libfuse without retaining the handle. Cheap — used as a
/// fail-fast check at the top of `mount::run` so we never surprise the user
/// with a load failure halfway through a diff.
pub fn ensure_available() -> std::result::Result<(), LibfuseUnavailable> {
    let mut tried = Vec::new();
    for name in libfuse_candidates() {
        // SAFETY: dlopen of a well-known system library; handle is dropped
        // immediately on success — the real mount reloads it.
        match unsafe { libloading::Library::new(name) } {
            Ok(_lib) => return Ok(()),
            Err(e) => tried.push((name.to_string(), e.to_string())),
        }
    }
    Err(LibfuseUnavailable { tried })
}

fn load_libfuse() -> Result<libloading::Library> {
    let mut errs = Vec::new();
    for name in libfuse_candidates() {
        // SAFETY: dlopen of a well-known system library. The handle is held
        // for the lifetime of the mount.
        match unsafe { libloading::Library::new(name) } {
            Ok(lib) => return Ok(lib),
            Err(e) => errs.push(format!("{name}: {e}")),
        }
    }
    // ensure_available should have caught this earlier; if we get here the
    // environment changed between the check and the mount.
    Err(anyhow!(
        "libfuse disappeared between availability check and mount. Tried: {}",
        errs.join("; ")
    ))
}

// ---------------------------------------------------------------------------
// FFI type definitions for libfuse 3.x
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct fuse_file_info {
    pub flags: c_int,
    pub bits1: u32, // bitfields: writepage:1, direct_io:1, keep_cache:1, ...
    pub bits2: u32, // padding bitfields (32)
    pub fh: u64,
    pub lock_owner: u64,
    pub poll_events: u32,
}

#[repr(C)]
pub struct fuse_conn_info {
    pub proto_major: c_uint,
    pub proto_minor: c_uint,
    pub max_write: c_uint,
    pub max_read: c_uint,
    pub max_readahead: c_uint,
    pub capable: c_uint,
    pub want: c_uint,
    pub max_background: c_uint,
    pub congestion_threshold: c_uint,
    pub time_gran: c_uint,
    pub reserved: [c_uint; 22],
}

#[repr(C)]
pub struct fuse_config {
    pub set_gid: c_int,
    pub gid: c_uint,
    pub set_uid: c_int,
    pub uid: c_uint,
    pub set_mode: c_int,
    pub umask: c_uint,
    pub entry_timeout: c_double,
    pub negative_timeout: c_double,
    pub attr_timeout: c_double,
    pub intr: c_int,
    pub intr_signal: c_int,
    pub remember: c_int,
    pub hard_remove: c_int,
    pub use_ino: c_int,
    pub readdir_ino: c_int,
    pub direct_io: c_int,
    pub kernel_cache: c_int,
    pub auto_cache: c_int,
    pub no_rofd_flush: c_int,
    pub ac_attr_timeout_set: c_int,
    pub ac_attr_timeout: c_double,
    pub nullpath_ok: c_int,
    pub parallel_direct_writes: c_int,
    pub show_help: c_int,
    pub modules: *mut c_char,
    pub debug: c_int,
}

pub type fuse_fill_dir_t = unsafe extern "C" fn(
    buf: *mut c_void,
    name: *const c_char,
    stbuf: *const libc_stat,
    off: off_t,
    flags: c_int,
) -> c_int;

/// All unused operations are `*mut c_void` so we don't have to write 30+
/// correct function-pointer signatures. Layout/order matches libfuse 3.x
/// exactly — the *position* of each field in the struct is the ABI, and we
/// only need typed pointers for the ones we actually populate.
#[repr(C)]
pub struct fuse_operations {
    pub getattr:
        Option<unsafe extern "C" fn(*const c_char, *mut libc_stat, *mut fuse_file_info) -> c_int>,
    pub readlink: *mut c_void,
    pub mknod: *mut c_void,
    pub mkdir: *mut c_void,
    pub unlink: *mut c_void,
    pub rmdir: *mut c_void,
    pub symlink: *mut c_void,
    pub rename: *mut c_void,
    pub link: *mut c_void,
    pub chmod: *mut c_void,
    pub chown: *mut c_void,
    pub truncate: *mut c_void,
    pub open: Option<unsafe extern "C" fn(*const c_char, *mut fuse_file_info) -> c_int>,
    pub read: Option<
        unsafe extern "C" fn(
            *const c_char,
            *mut c_char,
            size_t,
            off_t,
            *mut fuse_file_info,
        ) -> c_int,
    >,
    pub write: *mut c_void,
    pub statfs: *mut c_void,
    pub flush: *mut c_void,
    pub release: *mut c_void,
    pub fsync: *mut c_void,
    pub setxattr: *mut c_void,
    pub getxattr: *mut c_void,
    pub listxattr: *mut c_void,
    pub removexattr: *mut c_void,
    pub opendir: *mut c_void,
    pub readdir: Option<
        unsafe extern "C" fn(
            *const c_char,
            *mut c_void,
            fuse_fill_dir_t,
            off_t,
            *mut fuse_file_info,
            c_int,
        ) -> c_int,
    >,
    pub releasedir: *mut c_void,
    pub fsyncdir: *mut c_void,
    pub init: Option<unsafe extern "C" fn(*mut fuse_conn_info, *mut fuse_config) -> *mut c_void>,
    pub destroy: Option<unsafe extern "C" fn(*mut c_void)>,
    pub access: *mut c_void,
    pub create: *mut c_void,
    pub lock: *mut c_void,
    pub utimens: *mut c_void,
    pub bmap: *mut c_void,
    pub ioctl: *mut c_void,
    pub poll: *mut c_void,
    pub write_buf: *mut c_void,
    pub read_buf: *mut c_void,
    pub flock: *mut c_void,
    pub fallocate: *mut c_void,
    pub copy_file_range: *mut c_void,
    pub lseek: *mut c_void,
}

fn build_operations() -> fuse_operations {
    fuse_operations {
        getattr: Some(op_getattr),
        readlink: std::ptr::null_mut(),
        mknod: std::ptr::null_mut(),
        mkdir: std::ptr::null_mut(),
        unlink: std::ptr::null_mut(),
        rmdir: std::ptr::null_mut(),
        symlink: std::ptr::null_mut(),
        rename: std::ptr::null_mut(),
        link: std::ptr::null_mut(),
        chmod: std::ptr::null_mut(),
        chown: std::ptr::null_mut(),
        truncate: std::ptr::null_mut(),
        open: Some(op_open),
        read: Some(op_read),
        write: std::ptr::null_mut(),
        statfs: std::ptr::null_mut(),
        flush: std::ptr::null_mut(),
        release: std::ptr::null_mut(),
        fsync: std::ptr::null_mut(),
        setxattr: std::ptr::null_mut(),
        getxattr: std::ptr::null_mut(),
        listxattr: std::ptr::null_mut(),
        removexattr: std::ptr::null_mut(),
        opendir: std::ptr::null_mut(),
        readdir: Some(op_readdir),
        releasedir: std::ptr::null_mut(),
        fsyncdir: std::ptr::null_mut(),
        init: Some(op_init),
        destroy: Some(op_destroy),
        access: std::ptr::null_mut(),
        create: std::ptr::null_mut(),
        lock: std::ptr::null_mut(),
        utimens: std::ptr::null_mut(),
        bmap: std::ptr::null_mut(),
        ioctl: std::ptr::null_mut(),
        poll: std::ptr::null_mut(),
        write_buf: std::ptr::null_mut(),
        read_buf: std::ptr::null_mut(),
        flock: std::ptr::null_mut(),
        fallocate: std::ptr::null_mut(),
        copy_file_range: std::ptr::null_mut(),
        lseek: std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Callback implementations
// ---------------------------------------------------------------------------

unsafe extern "C" fn op_init(_conn: *mut fuse_conn_info, cfg: *mut fuse_config) -> *mut c_void {
    if !cfg.is_null() {
        // We hand out stable inodes; let the kernel cache attrs aggressively.
        (*cfg).use_ino = 1;
        (*cfg).kernel_cache = 1;
        (*cfg).attr_timeout = 30.0;
        (*cfg).entry_timeout = 30.0;
    }
    std::ptr::null_mut()
}

unsafe extern "C" fn op_destroy(_private: *mut c_void) {}

fn cstr_to_path(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: libfuse hands us a NUL-terminated C string from kernel input.
    let s = unsafe { CStr::from_ptr(p) };
    s.to_str().ok().map(|s| s.to_string())
}

/// Walk a slash-delimited path from the root, returning the resolved node.
/// The empty string and `/` both resolve to the root.
fn lookup_path(vfs: &DiffVfs, path: &str) -> Option<Node> {
    let mut current = vfs.lookup_by_inode(ROOT_INODE)?.clone();
    for component in path.split('/').filter(|c| !c.is_empty()) {
        let child = vfs.lookup_child(current.inode, component)?;
        current = child.clone();
    }
    Some(current)
}

unsafe extern "C" fn op_getattr(
    path: *const c_char,
    stbuf: *mut libc_stat,
    _fi: *mut fuse_file_info,
) -> c_int {
    if stbuf.is_null() {
        return -libc::EFAULT;
    }
    *stbuf = std::mem::zeroed();
    let Some(p) = cstr_to_path(path) else {
        return -libc::ENOENT;
    };
    let Some(vfs) = vfs() else {
        return -libc::EIO;
    };
    let Some(node) = lookup_path(vfs, &p) else {
        return -libc::ENOENT;
    };

    (*stbuf).st_ino = node.inode;
    (*stbuf).st_uid = libc::getuid();
    (*stbuf).st_gid = libc::getgid();
    (*stbuf).st_nlink = 1;
    match node.kind {
        NodeKind::Dir => {
            (*stbuf).st_mode = (libc::S_IFDIR | 0o555) as mode_t;
            (*stbuf).st_nlink = 2;
        }
        NodeKind::File { ref source, .. } => {
            (*stbuf).st_mode = (libc::S_IFREG | 0o444) as mode_t;
            // Determine size on demand. For Bale pointers this triggers
            // reconstruction the first time — which is what `stat` callers
            // generally want anyway.
            let reader = vfs.reader();
            match reader.size_of(source) {
                Ok(n) => (*stbuf).st_size = n as off_t,
                Err(e) => {
                    tracing::warn!("getattr({p}): size_of failed: {e:#}");
                    return -libc::EIO;
                }
            }
        }
    }
    0
}

unsafe extern "C" fn op_open(path: *const c_char, fi: *mut fuse_file_info) -> c_int {
    let Some(p) = cstr_to_path(path) else {
        return -libc::ENOENT;
    };
    let Some(vfs) = vfs() else {
        return -libc::EIO;
    };
    let Some(node) = lookup_path(vfs, &p) else {
        return -libc::ENOENT;
    };
    if !matches!(node.kind, NodeKind::File { .. }) {
        return -libc::EISDIR;
    }
    if !fi.is_null() {
        // Only read flags allowed; libfuse already rejects writes due to
        // the `-o ro` mount option but a defensive check is cheap.
        let flags = (*fi).flags;
        let mode = flags & libc::O_ACCMODE;
        if mode != libc::O_RDONLY {
            return -libc::EROFS;
        }
    }
    0
}

unsafe extern "C" fn op_read(
    path: *const c_char,
    buf: *mut c_char,
    size: size_t,
    offset: off_t,
    _fi: *mut fuse_file_info,
) -> c_int {
    if buf.is_null() {
        return -libc::EFAULT;
    }
    let Some(p) = cstr_to_path(path) else {
        return -libc::ENOENT;
    };
    let Some(vfs) = vfs() else {
        return -libc::EIO;
    };
    let Some(node) = lookup_path(vfs, &p) else {
        return -libc::ENOENT;
    };
    let NodeKind::File { ref source, .. } = node.kind else {
        return -libc::EISDIR;
    };
    let reader = vfs.reader();
    let bytes = match reader.read(source, offset as u64, size) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("read({p}, off={offset}, size={size}): {e:#}");
            return -libc::EIO;
        }
    };
    let n = bytes.len();
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
    n as c_int
}

unsafe extern "C" fn op_readdir(
    path: *const c_char,
    buf: *mut c_void,
    filler: fuse_fill_dir_t,
    _offset: off_t,
    _fi: *mut fuse_file_info,
    _flags: c_int,
) -> c_int {
    let Some(p) = cstr_to_path(path) else {
        return -libc::ENOENT;
    };
    let Some(vfs) = vfs() else {
        return -libc::EIO;
    };
    let Some(node) = lookup_path(vfs, &p) else {
        return -libc::ENOENT;
    };
    if !matches!(node.kind, NodeKind::Dir) {
        return -libc::ENOTDIR;
    }

    let dot = CString::new(".").unwrap();
    let dotdot = CString::new("..").unwrap();
    let _ = filler(buf, dot.as_ptr(), std::ptr::null(), 0, 0);
    let _ = filler(buf, dotdot.as_ptr(), std::ptr::null(), 0, 0);

    let Some(children) = vfs.readdir(node.inode) else {
        return 0;
    };
    for (name, _child) in children {
        let Ok(c) = CString::new(name) else { continue };
        // stbuf = NULL → kernel issues getattr for each. Cheaper than
        // computing every size eagerly here (Bale entries would trigger
        // reconstruction just to list a directory).
        let _ = filler(buf, c.as_ptr(), std::ptr::null(), 0, 0);
    }
    0
}
