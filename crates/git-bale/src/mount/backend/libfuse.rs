//! libfuse high-level (`fuse_main_real`, path-based) backend.
//!
//! dlopened via `libloading`, not linked, so the workspace builds without it;
//! only `mount`/`mount-diff` need it at runtime (`libfuse.so.2` on Linux,
//! fuse-t's `libfuse-t.dylib` on macOS).
//!
//! Targets the libfuse **2.x** ABI, not 3: fuse-t advertises 2.9.x compat, so one
//! layout works on both. Getting a 2.x-vs-3 slot wrong (see `fuse_operations`)
//! shifts every later slot — reads silently EIO because our `open` lands where
//! libfuse expects `truncate`.

#![allow(non_camel_case_types, non_snake_case)]

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uint, c_ulong, c_void};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Context, Result};
use libc::{mode_t, off_t, size_t, stat as libc_stat};

use crate::mount::backend::{cstr_to_path, lookup_path, MountBackend};
use crate::mount::vfs::{DiffVfs, NodeKind};

/// Path callbacks get no user-data. Set right before `fuse_main_real`, never cleared.
static ACTIVE_VFS: OnceLock<Arc<DiffVfs>> = OnceLock::new();

// fuse-t SIGPIPEs the process inside fuse_main_real on unmount, so under
// `-C instrument-coverage` the atexit profile flush never runs and the mount's
// `.profraw` is lost. The handler flushes then _exit(0)s instead.
#[cfg(feature = "coverage")]
extern "C" {
    fn __llvm_profile_write_file() -> c_int;
}

#[cfg(feature = "coverage")]
extern "C" fn coverage_sigpipe_flush(_sig: c_int) {
    // SAFETY: the profile-write routine takes no lock the interrupted main
    // thread could hold, and _exit bypasses libc atexit.
    unsafe {
        let _ = __llvm_profile_write_file();
        libc::_exit(0);
    }
}

fn arm_coverage_sigpipe_flush() {
    #[cfg(feature = "coverage")]
    // SAFETY: installing a handler with a constant fn pointer.
    unsafe {
        let handler: extern "C" fn(c_int) = coverage_sigpipe_flush;
        libc::signal(libc::SIGPIPE, handler as usize as libc::sighandler_t);
    }
}

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
        // SAFETY: signature matches libfuse 2.x's `fuse_main_real` exactly.
        let fuse_main_real: libloading::Symbol<FuseMainRealFn> = unsafe {
            lib.get(b"fuse_main_real\0")
                .context("looking up fuse_main_real in libfuse")?
        };

        let mount_str = mount_point
            .to_str()
            .ok_or_else(|| anyhow!("mount point path is not UTF-8: {}", mount_point.display()))?;

        // 2.x takes cache hints only as mount options (3.x uses `fuse_config`).
        // Multi-threaded is safe: `Reader` keeps its state behind `Mutex`/`Arc`.
        let argv_strings = [
            CString::new("git-bale-mount").unwrap(),
            CString::new(mount_str).context("CString for mount point")?,
            CString::new("-f").unwrap(),
            CString::new("-o").unwrap(),
            CString::new(
                "ro,default_permissions,use_ino,kernel_cache,\
                 attr_timeout=30,entry_timeout=30,fsname=git-bale",
            )
            .unwrap(),
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

        arm_coverage_sigpipe_flush();

        // SAFETY: argv and the stack-allocated ops outlive the call, which blocks
        // until unmount.
        let rc = unsafe {
            fuse_main_real(
                argv_ptrs.len() as c_int,
                argv_ptrs.as_mut_ptr(),
                &ops,
                std::mem::size_of::<fuse_operations>(),
                std::ptr::null_mut(),
            )
        };

        // Unloading while fuse still holds frames would crash.
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
            "libfuse.so.2",
            "libfuse.so",
            "/usr/lib/x86_64-linux-gnu/libfuse.so.2",
            "/usr/lib/aarch64-linux-gnu/libfuse.so.2",
            "/usr/lib64/libfuse.so.2",
        ]
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        &[]
    }
}

/// `Display` formats install hints; `mount::run` prints it as-is and exits.
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
            writeln!(f, "  • Debian/Ubuntu:  sudo apt install libfuse2")?;
            writeln!(f, "  • Fedora/RHEL:    sudo dnf install fuse-libs")?;
            writeln!(f, "  • Arch:           sudo pacman -S fuse2")?;
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

/// Fail-fast probe at the top of `mount::run`/`run_rev`, before any repo work.
pub fn ensure_available() -> std::result::Result<(), LibfuseUnavailable> {
    let mut tried = Vec::new();
    for name in libfuse_candidates() {
        // SAFETY: dlopen of a well-known system library; the real mount reloads it.
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
        // SAFETY: dlopen of a well-known system library, held for the mount's lifetime.
        match unsafe { libloading::Library::new(name) } {
            Ok(lib) => return Ok(lib),
            Err(e) => errs.push(format!("{name}: {e}")),
        }
    }
    Err(anyhow!(
        "libfuse disappeared between availability check and mount. Tried: {}",
        errs.join("; ")
    ))
}

/// libfuse 2.x `fuse_file_info`: `fh` sits at offset 24 (16 in libfuse 3) after
/// `fh_old` and `writepage`; get it wrong and the `open`→`read` handle is
/// garbage. Apple's extra bitfields share the 32-bit word, so it's 40 bytes on
/// both Linux and macOS.
#[repr(C)]
pub struct fuse_file_info {
    pub flags: c_int,
    pub fh_old: c_ulong,
    pub writepage: c_int,
    /// C bitfields (`direct_io`, `keep_cache`, …; macOS adds `purge_attr`,
    /// `purge_ubc`); only the 4-byte width matters to us.
    pub bits: u32,
    pub fh: u64,
    pub lock_owner: u64,
}

/// libfuse 2.x `fuse_conn_info`, only ever seen as `init`'s ignored pointer. The
/// reserved tail covers both libfuse 2.9 and fuse-t's macOS-extended layout.
#[repr(C)]
pub struct fuse_conn_info {
    pub proto_major: c_uint,
    pub proto_minor: c_uint,
    pub async_read: c_uint,
    pub max_write: c_uint,
    pub max_read: c_uint,
    pub max_readahead: c_uint,
    pub capable: c_uint,
    pub want: c_uint,
    pub max_background: c_uint,
    pub congestion_threshold: c_uint,
    pub reserved: [c_uint; 23],
}

pub type fuse_fill_dir_t = unsafe extern "C" fn(
    buf: *mut c_void,
    name: *const c_char,
    stbuf: *const libc_stat,
    off: off_t,
) -> c_int;

/// libfuse 2.x `fuse_operations`; field *position* is the ABI, so unused slots
/// are untyped `*mut c_void`. Versus libfuse 3: adds `getdir` (slot 2) and
/// `utime` (slot 13), `getattr`/`chmod`/`chown`/`truncate` have no `fi`, `init`
/// has no `fuse_config`, `readdir` has no trailing `flags`.
#[repr(C)]
pub struct fuse_operations {
    pub getattr: Option<unsafe extern "C" fn(*const c_char, *mut libc_stat) -> c_int>,
    pub readlink: *mut c_void,
    pub getdir: *mut c_void,
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
    pub utime: *mut c_void,
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
    pub release: Option<unsafe extern "C" fn(*const c_char, *mut fuse_file_info) -> c_int>,
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
        ) -> c_int,
    >,
    pub releasedir: *mut c_void,
    pub fsyncdir: *mut c_void,
    pub init: Option<unsafe extern "C" fn(*mut fuse_conn_info) -> *mut c_void>,
    pub destroy: Option<unsafe extern "C" fn(*mut c_void)>,
    pub access: *mut c_void,
    pub create: *mut c_void,
    pub ftruncate: *mut c_void,
    pub fgetattr: *mut c_void,
    pub lock: *mut c_void,
    pub utimens: *mut c_void,
    pub bmap: *mut c_void,
    /// `flag_nullpath_ok`/`flag_nopath`/`flag_utime_omit_ok` bitfields, all off;
    /// the 32-bit width keeps `ioctl` at the right offset.
    pub flag_bits: u32,
    pub ioctl: *mut c_void,
    pub poll: *mut c_void,
    pub write_buf: *mut c_void,
    pub read_buf: *mut c_void,
    pub flock: *mut c_void,
    pub fallocate: *mut c_void,
}

fn build_operations() -> fuse_operations {
    fuse_operations {
        getattr: Some(op_getattr),
        readlink: std::ptr::null_mut(),
        getdir: std::ptr::null_mut(),
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
        utime: std::ptr::null_mut(),
        open: Some(op_open),
        read: Some(op_read),
        write: std::ptr::null_mut(),
        statfs: std::ptr::null_mut(),
        flush: std::ptr::null_mut(),
        release: Some(op_release),
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
        ftruncate: std::ptr::null_mut(),
        fgetattr: std::ptr::null_mut(),
        lock: std::ptr::null_mut(),
        utimens: std::ptr::null_mut(),
        bmap: std::ptr::null_mut(),
        flag_bits: 0,
        ioctl: std::ptr::null_mut(),
        poll: std::ptr::null_mut(),
        write_buf: std::ptr::null_mut(),
        read_buf: std::ptr::null_mut(),
        flock: std::ptr::null_mut(),
        fallocate: std::ptr::null_mut(),
    }
}

unsafe extern "C" fn op_init(_conn: *mut fuse_conn_info) -> *mut c_void {
    std::ptr::null_mut()
}

unsafe extern "C" fn op_destroy(_private: *mut c_void) {}

unsafe extern "C" fn op_getattr(path: *const c_char, stbuf: *mut libc_stat) -> c_int {
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
            // size_of never reconstructs — it reads the pointer's file_size.
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
    let NodeKind::File { ref source, .. } = node.kind else {
        return -libc::EISDIR;
    };
    if fi.is_null() {
        return -libc::EIO;
    }
    // Defense in depth behind `-o ro`.
    let mode = (*fi).flags & libc::O_ACCMODE;
    if mode != libc::O_RDONLY {
        return -libc::EROFS;
    }
    let reader = vfs.reader();
    let handle = match reader.open(source) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!("open({p}): {e:#}");
            return -libc::EIO;
        }
    };
    (*fi).fh = handle;
    0
}

unsafe extern "C" fn op_read(
    path: *const c_char,
    buf: *mut c_char,
    size: size_t,
    offset: off_t,
    fi: *mut fuse_file_info,
) -> c_int {
    if buf.is_null() {
        return -libc::EFAULT;
    }
    let Some(vfs) = vfs() else {
        return -libc::EIO;
    };
    if fi.is_null() || (*fi).fh == 0 {
        return -libc::EBADF;
    }
    let fh = (*fi).fh;
    let reader = vfs.reader();
    let bytes = match reader.pread(fh, offset as u64, size) {
        Ok(b) => b,
        Err(e) => {
            let p = cstr_to_path(path).unwrap_or_default();
            tracing::warn!("read({p}, off={offset}, size={size}, fh={fh}): {e:#}");
            return -libc::EIO;
        }
    };
    let n = bytes.len();
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
    n as c_int
}

unsafe extern "C" fn op_release(_path: *const c_char, fi: *mut fuse_file_info) -> c_int {
    if fi.is_null() {
        return 0;
    }
    let fh = (*fi).fh;
    if fh == 0 {
        return 0;
    }
    if let Some(vfs) = vfs() {
        vfs.reader().close(fh);
    }
    0
}

unsafe extern "C" fn op_readdir(
    path: *const c_char,
    buf: *mut c_void,
    filler: fuse_fill_dir_t,
    _offset: off_t,
    _fi: *mut fuse_file_info,
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
    let _ = filler(buf, dot.as_ptr(), std::ptr::null(), 0);
    let _ = filler(buf, dotdot.as_ptr(), std::ptr::null(), 0);

    let Some(children) = vfs.readdir(node.inode) else {
        return 0;
    };
    for (name, _child) in children {
        let Ok(c) = CString::new(name) else { continue };
        // NULL stbuf: the kernel getattrs lazily instead of sizing every entry.
        let _ = filler(buf, c.as_ptr(), std::ptr::null(), 0);
    }
    0
}
