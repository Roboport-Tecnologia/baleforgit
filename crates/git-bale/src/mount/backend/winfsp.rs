//! WinFsp FUSE-compatibility backend (the Windows analogue of `libfuse.rs`).
//!
//! WinFsp ships a FUSE compat layer in `winfsp-x64.dll`; we dlopen it via
//! `libloading` rather than link it, so the workspace builds on a Windows box
//! without the WinFsp SDK installed — only `mount`/`mount-diff` need the DLL at
//! runtime (mirroring how `libfuse.rs` treats libfuse).
//!
//! ABI notes (load-bearing — transcribed from WinFsp's `inc/fuse/*.h`):
//! - The entry point is `fsp_fuse_main_real(env, argc, argv, ops, opsize,
//!   data)` — libfuse's `fuse_main_real` plus a leading `struct fsp_fuse_env *`
//!   the header would otherwise fill in via `fsp_fuse_env()`. We build that env
//!   ourselves: `daemonize`/`set_signal_handlers` are no-ops on Windows (static
//!   inline in the header, *not* exported), `memalloc`/`memfree` are the CRT
//!   `malloc`/`free`, the rest are NULL.
//! - WinFsp's `struct fuse_operations` is a single version-independent layout
//!   (not gated on `FUSE_USE_VERSION` like libfuse's). It differs from our
//!   libfuse 2.x binding: `getdir` is slot 1 / `readlink` slot 2, and every
//!   path/offset uses WinFsp's own `fuse_off_t` (i64) and `struct fuse_stat`
//!   (NOT the platform `stat`). We pass `opsize = size_of::<fuse_operations>()`
//!   so WinFsp reads the whole struct; unused slots are NULL.
//! - `fuse_stat` / `fuse_file_info` are WinFsp's Win64 definitions; the field
//!   widths below are exact (`#[repr(C)]` reproduces the C padding).
//! - Files are reported world-readable (dirs 0555, files 0444). WinFsp maps the
//!   POSIX "other" bits to an Everyone ACE, so the mounting user gets read
//!   access regardless of the st_uid/st_gid we report; `-o uid=-1,gid=-1`
//!   additionally makes the current user the owner.

#![allow(non_camel_case_types, non_snake_case)]

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Context, Result};

use crate::mount::backend::{cstr_to_path, lookup_path, MountBackend};
use crate::mount::vfs::{DiffVfs, NodeKind};

/// Live VFS for the running mount (FUSE path callbacks get no user-data). Set
/// right before `fsp_fuse_main_real`, never cleared. One mount per process.
static ACTIVE_VFS: OnceLock<Arc<DiffVfs>> = OnceLock::new();

fn vfs() -> Option<&'static Arc<DiffVfs>> {
    ACTIVE_VFS.get()
}

// MSVCRT/UCRT <errno.h> values. WinFsp maps these to NTSTATUS via
// fsp_fuse_ntstatus_from_errno, so they must match the C runtime numbering, not
// libc's per-target constants.
const ENOENT: c_int = 2;
const EIO: c_int = 5;
const EBADF: c_int = 9;
const EFAULT: c_int = 14;
const EISDIR: c_int = 21;
const ENOTDIR: c_int = 20;

// POSIX file-type bits (octal), as WinFsp's FUSE layer interprets fuse_mode_t.
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;

pub struct WinfspBackend;

impl WinfspBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WinfspBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MountBackend for WinfspBackend {
    fn mount(&self, mount_point: &Path, vfs_arc: Arc<DiffVfs>) -> Result<()> {
        // No exists/is_dir check (unlike libfuse): WinFsp mounts on a drive
        // letter (`Z:`) or a not-yet-existing directory and validates the
        // target itself, so a pre-existing empty dir would actually be rejected.
        ACTIVE_VFS
            .set(vfs_arc)
            .map_err(|_| anyhow!("mount: another mount is already active in this process"))?;

        let lib = load_winfsp().context("loading WinFsp")?;
        // SAFETY: signature matches WinFsp's exported `fsp_fuse_main_real`.
        let main_real: libloading::Symbol<FspFuseMainRealFn> = unsafe {
            lib.get(b"fsp_fuse_main_real\0")
                .context("looking up fsp_fuse_main_real in winfsp DLL")?
        };

        let mount_str = mount_point
            .to_str()
            .ok_or_else(|| anyhow!("mount point path is not UTF-8: {}", mount_point.display()))?;

        // FUSE-style argv: `-f` blocks in the foreground; `uid=-1,gid=-1` makes
        // the current user own every file (read access). The mountpoint is last.
        let argv_strings = [
            CString::new("git-bale-mount").unwrap(),
            CString::new("-f").unwrap(),
            CString::new("-o").unwrap(),
            CString::new("uid=-1,gid=-1").unwrap(),
            CString::new(mount_str).context("CString for mount point")?,
        ];
        let mut argv_ptrs: Vec<*mut c_char> = argv_strings
            .iter()
            .map(|c| c.as_ptr() as *mut c_char)
            .collect();

        // The env the header's `fsp_fuse_env()` would synthesize. Kept on this
        // stack frame, which outlives the blocking `fsp_fuse_main_real` call.
        let mut env = fsp_fuse_env {
            environment: 'W' as c_uint,
            memalloc: Some(libc::malloc),
            memfree: Some(libc::free),
            daemonize: Some(winfsp_daemonize),
            set_signal_handlers: Some(winfsp_set_signal_handlers),
            conv_to_win_path: None,
            winpid_to_pid: None,
            reserved: [std::ptr::null_mut(); 2],
        };

        let ops = build_operations();

        eprintln!(
            "git-bale: filesystem ready at {} (Ctrl-C to unmount)",
            mount_point.display()
        );

        // SAFETY: env, argv, and ops all outlive the call; fsp_fuse_main_real
        // blocks until the FS is unmounted (or returns non-zero on a mount
        // failure). On Ctrl-C the process is terminated and the WinFsp driver
        // tears the volume down, so we may never return here on success.
        let rc = unsafe {
            main_real(
                &mut env,
                argv_ptrs.len() as c_int,
                argv_ptrs.as_mut_ptr(),
                &ops,
                std::mem::size_of::<fuse_operations>(),
                std::ptr::null_mut(),
            )
        };

        drop(lib);

        if rc != 0 {
            return Err(anyhow!(
                "fsp_fuse_main_real returned status {rc}; check that the WinFsp \
                 driver is installed and the mount point ({mount_str}) is a free \
                 drive letter or a non-existent directory"
            ));
        }
        Ok(())
    }
}

type FspFuseMainRealFn = unsafe extern "C" fn(
    env: *mut fsp_fuse_env,
    argc: c_int,
    argv: *mut *mut c_char,
    op: *const fuse_operations,
    opsize: usize,
    private_data: *mut c_void,
) -> c_int;

// On Windows these are `static inline` no-ops in winfsp_fuse.h; we supply our
// own so the env's function pointers are valid.
unsafe extern "C" fn winfsp_daemonize(_foreground: c_int) -> c_int {
    0
}
unsafe extern "C" fn winfsp_set_signal_handlers(_se: *mut c_void) -> c_int {
    0
}

#[cfg(target_arch = "x86_64")]
const WINFSP_DLL: &str = "winfsp-x64.dll";
#[cfg(target_arch = "aarch64")]
const WINFSP_DLL: &str = "winfsp-a64.dll";
#[cfg(target_arch = "x86")]
const WINFSP_DLL: &str = "winfsp-x86.dll";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86")))]
const WINFSP_DLL: &str = "winfsp-x64.dll";

/// Bare name (PATH / app dir) first, then `%ProgramFiles*%\WinFsp\bin\` — WinFsp
/// installs there but doesn't add it to PATH, so the absolute paths are the
/// usual hit. Avoids reading the registry (no extra dependency).
fn winfsp_candidates() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from(WINFSP_DLL)];
    for var in ["ProgramFiles(x86)", "ProgramW6432", "ProgramFiles"] {
        if let Some(pf) = std::env::var_os(var) {
            v.push(
                PathBuf::from(pf)
                    .join("WinFsp")
                    .join("bin")
                    .join(WINFSP_DLL),
            );
        }
    }
    v.push(PathBuf::from(r"C:\Program Files (x86)\WinFsp\bin").join(WINFSP_DLL));
    v.push(PathBuf::from(r"C:\Program Files\WinFsp\bin").join(WINFSP_DLL));
    v
}

/// `Display` formats install hints; `mount::run` prints it as-is and exits.
#[derive(Debug)]
pub struct WinfspUnavailable {
    tried: Vec<(String, String)>,
}

impl std::fmt::Display for WinfspUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "git-bale mount needs WinFsp at runtime, but {WINFSP_DLL} couldn't be loaded.\n"
        )?;
        writeln!(f, "Install WinFsp:")?;
        writeln!(f, "  • winget install WinFsp.WinFsp")?;
        writeln!(f, "  • or download from https://winfsp.dev/")?;
        writeln!(f)?;
        writeln!(f, "Tried these locations:")?;
        for (name, err) in &self.tried {
            writeln!(f, "  - {name}: {err}")?;
        }
        Ok(())
    }
}

impl std::error::Error for WinfspUnavailable {}

/// Fail-fast probe (handle dropped) at the top of `mount::run`. Only checks the
/// user-mode DLL loads — the WinFsp kernel driver must also be installed for an
/// actual mount to succeed; that surfaces as a non-zero `fsp_fuse_main_real`.
pub fn ensure_available() -> std::result::Result<(), WinfspUnavailable> {
    let mut tried = Vec::new();
    for path in winfsp_candidates() {
        // SAFETY: dlopen of the WinFsp DLL; handle dropped immediately on
        // success — the real mount reloads it.
        match unsafe { libloading::Library::new(&path) } {
            Ok(_lib) => return Ok(()),
            Err(e) => tried.push((path.display().to_string(), e.to_string())),
        }
    }
    Err(WinfspUnavailable { tried })
}

fn load_winfsp() -> Result<libloading::Library> {
    let mut errs = Vec::new();
    for path in winfsp_candidates() {
        // SAFETY: dlopen of the WinFsp DLL; held for the lifetime of the mount.
        match unsafe { libloading::Library::new(&path) } {
            Ok(lib) => return Ok(lib),
            Err(e) => errs.push(format!("{}: {e}", path.display())),
        }
    }
    Err(anyhow!(
        "WinFsp disappeared between availability check and mount. Tried: {}",
        errs.join("; ")
    ))
}

/// WinFsp Win64 `struct fuse_timespec`.
#[repr(C)]
pub struct fuse_timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// WinFsp Win64 `struct fuse_stat` (non-`STAT_EX` variant). Field widths are
/// exact per `winfsp_fuse.h`: dev/mode/uid/gid/rdev are u32, ino is u64, nlink
/// is u16, size/blocks are i64, blksize is i32.
#[repr(C)]
pub struct fuse_stat {
    pub st_dev: u32,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u16,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u32,
    pub st_size: i64,
    pub st_atim: fuse_timespec,
    pub st_mtim: fuse_timespec,
    pub st_ctim: fuse_timespec,
    pub st_blksize: i32,
    pub st_blocks: i64,
    pub st_birthtim: fuse_timespec,
}

/// WinFsp `struct fuse_file_info`. Unlike libfuse 2.x, `fh_old` is `unsigned
/// int` (not `unsigned long`), so `fh` sits at offset 16. We only touch `flags`
/// and `fh`.
#[repr(C)]
pub struct fuse_file_info {
    pub flags: c_int,
    pub fh_old: c_uint,
    pub writepage: c_int,
    /// `direct_io:1, keep_cache:1, flush:1, nonseekable:1, padding:28` — one
    /// 32-bit word; we never set it.
    pub bits: u32,
    pub fh: u64,
    pub lock_owner: u64,
}

/// WinFsp `struct fuse_conn_info`. We never read it.
#[repr(C)]
pub struct fuse_conn_info {
    pub proto_major: c_uint,
    pub proto_minor: c_uint,
    pub async_read: c_uint,
    pub max_write: c_uint,
    pub max_readahead: c_uint,
    pub capable: c_uint,
    pub want: c_uint,
    pub reserved: [c_uint; 25],
}

/// WinFsp `struct fsp_fuse_env` (Win64). `reserved` is two function pointers.
#[repr(C)]
pub struct fsp_fuse_env {
    pub environment: c_uint,
    pub memalloc: Option<unsafe extern "C" fn(usize) -> *mut c_void>,
    pub memfree: Option<unsafe extern "C" fn(*mut c_void)>,
    pub daemonize: Option<unsafe extern "C" fn(c_int) -> c_int>,
    pub set_signal_handlers: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    pub conv_to_win_path: Option<unsafe extern "C" fn(*const c_char) -> *mut c_char>,
    pub winpid_to_pid: Option<unsafe extern "C" fn(u32) -> i32>,
    pub reserved: [*mut c_void; 2],
}

pub type fuse_fill_dir_t = unsafe extern "C" fn(
    buf: *mut c_void,
    name: *const c_char,
    stbuf: *const fuse_stat,
    off: i64,
) -> c_int;

/// WinFsp `struct fuse_operations` — the full, version-independent layout.
/// Unused slots are `*mut c_void` (NULL); their *position* is the ABI, so the
/// order here is transcribed verbatim from `fuse.h`. The `flag_bits` u32 stands
/// in for the four `flag_*` bitfields after `bmap`.
#[repr(C)]
pub struct fuse_operations {
    pub getattr: Option<unsafe extern "C" fn(*const c_char, *mut fuse_stat) -> c_int>,
    pub getdir: *mut c_void,
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
    pub utime: *mut c_void,
    pub open: Option<unsafe extern "C" fn(*const c_char, *mut fuse_file_info) -> c_int>,
    pub read: Option<
        unsafe extern "C" fn(*const c_char, *mut c_char, usize, i64, *mut fuse_file_info) -> c_int,
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
            i64,
            *mut fuse_file_info,
        ) -> c_int,
    >,
    pub releasedir: *mut c_void,
    pub fsyncdir: *mut c_void,
    pub init: *mut c_void,
    pub destroy: *mut c_void,
    pub access: *mut c_void,
    pub create: *mut c_void,
    pub ftruncate: *mut c_void,
    pub fgetattr: *mut c_void,
    pub lock: *mut c_void,
    pub utimens: *mut c_void,
    pub bmap: *mut c_void,
    pub flag_bits: u32,
    pub ioctl: *mut c_void,
    pub poll: *mut c_void,
    pub write_buf: *mut c_void,
    pub read_buf: *mut c_void,
    pub flock: *mut c_void,
    pub fallocate: *mut c_void,
    pub getpath: *mut c_void,
    pub reserved01: *mut c_void,
    pub reserved02: *mut c_void,
    pub statfs_x: *mut c_void,
    pub setvolname: *mut c_void,
    pub exchange: *mut c_void,
    pub getxtimes: *mut c_void,
    pub setbkuptime: *mut c_void,
    pub setchgtime: *mut c_void,
    pub setcrtime: *mut c_void,
    pub chflags: *mut c_void,
    pub setattr_x: *mut c_void,
    pub fsetattr_x: *mut c_void,
}

fn build_operations() -> fuse_operations {
    fuse_operations {
        getattr: Some(op_getattr),
        getdir: std::ptr::null_mut(),
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
        init: std::ptr::null_mut(),
        destroy: std::ptr::null_mut(),
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
        getpath: std::ptr::null_mut(),
        reserved01: std::ptr::null_mut(),
        reserved02: std::ptr::null_mut(),
        statfs_x: std::ptr::null_mut(),
        setvolname: std::ptr::null_mut(),
        exchange: std::ptr::null_mut(),
        getxtimes: std::ptr::null_mut(),
        setbkuptime: std::ptr::null_mut(),
        setchgtime: std::ptr::null_mut(),
        setcrtime: std::ptr::null_mut(),
        chflags: std::ptr::null_mut(),
        setattr_x: std::ptr::null_mut(),
        fsetattr_x: std::ptr::null_mut(),
    }
}

unsafe extern "C" fn op_getattr(path: *const c_char, stbuf: *mut fuse_stat) -> c_int {
    if stbuf.is_null() {
        return -EFAULT;
    }
    std::ptr::write_bytes(stbuf, 0, 1);
    let Some(p) = cstr_to_path(path) else {
        return -ENOENT;
    };
    let Some(vfs) = vfs() else {
        return -EIO;
    };
    let Some(node) = lookup_path(vfs, &p) else {
        return -ENOENT;
    };

    (*stbuf).st_ino = node.inode;
    (*stbuf).st_nlink = 1;
    match node.kind {
        NodeKind::Dir => {
            (*stbuf).st_mode = S_IFDIR | 0o555;
            (*stbuf).st_nlink = 2;
        }
        NodeKind::File { ref source, .. } => {
            (*stbuf).st_mode = S_IFREG | 0o444;
            // size_of never reconstructs — it reads the pointer's file_size.
            let reader = vfs.reader();
            match reader.size_of(source) {
                Ok(n) => (*stbuf).st_size = n as i64,
                Err(e) => {
                    tracing::warn!("getattr({p}): size_of failed: {e:#}");
                    return -EIO;
                }
            }
        }
    }
    0
}

unsafe extern "C" fn op_open(path: *const c_char, fi: *mut fuse_file_info) -> c_int {
    let Some(p) = cstr_to_path(path) else {
        return -ENOENT;
    };
    let Some(vfs) = vfs() else {
        return -EIO;
    };
    let Some(node) = lookup_path(vfs, &p) else {
        return -ENOENT;
    };
    let NodeKind::File { ref source, .. } = node.kind else {
        return -EISDIR;
    };
    if fi.is_null() {
        return -EIO;
    }
    // No write callbacks are registered, so writes already fail; we don't
    // inspect fi.flags here (Windows access→POSIX-flag mapping is fuzzier than
    // libfuse's, and rejecting on it risks blocking legitimate reads).
    let reader = vfs.reader();
    let handle = match reader.open(source) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!("open({p}): {e:#}");
            return -EIO;
        }
    };
    (*fi).fh = handle;
    0
}

unsafe extern "C" fn op_read(
    path: *const c_char,
    buf: *mut c_char,
    size: usize,
    offset: i64,
    fi: *mut fuse_file_info,
) -> c_int {
    if buf.is_null() {
        return -EFAULT;
    }
    let Some(vfs) = vfs() else {
        return -EIO;
    };
    if fi.is_null() || (*fi).fh == 0 {
        return -EBADF;
    }
    let fh = (*fi).fh;
    let reader = vfs.reader();
    let bytes = match reader.pread(fh, offset.max(0) as u64, size) {
        Ok(b) => b,
        Err(e) => {
            let p = cstr_to_path(path).unwrap_or_default();
            tracing::warn!("read({p}, off={offset}, size={size}, fh={fh}): {e:#}");
            return -EIO;
        }
    };
    let n = bytes.len().min(size);
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
    _offset: i64,
    _fi: *mut fuse_file_info,
) -> c_int {
    let Some(p) = cstr_to_path(path) else {
        return -ENOENT;
    };
    let Some(vfs) = vfs() else {
        return -EIO;
    };
    let Some(node) = lookup_path(vfs, &p) else {
        return -ENOENT;
    };
    if !matches!(node.kind, NodeKind::Dir) {
        return -ENOTDIR;
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
        // NULL stbuf → WinFsp getattrs lazily, so listing a dir doesn't size
        // every entry up front.
        let _ = filler(buf, c.as_ptr(), std::ptr::null(), 0);
    }
    0
}
