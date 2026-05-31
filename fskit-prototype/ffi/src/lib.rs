//! C-ABI surface the Swift FSKit shim links against. Shaped to mirror the real
//! `mount::vfs::DiffVfs` + `mount::reader::Reader` API (open → lookup → getattr →
//! readdir → open/read/close), so wiring the real VFS later is a drop-in.
//!
//! Every entry point is wrapped in `catch_unwind`: a Rust panic must never unwind
//! across the C boundary into Swift (that's UB), and reconstruction in the real
//! Reader *can* fail. A caught panic becomes an error return + a thread-local
//! message retrievable via `bale_vfs_last_error`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const BALE_ROOT_INODE: u64 = 1;

const KIND_DIR: c_int = 0;
const KIND_FILE: c_int = 1;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_error(msg: impl Into<String>) {
    let c = CString::new(msg.into()).unwrap_or_else(|_| CString::new("error").unwrap());
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(c));
}

/// Run `f`, turning a panic into `on_panic` and recording the message. Mirrors
/// the `std::panic::catch_unwind` discipline the agent-harbor FSKit bridge uses.
fn guard<T>(on_panic: T, f: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(e) => {
            let msg = e
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic across FFI boundary".to_string());
            set_error(format!("panic: {msg}"));
            on_panic
        }
    }
}

enum Node {
    Dir(Vec<(String, u64)>),
    File(Vec<u8>),
}

/// Stand-in for `DiffVfs` + `Reader`. The real impl replaces this struct body;
/// the C signatures below stay identical.
pub struct BaleVfs {
    nodes: HashMap<u64, Node>,
    handles: HashMap<u64, Vec<u8>>,
    next_handle: u64,
}

impl BaleVfs {
    /// Hardcoded tree standing in for a real rev's worktree:
    ///   /hello.txt        "hello from bale fskit\n"
    ///   /sub/world.bin     256 bytes of 0x00..0xff
    fn fake(repo_path: &str, rev: &str) -> Self {
        let mut nodes = HashMap::new();
        let hello = format!("hello from bale fskit\nrepo={repo_path}\nrev={rev}\n").into_bytes();
        let world: Vec<u8> = (0..=255u8).collect();

        nodes.insert(
            BALE_ROOT_INODE,
            Node::Dir(vec![("hello.txt".into(), 2), ("sub".into(), 3)]),
        );
        nodes.insert(2, Node::File(hello));
        nodes.insert(3, Node::Dir(vec![("world.bin".into(), 4)]));
        nodes.insert(4, Node::File(world));

        BaleVfs {
            nodes,
            handles: HashMap::new(),
            next_handle: 0,
        }
    }
}

#[repr(C)]
pub struct BaleAttr {
    pub kind: c_int,
    pub size: u64,
    pub inode: u64,
}

/// Open a read-only view of `rev` in the repo at `repo_path`. Returns an opaque
/// handle, or null on error (see `bale_vfs_last_error`).
///
/// # Safety
/// `repo_path` and `rev` must be valid NUL-terminated UTF-8 C strings.
#[no_mangle]
pub unsafe extern "C" fn bale_vfs_open(
    repo_path: *const c_char,
    rev: *const c_char,
) -> *mut BaleVfs {
    guard(std::ptr::null_mut(), || {
        let Some(repo) = cstr(repo_path) else {
            set_error("repo_path was null or not UTF-8");
            return std::ptr::null_mut();
        };
        let Some(rev) = cstr(rev) else {
            set_error("rev was null or not UTF-8");
            return std::ptr::null_mut();
        };
        Box::into_raw(Box::new(BaleVfs::fake(&repo, &rev)))
    })
}

/// # Safety
/// `vfs` must be a pointer returned by `bale_vfs_open` and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn bale_vfs_free(vfs: *mut BaleVfs) {
    if vfs.is_null() {
        return;
    }
    guard((), || {
        drop(Box::from_raw(vfs));
    });
}

/// Fill `out` for `inode`. Returns 0 on success, -errno-style on failure.
///
/// # Safety
/// `vfs` valid; `out` points to writable `BaleAttr`.
#[no_mangle]
pub unsafe extern "C" fn bale_vfs_getattr(
    vfs: *mut BaleVfs,
    inode: u64,
    out: *mut BaleAttr,
) -> c_int {
    guard(-libc_eio(), || {
        let Some(vfs) = vfs.as_ref() else {
            return -libc_einval();
        };
        if out.is_null() {
            return -libc_einval();
        }
        match vfs.nodes.get(&inode) {
            Some(Node::Dir(_)) => {
                *out = BaleAttr {
                    kind: KIND_DIR,
                    size: 0,
                    inode,
                };
                0
            }
            Some(Node::File(data)) => {
                *out = BaleAttr {
                    kind: KIND_FILE,
                    size: data.len() as u64,
                    inode,
                };
                0
            }
            None => -libc_enoent(),
        }
    })
}

/// Look up `name` under `parent`. Returns the child inode, or 0 if absent.
///
/// # Safety
/// `vfs` valid; `name` a valid C string.
#[no_mangle]
pub unsafe extern "C" fn bale_vfs_lookup(
    vfs: *mut BaleVfs,
    parent: u64,
    name: *const c_char,
) -> u64 {
    guard(0, || {
        let Some(vfs) = vfs.as_ref() else { return 0 };
        let Some(name) = cstr(name) else { return 0 };
        match vfs.nodes.get(&parent) {
            Some(Node::Dir(children)) => children
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, ino)| *ino)
                .unwrap_or(0),
            _ => 0,
        }
    })
}

pub type BaleDirCb = extern "C" fn(ctx: *mut c_void, name: *const c_char, inode: u64, kind: c_int);

/// Invoke `cb` once per child of `dir`. Returns 0 on success, -errno otherwise.
///
/// # Safety
/// `vfs` valid; `cb` a valid function pointer; `ctx` opaque, passed back as-is.
#[no_mangle]
pub unsafe extern "C" fn bale_vfs_readdir(
    vfs: *mut BaleVfs,
    dir: u64,
    cb: BaleDirCb,
    ctx: *mut c_void,
) -> c_int {
    guard(-libc_eio(), || {
        let Some(vfs) = vfs.as_ref() else {
            return -libc_einval();
        };
        let Some(Node::Dir(children)) = vfs.nodes.get(&dir) else {
            return -libc_enoent();
        };
        for (name, inode) in children {
            let kind = match vfs.nodes.get(inode) {
                Some(Node::Dir(_)) => KIND_DIR,
                _ => KIND_FILE,
            };
            let Ok(cname) = CString::new(name.as_str()) else {
                continue;
            };
            cb(ctx, cname.as_ptr(), *inode, kind);
        }
        0
    })
}

/// Open a file inode for reading. Returns a handle (>0), or 0 on error. In the
/// real impl this is where `Reader::open` reconstructs Bale pointers.
///
/// # Safety
/// `vfs` valid.
#[no_mangle]
pub unsafe extern "C" fn bale_vfs_open_file(vfs: *mut BaleVfs, inode: u64) -> u64 {
    guard(0, || {
        let Some(vfs) = vfs.as_mut() else { return 0 };
        let data = match vfs.nodes.get(&inode) {
            Some(Node::File(d)) => d.clone(),
            _ => {
                set_error("open_file on non-file inode");
                return 0;
            }
        };
        vfs.next_handle += 1;
        let fh = vfs.next_handle;
        vfs.handles.insert(fh, data);
        fh
    })
}

/// Read up to `len` bytes at `offset` from handle `fh` into `buf`. Returns bytes
/// read (>=0, 0 at EOF) or -errno.
///
/// # Safety
/// `vfs` valid; `buf` writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn bale_vfs_read(
    vfs: *mut BaleVfs,
    fh: u64,
    offset: u64,
    buf: *mut u8,
    len: usize,
) -> isize {
    guard(-(libc_eio() as isize), || {
        let Some(vfs) = vfs.as_ref() else {
            return -(libc_einval() as isize);
        };
        if buf.is_null() {
            return -(libc_einval() as isize);
        }
        let Some(data) = vfs.handles.get(&fh) else {
            return -(libc_ebadf() as isize);
        };
        let off = offset as usize;
        if off >= data.len() {
            return 0;
        }
        let n = len.min(data.len() - off);
        std::ptr::copy_nonoverlapping(data.as_ptr().add(off), buf, n);
        n as isize
    })
}

/// # Safety
/// `vfs` valid.
#[no_mangle]
pub unsafe extern "C" fn bale_vfs_close(vfs: *mut BaleVfs, fh: u64) {
    guard((), || {
        if let Some(vfs) = vfs.as_mut() {
            vfs.handles.remove(&fh);
        }
    });
}

/// Thread-local last error message, or null. Valid until the next failing call
/// on this thread. Do not free.
#[no_mangle]
pub extern "C" fn bale_vfs_last_error() -> *const c_char {
    LAST_ERROR.with(|e| match &*e.borrow() {
        Some(c) => c.as_ptr(),
        None => std::ptr::null(),
    })
}

unsafe fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok().map(|s| s.to_string())
}

// Small errno set, kept local so the prototype links no libc.
fn libc_enoent() -> c_int {
    2
}
fn libc_eio() -> c_int {
    5
}
fn libc_ebadf() -> c_int {
    9
}
fn libc_einval() -> c_int {
    22
}
