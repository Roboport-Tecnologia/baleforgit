//! Small helpers shared across the `<git_dir>/bale/` cache modules.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// Create `<git_dir>/bale/<subdir>` and tighten `bale/` to 0o700 on Unix so
/// cache contents aren't world-readable. Idempotent.
pub fn create_bale_subdir(git_dir: &Path, subdir: &str) -> io::Result<()> {
    let bale = git_dir.join("bale");
    let sub = bale.join(subdir);
    std::fs::create_dir_all(&sub)?;
    #[cfg(unix)]
    restrict_bale_perms(&bale)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_bale_perms(bale: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::metadata(bale)?.permissions();
    if perms.mode() & 0o777 != 0o700 {
        std::fs::set_permissions(bale, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Tighten `dir` (and a parent named `bale`) to 0o700. The user-wide chunk
/// cache is created by `xet-client`, so we can only lock it down after the fact.
pub fn restrict_user_cache_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(dir) {
            if meta.is_dir() && meta.permissions().mode() & 0o777 != 0o700 {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        if let Some(parent) = dir.parent() {
            if parent.file_name().and_then(|s| s.to_str()) == Some("bale") {
                restrict_bale_perms(parent)?;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Positional read (`pread`) that doesn't disturb a shared file cursor, so
/// worker threads can read disjoint regions of one handle concurrently. Unix
/// has `read_at`; Windows has `seek_read`; the fallback clones and seeks.
#[cfg(unix)]
pub fn pread(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buf, offset)
}

#[cfg(windows)]
pub fn pread(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buf, offset)
}

#[cfg(not(any(unix, windows)))]
pub fn pread(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::io::{Read, Seek, SeekFrom};
    let mut handle = file.try_clone()?;
    handle.seek(SeekFrom::Start(offset))?;
    handle.read(buf)
}

/// fsync a file's contents to stable storage.
pub fn fsync_file(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        // FlushFileBuffers needs GENERIC_WRITE; xet stores objects read-only,
        // so lift the attribute for the flush and put it back.
        let open_w = || std::fs::OpenOptions::new().write(true).open(path);
        match open_w() {
            Ok(f) => f.sync_all(),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                let mut perms = std::fs::metadata(path)?.permissions();
                if !perms.readonly() {
                    return Err(e);
                }
                perms.set_readonly(false);
                std::fs::set_permissions(path, perms.clone())?;
                let res = open_w().and_then(|f| f.sync_all());
                perms.set_readonly(true);
                std::fs::set_permissions(path, perms)?;
                res
            }
            Err(e) => Err(e),
        }
    }
    #[cfg(not(windows))]
    {
        File::open(path)?.sync_all()
    }
}

/// fsync a directory so a rename/create inside it survives a crash. Windows
/// can't open directories for sync (NTFS journals metadata itself): no-op.
pub fn fsync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// fsync the nearest `levels` ancestors of `dir`. A freshly created store or
/// staging dir is only durable once its parents' entries are, or a crash can
/// drop the whole tree while git's index already holds the pointer.
pub fn fsync_ancestors(dir: &Path, levels: usize) -> io::Result<()> {
    let mut cur = dir.parent();
    for _ in 0..levels {
        match cur {
            Some(p) if !p.as_os_str().is_empty() && p.is_dir() => {
                fsync_dir(p)?;
                cur = p.parent();
            }
            _ => break,
        }
    }
    Ok(())
}

/// Crash-safe replace: `<dir>/<tmp_name>` → write → fsync → rename onto
/// `final_path` → fsync `dir`. Readers see the old file or the complete new one.
pub fn write_durable(dir: &Path, tmp_name: &str, final_path: &Path, body: &[u8]) -> io::Result<()> {
    let tmp = dir.join(tmp_name);
    let res = (|| {
        let mut f = File::create(&tmp)?;
        f.write_all(body)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, final_path)?;
        fsync_dir(dir)?;
        fsync_ancestors(dir, 3)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// fsync every file and directory under `root` (bottom-up), then `root`.
pub fn fsync_tree(root: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            fsync_tree(&entry.path())?;
        } else if ft.is_file() {
            fsync_file(&entry.path())?;
        }
    }
    fsync_dir(root)
}
