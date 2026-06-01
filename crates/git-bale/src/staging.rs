//! Per-repo staging area for pending uploads. `git add` writes xorbs/shards
//! here via `TranslatorConfig::local_config`; `git-bale push-pending` (pre-push
//! hook) re-translates and drains them. See [`crate::push_pending`].
//!
//! Layout mirrors xet-data's `LocalClient`, with a sidecar index:
//!   `<staging>/xet/xorbs/xorbs/default.<merkle_hex>`     # xorbs
//!   `<staging>/xet/xorbs/shards/<merkle_hex>.mdb`        # shards
//!   `<staging>/file-index/<file_hex>`                    # per-file markers
//!
//! The marker body is the file size (decimal ASCII) so push-pending can give
//! `download_to_writer` a byte range without re-parsing the shard. Readers
//! tolerate empty/legacy markers (smudge only needs the existence check).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub fn staging_root(git_dir: &Path) -> PathBuf {
    git_dir.join("bale").join("staging")
}

fn file_index_dir(git_dir: &Path) -> PathBuf {
    staging_root(git_dir).join("file-index")
}

fn file_marker_path(git_dir: &Path, file_hex: &str) -> PathBuf {
    file_index_dir(git_dir).join(file_hex)
}

/// Write the `<file_hex>` marker (body = file size, decimal ASCII) after clean,
/// gating the lukewarm smudge and giving push-pending the reconstruct range.
pub fn mark_file_staged(git_dir: &Path, file_hex: &str, file_size: u64) -> std::io::Result<()> {
    crate::fs_util::create_bale_subdir(git_dir, "staging/file-index")?;
    let path = file_marker_path(git_dir, file_hex);
    let mut f = std::fs::File::create(&path)?;
    f.write_all(file_size.to_string().as_bytes())?;
    Ok(())
}

pub fn file_is_staged(git_dir: &Path, file_hex: &str) -> bool {
    file_marker_path(git_dir, file_hex).exists()
}

/// Modification time of a `<file_hex>` marker, i.e. when its content was last
/// cleaned (clean refreshes the marker on every add, hit or miss). `None` if the
/// marker is absent or unstattable. Used by gc's reclaim grace.
pub fn marker_mtime(git_dir: &Path, file_hex: &str) -> Option<std::time::SystemTime> {
    std::fs::metadata(file_marker_path(git_dir, file_hex))
        .and_then(|m| m.modified())
        .ok()
}

/// Bump an existing marker's mtime to now, WITHOUT creating it. Used by the
/// clean-cache-hit path so gc's reclaim grace keys on the most recent add. Must
/// not create a missing marker: a hit can re-emit a pointer for content whose
/// objects were already drained (server mode, post-push), and a marker with no
/// staged backing would make `push-pending` try to re-translate from empty
/// staging. Returns whether a marker was present. Preserves the size body.
pub fn touch_marker_if_exists(git_dir: &Path, file_hex: &str) -> std::io::Result<bool> {
    match std::fs::OpenOptions::new()
        .write(true)
        .open(file_marker_path(git_dir, file_hex))
    {
        Ok(f) => {
            f.set_modified(std::time::SystemTime::now())?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Every `(file_hex, file_size)` in `file-index/`; an empty/malformed body
/// yields `None` (push-pending can't prime FileDownloadSession, so it warns).
pub fn list_staged_files(git_dir: &Path) -> std::io::Result<Vec<(String, Option<u64>)>> {
    let dir = file_index_dir(git_dir);
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !is_64_lower_hex(name) {
            continue;
        }
        let mut buf = String::new();
        let _ = std::fs::File::open(&path).and_then(|mut f| f.read_to_string(&mut buf));
        let size = buf.trim().parse::<u64>().ok();
        out.push((name.to_string(), size));
    }
    out.sort();
    Ok(out)
}

fn is_64_lower_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Drop `file-index/`. push-pending calls this after a drain so markers don't
/// outlive the bytes they advertise.
pub fn clear_file_markers(git_dir: &Path) -> std::io::Result<()> {
    let dir = file_index_dir(git_dir);
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Forget one `<file_hex>` marker (gc). NotFound is fine — concurrent
/// push-pending may have cleared it.
pub fn remove_marker(git_dir: &Path, file_hex: &str) -> std::io::Result<()> {
    match std::fs::remove_file(file_marker_path(git_dir, file_hex)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Recursively delete every `default.<hex>` (xorb) and `<hex>.mdb` (shard) leaf
/// under `staging`; empty dirs are left for [`remove_empty_dirs`]. Called once
/// nothing references these xorbs (push-pending drain / gc with no markers).
pub fn remove_all_staged_objects(staging: &Path) -> std::io::Result<()> {
    let rd = match std::fs::read_dir(staging) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in rd {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            remove_all_staged_objects(&path)?;
        } else if ft.is_file() {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if is_xorb_filename(name) || is_shard_filename(name) {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
    Ok(())
}

/// Best-effort recursive rmdir: removes directories that are (or become) empty.
/// `rmdir` fails on non-empty dirs, which is exactly the guard we want.
pub fn remove_empty_dirs(root: &Path) -> std::io::Result<()> {
    if !root.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let _ = remove_empty_dirs(&entry.path());
        }
    }
    let _ = std::fs::remove_dir(root);
    Ok(())
}

fn is_xorb_filename(name: &str) -> bool {
    name.strip_prefix("default.").is_some_and(is_64_lower_hex)
}

fn is_shard_filename(name: &str) -> bool {
    name.strip_suffix(".mdb").is_some_and(is_64_lower_hex)
}
