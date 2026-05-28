//! Per-repo staging area for pending uploads.
//!
//! `git add` writes xorbs/shards under `<git_dir>/bale/staging/` via xet-data's
//! `TranslatorConfig::local_config`. `git push` (driven by a pre-push hook
//! that runs `git-bale push-pending`) reconstructs each staged file via that
//! same local config, then re-translates it through an online
//! `FileUploadSession` so xet-data's global-dedup query path runs against the
//! real bale server before any new xorbs leave the host. The original staged
//! files are then deleted.
//!
//! Layout mirrors xet-data's `LocalClient`, with an extra sidecar directory:
//!   `<staging>/xet/xorbs/xorbs/default.<merkle_hex>`     # xorbs
//!   `<staging>/xet/xorbs/shards/<merkle_hex>.mdb`        # shards
//!   `<staging>/file-index/<file_hex>`                    # per-file markers
//!
//! The marker stores the file's size (decimal ASCII) so push-pending can hand
//! it to `FileDownloadSession::download_to_writer` (which needs an explicit
//! byte range) without re-parsing the shard's File Info. The lukewarm smudge
//! fallback only needs the existence check, so empty/legacy markers are still
//! accepted on read.

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

/// Best-effort: writes `<staging>/file-index/<file_hex>` after `clean` so the
/// lukewarm smudge knows this file's bytes are stageable locally AND
/// push-pending knows how big a byte range to ask the local reconstructor
/// for. Content is the file size in decimal ASCII; readers tolerate empty
/// markers for backward compat.
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

/// Returns every `(file_hex, file_size)` pair currently in `file-index/`. A
/// marker with an empty or malformed body yields `file_size = None`, so
/// push-pending can decide what to do (typically: skip it and warn — without
/// a size, FileDownloadSession can't be primed).
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

/// Drop the entire `file-index/` directory. `push-pending` calls this after a
/// successful drain so markers don't outlive the bytes they advertise.
pub fn clear_file_markers(git_dir: &Path) -> std::io::Result<()> {
    let dir = file_index_dir(git_dir);
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Forget a single `<file_hex>` marker. `git-bale gc` calls this when a staged
/// file is no longer referenced by the index or any unpushed commit. NotFound
/// is fine (concurrent push-pending may have already cleared it).
pub fn remove_marker(git_dir: &Path, file_hex: &str) -> std::io::Result<()> {
    match std::fs::remove_file(file_marker_path(git_dir, file_hex)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Recursively delete every `default.<hex>` (xorb) and `<hex>.mdb` (shard) leaf
/// under `staging`. The `file-index/` dir and the now-empty `xet/` tree are
/// left for [`remove_empty_dirs`]. Shared by `push-pending` (after a drain) and
/// `git-bale gc` (when no markers remain, so nothing references these xorbs).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path();
        let h = "a".repeat(64);

        assert!(!file_is_staged(git_dir, &h));
        mark_file_staged(git_dir, &h, 123).unwrap();
        assert!(file_is_staged(git_dir, &h));

        // Idempotent: re-marking the same hash succeeds.
        mark_file_staged(git_dir, &h, 123).unwrap();
        assert!(file_is_staged(git_dir, &h));

        clear_file_markers(git_dir).unwrap();
        assert!(!file_is_staged(git_dir, &h));

        // Clearing a non-existent file-index/ is a no-op.
        clear_file_markers(git_dir).unwrap();
    }

    #[test]
    fn unstaged_file_is_not_staged() {
        let dir = tempfile::tempdir().unwrap();
        let staged = "a".repeat(64);
        let other = "b".repeat(64);

        mark_file_staged(dir.path(), &staged, 7).unwrap();
        assert!(file_is_staged(dir.path(), &staged));
        assert!(!file_is_staged(dir.path(), &other));
    }

    #[test]
    fn list_staged_files_returns_hex_size_pairs() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        mark_file_staged(git_dir, &a, 42).unwrap();
        mark_file_staged(git_dir, &b, 99).unwrap();
        let mut listed = list_staged_files(git_dir).unwrap();
        listed.sort();
        assert_eq!(listed, vec![(a, Some(42)), (b, Some(99))]);
    }

    #[test]
    fn xorb_and_shard_filename_recognition() {
        let h = "a".repeat(64);
        assert!(is_xorb_filename(&format!("default.{h}")));
        assert!(!is_xorb_filename(&format!("foo.{h}")));
        assert!(!is_xorb_filename(&format!("default.{}", "a".repeat(63))));
        assert!(is_shard_filename(&format!("{h}.mdb")));
        assert!(!is_shard_filename("not-a-shard.txt"));
        assert!(!is_shard_filename(&format!("{}.mdb", "A".repeat(64))));
    }

    #[test]
    fn remove_marker_is_idempotent_and_targeted() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        mark_file_staged(git_dir, &a, 1).unwrap();
        mark_file_staged(git_dir, &b, 2).unwrap();
        remove_marker(git_dir, &a).unwrap();
        assert!(!file_is_staged(git_dir, &a));
        assert!(file_is_staged(git_dir, &b));
        // Removing an absent marker is a no-op.
        remove_marker(git_dir, &a).unwrap();
    }

    #[test]
    fn sweep_removes_xorbs_and_shards_but_keeps_other_files() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        let xorbs = staging.join("xet/xorbs/xorbs");
        let shards = staging.join("xet/xorbs/shards");
        std::fs::create_dir_all(&xorbs).unwrap();
        std::fs::create_dir_all(&shards).unwrap();
        let h = "0".repeat(64);
        std::fs::write(xorbs.join(format!("default.{h}")), b"x").unwrap();
        std::fs::write(shards.join(format!("{h}.mdb")), b"s").unwrap();
        std::fs::write(staging.join("file-index-placeholder"), b"keep").unwrap();

        remove_all_staged_objects(&staging).unwrap();
        assert!(!xorbs.join(format!("default.{h}")).exists());
        assert!(!shards.join(format!("{h}.mdb")).exists());
        assert!(staging.join("file-index-placeholder").exists());

        remove_empty_dirs(&staging).unwrap();
        // The xet/ tree was emptied by the sweep, so it's gone; the placeholder
        // file kept `staging` itself alive.
        assert!(!xorbs.exists());
        assert!(staging.exists());
    }

    #[test]
    fn list_staged_files_tolerates_empty_marker() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path();
        // Simulate a marker written by an older client (no size body).
        let h = "c".repeat(64);
        let path = file_marker_path(git_dir, &h);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::File::create(&path).unwrap();
        let listed = list_staged_files(git_dir).unwrap();
        assert_eq!(listed, vec![(h, None)]);
    }
}
