//! Per-repo staging area for pending uploads.
//!
//! `git add` writes xorbs/shards under `<git_dir>/bale/staging/` via xet-data's
//! `TranslatorConfig::local_config`. `git push` (driven by a pre-push hook
//! that runs `git-bale push-pending`) drains the directory by POSTing each
//! object to the configured bale server, then deletes the local copy.
//!
//! Layout mirrors xet-data's `LocalClient`, with an extra sidecar directory:
//!   `<staging>/xet/xorbs/xorbs/default.<merkle_hex>`     # xorbs
//!   `<staging>/xet/xorbs/shards/<merkle_hex>.mdb`        # shards
//!   `<staging>/file-index/<file_hex>`                    # per-file markers
//!
//! The marker is written by `clean` after a successful local upload session
//! and read by the lukewarm smudge fallback to decide whether attempting a
//! local reconstruction for `file_hex` is worth it. Without it, smudges for
//! file hashes we never staged enter xet-data's `ReconstructionTermManager`
//! and trip a `debug_assert_eq!` in `update_item_size` (the manager finalizes
//! a size of 0 after returning zero terms, conflicting with the upfront size
//! set by `FileDownloadSession::setup_reconstructor`). Release builds drop
//! the assert, but it spams panics on dev builds during normal `git stash`.

use std::io::Write;
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
/// lukewarm smudge knows this file's bytes are stageable locally. Empty file —
/// the existence check is what matters.
pub fn mark_file_staged(git_dir: &Path, file_hex: &str) -> std::io::Result<()> {
    let dir = file_index_dir(git_dir);
    std::fs::create_dir_all(&dir)?;
    let path = file_marker_path(git_dir, file_hex);
    // Truncate+create is fine: marker is content-free, idempotent.
    let mut f = std::fs::File::create(&path)?;
    f.write_all(b"")?;
    Ok(())
}

pub fn file_is_staged(git_dir: &Path, file_hex: &str) -> bool {
    file_marker_path(git_dir, file_hex).exists()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path();
        let h = "a".repeat(64);

        assert!(!file_is_staged(git_dir, &h));
        mark_file_staged(git_dir, &h).unwrap();
        assert!(file_is_staged(git_dir, &h));

        // Idempotent: re-marking the same hash succeeds.
        mark_file_staged(git_dir, &h).unwrap();
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

        mark_file_staged(dir.path(), &staged).unwrap();
        assert!(file_is_staged(dir.path(), &staged));
        assert!(!file_is_staged(dir.path(), &other));
    }
}
