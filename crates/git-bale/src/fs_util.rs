//! Small helpers shared across the `<git_dir>/bale/` cache modules.

use std::io;
use std::path::Path;

/// Create `<git_dir>/bale/<subdir>` (and parents) and, on Unix, tighten
/// `<git_dir>/bale/` to 0o700 so cache contents (pathname-keyed content
/// hashes, file-id markers, in-flight xorbs) aren't world-readable.
/// Idempotent and cheap to call from any cache-write entry point.
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

/// Tighten `dir` (and its parent named `bale`, if present) to 0o700.
/// Used for the user-wide chunk cache `~/.cache/bale/chunks`, which is
/// created by `xet-client` rather than by us — we only get to lock it
/// down after the fact. No-op on non-Unix.
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn bale_dir_is_0o700_after_create() {
        let dir = tempfile::tempdir().unwrap();
        create_bale_subdir(dir.path(), "manifests").unwrap();
        let mode = std::fs::metadata(dir.path().join("bale"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "bale/ should be 0o700");
    }

    #[test]
    fn tightens_loose_existing_perms() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bale/something")).unwrap();
        std::fs::set_permissions(
            dir.path().join("bale"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        create_bale_subdir(dir.path(), "manifests").unwrap();
        let mode = std::fs::metadata(dir.path().join("bale"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }
}
