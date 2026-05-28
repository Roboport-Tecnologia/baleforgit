//! Small helpers shared across the `<git_dir>/bale/` cache modules.

use std::io;
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
