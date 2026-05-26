//! Append `filter=bale` lines to `.gitattributes`. We don't claim `diff` /
//! `merge` drivers — the pointer is JSON and Git's default diff handles it.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

const FILTER_SUFFIX: &str = "filter=bale -text";

/// Add `patterns` to `<repo>/.gitattributes`, skipping any that already have a
/// `filter=bale` line. Each pattern gets one line: `<pattern> filter=bale -text`.
pub fn track(repo: &Path, patterns: &[String]) -> Result<()> {
    let attrs_path = repo.join(".gitattributes");
    let existing = match fs::read_to_string(&attrs_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).context("reading .gitattributes"),
    };

    let line_end = if existing.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut appended = 0;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&attrs_path)
        .with_context(|| format!("opening {}", attrs_path.display()))?;

    if !existing.is_empty() && !existing.ends_with('\n') && !existing.ends_with("\r\n") {
        file.write_all(line_end.as_bytes())?;
    }

    for raw in patterns {
        let pattern = raw.trim();
        if pattern.is_empty() {
            continue;
        }
        if pattern_already_tracked(&existing, pattern) {
            println!("\"{pattern}\" already tracked");
            continue;
        }
        writeln!(file, "{pattern} {FILTER_SUFFIX}")
            .map_err(|e| std::io::Error::new(e.kind(), format!(".gitattributes write: {e}")))?;
        appended += 1;
        println!("Tracking \"{pattern}\"");
    }

    if appended == 0 {
        return Ok(());
    }

    Ok(())
}

fn pattern_already_tracked(existing: &str, pattern: &str) -> bool {
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(first) = parts.next() else { continue };
        if first == pattern && parts.any(|t| t == "filter=bale") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn appends_new_pattern() {
        let dir = tempdir().unwrap();
        track(dir.path(), &["*.bin".to_string()]).unwrap();
        let body = fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
        assert!(body.contains("*.bin filter=bale -text"));
    }

    #[test]
    fn skips_already_tracked_pattern() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".gitattributes");
        fs::write(&path, "*.bin filter=bale -text\n").unwrap();
        track(dir.path(), &["*.bin".to_string()]).unwrap();
        let body = fs::read_to_string(&path).unwrap();
        // Still exactly one line for *.bin.
        assert_eq!(body.matches("*.bin filter=bale -text").count(), 1);
    }

    #[test]
    fn appends_after_missing_trailing_newline() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".gitattributes");
        fs::write(&path, "*.txt text").unwrap();
        track(dir.path(), &["*.bin".to_string()]).unwrap();
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("*.txt text\n"));
        assert!(body.contains("*.bin filter=bale -text"));
    }
}
