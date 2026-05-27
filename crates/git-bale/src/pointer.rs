//! Bale pointer file: pretty-printed JSON wrapping a [`XetFileInfo`], with a
//! trailing newline so `git diff` and trailing-newline-stripping editors
//! don't churn it. Field order is stable (struct declaration order).

use std::io::{self, Read, Write};

use xet_data::processing::XetFileInfo;

/// Soft cap on pointer file size. Real pointers are ~150 bytes; anything
/// over this is almost certainly a real binary that wasn't filtered.
pub const POINTER_MAX_BYTES: usize = 4096;

/// Cheap pre-check before JSON parse — real pointers always contain `"hash"`.
const POINTER_SENTINEL: &str = "\"hash\"";

#[derive(Debug, thiserror::Error)]
pub enum PointerError {
    #[error("input exceeds pointer size cap of {POINTER_MAX_BYTES} bytes")]
    TooLarge,
    #[error("input does not contain a `hash` key; not a bale pointer")]
    NotAPointer,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub fn write_pointer<W: Write>(mut w: W, info: &XetFileInfo) -> Result<(), PointerError> {
    let s = encode_pointer_string(info)?;
    w.write_all(s.as_bytes())?;
    Ok(())
}

pub fn encode_pointer(info: &XetFileInfo) -> Result<Vec<u8>, PointerError> {
    Ok(encode_pointer_string(info)?.into_bytes())
}

/// Like `encode_pointer` but skips the `String → bytes → String` round-trip
/// when the caller wants both representations (e.g. to stream over pkt-line
/// *and* stash in the clean cache without a `from_utf8` revalidation).
pub fn encode_pointer_string(info: &XetFileInfo) -> Result<String, PointerError> {
    let mut s = serde_json::to_string_pretty(info)?;
    s.push('\n');
    Ok(s)
}

pub fn parse_pointer(bytes: &[u8]) -> Result<XetFileInfo, PointerError> {
    if bytes.len() > POINTER_MAX_BYTES {
        return Err(PointerError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| PointerError::NotAPointer)?;
    if !text.contains(POINTER_SENTINEL) {
        return Err(PointerError::NotAPointer);
    }
    Ok(serde_json::from_str(text.trim())?)
}

/// Returns the parsed pointer and the bytes we read, so the caller can spool
/// real content through if parsing fails. Reads `POINTER_MAX_BYTES + 1` to
/// distinguish "exactly the cap" from "over it".
pub fn read_pointer<R: Read>(mut r: R) -> Result<(XetFileInfo, Vec<u8>), PointerError> {
    let mut buf = Vec::with_capacity(256);
    r.by_ref()
        .take((POINTER_MAX_BYTES + 1) as u64)
        .read_to_end(&mut buf)?;
    let info = parse_pointer(&buf)?;
    Ok((info, buf))
}

/// Cheap allocation-free check for re-staged pointers.
pub fn looks_like_pointer(bytes: &[u8]) -> bool {
    if bytes.len() > POINTER_MAX_BYTES {
        return false;
    }
    let probe = &bytes[..bytes.len().min(64)];
    probe
        .windows(POINTER_SENTINEL.len())
        .any(|w| w == POINTER_SENTINEL.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> XetFileInfo {
        XetFileInfo::new_with_sha256("a".repeat(64), 12345, "b".repeat(64))
    }

    #[test]
    fn pretty_with_stable_key_order_and_trailing_newline() {
        let encoded = String::from_utf8(encode_pointer(&sample()).unwrap()).unwrap();
        assert!(encoded.ends_with('\n'), "trailing newline expected");

        // Stable order is hash, file_size, sha256 (struct declaration order).
        let hash_at = encoded.find("\"hash\"").unwrap();
        let size_at = encoded.find("\"file_size\"").unwrap();
        let sha_at = encoded.find("\"sha256\"").unwrap();
        assert!(
            hash_at < size_at && size_at < sha_at,
            "field order changed: {encoded}"
        );

        // Pretty-printed (multi-line, indented with 2 spaces).
        assert!(
            encoded.contains("\n  \"file_size\""),
            "expected pretty indent"
        );
    }

    #[test]
    fn round_trip() {
        let info = sample();
        let bytes = encode_pointer(&info).unwrap();
        let parsed = parse_pointer(&bytes).unwrap();
        assert_eq!(parsed.hash(), info.hash());
        assert_eq!(parsed.file_size(), info.file_size());
        assert_eq!(parsed.sha256(), info.sha256());
    }

    #[test]
    fn rejects_oversize_input() {
        let huge = vec![b'a'; POINTER_MAX_BYTES + 1];
        assert!(matches!(parse_pointer(&huge), Err(PointerError::TooLarge)));
    }

    #[test]
    fn rejects_non_pointer() {
        let not_pointer = b"hello world\n";
        assert!(matches!(
            parse_pointer(not_pointer),
            Err(PointerError::NotAPointer)
        ));
    }

    #[test]
    fn looks_like_pointer_matches_real_pointer() {
        let bytes = encode_pointer(&sample()).unwrap();
        assert!(looks_like_pointer(&bytes));
    }

    #[test]
    fn looks_like_pointer_rejects_binary() {
        assert!(!looks_like_pointer(&[0u8; 200]));
        assert!(!looks_like_pointer(b"some random text without the key"));
    }
}
