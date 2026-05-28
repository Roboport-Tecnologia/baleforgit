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

/// String form, avoiding the bytes round-trip when the caller wants both (stream
/// over pkt-line *and* stash in the clean cache without a `from_utf8` recheck).
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
