//! Test-only helper for the e2e harness, which is stdlib Python and can't
//! compute xet's keyed-BLAKE3 hashes. Uses the exact functions the server
//! verifies with, so a crafted xorb or shard is valid by construction.
//!
//! ```text
//! bale-e2e-tools xorb <out-body> <chunk-file>...
//!   -> {"hash": <wire hex>, "chunks": [{"hash": <raw hex>, "len": n}, ...]}
//! bale-e2e-tools shard <out-shard> <spec.json>
//!   spec: {"files": [{"terms": [{"xorb": <wire hex>, "start": s, "end": e,
//!          "chunks": <that xorb's "chunks" from `xorb`>}]}]}
//!   -> {"files": [{"hash": <wire hex>, "size": n}]}
//! bale-e2e-tools selfcheck
//!   -> server's streaming FileHasher == xet's file_hash on random sequences
//! ```

use bale_server_core::{ChunkHash, Hash32};
use bale_server_shard::{
    file_hash_of, serialize, term_verification_hash, FileTermEntry, ParsedFile, ParsedShard,
    ShardHeader, MDB_SHARD_HEADER_TAG, MDB_SHARD_HEADER_VERSION,
};
use bale_server_wire::{decode_hash, encode_hash};
use serde_json::{json, Value};
use std::process::ExitCode;
use xet_core_structures::merklehash::compute_data_hash;

const FLAG_WITH_VERIFICATION: u32 = 1 << 31;

type Res<T> = Result<T, String>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("xorb") if args.len() >= 3 => xorb(&args[1], &args[2..]),
        Some("shard") if args.len() == 3 => shard(&args[1], &args[2]),
        Some("selfcheck") => selfcheck(),
        _ => Err("usage: bale-e2e-tools xorb <out> <chunk>... | shard <out> <spec.json>".into()),
    };
    match result {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("bale-e2e-tools: {e}");
            ExitCode::FAILURE
        }
    }
}

// Uncompressed frames (scheme 0), no footer: what xet uploads for incompressible chunks.
fn xorb(out: &str, chunk_files: &[String]) -> Res<Value> {
    let mut body = Vec::new();
    let mut chunks = Vec::new();
    for path in chunk_files {
        let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
        let len = u32::try_from(data.len())
            .ok()
            .filter(|n| *n < 1 << 24)
            .ok_or_else(|| format!("{path}: chunk must be < 16 MiB"))?;
        let mut header = [0u8; 8];
        header[1..4].copy_from_slice(&len.to_le_bytes()[..3]);
        header[5..8].copy_from_slice(&len.to_le_bytes()[..3]);
        body.extend_from_slice(&header);
        body.extend_from_slice(&data);
        let hash = ChunkHash::from_bytes(compute_data_hash(&data).into());
        chunks.push((hash, data.len() as u64));
    }
    std::fs::write(out, &body).map_err(|e| format!("write {out}: {e}"))?;
    Ok(json!({
        "hash": encode_hash(&bale_server_shard::xorb_hash_of(&chunks).0),
        "chunks": chunks
            .iter()
            .map(|(h, len)| json!({"hash": hex::encode(h.as_bytes()), "len": len}))
            .collect::<Vec<_>>(),
    }))
}

fn shard(out: &str, spec_path: &str) -> Res<Value> {
    let spec: Value = serde_json::from_slice(
        &std::fs::read(spec_path).map_err(|e| format!("read {spec_path}: {e}"))?,
    )
    .map_err(|e| format!("parse {spec_path}: {e}"))?;
    let mut files = Vec::new();
    let mut summary = Vec::new();
    for f in spec["files"]
        .as_array()
        .ok_or("spec.files must be an array")?
    {
        let mut entries = Vec::new();
        let mut verifications = Vec::new();
        let mut all: Vec<(ChunkHash, u64)> = Vec::new();
        for t in f["terms"].as_array().ok_or("file.terms must be an array")? {
            let xorb = bale_server_core::XorbHash(
                decode_hash(t["xorb"].as_str().ok_or("term.xorb")?)
                    .map_err(|e| format!("term.xorb: {e:?}"))?,
            );
            let start = t["start"].as_u64().ok_or("term.start")? as usize;
            let end = t["end"].as_u64().ok_or("term.end")? as usize;
            let chunks = parse_chunks(&t["chunks"])?;
            let span = chunks.get(start..end).ok_or("term range outside chunks")?;
            let hashes: Vec<ChunkHash> = span.iter().map(|(h, _)| *h).collect();
            let unpacked: u64 = span.iter().map(|(_, len)| len).sum();
            entries.push(FileTermEntry {
                xorb,
                cas_flags: 0,
                unpacked_segment_bytes: unpacked as u32,
                chunk_idx_start: start as u32,
                chunk_idx_end: end as u32,
            });
            verifications.push(term_verification_hash(&hashes));
            all.extend_from_slice(span);
        }
        let file_hash = file_hash_of(&all);
        summary.push(json!({
            "hash": encode_hash(&file_hash.0),
            "size": all.iter().map(|(_, len)| len).sum::<u64>(),
        }));
        files.push(ParsedFile {
            file_hash,
            file_flags: FLAG_WITH_VERIFICATION,
            entries,
            verifications,
            sha256: None,
        });
    }
    let bytes = serialize(&ParsedShard {
        header: ShardHeader {
            tag: MDB_SHARD_HEADER_TAG,
            version: MDB_SHARD_HEADER_VERSION,
            footer_size: 0,
        },
        files,
        cas_blocks: Vec::new(),
        footer: None,
    });
    std::fs::write(out, bytes).map_err(|e| format!("write {out}: {e}"))?;
    Ok(json!({ "files": summary }))
}

fn selfcheck() -> Res<Value> {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut lengths: Vec<usize> = (0..64).collect();
    lengths.extend([100, 255, 1000, 4096, 8191, 8192, 8193, 65_537, 200_003]);
    for _ in 0..300 {
        lengths.push((next() % 20_000) as usize);
    }
    for &n in &lengths {
        let chunks: Vec<(ChunkHash, u64)> = (0..n)
            .map(|_| {
                let mut h = [0u8; 32];
                for w in h.chunks_mut(8) {
                    w.copy_from_slice(&next().to_le_bytes());
                }
                (ChunkHash(Hash32(h)), next() % 131_072 + 1)
            })
            .collect();
        let mut streaming = bale_server_shard::FileHasher::default();
        for (h, len) in &chunks {
            streaming.push(*h, *len);
        }
        if streaming.finish() != file_hash_of(&chunks) {
            return Err(format!(
                "FileHasher diverges from xet file_hash at length {n}"
            ));
        }
    }
    Ok(json!({ "checked": lengths.len() }))
}

fn parse_chunks(v: &Value) -> Res<Vec<(ChunkHash, u64)>> {
    v.as_array()
        .ok_or("term.chunks must be an array")?
        .iter()
        .map(|c| {
            let raw = hex::decode(c["hash"].as_str().ok_or("chunk.hash")?)
                .map_err(|e| format!("chunk.hash: {e}"))?;
            let arr: [u8; 32] = raw.try_into().map_err(|_| "chunk.hash must be 32 bytes")?;
            Ok((
                ChunkHash(Hash32(arr)),
                c["len"].as_u64().ok_or("chunk.len")?,
            ))
        })
        .collect()
}
