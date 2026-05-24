//! M2 integration: the FS blob store and the SQLite metadata store cooperate
//! the way the upload+download path in M3/M4 will rely on.

use bytes::Bytes;
use xet_server_core::{
    BlobStore, ChunkHash, ChunkRow, FileHash, FileTerm, Hash32, MetadataStore, RepoRef, RepoType,
    XorbHash, XorbInfo,
};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_storage_fs::FsBlobStore;

fn h(seed: u8) -> Hash32 {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = seed.wrapping_add(i as u8);
    }
    Hash32(b)
}

#[tokio::test]
async fn upload_indexes_and_reconstruction_can_be_assembled() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = FsBlobStore::open(dir.path().join("blobs")).await.unwrap();
    let meta = SqliteMetadataStore::open_path(":memory:").await.unwrap();

    // Pretend we have one 1000-byte xorb that holds two chunks [0..400, 400..1000].
    let xorb = XorbHash(h(0x10));
    let xorb_body: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    blobs.put_xorb(&xorb, Bytes::from(xorb_body.clone())).await.unwrap();
    assert!(blobs.xorb_exists(&xorb).await.unwrap());

    meta.register_xorb(
        &XorbInfo {
            xorb,
            num_chunks: 2,
            num_bytes_in_cas: 1000,
            num_bytes_on_disk: 1000,
        },
        &[
            ChunkRow {
                chunk_hash: ChunkHash(h(0xA0)),
                chunk_index: 0,
                byte_start: 0,
                unpacked_segment_bytes: 400,
            },
            ChunkRow {
                chunk_hash: ChunkHash(h(0xA1)),
                chunk_index: 1,
                byte_start: 400,
                unpacked_segment_bytes: 600,
            },
        ],
    )
    .await
    .unwrap();

    // Pretend a file is just the second chunk of that xorb.
    let file = FileHash(h(0xF0));
    let repo = RepoRef {
        repo_type: RepoType::Model,
        repo_id: "team/asset".into(),
        revision: "main".into(),
    };
    meta.register_file(
        &file,
        &repo,
        None,
        &[FileTerm {
            xorb,
            chunk_idx_start: 1,
            chunk_idx_end: 2,
            unpacked_segment_bytes: 600,
            verification: Some(h(0xE1)),
        }],
    )
    .await
    .unwrap();

    // Now simulate the reconstruction path: pull terms, find xorb byte range,
    // fetch it from the blob store, sanity-check the bytes.
    let terms = meta.lookup_file(&file).await.unwrap().expect("registered");
    assert_eq!(terms.len(), 1);
    let t = &terms[0];
    assert_eq!(t.xorb, xorb);

    let offsets = meta.xorb_chunk_offsets(&t.xorb).await.unwrap();
    assert_eq!(offsets.len(), 2);

    // Translate chunk-index range [1, 2) into byte range [400, 1000).
    let start = offsets[t.chunk_idx_start as usize].byte_start as u64;
    let end_chunk = &offsets[(t.chunk_idx_end - 1) as usize];
    let end = end_chunk.byte_start as u64 + end_chunk.unpacked_segment_bytes as u64;
    assert_eq!(start, 400);
    assert_eq!(end, 1000);

    let slice = blobs.get_xorb_range(&t.xorb, start..end).await.unwrap();
    assert_eq!(slice.len(), 600);
    assert_eq!(&slice[..], &xorb_body[400..1000]);
}

#[tokio::test]
async fn chunk_lookup_drives_global_dedup() {
    let dir = tempfile::tempdir().unwrap();
    let _blobs = FsBlobStore::open(dir.path().join("blobs")).await.unwrap();
    let meta = SqliteMetadataStore::open_path(":memory:").await.unwrap();

    let xorb = XorbHash(h(0x99));
    meta.register_xorb(
        &XorbInfo {
            xorb,
            num_chunks: 1,
            num_bytes_in_cas: 64,
            num_bytes_on_disk: 60,
        },
        &[ChunkRow {
            chunk_hash: ChunkHash(h(0xAB)),
            chunk_index: 0,
            byte_start: 0,
            unpacked_segment_bytes: 64,
        }],
    )
    .await
    .unwrap();

    // The global-dedup endpoint will use these two queries:
    let loc = meta
        .lookup_chunk(&ChunkHash(h(0xAB)))
        .await
        .unwrap()
        .expect("chunk known");
    assert_eq!(loc.xorb, xorb);

    let near = meta.xorbs_near_chunk(&ChunkHash(h(0xAB)), 5).await.unwrap();
    assert_eq!(near.len(), 1);
    assert_eq!(near[0].xorb, xorb);
}
