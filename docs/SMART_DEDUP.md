# Smart dedup wrapper (sketch)

Design notes for an opt-in transform that decompresses well-known
container formats (gzip first; zstd/xz later) inside `git-bale
filter-process` — **before** content reaches CDC chunking — so small
source edits to compressed files like `.blend`, `.fcstd`, `.xcf`
actually dedup across versions.

Status: **proposal only**, no code yet. Open questions at the bottom.

## Why

`gearhash` CDC finds boundaries based on byte content. A 1-byte change
in the *uncompressed* source becomes a wholly different *compressed*
byte stream (deflate is locally chaotic), so the chunker sees no
repeated regions and almost nothing dedups. Decompressing before
chunking restores the dedup signal — the inflated bodies of two
near-identical `.blend` saves share long runs.

The baleforgit-server is intentionally payload-agnostic past the upload-time
chunk integrity check (`docs/ARCHITECTURE.md` — "The server does
decompress on `POST /v1/xorbs/...`" only to verify chunk hashes, never
as a transformation). So this layer is **client-side only** and lives
entirely inside `git-bale`.

## Insertion points

With LFS removed from the picture (`git-bale` is a native Git filter
registered as `filter.bale.process`), the data path is a single
filter-process subprocess Git invokes on staging (`clean`) and
checkout (`smudge`). Both directions live in
`crates/git-bale/src/filter_process.rs`:

- **Clean** (`do_clean` → `handle_clean`): we already spool the input
  bytes from Git's pkt-line stream into a `NamedTempFile` so we can
  hand a path to `clean_file`. Insert the transform between spooling
  and `FileUploadSession::new`: if the spooled bytes look like a
  supported container, write a SMART_BLOB to a second tempfile and
  feed *that* path to `clean_file`. The resulting `XetFileInfo`
  describes the SMART_BLOB.
- **Smudge** (`handle_smudge` → `finish_smudge`): we already write
  reconstructed bytes to a `NamedTempFile` before pkt-lining them
  back to Git. Insert the inverse transform between writing the
  tempfile and reading it back — peek the first 4 bytes, and if
  they're `XSD1`, stream-recompress to a second tempfile and emit
  those bytes instead.

```
clean (stage):
  git --pkt-line clean--> do_clean (spool input -> tmp)
                                |  detect format, transform tmp -> tmp'
                                v
                            FileUploadSession (chunks tmp' bytes
                              -> xorbs/shards on baleforgit-server)
                                |
                                v
                            pointer JSON
                              (hash=merkle of tmp', sha256/size of tmp')

smudge (checkout):
  pointer JSON --pkt-line smudge--> handle_smudge (reconstruct to tmp)
                                         |  peek first 4 bytes
                                         |  if XSD1: tmp -> tmp' via
                                         |  inverse transform, then
                                         |  verify SHA-256
                                         v
                                       git (working copy = original bytes)
```

Critical invariant: the bytes written into the working copy on smudge
MUST be **bit-identical** to the bytes Git cleaned. Git itself does
not hash-check across the filter (it identifies the blob by the SHA-1
of the *pointer*, not the original content), so the SMART_BLOB header
carries the original file's SHA-256 and the smudge path verifies after
the inverse transform. That self-check is the only thing standing
between us and silent file corruption.

## SMART_BLOB on-storage format

What the chunker actually sees (and what the smudge path inverts):

```
offset  size      field
------  --------  ------------------------------------------------------
0       4         MAGIC = "XSD1" (Xet Smart Dedup, version 1)
4       1         FLAGS  bit 0: container = gzip
                          bit 1: strategy = deterministic-recompress (0)
                                          or delta-recompress (1)
                          bits 2-7: reserved, MUST be zero
5       32        ORIG_SHA256  sha256 of original file (verified on smudge)
37      varint    ORIG_SIZE    original file size in bytes
...     varint    RECIPE_LEN
...     RECIPE    recipe bytes (see below)
...     varint    INFLATED_LEN
...     INFLATED  the inflated body — this is what dedups across versions
```

The recipe for gzip + deterministic-recompress:

```
- header_len: varint
- header[header_len]: the original gzip header verbatim (FLG, MTIME, OS,
  optional FNAME/FCOMMENT/FEXTRA) — not recoverable from inflated bytes
- trailer[8]: the original 8-byte gzip trailer (CRC32 + ISIZE) —
  preserved verbatim so we don't recompute and accidentally differ
- deflate_params: 1 byte level (0-9) || 1 byte strategy || 1 byte
  window_bits || 1 byte mem_level — values detected during the
  self-test below
```

For delta-recompress, the recipe is the same plus a trailing `bsdiff`
patch over the canonical re-deflated stream. The flag bit picks which
applies. The inflated body is identical in both — that's the part CDC
chunks, and it's stable across versions of the source app modulo
genuine content changes.

## Reversibility — the critical bit

Three strategies, in order of complexity. Use the cheapest that passes
its self-test for a given file.

### Strategy 0: deterministic recompress

On clean:

1. Inflate the original gzip stream → INFLATED.
2. Re-deflate INFLATED with a sweep of zlib parameter combos (level
   1..9 × strategy DEFAULT/FILTERED/HUFFMAN_ONLY × window_bits 9..15).
3. For each combo, splice on the original header + trailer. If any
   combo produces bytes equal to the original file, record those
   params in the recipe and store SMART_BLOB with flag = 0.
4. If no combo matches, fall through to Strategy 1.

The parameter sweep is at most ~9 × 3 × 7 = 189 deflate runs of one
file. For 50 MB inputs that is real CPU; gate it behind a size cap
(say, ≤ 200 MB) and cache the winning combo per file extension to
short-circuit subsequent saves from the same source app.

Cross-zlib-version reproducibility is the wildcard. zlib's bit-exact
output has historically been stable but is not contractually
guaranteed. The self-test catches drift immediately — if a future zlib
release changes its output, Strategy 0 just stops claiming hits and the
pipeline falls back. **No silent corruption.**

### Strategy 1: delta-recompress

If Strategy 0 fails:

1. Pick a single canonical (level=6, strategy=DEFAULT, window_bits=15)
   re-deflation. Splice header + trailer.
2. Compute `bsdiff` (or `vcdiff`) patch from canonical bytes →
   original bytes.
3. Verify: apply patch, compare to original. MUST be byte-equal or we
   bail to Strategy 2.
4. Store SMART_BLOB with flag = 1, recipe carries the patch.

The patch is small when the source app's deflater is close to canonical
(typical for Blender, FreeCAD, Krita on a stable release); it grows
when the deflater is exotic. Per-file size cap: if the patch exceeds
~5% of INFLATED_LEN, the dedup math probably stops being worth it and
we fall back to Strategy 2.

### Strategy 2: pass through

Feed the original bytes to `clean_file` unchanged. No SMART_BLOB, no
transform, no dedup benefit, no risk. Smudge sees no `XSD1` magic on
the reconstructed tempfile and pkt-lines the bytes straight through.

This MUST always be a safe fallback. The whole design is "try to be
clever, fall back to dumb when clever can't prove correctness."

## Self-test (the same test, applied at every strategy boundary)

After producing what we think the SMART_BLOB inverse will yield, run
the actual inverse code on the SMART_BLOB and compare the output bytes
to the original file. SHA-256 of both. If they don't match, the
strategy didn't work — bail to the next strategy. The self-test is
what stops silent file corruption; it runs **unconditionally** on
every clean that takes a non-passthrough path. The cost is one extra
read of the original file plus one inverse-transform — cheap compared
to the deflate sweep, and worth it.

## Format detection / pass-through rules

- Sniff only fixed-position magic bytes. Do not trust file extensions.
- Containers in scope for v1: **gzip only.** zstd, xz, bzip2 are
  obvious follow-ups but the gzip win covers `.blend`, `.svgz`,
  `.fcstd`, `.xcf`, and many one-off application formats.
- Hard skip list: anything < 1 KiB (overhead beats benefit), anything
  whose first 64 KiB doesn't inflate cleanly (truncated/concatenated
  gzip streams), and any file already starting with the SMART_BLOB
  magic (defense in depth against double-wrapping if a file with
  literal "XSD1" prefix ever shows up).
- Multi-member gzip streams (`cat a.gz b.gz`): detectable by trailing
  bytes after the first member. Punt — pass through. Real-world hits
  on this are vanishingly rare and the recipe layout doesn't model it.
- Zip-based containers (`.docx`, `.odt`, `.kra` is actually zip not
  gzip, etc.) are out of scope for v1. They need per-entry transform
  to be useful, which is a much bigger design.

## Smudge-path changes (`handle_smudge`)

Today's cold path lands reconstructed bytes in a `NamedTempFile` and
then `finish_smudge` pkt-lines the file out to Git. Add a pre-emit
step:

1. Open the tempfile and read its first 4 bytes.
2. If bytes != `XSD1`, behave as today — pkt-line the tempfile
   contents straight through. Status quo, no overhead beyond a 4-byte
   read.
3. If bytes == `XSD1`, parse the SMART_BLOB header in a streaming
   way (header + recipe are small, fit in one read), then
   stream-inflate the INFLATED section through a deflater configured
   per the recipe, prepending the saved gzip header and appending the
   saved trailer. Pipe the resulting bytes to a second tempfile.
4. Compute SHA-256 of the second tempfile and compare to ORIG_SHA256
   from the header. If mismatch → report `status=error` for this
   entry via `report_request_error`. The clean-time self-test means
   this should be impossible, so a mismatch here is a real bug, not
   an expected failure mode.
5. pkt-line the second tempfile out via the same loop
   `finish_smudge` uses today.

The hot path (cache-only reconstruction via
`try_reconstruct_from_cache`) writes into the same tempfile, so the
sniff happens after it too — no extra plumbing needed.

The smudge path needs no parameter sweep — the recipe tells it
exactly which deflate params to use.

## Knock-on effects on git-bale / Xet invariants

- **Pointer file metadata describes the SMART_BLOB, not the original
  file.** `XetFileInfo.hash` is the merkle hash of the chunked
  SMART_BLOB; `file_size` and `sha256` describe the SMART_BLOB bytes.
  The pointer no longer carries the original file's SHA-256 in its
  `sha256` field for transformed entries — that lives inside the
  SMART_BLOB header (ORIG_SHA256). External tools that read the
  pointer JSON expecting the working-copy SHA-256 will get the
  SMART_BLOB's SHA-256 instead.
- **Pointer parsing unchanged.** The pointer JSON's wire format
  (`crates/git-bale/src/pointer.rs`) doesn't change. No new fields,
  no schema bump.
- **Chunk cache + manifest cache unchanged.** Both key on the
  pointer's merkle hash, which is now the SMART_BLOB's merkle —
  same code path, same on-disk layout (`~/.cache/bale/chunks`,
  `.git/bale/manifests/`).
- **Cross-repo dedup.** A SMART_BLOB and its un-transformed twin
  share no chunks (different first bytes, different inflated
  framing). Don't expect cross-pollination between repos that opt in
  vs. opt out. Within the smart-dedup neighborhood, near-identical
  inputs share most chunks via their INFLATED bodies — that's the
  whole point.
- **baleforgit-server unchanged.** The server sees only chunks; smart-dedup
  is purely client-side. The upload-time chunk integrity check
  (`POST /v1/xorbs/...`, see `docs/ARCHITECTURE.md`) still applies,
  but operates on SMART_BLOB chunks, not original-file chunks.

## Opt-in / rollout

Per-repo opt-in via a git config key, e.g. `dfs.smartDedup = gzip`
(parallel to the existing `bale.serverUrl` / `bale.token` /
`bale.cacheDir` set read by `crates/git-bale/src/config.rs`).
`filter-process` would read it on startup through the same
`RawConfig` path; if unset, the filter behaves identically to today.
This lets a user enable smart dedup for one repo storing `.blend`
files without affecting any other Bale workflow on the same machine.

`git-bale install` and `git-bale track` need no changes — they
configure the filter; the filter reads `dfs.smartDedup` per
invocation.

## Open questions

1. **Where does the deflate-param cache live?** A per-user file under
   `~/.cache/bale/smart/deflate-params.json` (alongside the existing
   chunk cache) keyed on file extension + first-N-bytes-of-header
   would avoid re-sweeping for repeated saves from the same app.
   Cache poisoning is a real concern — the self-test must still run
   unconditionally, the cache only shortcuts the *sweep order*.
2. **How do we test this end-to-end?** Need a fixture corpus of
   `.blend` files saved by multiple Blender versions, plus a
   round-trip test that asserts bit-exact reconstruction. Pulling real
   Blender into CI is heavy — probably commit a small set of
   pre-generated fixtures and add an `m13_smart_dedup.rs` integration
   test that drives `git add` / `git checkout` against a
   smart-dedup-enabled repo and asserts (a) staged blob is a JSON
   pointer, (b) checkout bytes equal original bytes, (c) two
   near-identical inputs share most chunks at the xorb level.
3. **Streaming vs buffering.** A 2 GB `.blend` would need to be
   inflated to disk before the parameter sweep can run on it.
   Tempfile in the same filesystem as the input (same approach
   `do_clean` already takes for spooling) is the obvious answer but
   adds 2× disk usage during clean. Acceptable for v1; revisit if it
   becomes a complaint.
4. **What's the actual measured dedup win on a typical Blender
   workflow?** Worth a quick experiment with two saves of the same
   scene before committing to the design. If the inflated bodies
   still only share ~50% of chunks (because Blender shuffles internal
   block order on save), the whole design needs a rethink — possibly
   a format-aware chunker that knows Blender's block structure, which
   is a much bigger lift.
5. **Should `dfs.smartDedup` ever be auto-set?** E.g. flipped on
   automatically when `git-bale track '*.blend'` runs. Probably no —
   explicit opt-in is safer, especially while the transform is
   experimental.
