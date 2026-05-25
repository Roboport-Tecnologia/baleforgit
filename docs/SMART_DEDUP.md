# Smart dedup wrapper (sketch)

Design notes for an opt-in transform layer that decompresses well-known
container formats (gzip first; zstd/xz later) **before** they reach CDC, so
small source edits to compressed files like `.blend`, `.fcstd`, `.kra`,
`.xcf` actually dedup across versions.

Status: **proposal only**, no code yet. Open questions live at the bottom.

## Why

`gearhash` CDC finds boundaries based on byte content. A 1-byte change in
the *uncompressed* source becomes a wholly different *compressed* byte
stream (deflate is locally chaotic), so the chunker sees no repeated
regions and almost nothing dedups. Decompressing before chunking restores
the dedup signal — the inflated bodies of two near-identical `.blend`
saves share long runs.

The Xet server is intentionally byte-agnostic
(`docs/ARCHITECTURE.md:289` — "the server never compresses or decompresses
chunks"), so this layer is **client-side only**.

## Insertion points

Two distinct insertion points, because the existing data path is
asymmetric:

- **Upload** flows `git → git-lfs → git-xet (custom-transfer agent on the
  user's machine) → xet-server`. The wrapper replaces `git-xet` in the
  user's LFS config and exec's the real `git-xet` underneath.
- **Download** flows `xet-server → lfs-adapter handleDownload → git-lfs
  (basic GET)`. The wrapper lives **inside the adapter**, sniffing
  reconstructed bytes for the SMART_BLOB magic and inverse-transforming
  on the fly.

Calling the new client binary `xet-lfs-smart` and the adapter change
`handleDownload (smart-aware)` throughout this doc.

```
upload:
  git-lfs  --LFS-custom-transfer-->  xet-lfs-smart
                                         |  detect format, transform to tmp
                                         v
                                      git-xet  -- xorbs/shards -->  xet-server

download:
  xet-server  -- reconstruction -->  lfs-adapter
                                         |  sniff SMART_BLOB magic
                                         |  if present: stream-recompress
                                         v
                                      git-lfs (basic GET)
```

Critical invariant: the bytes git-lfs writes to the working copy on
checkout MUST be **bit-identical** to the bytes that were originally
committed, because git-lfs verifies them against the SHA-256 OID in the
pointer file. The whole design hinges on guaranteeing that round-trip.

## Wire flow (LFS custom-transfer relay)

`xet-lfs-smart` speaks the LFS custom-transfer JSON-lines protocol
(<https://github.com/git-lfs/git-lfs/blob/main/docs/custom-transfers.md>)
on its stdio to git-lfs, and the same protocol on a child `git-xet`'s
stdio.

Per upload event from git-lfs:

```
{"event":"upload","oid":"abc...","size":1234567,"path":"/objects/ab/abc..."}
```

1. mmap or stream-read the file at `path`.
2. Sniff first 4 bytes. If not a known compressed-container magic, write
   a one-liner forwarding the **unchanged** event to the child git-xet
   and proxy its responses back. No transform, no risk.
3. If gzip (`1f 8b`):
   a. Stream-inflate to a tempfile `T` in the same filesystem as `path`.
   b. Run the self-test (see "Reversibility" below). If it fails, fall
      back to the pass-through path. **Correctness over cleverness.**
   c. If it passes, write a SMART_BLOB to a second tempfile `T'`.
   d. Forward a synthesized upload event to git-xet with
      `path=T'` and the **same** `oid` and a new `size` matching `T'`.
   e. Relay child's `progress`/`complete` events back to git-lfs with
      OID and original `size` preserved.
4. Clean up tempfiles in a deferred handler keyed on the OID.

The size mismatch in step (d) is the subtle part: git-lfs in the parent
process expects `size` to match what it computed at clean time
(=original file size). git-xet in the child just uploads whatever bytes
are at `path`. The OID is what threads the two together. As long as the
download path restores the original bytes, the SHA-256 check at smudge
time passes.

Per download: untouched — git-lfs uses `transfer:"basic"` and GETs the
adapter directly. The adapter's `handleDownload` (today at
`lfs-adapter/main.go` `dispatch` → `handleDownload`) does the inverse
transform.

## SMART_BLOB on-storage format

What the server actually stores (and what CDC actually chunks):

```
offset  size      field
------  --------  ------------------------------------------------------
0       4         MAGIC = "XSD1" (Xet Smart Dedup, version 1)
4       1         FLAGS  bit 0: container = gzip
                          bit 1: strategy = deterministic-recompress (0)
                                          or delta-recompress (1)
                          bits 2-7: reserved, MUST be zero
5       varint    RECIPE_LEN
...     RECIPE    recipe bytes (see below)
...     varint    INFLATED_LEN
...     INFLATED  the inflated body — this is what dedups across versions
```

The recipe for gzip + deterministic-recompress:

```
- header_len: varint
- header[header_len]: the original gzip header verbatim (FLG, MTIME, OS,
  optional FNAME/FCOMMENT/FEXTRA) — these are not recoverable from
  inflated bytes and must be preserved
- trailer[8]: the original 8-byte gzip trailer (CRC32 + ISIZE) — also
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

On upload:

1. Inflate the original gzip stream → INFLATED.
2. Re-deflate INFLATED with a sweep of zlib parameter combos (level
   1..9 × strategy DEFAULT/FILTERED/HUFFMAN_ONLY × window_bits 9..15).
   For each combo, prepend the original header bytes and append the
   original trailer.
3. If any combo produces bytes equal to the original file, record those
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

Emit the original bytes to git-xet unchanged. No SMART_BLOB, no
transform, no dedup benefit, no risk. Adapter's `handleDownload` sees
no magic and streams the bytes straight through.

This MUST always be a safe fallback. The whole design is "try to be
clever, fall back to dumb when clever can't prove correctness."

## Self-test (the same test, applied at every strategy boundary)

After producing what we think the SMART_BLOB inverse will yield, run
the actual inverse code on the SMART_BLOB and compare the output bytes
to the original file. SHA-256 of both. If they don't match, the
strategy didn't work — bail. The self-test is the only thing standing
between us and silent file corruption; it runs **unconditionally** on
every upload that takes a non-passthrough path. The cost is one extra
read of the original file plus one inverse-transform — cheap compared
to the deflate sweep, and worth it.

## Format detection / pass-through rules

- Sniff only fixed-position magic bytes. Do not trust file extensions.
- Containers in scope for v1: **gzip only.** zstd, xz, bzip2 are
  obvious follow-ups but the gzip win covers `.blend`, `.svgz`,
  `.fcstd`, `.kra`, `.xcf`, OOXML zip-likes (sort of — see below).
- Hard skip list: anything < 1 KiB (overhead beats benefit), anything
  whose first 64 KiB doesn't inflate cleanly (truncated/concatenated
  gzip streams), and any file already starting with the SMART_BLOB
  magic (defense in depth against double-wrapping if a file with
  literal "XSD1" prefix ever shows up).
- Multi-member gzip streams (`cat a.gz b.gz`): detectable by trailing
  bytes after the first member. Punt — pass through. Real-world hits
  on this are vanishingly rare and the recipe layout doesn't model it.
- Zip-based containers (`.docx`, `.odt`, `.kra` actually is zip not
  gzip, etc.) are out of scope for v1. They need per-entry transform
  to be useful, which is a much bigger design.

## Download path (adapter changes)

In `lfs-adapter/main.go` `handleDownload`:

1. Read the first 4 bytes of the reconstructed stream into a peek
   buffer before writing anything to the response.
2. If bytes != `XSD1`, write the peek buffer to the response and
   `io.Copy` the rest. Status quo, no overhead beyond a 4-byte read.
3. If bytes == `XSD1`, parse the SMART_BLOB header in a streaming way
   (header + recipe are small, fit in one read), then stream-inflate
   the INFLATED section through a deflater configured per the recipe,
   prepending the saved gzip header and appending the saved trailer.
   Pipe the resulting bytes to the response writer.
4. Failure to recompress for any reason → 500 with a log line. The
   self-test on upload means this should be impossible, so a 500 here
   is a real bug, not an expected failure mode.

The download path needs no parameter sweep — the recipe tells it
exactly which deflate params to use.

## Knock-on effects on Xet/LFS invariants

- **LFS OID still hashes the original bytes.** The pointer file in the
  git tree carries the SHA-256 of the un-transformed file. Working
  copy after checkout is the un-transformed file. External tools that
  cross-check OIDs (e.g., `git-lfs fsck`) keep working.
- **Xet `file_hash` is computed by git-xet over the SMART_BLOB**, not
  the original bytes. This is fine — Xet file hashes are server-side
  identity, not user-visible. The wrapper never tries to fake a Xet
  file hash.
- **`size` reported back to git-lfs MUST be the original file size**
  even though git-xet uploaded a smaller transformed payload. git-lfs
  uses the size for progress reporting and for the SHA-256 verification
  pre-check on download.
- **Dedup neighborhood**: a SMART_BLOB and its un-transformed twin
  share no chunks (different first bytes, different inflated framing).
  Don't expect cross-pollination between repos that opt in vs. opt
  out. This is fine, just worth knowing.

## Opt-in / rollout

Per-repo opt-in via a git config key, e.g. `xet.smartDedup = gzip`.
`xet-lfs-smart` reads it on startup; if unset, behaves identically to
plain `git-xet`. This lets a single user enable the wrapper for one
repo where they're storing `.blend` files without affecting any other
LFS workflow on the same machine.

## Open questions

1. **Where does the deflate-param cache live?** A per-user file under
   `~/.cache/xet-lfs-smart/deflate-params.json` keyed on file extension
   + first-N-bytes-of-header would avoid re-sweeping for repeated
   saves from the same app. But cache poisoning is a real concern —
   the self-test must still run unconditionally, the cache only
   shortcuts the *sweep order*.
2. **How do we test this end-to-end?** Need a fixture corpus of
   `.blend` files saved by multiple Blender versions, plus a round-trip
   test that asserts bit-exact reconstruction. Pulling real Blender
   into CI is heavy — probably commit a small set of pre-generated
   fixtures instead.
3. **Should the wrapper handle the case where `git-xet` isn't on PATH?**
   Today the LFS adapter integration tests skip with an eprintln. The
   wrapper has the same dependency; either inherit the skip behavior or
   bundle/link xet-core directly. Punting on this until v1 lands.
4. **Streaming vs buffering.** A 2 GB `.blend` would need to be
   inflated to disk before the parameter sweep can run on it. Tempfile
   in the same filesystem as the input is the obvious answer but adds
   2× disk usage during upload. Acceptable for v1; revisit if it
   becomes a complaint.
5. **What's the actual measured dedup win on a typical Blender
   workflow?** Worth a quick experiment with two saves of the same
   scene before committing to the design. If the inflated bodies still
   only share ~50% of chunks (because Blender shuffles internal block
   order on save), the whole design needs a rethink — possibly a
   format-aware chunker that knows Blender's block structure, which is
   a much bigger lift.
