# Smart dedup wrapper (sketch)

> **Status: unimplemented design sketch.** None of this exists in the code:
> no `XSD1` format, no `bale.smartDedup` key, no transform in the filter.
> Function and file names below point at where it *would* hook in, as of
> the current `filter_process.rs`. Open questions at the bottom.

An opt-in transform in `git-bale filter-process` that decompresses
well-known containers (gzip first; zstd/xz later) **before** CDC
chunking, so small edits to compressed files like `.blend`, `.fcstd`,
`.xcf` dedup across versions.

## Why

`gearhash` CDC picks boundaries from byte content. A 1-byte change in
the *uncompressed* source yields a wholly different *compressed* stream
(deflate is locally chaotic), so almost nothing dedups. Decompressing
first restores the signal: the inflated bodies of two near-identical
`.blend` saves share long runs.

The server is payload-agnostic beyond the upload-time chunk check (it
decompresses xorb frames on `POST /v1/xorbs/...` only to verify hashes;
see [`ARCHITECTURE.md`](ARCHITECTURE.md) "Tricky bits"), so this layer
is **client-side only**, entirely inside `git-bale`.

## Insertion points

Both directions live in `crates/git-bale/src/filter_process.rs`, the
`filter.bale.process` long-running filter:

- **Clean** (`do_clean` → `handle_clean_in_memory` / `handle_clean`):
  input is drained from pkt-line into memory, spilling to a
  `NamedTempFile` past `MAX_INLINE_CLEAN` (see
  [`ARCHITECTURE.md`](ARCHITECTURE.md#pointer-cache-clean-short-circuit)).
  After the clean-cache check (which must keep fingerprinting the
  *original* bytes) and before `FileUploadSession::new`: if the payload
  is a supported container, build a SMART_BLOB and clean *that*. The
  resulting `XetFileInfo` describes the SMART_BLOB.
- **Smudge** (`handle_smudge` → `finish_smudge`): every path (hot
  `try_smudge_from_cache`, lukewarm/local `try_smudge_from_store`, cold
  `download_cold_to`) reconstructs into one `NamedTempFile`, which
  `content_matches` verifies against the pointer. Insert the inverse
  after that check and before the clean-cache seed and `finish_smudge`:
  if the first 4 bytes are `XSD1`, stream-recompress to a second
  tempfile and emit that instead.

```
clean (stage):
  git --pkt-line clean--> do_clean (spool input -> tmp)
                                |  detect format, transform tmp -> tmp'
                                v
                            FileUploadSession (chunks tmp' bytes
                              -> xorbs/shards in staging or the local
                                 store; push-pending uploads later)
                                |
                                v
                            pointer JSON
                              (hash=merkle of tmp', sha256/size of tmp')

smudge (checkout):
  pointer JSON --pkt-line smudge--> handle_smudge (reconstruct to tmp,
                                         |  verify pointer sha256)
                                         |  peek first 4 bytes
                                         |  if XSD1: tmp -> tmp' via
                                         |  inverse transform, then
                                         |  verify SHA-256
                                         v
                                       git (working copy = original bytes)
```

Critical invariant: smudged bytes MUST be **bit-identical** to the bytes
Git cleaned. Git doesn't hash-check across the filter (it only knows the
*pointer's* blob id), and today's smudge check only proves the SMART_BLOB
matches the pointer. So the SMART_BLOB header carries the original
file's SHA-256, verified after the inverse transform; that is the only
guard against silent corruption from the transform itself.

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

Three strategies by complexity; use the cheapest that passes its
self-test.

### Strategy 0: deterministic recompress

On clean:

1. Inflate the original gzip stream → INFLATED.
2. Re-deflate INFLATED with a sweep of zlib parameter combos (level
   1..9 × strategy DEFAULT/FILTERED/HUFFMAN_ONLY × window_bits 9..15).
3. For each combo, splice on the original header + trailer. If any
   combo produces bytes equal to the original file, record those
   params in the recipe and store SMART_BLOB with flag = 0.
4. If no combo matches, fall through to Strategy 1.

The sweep is at most 9 × 3 × 7 = 189 deflate runs per file, real CPU at
50 MB; gate it behind a size cap (say ≤ 200 MB) and cache the winning
combo per extension for later saves from the same app.

Cross-zlib-version reproducibility is the wildcard: bit-exact output has
been stable historically but isn't guaranteed. The self-test catches
drift: Strategy 0 stops hitting and the pipeline falls back. **No silent
corruption.**

### Strategy 1: delta-recompress

If Strategy 0 fails:

1. Pick a single canonical (level=6, strategy=DEFAULT, window_bits=15)
   re-deflation. Splice header + trailer.
2. Compute `bsdiff` (or `vcdiff`) patch from canonical bytes →
   original bytes.
3. Verify: apply patch, compare to original. MUST be byte-equal or we
   bail to Strategy 2.
4. Store SMART_BLOB with flag = 1, recipe carries the patch.

The patch is small when the app's deflater is near canonical (typical
for Blender, FreeCAD, Krita stable releases) and grows when it's exotic.
If it exceeds ~5% of INFLATED_LEN, the dedup likely isn't worth it: fall
back to Strategy 2.

### Strategy 2: pass through

Clean the original bytes unchanged: no SMART_BLOB, no dedup benefit, no
risk. Smudge sees no `XSD1` magic and emits the bytes as today. This MUST
always be a safe fallback: be clever only when clever can prove
correctness.

## Self-test (the same test, applied at every strategy boundary)

Run the real smudge-side inverse on the candidate SMART_BLOB and compare
SHA-256 of the output with the original; on mismatch, bail to the next
strategy. It runs **unconditionally** on every non-passthrough clean.
Cost: one inverse transform plus one extra read of the original, cheap
next to the deflate sweep.

## Format detection / pass-through rules

- Sniff only fixed-position magic bytes. Do not trust file extensions.
- Containers in scope for v1: **gzip only.** zstd, xz, bzip2 are
  obvious follow-ups but the gzip win covers `.blend`, `.svgz`,
  `.fcstd`, `.xcf`, and many one-off application formats.
- Hard skip: anything < 1 KiB (overhead beats benefit), anything whose
  first 64 KiB doesn't inflate cleanly, and anything already starting
  with `XSD1` (no double-wrapping; push-pending and `prune` re-clean
  reconstructed SMART_BLOB bytes and must store them as-is).
- Multi-member gzip (`cat a.gz b.gz`, detectable by bytes after the first
  member): pass through. Rare, and the recipe doesn't model it.
- Zip-based containers (`.docx`, `.odt`, `.kra`) are out of scope for v1:
  they need a per-entry transform, a much bigger design.

## Smudge-path changes (`handle_smudge`)

Every reconstruction path lands in one `NamedTempFile`, verified by
`content_matches` before `finish_smudge` pkt-lines it out, so one
pre-emit step covers them all:

1. Read the tempfile's first 4 bytes.
2. Not `XSD1`: behave as today (cost: a 4-byte read).
3. `XSD1`: parse the header and recipe (small, one read), then
   stream the INFLATED section through a deflater configured per the
   recipe, between the saved gzip header and trailer, into a second
   tempfile.
4. Compare its SHA-256 with ORIG_SHA256. On mismatch, return an error
   so the dispatcher reports `status=error` via `report_request_error`.
   The clean-time self-test makes this a real bug, not an expected
   failure.
5. Seed the clean-cache from, and `finish_smudge` emit, the second
   tempfile, so the cache fingerprints worktree bytes.

No parameter sweep on smudge: the recipe names the deflate params. The
mount reader (`mount/reader.rs`) reconstructs pointers independently and
needs the same inverse.

## Knock-on effects on git-bale / Xet invariants

- **Pointer metadata describes the SMART_BLOB.** `hash`, `file_size`
  and `sha256` are the SMART_BLOB's; the original's SHA-256 lives only
  in its header (ORIG_SHA256). External tools expecting the working-copy
  SHA-256 in the pointer will get the SMART_BLOB's.
- **Pointer format unchanged** (`crates/git-bale/src/pointer.rs`): no
  new fields, no schema bump.
- **Chunk and manifest caches unchanged.** Both key on the pointer's
  merkle hash, now the SMART_BLOB's (chunk cache defaults to
  `~/.cache/bale/chunks`; manifests in `.git/bale/manifests/`).
- **Clean-cache must stay on worktree bytes.** Its xxh3 fingerprints are
  compared against what git feeds clean; fingerprinting the SMART_BLOB
  would never hit.
- **Cross-repo dedup.** A SMART_BLOB and its untransformed twin share no
  chunks, so repos that opt in don't dedup against those that don't.
  Within opted-in repos, near-identical inputs share most chunks via
  their INFLATED bodies, which is the point.
- **Server unchanged.** It sees only chunks; the upload-time chunk check
  applies to SMART_BLOB chunks.

## Opt-in / rollout

Per-repo opt-in via a git config key, e.g. `bale.smartDedup = gzip`,
read into `RawConfig` (`crates/git-bale/src/config.rs`) alongside
`bale.cacheDir`, `bale.local`, etc. Unset, the filter behaves as today.
`git-bale install` and `git-bale track` need no changes.

## Open questions

1. **Where does the deflate-param cache live?** E.g.
   `~/.cache/bale/smart/deflate-params.json`, keyed on extension +
   leading header bytes. Poisoning is a concern: the cache may only
   reorder the sweep; the self-test still runs unconditionally.
2. **End-to-end testing.** Commit a small corpus of pre-generated
   `.blend` fixtures from several Blender versions (real Blender in CI is
   heavy) and add an e2e phase under `tests/e2e/` (there are no Rust
   tests) that runs `git add` / `git checkout` in an opted-in repo and
   asserts (a) the staged blob is a pointer, (b) checkout is bit-exact,
   (c) two near-identical inputs share most chunks.
3. **Streaming vs buffering.** A 2 GB `.blend` must be inflated to disk
   before the sweep, in a tempfile as `do_clean` already does for spilled
   payloads. That doubles disk use during clean; acceptable for v1.
4. **Measured win on a real Blender workflow?** Try two saves of one
   scene before committing. If the inflated bodies share only ~50% of
   chunks (Blender reorders blocks on save), rethink, possibly toward a
   format-aware chunker, a much bigger lift.
5. **Auto-set `bale.smartDedup`** (e.g. on `git-bale track '*.blend'`)?
   Probably not; explicit opt-in is safer while experimental.
