package main

// LFS download path.
//
// git-lfs's basic transfer protocol drives downloads via a plain HTTPS GET to
// the `download` action URL, keyed by the file's sha256 OID. The git-xet
// custom-transfer agent only implements uploads, so we serve downloads here
// instead and let git-lfs treat us as a stock LFS server.
//
// Per-request flow (matches the "basic" transfer the batch response now
// advertises for downloads):
//
//   1. git-lfs GETs /repos/{owner}/{name}/objects/{oid} with the same
//      Authorization header used for the batch call.
//   2. We mint a Xet *read* token from xet-server (PAT verification happens
//      upstream in xet-server's RepoAuthz impl).
//   3. We ask xet-server for the file's reconstruction keyed by sha256:
//      GET /v1/reconstructions/by-sha256/{oid}.
//   4. For each term, we GET the signed xorb byte range (which now correctly
//      covers chunk frames on-disk after the xorb_frames fix), parse 8-byte
//      chunk headers in flight, decompress per scheme (None/LZ4-frame/BG4-LZ4),
//      and copy the raw bytes straight into the response writer.
//
// Streaming is end-to-end: the only buffering is per-chunk (≤16 MiB by xorb
// spec, in practice ~64 KiB) when scheme 2 forces us to fully decode before
// regrouping. Schemes 0 and 1 stream byte-for-byte.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pierrec/lz4/v4"
)

// Reconstruction response shapes — match xet-server's QueryReconstructionResponse.
type reconstructionResponse struct {
	OffsetIntoFirstRange uint64                         `json:"offset_into_first_range"`
	Terms                []reconstructionTerm           `json:"terms"`
	FetchInfo            map[string][]reconstructionURL `json:"fetch_info"`
}

type reconstructionTerm struct {
	Hash           string    `json:"hash"`
	UnpackedLength uint64    `json:"unpacked_length"`
	Range          rangeJSON `json:"range"`
}

type reconstructionURL struct {
	Range    rangeJSON `json:"range"`
	URL      string    `json:"url"`
	URLRange rangeJSON `json:"url_range"` // INCLUSIVE end
}

type rangeJSON struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

const xorbChunkHeaderLen = 8

func (a *adapter) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	owner, name, oid, ok := parseDownloadPath(r.URL.Path)
	if !ok {
		http.Error(w, "expected /repos/{owner}/{name}/objects/{oid}", http.StatusNotFound)
		return
	}
	if len(oid) != 64 {
		http.Error(w, "oid must be a 64-char sha256 hex", http.StatusBadRequest)
		return
	}
	if _, err := hex.DecodeString(oid); err != nil {
		http.Error(w, "oid is not valid hex", http.StatusBadRequest)
		return
	}

	bearer := normalizeToBearer(r.Header.Get("Authorization"))

	tok, status, err := a.mintXetToken(owner, name, "read", bearer)
	if err != nil {
		http.Error(w, "mint xet token: "+err.Error(), status)
		return
	}

	recon, status, err := a.fetchReconstruction(tok.CasURL, tok.AccessToken, oid)
	if err != nil {
		http.Error(w, "reconstruction: "+err.Error(), status)
		return
	}

	// HEAD requests just want the size; LFS can use the file's total bytes,
	// which we compute from the term unpacked lengths.
	if r.Method == http.MethodHead {
		var total uint64
		for _, t := range recon.Terms {
			total += t.UnpackedLength
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", total))
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	// Iterate terms in order. The first term may be partially skipped if the
	// server set offset_into_first_range > 0, but our by-sha256 endpoint always
	// sets it to 0 (whole-file reconstruction). Honor it anyway.
	skip := recon.OffsetIntoFirstRange
	for ti, term := range recon.Terms {
		entries, ok := recon.FetchInfo[term.Hash]
		if !ok || len(entries) == 0 {
			a.logAbort(w, ti, fmt.Errorf("no fetch_info for term %s", term.Hash))
			return
		}
		entry := findEncompassing(entries, term.Range.Start, term.Range.End)
		if entry == nil {
			a.logAbort(w, ti, fmt.Errorf("no encompassing fetch_info for term %s", term.Hash))
			return
		}

		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, entry.URL, nil)
		if err != nil {
			a.logAbort(w, ti, fmt.Errorf("build xorb GET: %w", err))
			return
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", entry.URLRange.Start, entry.URLRange.End))
		resp, err := a.client.Do(req)
		if err != nil {
			a.logAbort(w, ti, fmt.Errorf("xorb GET: %w", err))
			return
		}
		if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			a.logAbort(w, ti, fmt.Errorf("xorb GET %s -> %d: %s", entry.URL, resp.StatusCode, body))
			return
		}

		if err := streamFrames(resp.Body, w, &skip); err != nil {
			resp.Body.Close()
			a.logAbort(w, ti, fmt.Errorf("decode frames: %w", err))
			return
		}
		resp.Body.Close()
	}
}

func (a *adapter) fetchReconstruction(casURL, token, oid string) (*reconstructionResponse, int, error) {
	url := fmt.Sprintf("%s/v1/reconstructions/by-sha256/%s", strings.TrimRight(casURL, "/"), oid)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, resp.StatusCode, fmt.Errorf("upstream %d: %s", resp.StatusCode, body)
	}
	var out reconstructionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("decode: %w", err)
	}
	return &out, http.StatusOK, nil
}

// findEncompassing returns the fetch_info entry whose chunk-index range fully
// contains [termStart, termEnd). xet-server today emits exactly one entry per
// term, but per protocol multiple are allowed.
func findEncompassing(entries []reconstructionURL, termStart, termEnd uint64) *reconstructionURL {
	for i := range entries {
		e := &entries[i]
		if e.Range.Start <= termStart && e.Range.End >= termEnd {
			return e
		}
	}
	return nil
}

// streamFrames reads consecutive chunk frames from `r` (one term's worth of
// xorb bytes), decompresses each, and writes the uncompressed payload to `w`.
// `*skip` is decremented as bytes are consumed; bytes inside the skip window
// are dropped, the rest are written.
func streamFrames(r io.Reader, w io.Writer, skip *uint64) error {
	header := make([]byte, xorbChunkHeaderLen)
	for {
		_, err := io.ReadFull(r, header)
		if errors.Is(err, io.EOF) {
			return nil // clean end of this term's byte range
		}
		if err != nil {
			return fmt.Errorf("read chunk header: %w", err)
		}
		version := header[0]
		if version != 0 {
			return fmt.Errorf("unsupported chunk version %d", version)
		}
		compressedLen := uint32(header[1]) | uint32(header[2])<<8 | uint32(header[3])<<16
		scheme := header[4]
		uncompressedLen := uint32(header[5]) | uint32(header[6])<<8 | uint32(header[7])<<16
		// Wrap the payload in a LimitReader so the decoder can't accidentally
		// consume bytes from the NEXT frame, AND so we can drain whatever the
		// decoder left behind (LZ4 frame readers may stop at the in-stream
		// EndMark before consuming the full `compressedLen`).
		payload := io.LimitReader(r, int64(compressedLen))

		switch scheme {
		case 0: // raw
			if err := emitRawChunk(w, payload, uncompressedLen, skip); err != nil {
				return err
			}
		case 1: // LZ4 frame
			if err := emitLZ4Chunk(w, payload, uncompressedLen, skip); err != nil {
				return err
			}
		case 2: // BG4-LZ4 frame (group-of-4 deinterleave + LZ4)
			if err := emitBG4Chunk(w, payload, uncompressedLen, skip); err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid compression scheme %d", scheme)
		}

		// Guarantee `r` is advanced exactly `compressedLen` past the header,
		// so the next ReadFull lands on the next frame's header.
		if _, err := io.Copy(io.Discard, payload); err != nil {
			return fmt.Errorf("drain frame tail: %w", err)
		}
	}
}

func emitRawChunk(w io.Writer, r io.Reader, n uint32, skip *uint64) error {
	return streamWithSkip(w, r, int64(n), skip)
}

func emitLZ4Chunk(w io.Writer, r io.Reader, n uint32, skip *uint64) error {
	dec := lz4.NewReader(r)
	return streamWithSkip(w, dec, int64(n), skip)
}

func emitBG4Chunk(w io.Writer, r io.Reader, n uint32, skip *uint64) error {
	// BG4 needs the full uncompressed payload before regrouping. Chunks are
	// bounded by xet-core to ≤16 MiB by the u24 header field; typical is ~64 KiB.
	dec := lz4.NewReader(r)
	buf := make([]byte, n)
	if _, err := io.ReadFull(dec, buf); err != nil {
		return fmt.Errorf("lz4 decode bg4 payload: %w", err)
	}
	regrouped := bg4Regroup(buf)
	return writeWithSkip(w, regrouped, skip)
}

// streamWithSkip copies up to `total` decoded bytes from r to w, dropping the
// first `*skip` bytes if any.
func streamWithSkip(w io.Writer, r io.Reader, total int64, skip *uint64) error {
	if *skip >= uint64(total) {
		// Whole chunk lands inside the skip window — just drain it.
		if _, err := io.CopyN(io.Discard, r, total); err != nil {
			return fmt.Errorf("drain skipped chunk: %w", err)
		}
		*skip -= uint64(total)
		return nil
	}
	if *skip > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(*skip)); err != nil {
			return fmt.Errorf("drain skip prefix: %w", err)
		}
		total -= int64(*skip)
		*skip = 0
	}
	if _, err := io.CopyN(w, r, total); err != nil {
		return fmt.Errorf("copy chunk payload: %w", err)
	}
	return nil
}

func writeWithSkip(w io.Writer, buf []byte, skip *uint64) error {
	if *skip >= uint64(len(buf)) {
		*skip -= uint64(len(buf))
		return nil
	}
	start := *skip
	*skip = 0
	if _, err := w.Write(buf[start:]); err != nil {
		return fmt.Errorf("write regrouped chunk: %w", err)
	}
	return nil
}

func (a *adapter) logAbort(w http.ResponseWriter, termIdx int, err error) {
	// We've already sent 200 + the start of the body when failing mid-stream;
	// the LFS client will detect truncation via the recorded object size. Log
	// so an operator can see what went wrong.
	fmt.Printf("download aborted at term %d: %v\n", termIdx, err)
}

// parseDownloadPath matches /repos/{owner}/{name}/objects/{oid}
// (sibling of parseRepoFromPath which matches the /objects/batch endpoint).
func parseDownloadPath(p string) (owner, name, oid string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) != 5 || parts[0] != "repos" || parts[3] != "objects" {
		return "", "", "", false
	}
	return parts[1], parts[2], parts[4], true
}
