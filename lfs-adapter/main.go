// xet-lfs-adapter: a tiny git-lfs Batch API server that bridges incoming
// LFS uploads/downloads to a Xet CAS server using the "xet" custom transfer
// agent (https://github.com/huggingface/xet-core).
//
// Per-request flow:
//
//  1. git-lfs POSTs /repos/{owner}/{name}/objects/batch with an Authorization
//     header carrying a platform credential (a GitLab PAT, a Gitea token, etc.).
//  2. The adapter forwards that same Authorization to xet-server's HF-Hub-
//     compatible token endpoint
//     GET /api/models/{owner}/{name}/xet-{read|write}-token/main
//     to mint a Xet token. xet-server's own authz layer (e.g.
//     xet-server-authz-http) is what actually verifies the credential against
//     the platform — the adapter holds no secrets, knows nothing about users.
//  3. The adapter repackages the {accessToken, exp, casUrl} response into a
//     standard LFS Batch response with transfer="xet" and per-object
//     action.header carrying X-Xet-Cas-Url, X-Xet-Access-Token, and
//     X-Xet-Token-Expiration. git-lfs sees transfer="xet" and dispatches to
//     the git-xet binary, which reads those headers and uploads/downloads
//     bytes directly to/from xet-server.
//
// This is intended as a reference shape for a real GitLab/Gitea integration:
// it's small enough to read end-to-end, written in Go so the same engineers
// who already maintain those LFS servers can adapt it without learning Rust.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// LFS batch v1 request/response shapes — see
// https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md
type batchRequest struct {
	Operation string             `json:"operation"`
	Transfers []string           `json:"transfers,omitempty"`
	Ref       *batchRef          `json:"ref,omitempty"`
	Objects   []batchRequestItem `json:"objects"`
}

type batchRef struct {
	Name string `json:"name"`
}

type batchRequestItem struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

type batchResponse struct {
	Transfer string              `json:"transfer"`
	Objects  []batchResponseItem `json:"objects"`
}

type batchResponseItem struct {
	OID           string                    `json:"oid"`
	Size          int64                     `json:"size"`
	Authenticated bool                      `json:"authenticated"`
	Actions       map[string]batchActionDoc `json:"actions"`
}

type batchActionDoc struct {
	Href      string            `json:"href"`
	Header    map[string]string `json:"header,omitempty"`
	ExpiresAt string            `json:"expires_at,omitempty"`
}

// xet-server's /api/.../xet-{rw}-token/main response shape, mirrors
// huggingface_hub's XetTokenResponse.
type xetTokenResponse struct {
	AccessToken     string `json:"accessToken"`
	Exp             int64  `json:"exp"`
	CasURL          string `json:"casUrl"`
	TokenRefreshURL string `json:"tokenRefreshUrl,omitempty"`
}

type adapter struct {
	xetServerBase string
	client        *http.Client
}

func (a *adapter) handleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Path looks like /repos/{owner}/{name}/objects/batch.
	owner, name, ok := parseRepoFromPath(r.URL.Path)
	if !ok {
		http.Error(w, "expected POST /repos/{owner}/{name}/objects/batch", http.StatusNotFound)
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var req batchRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		http.Error(w, "parse batch request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Operation != "upload" && req.Operation != "download" {
		http.Error(w, "unsupported operation: "+req.Operation, http.StatusBadRequest)
		return
	}

	// git-lfs presents URL-embedded credentials as Basic auth; xet-server's
	// HF-Hub-compatible token endpoint only knows Bearer. Translate before
	// forwarding so the chain works regardless of how the LFS client built
	// its Authorization header.
	bearer := normalizeToBearer(r.Header.Get("Authorization"))

	scope := "write"
	if req.Operation == "download" {
		scope = "read"
	}

	tok, status, err := a.mintXetToken(owner, name, scope, bearer)
	if err != nil {
		http.Error(w, "mint xet token: "+err.Error(), status)
		return
	}

	resp := batchResponse{
		Transfer: "xet",
		Objects:  make([]batchResponseItem, 0, len(req.Objects)),
	}
	for _, obj := range req.Objects {
		actionName := "upload"
		if req.Operation == "download" {
			actionName = "download"
		}
		// `href` must be non-empty per the LFS spec; git-xet doesn't care what
		// the value is (it reads X-Xet-Cas-Url from the header), but we set it
		// to the CAS URL for clarity.
		item := batchResponseItem{
			OID:           obj.OID,
			Size:          obj.Size,
			Authenticated: true,
			Actions: map[string]batchActionDoc{
				actionName: {
					Href: tok.CasURL,
					Header: map[string]string{
						"X-Xet-Cas-Url":          tok.CasURL,
						"X-Xet-Access-Token":     tok.AccessToken,
						"X-Xet-Token-Expiration": fmt.Sprintf("%d", tok.Exp),
					},
				},
			},
		}
		resp.Objects = append(resp.Objects, item)
	}

	w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("encode batch response: %v", err)
	}
}

// mintXetToken forwards the caller's credential to xet-server's
// HF-Hub-compatible token endpoint. Returns the minted token, or the upstream
// status to relay back to the LFS client.
func (a *adapter) mintXetToken(owner, name, scope, callerAuth string) (*xetTokenResponse, int, error) {
	url := fmt.Sprintf("%s/api/models/%s/%s/xet-%s-token/main", a.xetServerBase, owner, name, scope)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if callerAuth != "" {
		req.Header.Set("Authorization", callerAuth)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, resp.StatusCode, fmt.Errorf("upstream %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	var out xetTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("decode upstream: %w", err)
	}
	if out.CasURL == "" || out.AccessToken == "" {
		return nil, http.StatusBadGateway, fmt.Errorf("upstream returned empty token or casUrl")
	}
	return &out, http.StatusOK, nil
}

// normalizeToBearer accepts either a "Bearer <token>" header or a "Basic
// base64(user:pass)" header and returns "Bearer <token>" to forward upstream.
// For Basic auth, the *password* part is treated as the bearer token (matches
// how `http://token:<PAT>@host` URLs get translated by git-lfs).
func normalizeToBearer(authHeader string) string {
	if authHeader == "" {
		return ""
	}
	if strings.HasPrefix(authHeader, "Bearer ") {
		return authHeader
	}
	if strings.HasPrefix(authHeader, "Basic ") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
		if err == nil {
			if i := bytes.IndexByte(raw, ':'); i >= 0 {
				return "Bearer " + string(raw[i+1:])
			}
		}
	}
	return ""
}

func parseRepoFromPath(p string) (owner, name string, ok bool) {
	// Expected: /repos/{owner}/{name}/objects/batch
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) != 5 || parts[0] != "repos" || parts[3] != "objects" || parts[4] != "batch" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "bind address")
	xetServer := flag.String("xet-server", "", "base URL of xet-server (required)")
	flag.Parse()
	if *xetServer == "" {
		fmt.Fprintln(flag.CommandLine.Output(), "--xet-server is required")
		flag.Usage()
		return
	}

	a := &adapter{
		xetServerBase: strings.TrimRight(*xetServer, "/"),
		client:        &http.Client{Timeout: 30 * time.Second},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleBatch)

	srv := &http.Server{
		Addr:         *listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Open the listener up-front so we can print the bound port (useful when
	// invoked with :0). Then hand it off to Serve.
	ln, err := newListener(srv.Addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	fmt.Printf("xet-lfs-adapter listening on http://%s\n", ln.Addr())
	log.Fatal(srv.Serve(ln))
}
