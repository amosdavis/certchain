package annotation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CertBundle is the public-material view of a certchain record returned
// by the certd query API for a given Common Name.
type CertBundle struct {
	// CN is the canonical Common Name of the issued certificate.
	CN string
	// CertPEM holds the end-entity certificate in PEM form.
	CertPEM []byte
	// ChainPEM holds any intermediate/root PEM blocks certd is willing
	// to share (may be empty if certd only returns the leaf).
	ChainPEM []byte
	// NotAfter is the certificate's expiry; zero if unknown.
	NotAfter time.Time
}

// CertFetcher retrieves certificate material from certd (or an
// equivalent source) for a given Common Name. It is factored behind an
// interface so the reconciler can be exercised with an in-memory fake in
// unit tests without standing up an HTTP server (CM-27: the real
// implementation must never block the reconcile hot path on a dead
// backend without surfacing the error).
type CertFetcher interface {
	Fetch(ctx context.Context, cn string) (*CertBundle, error)
}

// ErrCertNotFound is returned by CertFetcher implementations when the
// backend reports that no certificate currently exists for the CN. The
// reconciler distinguishes this from transport errors so it can emit a
// meaningful "waiting for issuance" Event instead of a generic error.
var ErrCertNotFound = errors.New("certchain/annotation: no cert for CN")

// HTTPFetcher is the production CertFetcher backed by certd's HTTP
// query API. It is Bearer-authenticated (CM-28) using a token read from
// disk via certd's --query-token-file convention.
type HTTPFetcher struct {
	// BaseURL is the certd query API root, e.g. "http://certd:9879".
	BaseURL string
	// Token is the Bearer token certd requires under its queryAuth
	// middleware. May be empty in dev; in production must be non-empty.
	Token string
	// Client is the HTTP client used for all calls. A sensible default
	// with a short timeout is applied when nil.
	Client *http.Client
}

// NewHTTPFetcher builds an HTTPFetcher with a conservative default
// timeout so reconciliation cannot hang indefinitely on a stuck backend.
func NewHTTPFetcher(baseURL, token string) *HTTPFetcher {
	return &HTTPFetcher{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		Client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Fetch issues GET <base>/cert?cn=<cn> and translates the response into
// a CertBundle. Transport errors, non-2xx responses, and 404s are mapped
// to distinct errors so the caller can distinguish "backend dead" (retry
// + increment errors counter) from "not yet issued" (retry quietly).
func (h *HTTPFetcher) Fetch(ctx context.Context, cn string) (*CertBundle, error) {
	if h.BaseURL == "" {
		return nil, errors.New("certchain/annotation: HTTPFetcher.BaseURL is empty")
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	url := fmt.Sprintf("%s/cert?cn=%s", h.BaseURL, cn)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if h.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certd unreachable: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrCertNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("certd status %d", resp.StatusCode)
	}

	var payload struct {
		CN       string `json:"cn"`
		NotAfter int64  `json:"not_after"`
		CertPEM  string `json:"cert_pem"`
		ChainPEM string `json:"chain_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode certd response: %w", err)
	}
	if payload.CN == "" {
		payload.CN = cn
	}
	bundle := &CertBundle{
		CN:       payload.CN,
		CertPEM:  []byte(payload.CertPEM),
		ChainPEM: []byte(payload.ChainPEM),
	}
	if payload.NotAfter > 0 {
		bundle.NotAfter = time.Unix(payload.NotAfter, 0)
	}
	return bundle, nil
}
