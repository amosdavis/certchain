// Package avx provides an AppViewX REST API client for certchain.
package avx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

// ErrRateLimited is returned by Poll when AVX responds with HTTP 429.
// RetryAfter is the parsed Retry-After delay (0 if header absent or unparseable).
type ErrRateLimited struct {
	RetryAfter time.Duration
}

func (e *ErrRateLimited) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("AVX API rate limited; retry after %v", e.RetryAfter)
	}
	return "AVX API rate limited"
}

// Config holds the AppViewX connection configuration.
type Config struct {
	BaseURL      string
	APIKey       string
	PollInterval time.Duration // default 60 s
	HTTPTimeout  time.Duration // default 10 s
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		PollInterval: 60 * time.Second,
		HTTPTimeout:  10 * time.Second,
	}
}

// Cert is a certificate record returned by the AppViewX API.
type Cert struct {
	AVXCertID  string    `json:"id"`
	CommonName string    `json:"commonName"`
	Status     string    `json:"status"` // ACTIVE, REVOKED, EXPIRED
	NotBefore  time.Time `json:"notBefore"`
	NotAfter   time.Time `json:"notAfter"`
	SANs       []string  `json:"subjectAltNames"`
	Serial     string    `json:"serialNumber"`
}

// Client polls the AppViewX REST API for certificate events.
type Client struct {
	cfg        Config
	httpClient *http.Client
	// publishedIDs tracks avx_cert_ids already on chain to avoid re-publishing.
	publishedIDs map[string]struct{}
}

// NewClient creates a new AppViewX API client.
func NewClient(cfg Config) *Client {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = DefaultConfig().PollInterval
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = DefaultConfig().HTTPTimeout
	}
	return &Client{
		cfg:          cfg,
		httpClient:   &http.Client{Timeout: cfg.HTTPTimeout},
		publishedIDs: make(map[string]struct{}),
	}
}

// MarkPublished records that a cert with the given avx_cert_id is already
// on-chain so that future polls skip it.
func (c *Client) MarkPublished(avxCertID string) {
	c.publishedIDs[avxCertID] = struct{}{}
}

// MarkUnpublished removes the cert with the given avx_cert_id from the
// published set. Used after a renewal so that the replaced cert's AVX ID
// is not processed again as a revocation target.
func (c *Client) MarkUnpublished(avxCertID string) {
	delete(c.publishedIDs, avxCertID)
}

// IsPublished reports whether the cert with the given avx_cert_id is already
// tracked as published.
func (c *Client) IsPublished(avxCertID string) bool {
	_, ok := c.publishedIDs[avxCertID]
	return ok
}

// PollResult holds the output of a single poll cycle.
type PollResult struct {
	NewCerts     []*Cert // certs not yet published to chain
	RevokedCerts []*Cert // certs that AVX now reports as REVOKED or EXPIRED
}

// Poll queries AppViewX for the current certificate list.
// New certs (not in publishedIDs) are returned in NewCerts.
// Certs previously marked published but now REVOKED/EXPIRED are in RevokedCerts.
func (c *Client) Poll(ctx context.Context) (*PollResult, error) {
	certs, err := c.listCerts(ctx)
	if err != nil {
		return nil, err
	}

	result := &PollResult{}
	seen := make(map[string]struct{}, len(certs))

	for _, cert := range certs {
		seen[cert.AVXCertID] = struct{}{}

		switch cert.Status {
		case "ACTIVE":
			if !c.IsPublished(cert.AVXCertID) {
				result.NewCerts = append(result.NewCerts, cert)
			}
		case "REVOKED", "EXPIRED":
			if c.IsPublished(cert.AVXCertID) {
				result.RevokedCerts = append(result.RevokedCerts, cert)
			}
		}
	}

	// Certs previously published but no longer returned by AVX are also revoked.
	for id := range c.publishedIDs {
		if _, ok := seen[id]; !ok {
			result.RevokedCerts = append(result.RevokedCerts, &Cert{
				AVXCertID: id,
				Status:    "REVOKED",
			})
		}
	}

	return result, nil
}

// GetDER downloads the DER-encoded certificate bytes for the given AVX cert ID.
func (c *Client) GetDER(ctx context.Context, avxCertID string) ([]byte, error) {
	url := fmt.Sprintf("%s/avxapi/certificate/%s/download", c.cfg.BaseURL, avxCertID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c.setAuthHeader(req)
	req.Header.Set("Accept", "application/pkix-cert")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AVX DER download status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// PollIntervalWithJitter returns the poll interval with ±10% random jitter.
func (c *Client) PollIntervalWithJitter() time.Duration {
	base := c.cfg.PollInterval
	jitter := time.Duration(rand.Int63n(int64(base/10)*2) - int64(base/10))
	return base + jitter
}

// RenewCert requests AppViewX to renew the certificate with the given AVX cert ID.
// The renewed certificate will appear in the next Poll cycle as a new cert.
func (c *Client) RenewCert(ctx context.Context, avxCertID string) error {
	url := fmt.Sprintf("%s/avxapi/certificate/%s/renew", c.cfg.BaseURL, avxCertID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	c.setAuthHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("AVX renew request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("AVX renew auth error: HTTP %d", resp.StatusCode)
	case http.StatusConflict:
		return fmt.Errorf("AVX renew conflict: renewal already in progress for %s", avxCertID)
	default:
		return fmt.Errorf("AVX renew unexpected status: %d", resp.StatusCode)
	}
}

// csrRequest is the payload sent to AppViewX to request certificate issuance via CSR.
type csrRequest struct {
	CommonName      string   `json:"commonName"`
	SubjectAltNames []string `json:"subjectAltNames,omitempty"`
	CSR             string   `json:"csr"` // PEM-encoded
	ValidityDays    int      `json:"validityDays"`
}

// SubmitCSR submits a PEM-encoded CSR to AppViewX and returns the AVX request ID.
// validityDays of 0 defaults to 365.
func (c *Client) SubmitCSR(ctx context.Context, cn string, sans []string, csrPEM []byte, validityDays int) (string, error) {
	if validityDays == 0 {
		validityDays = 365
	}
	body, err := json.Marshal(csrRequest{
		CommonName:      cn,
		SubjectAltNames: sans,
		CSR:             string(csrPEM),
		ValidityDays:    validityDays,
	})
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/avxapi/certificate/request", c.cfg.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	c.setAuthHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("AVX CSR submit: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
	case http.StatusConflict:
		return "", fmt.Errorf("AVX CSR already pending for %s", cn)
	default:
		return "", fmt.Errorf("AVX CSR submit: HTTP %d", resp.StatusCode)
	}

	var result struct {
		RequestID string `json:"requestId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("AVX CSR response decode: %w", err)
	}
	if result.RequestID == "" {
		return "", fmt.Errorf("AVX CSR response: empty requestId")
	}
	return result.RequestID, nil
}

// ---- private helpers ----

type avxListResponse struct {
	Certificates []*Cert `json:"certificates"`
}

func (c *Client) listCerts(ctx context.Context) ([]*Cert, error) {
	url := fmt.Sprintf("%s/avxapi/certificate?status=ACTIVE&type=SSL", c.cfg.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c.setAuthHeader(req)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AVX API request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// handled below
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("AVX API auth error: HTTP %d", resp.StatusCode)
	case http.StatusTooManyRequests:
		var retryAfter time.Duration
		if s := resp.Header.Get("Retry-After"); s != "" {
			if secs, err := strconv.Atoi(s); err == nil && secs > 0 {
				retryAfter = time.Duration(secs) * time.Second
			}
		}
		return nil, &ErrRateLimited{RetryAfter: retryAfter}
	default:
		return nil, fmt.Errorf("AVX API unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("AVX API read body: %w", err)
	}

	var list avxListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("AVX API JSON parse: %w", err)
	}

	return list.Certificates, nil
}

func (c *Client) setAuthHeader(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
}
