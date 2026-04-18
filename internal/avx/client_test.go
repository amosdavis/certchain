package avx_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amosdavis/certchain/internal/avx"
)

func fakeCert(id, cn, status string) *avx.Cert {
	return &avx.Cert{
		AVXCertID:  id,
		CommonName: cn,
		Status:     status,
		NotBefore:  time.Now().Add(-time.Hour),
		NotAfter:   time.Now().Add(24 * time.Hour),
		SANs:       []string{cn},
		Serial:     "01",
	}
}

type fakeResponse struct {
	Certificates []*avx.Cert `json:"certificates"`
}

func mockServer(t *testing.T, certs []*avx.Cert, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fakeResponse{Certificates: certs})
	}))
}

func TestPollReturnsActiveCerts(t *testing.T) {
	cert := fakeCert("AVX-001", "example.com", "ACTIVE")
	srv := mockServer(t, []*avx.Cert{cert}, http.StatusOK)
	defer srv.Close()

	client := avx.NewClient(avx.Config{BaseURL: srv.URL, APIKey: "test-key"})
	result, err := client.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(result.NewCerts) != 1 {
		t.Errorf("NewCerts = %d, want 1", len(result.NewCerts))
	}
	if result.NewCerts[0].AVXCertID != "AVX-001" {
		t.Errorf("AVXCertID = %q, want AVX-001", result.NewCerts[0].AVXCertID)
	}
}

func TestPollHandles401(t *testing.T) {
	srv := mockServer(t, nil, http.StatusUnauthorized)
	defer srv.Close()

	client := avx.NewClient(avx.Config{BaseURL: srv.URL, APIKey: "bad-key"})
	_, err := client.Poll(context.Background())
	if err == nil {
		t.Error("expected error for 401, got nil")
	}
}

func TestPollHandles503(t *testing.T) {
	srv := mockServer(t, nil, http.StatusServiceUnavailable)
	defer srv.Close()

	client := avx.NewClient(avx.Config{BaseURL: srv.URL, APIKey: "key"})
	_, err := client.Poll(context.Background())
	if err == nil {
		t.Error("expected error for 503, got nil")
	}
}

func TestDuplicateSkipped(t *testing.T) {
	cert := fakeCert("AVX-002", "dup.com", "ACTIVE")
	srv := mockServer(t, []*avx.Cert{cert}, http.StatusOK)
	defer srv.Close()

	client := avx.NewClient(avx.Config{BaseURL: srv.URL, APIKey: "key"})

	// First poll — cert is new.
	r1, err := client.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll 1: %v", err)
	}
	if len(r1.NewCerts) != 1 {
		t.Fatalf("Poll 1 NewCerts = %d, want 1", len(r1.NewCerts))
	}

	// Mark as published.
	client.MarkPublished("AVX-002")

	// Second poll — cert should be skipped.
	r2, err := client.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll 2: %v", err)
	}
	if len(r2.NewCerts) != 0 {
		t.Errorf("Poll 2 NewCerts = %d, want 0 (duplicate should be skipped)", len(r2.NewCerts))
	}
}

func TestRevokedCertDetected(t *testing.T) {
	cert := fakeCert("AVX-003", "revoke.com", "REVOKED")
	srv := mockServer(t, []*avx.Cert{cert}, http.StatusOK)
	defer srv.Close()

	client := avx.NewClient(avx.Config{BaseURL: srv.URL, APIKey: "key"})
	// Pretend this cert was already published.
	client.MarkPublished("AVX-003")

	r, err := client.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(r.RevokedCerts) != 1 {
		t.Errorf("RevokedCerts = %d, want 1", len(r.RevokedCerts))
	}
}

func TestPollIntervalWithJitter(t *testing.T) {
	client := avx.NewClient(avx.Config{
		BaseURL:      "http://localhost",
		PollInterval: 60 * time.Second,
	})
	for i := 0; i < 20; i++ {
		d := client.PollIntervalWithJitter()
		if d < 54*time.Second || d > 66*time.Second {
			t.Errorf("jittered interval %v out of ±10%% band [54s,66s]", d)
		}
	}
}

func TestRenewCertSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client := avx.NewClient(avx.Config{BaseURL: srv.URL, APIKey: "key"})
	if err := client.RenewCert(context.Background(), "AVX-999"); err != nil {
		t.Fatalf("RenewCert: %v", err)
	}
}

func TestRenewCertAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := avx.NewClient(avx.Config{BaseURL: srv.URL, APIKey: "bad-key"})
	err := client.RenewCert(context.Background(), "AVX-999")
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
}

func TestRenewCertConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	client := avx.NewClient(avx.Config{BaseURL: srv.URL, APIKey: "key"})
	err := client.RenewCert(context.Background(), "AVX-999")
	if err == nil {
		t.Fatal("expected error for 409, got nil")
	}
}

func TestRenewCertCallsCorrectPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client := avx.NewClient(avx.Config{BaseURL: srv.URL, APIKey: "key"})
	if err := client.RenewCert(context.Background(), "AVX-abc-123"); err != nil {
		t.Fatalf("RenewCert: %v", err)
	}
	want := "/avxapi/certificate/AVX-abc-123/renew"
	if gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}
