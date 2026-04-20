package annotation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHTTPFetcher_SendsBearerAndParses covers the happy path of the
// production fetcher: it must send Authorization: Bearer <token> and
// decode certd's JSON body into a CertBundle.
func TestHTTPFetcher_SendsBearerAndParses(t *testing.T) {
	t.Parallel()
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"cn":        "api.example.com",
			"not_after": 1234567890,
			"cert_pem":  "CERT",
			"chain_pem": "CHAIN",
		})
	}))
	defer srv.Close()

	f := NewHTTPFetcher(srv.URL, "secret-token")
	b, err := f.Fetch(context.Background(), "api.example.com")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want Bearer secret-token", gotAuth)
	}
	if string(b.CertPEM) != "CERT" || string(b.ChainPEM) != "CHAIN" {
		t.Errorf("unexpected bundle: %+v", b)
	}
	if b.NotAfter.IsZero() {
		t.Errorf("expected NotAfter to be set")
	}
}

// TestHTTPFetcher_404MapsToErrNotFound distinguishes "cert not yet
// issued" from hard transport errors.
func TestHTTPFetcher_404MapsToErrNotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	f := NewHTTPFetcher(srv.URL, "tok")
	_, err := f.Fetch(context.Background(), "missing.example.com")
	if err != ErrCertNotFound {
		t.Errorf("err = %v, want ErrCertNotFound", err)
	}
}

// TestHTTPFetcher_Non2xxIsError makes sure 5xx responses surface as
// errors so the controller's errors_total counter increments.
func TestHTTPFetcher_Non2xxIsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := NewHTTPFetcher(srv.URL, "tok")
	if _, err := f.Fetch(context.Background(), "api.example.com"); err == nil {
		t.Fatal("expected error for 500 response")
	}
}
