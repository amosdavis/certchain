package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// dummyHandler writes 200 so we can tell middleware pass-through from a
// 401 rejection.
func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func do(t *testing.T, h http.Handler, path, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestQueryAuthMiddlewareMissingHeader(t *testing.T) {
	h := queryAuthMiddleware(dummyHandler(), []byte("secret"))
	rr := do(t, h, "/cert/list", "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing header: got %d, want 401", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatalf("missing WWW-Authenticate challenge header")
	}
}

func TestQueryAuthMiddlewareWrongToken(t *testing.T) {
	h := queryAuthMiddleware(dummyHandler(), []byte("secret"))
	rr := do(t, h, "/cert/list", "Bearer wrong")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", rr.Code)
	}
}

func TestQueryAuthMiddlewareWrongScheme(t *testing.T) {
	h := queryAuthMiddleware(dummyHandler(), []byte("secret"))
	rr := do(t, h, "/cert/list", "Basic secret")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong scheme: got %d, want 401", rr.Code)
	}
}

func TestQueryAuthMiddlewareCorrectToken(t *testing.T) {
	h := queryAuthMiddleware(dummyHandler(), []byte("secret"))
	rr := do(t, h, "/cert/list", "Bearer secret")
	if rr.Code != http.StatusOK {
		t.Fatalf("correct token: got %d, want 200", rr.Code)
	}
}

func TestQueryAuthMiddlewareHealthzAllowlisted(t *testing.T) {
	h := queryAuthMiddleware(dummyHandler(), []byte("secret"))
	for _, p := range []string{"/healthz", "/readyz", "/metrics"} {
		rr := do(t, h, p, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200 without auth", p, rr.Code)
		}
	}
}

func TestQueryAuthMiddlewareEmptyTokenDisabled(t *testing.T) {
	h := queryAuthMiddleware(dummyHandler(), nil)
	rr := do(t, h, "/cert/list", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("empty-token legacy mode: got %d, want 200", rr.Code)
	}
}

// TestQueryAuthMiddlewareTokenIsConstantTimeCompared can't directly
// measure wall-clock timing deterministically in CI, but we can assert
// two common shapes (short wrong, exact-length wrong) both still return
// 401 — i.e. the compare reaches the subtle.ConstantTimeCompare branch
// in both cases.
func TestQueryAuthMiddlewareTokenShapesBothReject(t *testing.T) {
	h := queryAuthMiddleware(dummyHandler(), []byte("secret"))
	for _, tok := range []string{"Bearer s", "Bearer secreX", "Bearer xxxxxx"} {
		rr := do(t, h, "/cert/list", tok)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: got %d, want 401", tok, rr.Code)
		}
	}
}

func TestResolveSecretPrefersFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tok")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := resolveSecret(path, "flag-secret", "ENV_NOT_SET")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if string(got) != "file-secret" {
		t.Fatalf("got %q, want 'file-secret' (file must win and CR/LF trimmed)", got)
	}
}

func TestResolveSecretFlagFallback(t *testing.T) {
	got, err := resolveSecret("", "flag-secret", "ENV_NOT_SET")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if string(got) != "flag-secret" {
		t.Fatalf("got %q, want 'flag-secret'", got)
	}
}

func TestResolveSecretEnvFallback(t *testing.T) {
	t.Setenv("MY_TEST_SECRET", "env-secret")
	got, err := resolveSecret("", "", "MY_TEST_SECRET")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if string(got) != "env-secret" {
		t.Fatalf("got %q, want 'env-secret'", got)
	}
}

func TestResolveSecretAllEmpty(t *testing.T) {
	got, err := resolveSecret("", "", "UNSET_KEY_XYZ")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestResolveSecretMissingFileIsFatal(t *testing.T) {
	_, err := resolveSecret(filepath.Join(t.TempDir(), "nope"), "", "")
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}
