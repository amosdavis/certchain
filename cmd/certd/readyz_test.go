package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestCertdReadinessHandler covers the /readyz contract introduced for
// CM-27: 503 with a {leader, chain} JSON body until every signal is
// satisfied, and 200 once they are.
func TestCertdReadinessHandler(t *testing.T) {
	t.Parallel()

	t.Run("chain_not_loaded_returns_503_with_json", func(t *testing.T) {
		t.Parallel()
		r := newCertdReadiness()

		resp := serveCertdReadyz(t, r)
		if resp.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", resp.Code)
		}
		if ct := resp.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("Content-Type = %q, want application/json*", ct)
		}
		body := decodeCertdBody(t, resp)
		if body["chain"] != "loading" {
			t.Errorf("chain = %q, want loading", body["chain"])
		}
		if body["leader"] != "disabled" {
			t.Errorf("leader = %q, want disabled (certd leader election off by default)", body["leader"])
		}
	})

	t.Run("chain_loaded_and_leader_disabled_returns_200", func(t *testing.T) {
		t.Parallel()
		r := newCertdReadiness()
		r.SetChainLoaded(true)

		resp := serveCertdReadyz(t, r)
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.Code)
		}
		body := decodeCertdBody(t, resp)
		if body["chain"] != "loaded" || body["leader"] != "disabled" {
			t.Errorf("body = %v, want chain=loaded leader=disabled", body)
		}
	})

	t.Run("leader_enabled_but_not_acquired_returns_503", func(t *testing.T) {
		t.Parallel()
		r := newCertdReadiness()
		r.SetChainLoaded(true)
		r.EnableLeader(true)

		resp := serveCertdReadyz(t, r)
		if resp.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", resp.Code)
		}
		if body := decodeCertdBody(t, resp); body["leader"] != "not_acquired" {
			t.Errorf("leader = %q, want not_acquired", body["leader"])
		}
	})

	t.Run("leader_acquired_and_chain_loaded_returns_200", func(t *testing.T) {
		t.Parallel()
		r := newCertdReadiness()
		r.SetChainLoaded(true)
		r.EnableLeader(true)
		r.SetLeader(true)

		resp := serveCertdReadyz(t, r)
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.Code)
		}
	})

	t.Run("handler_responds_well_under_50ms", func(t *testing.T) {
		t.Parallel()
		r := newCertdReadiness()
		start := time.Now()
		_ = serveCertdReadyz(t, r)
		if d := time.Since(start); d > 50*time.Millisecond {
			t.Fatalf("handler took %v, want <50ms", d)
		}
	})
}

func serveCertdReadyz(t *testing.T, r *certdReadiness) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	r.ServeReadyz(rec, req)
	return rec
}

func decodeCertdBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return out
}
