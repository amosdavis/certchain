package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestIssuerReadinessHandler covers the /readyz contract introduced for
// CM-27: 503 with a {leader, caches, certd} JSON body until every signal
// is satisfied, and 200 once they are.
func TestIssuerReadinessHandler(t *testing.T) {
	t.Parallel()

	t.Run("all_signals_false_returns_503_with_json", func(t *testing.T) {
		t.Parallel()
		r := newReadiness("http://certd:9879", 60*time.Second)

		resp := serveReadyz(t, r)
		if resp.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", resp.Code)
		}
		if ct := resp.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("Content-Type = %q, want application/json*", ct)
		}
		body := decodeBody(t, resp)
		wantKeys := []string{"leader", "caches", "certd"}
		for _, k := range wantKeys {
			if _, ok := body[k]; !ok {
				t.Errorf("missing JSON key %q in %v", k, body)
			}
		}
		if body["leader"] != "not_acquired" {
			t.Errorf("leader = %q, want not_acquired", body["leader"])
		}
		if body["caches"] != "syncing" {
			t.Errorf("caches = %q, want syncing", body["caches"])
		}
		if body["certd"] != "never" {
			t.Errorf("certd = %q, want never", body["certd"])
		}
	})

	t.Run("stale_certd_probe_returns_503", func(t *testing.T) {
		t.Parallel()
		r := newReadiness("http://certd:9879", 60*time.Second)
		r.SetLeader(true)
		r.SetCachesSynced(true)
		// Simulate a probe that succeeded five minutes ago.
		now := time.Now()
		r.now = func() time.Time { return now }
		r.MarkCertdOK(now.Add(-5 * time.Minute))

		resp := serveReadyz(t, r)
		if resp.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503 for stale certd probe", resp.Code)
		}
		body := decodeBody(t, resp)
		if !strings.HasPrefix(body["certd"], "stale_") {
			t.Errorf("certd = %q, want stale_* prefix", body["certd"])
		}
	})

	t.Run("all_signals_true_returns_200", func(t *testing.T) {
		t.Parallel()
		r := newReadiness("http://certd:9879", 60*time.Second)
		r.SetLeader(true)
		r.SetCachesSynced(true)
		r.MarkCertdOK(time.Now())

		resp := serveReadyz(t, r)
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.Code)
		}
		body := decodeBody(t, resp)
		if body["leader"] != "ok" || body["caches"] != "synced" || body["certd"] != "ok" {
			t.Errorf("body = %v, want all ok/synced", body)
		}
	})

	t.Run("certd_url_empty_marks_probe_disabled", func(t *testing.T) {
		t.Parallel()
		r := newReadiness("", 60*time.Second)
		r.SetLeader(true)
		r.SetCachesSynced(true)

		resp := serveReadyz(t, r)
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 when certd probe disabled", resp.Code)
		}
		if body := decodeBody(t, resp); body["certd"] != "disabled" {
			t.Errorf("certd = %q, want disabled", body["certd"])
		}
	})

	t.Run("handler_responds_well_under_50ms", func(t *testing.T) {
		t.Parallel()
		r := newReadiness("http://certd:9879", 60*time.Second)
		start := time.Now()
		_ = serveReadyz(t, r)
		if d := time.Since(start); d > 50*time.Millisecond {
			t.Fatalf("handler took %v, want <50ms", d)
		}
	})
}

func serveReadyz(t *testing.T, r *readiness) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	r.ServeReadyz(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return out
}
