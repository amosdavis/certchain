package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistryHandlerExposesChainMetrics(t *testing.T) {
	r := NewRegistry()
	chain := NewChainMetrics(r)
	chain.BlockHeight.Set(42)
	chain.BlocksAppendedTotal.Inc()
	chain.ValidationFailTotal.WithLabelValues("bad_signature").Inc()

	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)

	for _, want := range []string{
		"certchain_chain_height 42",
		"certchain_chain_blocks_appended_total 1",
		`certchain_chain_validation_fail_total{reason="bad_signature"} 1`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("metrics output missing %q\nfull body:\n%s", want, s)
		}
	}
}

func TestMultipleSubsystemsCoexist(t *testing.T) {
	r := NewRegistry()
	_ = NewChainMetrics(r)
	_ = NewAVXMetrics(r)
	_ = NewIssuerMetrics(r)
	// Will panic via MustRegister if any collector collides.
}
