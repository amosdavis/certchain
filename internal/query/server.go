// Package query provides the certchain HTTP query API on :9879.
//
// Endpoints:
//
//	GET /status                  — chain height, peer count, cert count
//	GET /cert?cn=<hostname>      — cert metadata by Common Name
//	GET /cert?id=<hex>           — cert metadata by cert_id
//	GET /cert/<hex>/der          — raw DER bytes (if cached locally)
//	GET /cert/list               — active certs (paginated: ?page=N&limit=M)
package query

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/amosdavis/certchain/internal/cert"
	"github.com/amosdavis/certchain/internal/peer"
)

// ChainInfo supplies chain metadata to the server.
type ChainInfo interface {
	Len() int
}

// Server is the HTTP query API server.
type Server struct {
	store     *cert.Store
	chain     ChainInfo
	peers     *peer.Table
	configDir string // directory that holds certs/<hex>.der files
	mux       *http.ServeMux
}

// NewServer creates a Server wired to the provided dependencies.
func NewServer(store *cert.Store, chain ChainInfo, peers *peer.Table, configDir string) *Server {
	s := &Server{
		store:     store,
		chain:     chain,
		peers:     peers,
		configDir: configDir,
		mux:       http.NewServeMux(),
	}
	s.mux.HandleFunc("/status", s.handleStatus)
	s.mux.HandleFunc("/cert/list", s.handleCertList)
	s.mux.HandleFunc("/cert/", s.handleCertByPath) // /cert/<hex>/der
	s.mux.HandleFunc("/cert", s.handleCert)        // ?cn= or ?id=
	return s
}

// Handler returns the http.Handler for use with http.ListenAndServe.
func (s *Server) Handler() http.Handler { return s.mux }

// ---- response types ----

type statusResponse struct {
	ChainHeight int `json:"chain_height"`
	PeerCount   int `json:"peer_count"`
	CertCount   int `json:"cert_count"`
}

type certResponse struct {
	CertID      string   `json:"cert_id"`
	CN          string   `json:"cn"`
	AVXCertID   string   `json:"avx_cert_id"`
	NotBefore   int64    `json:"not_before"`
	NotAfter    int64    `json:"not_after"`
	SANs        []string `json:"sans"`
	Serial      string   `json:"serial"`
	Status      string   `json:"status"`
	BlockHeight uint32   `json:"block_height"`
}

// ---- handlers ----

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, statusResponse{
		ChainHeight: s.chain.Len(),
		PeerCount:   s.peers.Count(),
		CertCount:   s.store.Count(),
	})
}

func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()

	if cn := q.Get("cn"); cn != "" {
		rec, ok := s.store.GetByCN(cn)
		if !ok {
			http.Error(w, "cert not found", http.StatusNotFound)
			return
		}
		writeJSON(w, recordToResponse(rec))
		return
	}

	if id := q.Get("id"); id != "" {
		certID, err := hexTo32(id)
		if err != nil {
			http.Error(w, "invalid cert_id hex", http.StatusBadRequest)
			return
		}
		rec, ok := s.store.GetByID(certID)
		if !ok {
			http.Error(w, "cert not found", http.StatusNotFound)
			return
		}
		writeJSON(w, recordToResponse(rec))
		return
	}

	http.Error(w, "query parameter 'cn' or 'id' required", http.StatusBadRequest)
}

func (s *Server) handleCertList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	page := intParam(q.Get("page"), 1)
	limit := intParam(q.Get("limit"), 50)
	if limit > 200 {
		limit = 200
	}

	all := s.store.List(true)
	total := len(all)

	start := (page - 1) * limit
	if start >= total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	slice := make([]certResponse, 0, end-start)
	for _, rec := range all[start:end] {
		slice = append(slice, recordToResponse(rec))
	}

	writeJSON(w, map[string]interface{}{
		"total": total,
		"page":  page,
		"limit": limit,
		"certs": slice,
	})
}

// handleCertByPath handles /cert/<hex>/der.
func (s *Server) handleCertByPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Path: /cert/<hex>/der
	path := r.URL.Path
	const prefix = "/cert/"
	if len(path) < len(prefix) {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	rest := path[len(prefix):] // e.g. "abc123.../der"

	const suffix = "/der"
	if len(rest) < len(suffix) || rest[len(rest)-len(suffix):] != suffix {
		http.Error(w, "path must be /cert/<hex>/der", http.StatusBadRequest)
		return
	}
	hexID := rest[:len(rest)-len(suffix)]

	certID, err := hexTo32(hexID)
	if err != nil {
		http.Error(w, "invalid cert_id hex", http.StatusBadRequest)
		return
	}

	// Verify the cert exists on chain.
	if _, ok := s.store.GetByID(certID); !ok {
		http.Error(w, "cert not found", http.StatusNotFound)
		return
	}

	// Serve DER from local cache (CM-12: return metadata-only if DER absent).
	derPath := filepath.Join(s.configDir, "certs", fmt.Sprintf("%s.der", hexID))
	data, err := os.ReadFile(derPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "DER not cached on this node", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-cert")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ---- helpers ----

func recordToResponse(r *cert.Record) certResponse {
	return certResponse{
		CertID:      hex.EncodeToString(r.CertID[:]),
		CN:          r.CN,
		AVXCertID:   r.AVXCertID,
		NotBefore:   r.NotBefore,
		NotAfter:    r.NotAfter,
		SANs:        r.SANs,
		Serial:      r.Serial,
		Status:      string(r.Status),
		BlockHeight: r.BlockHeight,
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "encoding error", http.StatusInternalServerError)
	}
}

func hexTo32(s string) ([32]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return [32]byte{}, fmt.Errorf("invalid 32-byte hex: %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func intParam(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 1 {
		return def
	}
	return v
}
