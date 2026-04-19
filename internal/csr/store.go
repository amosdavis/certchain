package csr

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record tracks a submitted CSR and its association with an issued certificate.
type Record struct {
	CN           string   `json:"cn"`
	SANs         []string `json:"sans"`
	AVXRequestID string   `json:"avx_request_id"`
	SubmittedAt  int64    `json:"submitted_at"`
	// CertID is the hex cert_id once the cert has been issued and published.
	CertID string `json:"cert_id,omitempty"`
}

// Store persists CSR records and manages private key files on disk.
//
// Layout under configDir:
//
//	csrs.json                     — JSON array of Record
//	keys/<avx_request_id>.key     — PEM key for a pending CSR
//	keys/<cert_id_hex>.key        — PEM key copied here when cert is linked
type Store struct {
	mu     sync.Mutex
	path   string // csrs.json
	keyDir string
	byCN   map[string]*Record
}

// NewStore loads (or creates) the store rooted at configDir.
func NewStore(configDir string) (*Store, error) {
	s := &Store{
		path:   filepath.Join(configDir, "csrs.json"),
		keyDir: filepath.Join(configDir, "keys"),
		byCN:   make(map[string]*Record),
	}
	if err := os.MkdirAll(s.keyDir, 0700); err != nil {
		return nil, err
	}
	_ = s.load() // ignore not-found on first run
	return s, nil
}

// Add records a newly-submitted CSR and persists its private key to disk.
func (s *Store) Add(cn string, sans []string, avxRequestID string, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyPath := filepath.Join(s.keyDir, avxRequestID+".key")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	s.byCN[cn] = &Record{
		CN:           cn,
		SANs:         sans,
		AVXRequestID: avxRequestID,
		SubmittedAt:  time.Now().Unix(),
	}
	return s.save()
}

// HasPending reports whether a CSR has been submitted for cn but not yet linked
// to an issued certificate.
func (s *Store) HasPending(cn string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byCN[cn]
	return ok && rec.CertID == ""
}

// LinkCert associates an issued cert (by hex cert_id) with a pending CSR for
// the same CN. It copies the private key to keys/<certIDHex>.key so it can be
// served by cert_id. Returns the key PEM, or (nil, nil) if no pending CSR exists.
func (s *Store) LinkCert(cn, certIDHex string, keyDir string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.byCN[cn]
	if !ok || rec.AVXRequestID == "" || rec.CertID == certIDHex {
		return nil, nil
	}

	srcPath := filepath.Join(s.keyDir, rec.AVXRequestID+".key")
	keyPEM, err := os.ReadFile(srcPath)
	if err != nil {
		return nil, err
	}

	dstPath := filepath.Join(keyDir, certIDHex+".key")
	if err := os.WriteFile(dstPath, keyPEM, 0600); err != nil {
		return nil, err
	}
	rec.CertID = certIDHex
	return keyPEM, s.save()
}

func (s *Store) save() error {
	recs := make([]*Record, 0, len(s.byCN))
	for _, r := range s.byCN {
		recs = append(recs, r)
	}
	data, err := json.Marshal(recs)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var recs []*Record
	if err := json.Unmarshal(data, &recs); err != nil {
		return err
	}
	for _, r := range recs {
		s.byCN[r.CN] = r
	}
	return nil
}
