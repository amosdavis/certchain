// Package cert provides the certificate store for certchain.
//
// The store is built by applying blocks from the chain. It maintains per-cert
// records indexed by cert_id and by Common Name.
//
// Thread-safe: all exported methods acquire cs.mu.
// Lock order: chain.mu → cert.Store.mu (never acquire in reverse).
package cert

import (
	"errors"
	"sync"

	"github.com/amosdavis/certchain/internal/chain"
)

// Status represents the lifecycle state of a certificate.
type Status string

const (
	StatusActive      Status = "active"
	StatusNotYetValid Status = "not_yet_valid"
	StatusExpired     Status = "expired"
	StatusRevoked     Status = "revoked"
	StatusReplaced    Status = "replaced"
)

// Record holds the on-chain metadata for a single certificate.
type Record struct {
	CertID       [32]byte
	CN           string
	AVXCertID    string
	NotBefore    int64
	NotAfter     int64
	SANs         []string
	Serial       string
	IssuerDN     string
	KeyAlgorithm string
	Template     string
	Requester    string
	KeyVaultRef  string
	Environments []string
	Status       Status
	RevokeReason uint8
	RevokedAt    int64
	BlockHeight  uint32
	// Publisher is the node that submitted the TxCertPublish.
	Publisher [32]byte
}

// Store is the thread-safe certificate store.
type Store struct {
	mu       sync.RWMutex
	byID     map[[32]byte]*Record // cert_id → Record
	byCN     map[string]*Record   // CN → most-recent active Record
	maxCerts int                  // 0 = unlimited
}

// NewStore creates an empty Store.
// maxCerts: maximum number of records (0 = unlimited, see CM-13).
func NewStore(maxCerts int) *Store {
	return &Store{
		byID:     make(map[[32]byte]*Record),
		byCN:     make(map[string]*Record),
		maxCerts: maxCerts,
	}
}

// GetByID returns the record for the given cert_id.
func (s *Store) GetByID(certID [32]byte) (*Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.byID[certID]
	return r, ok
}

// GetByCN returns the most-recent active record for the given CN.
func (s *Store) GetByCN(cn string) (*Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.byCN[cn]
	return r, ok
}

// Count returns the total number of cert records (all statuses).
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// List returns all records. If activeOnly is true, only non-revoked,
// non-replaced, non-expired records are returned.
func (s *Store) List(activeOnly bool) []*Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Record, 0, len(s.byID))
	for _, r := range s.byID {
		if activeOnly && r.Status != StatusActive && r.Status != StatusNotYetValid {
			continue
		}
		out = append(out, r)
	}
	return out
}

// ValidateBlock performs read-only validation of cert transactions in a block
// against the current store state.
func (s *Store) ValidateBlock(b chain.Block) error {
	// Collect cert_ids being published in this block so that same-block
	// REVOKE-wins (CM-06) is allowed without requiring prior PUBLISH.
	pubsInBlock := make(map[[32]byte]struct{})
	for i := range b.Txs {
		if b.Txs[i].Type == chain.TxCertPublish {
			if p, err := chain.UnmarshalPublish(&b.Txs[i]); err == nil {
				pubsInBlock[p.CertID] = struct{}{}
			}
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range b.Txs {
		tx := &b.Txs[i]
		switch tx.Type {
		case chain.TxCertPublish:
			if err := s.validatePublish(tx); err != nil {
				return err
			}
		case chain.TxCertRevoke:
			if err := s.validateRevoke(tx, pubsInBlock); err != nil {
				return err
			}
		case chain.TxCertRenew:
			if err := s.validateRenew(tx); err != nil {
				return err
			}
		}
	}
	return nil
}

// ApplyBlock applies all cert transactions in a block to the store.
// It enforces the REVOKE-wins rule (CM-06): any cert_id that has a REVOKE
// in the block wins over a PUBLISH in the same block.
func (s *Store) ApplyBlock(b chain.Block) error {
	// Validate before applying (catches unknown-cert revokes, duplicates, etc.).
	if err := s.ValidateBlock(b); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// First pass: collect all revoke cert_ids in this block (CM-06).
	revokedInBlock := make(map[[32]byte]chain.CertRevokePayload)
	for i := range b.Txs {
		if b.Txs[i].Type == chain.TxCertRevoke {
			p, err := chain.UnmarshalRevoke(&b.Txs[i])
			if err != nil {
				return err
			}
			revokedInBlock[p.CertID] = *p
		}
	}

	// Second pass: apply all transactions.
	for i := range b.Txs {
		tx := &b.Txs[i]
		switch tx.Type {
		case chain.TxCertPublish:
			if err := s.applyPublish(tx, b.Index, b.Timestamp, revokedInBlock); err != nil {
				return err
			}
		case chain.TxCertRevoke:
			if err := s.applyRevoke(tx, b.Index); err != nil {
				return err
			}
		case chain.TxCertRenew:
			if err := s.applyRenew(tx, b.Index, b.Timestamp, revokedInBlock); err != nil {
				return err
			}
		}
	}

	// Evict oldest revoked/replaced records if over limit (CM-13).
	s.evictIfNeeded()
	return nil
}

// RebuildFrom replays all blocks from a chain to reconstruct the store.
func (s *Store) RebuildFrom(blocks []chain.Block) error {
	s.mu.Lock()
	s.byID = make(map[[32]byte]*Record)
	s.byCN = make(map[string]*Record)
	s.mu.Unlock()

	for _, blk := range blocks[1:] { // skip genesis
		if err := s.ApplyBlock(blk); err != nil {
			return err
		}
	}
	return nil
}

// ---- validation helpers (called with s.mu.RLock held) ----

func (s *Store) validatePublish(tx *chain.Transaction) error {
	p, err := chain.UnmarshalPublish(tx)
	if err != nil {
		return err
	}
	existing, ok := s.byID[p.CertID]
	if ok && (existing.Status == StatusActive || existing.Status == StatusNotYetValid) {
		return errors.New("cert already active on chain")
	}
	return nil
}

func (s *Store) validateRevoke(tx *chain.Transaction, pubsInBlock map[[32]byte]struct{}) error {
	p, err := chain.UnmarshalRevoke(tx)
	if err != nil {
		return err
	}
	// Same-block REVOKE-wins: revoke is allowed even if cert is being published
	// in the same block (CM-06). The apply phase handles the merge.
	if _, inBlock := pubsInBlock[p.CertID]; inBlock {
		return nil
	}
	existing, ok := s.byID[p.CertID]
	// Allow revoking an already-revoked cert (idempotent, CM-04).
	if !ok {
		return errors.New("cert_id not found; cannot revoke unknown cert")
	}
	if existing.Status == StatusReplaced {
		return errors.New("cannot revoke a replaced cert")
	}
	return nil
}

func (s *Store) validateRenew(tx *chain.Transaction) error {
	p, err := chain.UnmarshalRenew(tx)
	if err != nil {
		return err
	}
	old, ok := s.byID[p.OldCertID]
	if !ok || old.Status != StatusActive {
		return errors.New("old_cert_id not found or not active")
	}
	if old.Publisher != tx.NodePubkey {
		return errors.New("renew must be submitted by the original publisher")
	}
	// New cert must already be published (TxCertPublish in a prior block).
	newRec, exists := s.byID[p.NewCertID]
	if !exists {
		return errors.New("new_cert_id not found; publish new cert before renewing")
	}
	if newRec.Status != StatusActive && newRec.Status != StatusNotYetValid {
		return errors.New("new_cert_id is not active or not_yet_valid")
	}
	return nil
}

// ---- apply helpers (called with s.mu.Lock held) ----

func (s *Store) applyPublish(tx *chain.Transaction, blockHeight uint32, blockTime int64, revoked map[[32]byte]chain.CertRevokePayload) error {
	p, err := chain.UnmarshalPublish(tx)
	if err != nil {
		return err
	}

	status := computeStatus(p.NotBefore, p.NotAfter, blockTime)

	// REVOKE-wins: if this cert_id is also revoked in the same block, mark revoked (CM-06).
	rp, isRevoked := revoked[p.CertID]
	if isRevoked {
		status = StatusRevoked
		_ = rp
	}

	rec := &Record{
		CertID:       p.CertID,
		CN:           p.CN,
		AVXCertID:    p.AVXCertID,
		NotBefore:    p.NotBefore,
		NotAfter:     p.NotAfter,
		SANs:         p.SANs,
		Serial:       p.Serial,
		IssuerDN:     p.IssuerDN,
		KeyAlgorithm: p.KeyAlgorithm,
		Template:     p.Template,
		Requester:    p.Requester,
		KeyVaultRef:  p.KeyVaultRef,
		Environments: p.Environments,
		Status:       status,
		BlockHeight:  blockHeight,
		Publisher:    tx.NodePubkey,
	}
	s.byID[p.CertID] = rec

	if status == StatusActive || status == StatusNotYetValid {
		s.byCN[p.CN] = rec
	}
	return nil
}

func (s *Store) applyRevoke(tx *chain.Transaction, blockHeight uint32) error {
	p, err := chain.UnmarshalRevoke(tx)
	if err != nil {
		return err
	}
	rec, ok := s.byID[p.CertID]
	if !ok {
		// Unknown cert — validation should have caught this; skip silently.
		return nil
	}
	rec.Status = StatusRevoked
	rec.RevokeReason = p.Reason
	rec.RevokedAt = p.RevokedAt
	_ = blockHeight

	// Remove from CN index if this was the active cert for that CN.
	if active, ok := s.byCN[rec.CN]; ok && active.CertID == rec.CertID {
		delete(s.byCN, rec.CN)
	}
	return nil
}

func (s *Store) applyRenew(tx *chain.Transaction, blockHeight uint32, blockTime int64, revoked map[[32]byte]chain.CertRevokePayload) error {
	p, err := chain.UnmarshalRenew(tx)
	if err != nil {
		return err
	}
	old, ok := s.byID[p.OldCertID]
	if !ok {
		return nil
	}
	old.Status = StatusReplaced

	// Remove old from CN index.
	if active, ok := s.byCN[old.CN]; ok && active.CertID == old.CertID {
		delete(s.byCN, old.CN)
	}

	// The new cert must already be published (TxCertPublish in same or prior block).
	// If it's in this block's revoked set, apply REVOKE-wins.
	if newRec, exists := s.byID[p.NewCertID]; exists {
		if _, isRevoked := revoked[p.NewCertID]; isRevoked {
			newRec.Status = StatusRevoked
		} else {
			newRec.Status = computeStatus(newRec.NotBefore, newRec.NotAfter, blockTime)
			if newRec.Status == StatusActive || newRec.Status == StatusNotYetValid {
				s.byCN[newRec.CN] = newRec
			}
		}
	}
	_ = blockHeight
	return nil
}

func computeStatus(notBefore, notAfter, blockTime int64) Status {
	if blockTime < notBefore {
		return StatusNotYetValid
	}
	if blockTime > notAfter {
		return StatusExpired
	}
	return StatusActive
}

// evictIfNeeded removes the oldest revoked/replaced records when over maxCerts (CM-13).
func (s *Store) evictIfNeeded() {
	if s.maxCerts == 0 || len(s.byID) <= s.maxCerts {
		return
	}

	// Collect evictable (revoked or replaced) records, oldest block first.
	type candidate struct {
		id          [32]byte
		blockHeight uint32
	}
	var evictable []candidate
	for id, r := range s.byID {
		if r.Status == StatusRevoked || r.Status == StatusReplaced {
			evictable = append(evictable, candidate{id, r.BlockHeight})
		}
	}
	// Sort ascending by blockHeight (oldest first).
	for i := 0; i < len(evictable)-1; i++ {
		for j := i + 1; j < len(evictable); j++ {
			if evictable[j].blockHeight < evictable[i].blockHeight {
				evictable[i], evictable[j] = evictable[j], evictable[i]
			}
		}
	}

	for _, e := range evictable {
		if len(s.byID) <= s.maxCerts {
			break
		}
		delete(s.byID, e.id)
	}
}
