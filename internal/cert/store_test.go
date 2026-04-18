package cert_test

import (
	"crypto/sha256"
	"testing"

	"github.com/amosdavis/certchain/internal/cert"
	"github.com/amosdavis/certchain/internal/chain"
	"github.com/amosdavis/certchain/internal/crypto"
)

// ---- helpers ----

func newID(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}

func publishBlock(t *testing.T, prev chain.Block, id *crypto.Identity, nonce uint32, cn string, notBefore, notAfter, blockTime int64) chain.Block {
	t.Helper()
	certID := sha256.Sum256([]byte(cn))
	payload, err := chain.MarshalPublish(&chain.CertPublishPayload{
		CertID:    certID,
		CN:        cn,
		AVXCertID: "AVX-" + cn,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		SANs:      []string{cn},
		Serial:    "01",
	})
	if err != nil {
		t.Fatalf("MarshalPublish: %v", err)
	}
	tx := chain.Transaction{
		Type:       chain.TxCertPublish,
		NodePubkey: id.PublicKey,
		Timestamp:  blockTime,
		Nonce:      nonce,
		Payload:    payload,
	}
	chain.Sign(&tx, id)
	blk := chain.Block{
		Index:     prev.Index + 1,
		Timestamp: blockTime,
		PrevHash:  prev.Hash,
		Txs:       []chain.Transaction{tx},
	}
	blk.Hash = chain.ComputeHash(&blk)
	return blk
}

func revokeBlock(t *testing.T, prev chain.Block, id *crypto.Identity, nonce uint32, certID [32]byte, blockTime int64) chain.Block {
	t.Helper()
	payload, err := chain.MarshalRevoke(&chain.CertRevokePayload{
		CertID:    certID,
		Reason:    0,
		RevokedAt: blockTime,
	})
	if err != nil {
		t.Fatalf("MarshalRevoke: %v", err)
	}
	tx := chain.Transaction{
		Type:       chain.TxCertRevoke,
		NodePubkey: id.PublicKey,
		Timestamp:  blockTime,
		Nonce:      nonce,
		Payload:    payload,
	}
	chain.Sign(&tx, id)
	blk := chain.Block{
		Index:     prev.Index + 1,
		Timestamp: blockTime,
		PrevHash:  prev.Hash,
		Txs:       []chain.Transaction{tx},
	}
	blk.Hash = chain.ComputeHash(&blk)
	return blk
}

// ---- tests ----

func TestPublishActiveStatus(t *testing.T) {
	s := cert.NewStore(0)
	id := newID(t)

	const blockTime = 1500
	blk := publishBlock(t, chain.GenesisBlock(), id, 1, "active.com", 1000, 2000, blockTime)
	if err := s.ApplyBlock(blk); err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}

	certID := sha256.Sum256([]byte("active.com"))
	rec, ok := s.GetByID(certID)
	if !ok {
		t.Fatal("cert not found by ID")
	}
	if rec.Status != cert.StatusActive {
		t.Errorf("status = %q, want %q", rec.Status, cert.StatusActive)
	}
	if rec.CN != "active.com" {
		t.Errorf("CN = %q, want active.com", rec.CN)
	}

	// Also reachable by CN.
	byCN, ok := s.GetByCN("active.com")
	if !ok {
		t.Fatal("cert not found by CN")
	}
	if byCN.CertID != certID {
		t.Error("GetByCN returned wrong cert")
	}
}

func TestPublishNotYetValidStatus(t *testing.T) {
	s := cert.NewStore(0)
	id := newID(t)

	// Block time is before not_before → not_yet_valid.
	const blockTime = 500
	blk := publishBlock(t, chain.GenesisBlock(), id, 1, "future.com", 1000, 2000, blockTime)
	if err := s.ApplyBlock(blk); err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}

	certID := sha256.Sum256([]byte("future.com"))
	rec, ok := s.GetByID(certID)
	if !ok {
		t.Fatal("cert not found by ID")
	}
	if rec.Status != cert.StatusNotYetValid {
		t.Errorf("status = %q, want %q", rec.Status, cert.StatusNotYetValid)
	}
}

func TestPublishExpiredStatus(t *testing.T) {
	s := cert.NewStore(0)
	id := newID(t)

	// Block time is after not_after → expired.
	const blockTime = 3000
	blk := publishBlock(t, chain.GenesisBlock(), id, 1, "old.com", 1000, 2000, blockTime)
	if err := s.ApplyBlock(blk); err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}

	certID := sha256.Sum256([]byte("old.com"))
	rec, ok := s.GetByID(certID)
	if !ok {
		t.Fatal("cert not found")
	}
	if rec.Status != cert.StatusExpired {
		t.Errorf("status = %q, want %q", rec.Status, cert.StatusExpired)
	}
}

func TestRevokeActiveCert(t *testing.T) {
	s := cert.NewStore(0)
	id := newID(t)
	genesis := chain.GenesisBlock()

	// Block 1: publish.
	blk1 := publishBlock(t, genesis, id, 1, "revokeme.com", 1000, 2000, 1500)
	if err := s.ApplyBlock(blk1); err != nil {
		t.Fatalf("ApplyBlock publish: %v", err)
	}

	certID := sha256.Sum256([]byte("revokeme.com"))

	// Block 2: revoke.
	blk2 := revokeBlock(t, blk1, id, 2, certID, 1600)
	if err := s.ApplyBlock(blk2); err != nil {
		t.Fatalf("ApplyBlock revoke: %v", err)
	}

	rec, ok := s.GetByID(certID)
	if !ok {
		t.Fatal("cert not found after revoke")
	}
	if rec.Status != cert.StatusRevoked {
		t.Errorf("status = %q, want %q", rec.Status, cert.StatusRevoked)
	}

	// CN index should no longer map to this cert.
	_, found := s.GetByCN("revokeme.com")
	if found {
		t.Error("revoked cert should not appear in CN index")
	}
}

func TestRevokeWinsInSameBlock(t *testing.T) {
	s := cert.NewStore(0)
	id := newID(t)
	genesis := chain.GenesisBlock()

	certID := sha256.Sum256([]byte("conflict.com"))

	// Single block containing both PUBLISH and REVOKE for same cert_id.
	pubPayload, err := chain.MarshalPublish(&chain.CertPublishPayload{
		CertID:    certID,
		CN:        "conflict.com",
		AVXCertID: "AVX-conflict",
		NotBefore: 1000,
		NotAfter:  2000,
		SANs:      []string{"conflict.com"},
		Serial:    "01",
	})
	if err != nil {
		t.Fatalf("MarshalPublish: %v", err)
	}
	revokePayload, err := chain.MarshalRevoke(&chain.CertRevokePayload{
		CertID:    certID,
		Reason:    0,
		RevokedAt: 1500,
	})
	if err != nil {
		t.Fatalf("MarshalRevoke: %v", err)
	}

	pubTx := chain.Transaction{
		Type:       chain.TxCertPublish,
		NodePubkey: id.PublicKey,
		Timestamp:  1500,
		Nonce:      1,
		Payload:    pubPayload,
	}
	chain.Sign(&pubTx, id)

	id2, _ := crypto.GenerateIdentity()
	revokeTx := chain.Transaction{
		Type:       chain.TxCertRevoke,
		NodePubkey: id2.PublicKey,
		Timestamp:  1500,
		Nonce:      1,
		Payload:    revokePayload,
	}
	chain.Sign(&revokeTx, id2)

	blk := chain.Block{
		Index:     1,
		Timestamp: 1500,
		PrevHash:  genesis.Hash,
		Txs:       []chain.Transaction{pubTx, revokeTx},
	}
	blk.Hash = chain.ComputeHash(&blk)

	if err := s.ApplyBlock(blk); err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}

	rec, ok := s.GetByID(certID)
	if !ok {
		t.Fatal("cert not found after conflict block")
	}
	// REVOKE wins (CM-06).
	if rec.Status != cert.StatusRevoked {
		t.Errorf("REVOKE-wins violated: status = %q, want %q", rec.Status, cert.StatusRevoked)
	}
}

func TestCountAndList(t *testing.T) {
	s := cert.NewStore(0)
	id := newID(t)
	genesis := chain.GenesisBlock()

	blk1 := publishBlock(t, genesis, id, 1, "a.com", 1000, 2000, 1500)
	_ = s.ApplyBlock(blk1)
	blk2 := publishBlock(t, blk1, id, 2, "b.com", 1000, 2000, 1500)
	_ = s.ApplyBlock(blk2)

	if s.Count() != 2 {
		t.Errorf("Count = %d, want 2", s.Count())
	}
	all := s.List(false)
	if len(all) != 2 {
		t.Errorf("List(all) = %d, want 2", len(all))
	}
	active := s.List(true)
	if len(active) != 2 {
		t.Errorf("List(active) = %d, want 2", len(active))
	}

	// Revoke one; active list shrinks.
	certID := sha256.Sum256([]byte("a.com"))
	blk3 := revokeBlock(t, blk2, id, 3, certID, 1600)
	_ = s.ApplyBlock(blk3)

	if s.Count() != 2 {
		t.Errorf("Count after revoke = %d, want 2 (record kept)", s.Count())
	}
	active2 := s.List(true)
	if len(active2) != 1 {
		t.Errorf("List(active) after revoke = %d, want 1", len(active2))
	}
}

func TestRebuildFrom(t *testing.T) {
	id := newID(t)
	genesis := chain.GenesisBlock()

	// Build a small chain: publish 2 certs, revoke 1.
	blk1 := publishBlock(t, genesis, id, 1, "x.com", 1000, 2000, 1500)
	blk2 := publishBlock(t, blk1, id, 2, "y.com", 1000, 2000, 1500)
	xID := sha256.Sum256([]byte("x.com"))
	blk3 := revokeBlock(t, blk2, id, 3, xID, 1600)

	// Rebuild store from blocks.
	s := cert.NewStore(0)
	if err := s.RebuildFrom([]chain.Block{genesis, blk1, blk2, blk3}); err != nil {
		t.Fatalf("RebuildFrom: %v", err)
	}

	xRec, ok := s.GetByID(xID)
	if !ok {
		t.Fatal("x.com not found after rebuild")
	}
	if xRec.Status != cert.StatusRevoked {
		t.Errorf("x.com status = %q, want revoked", xRec.Status)
	}

	yID := sha256.Sum256([]byte("y.com"))
	yRec, ok := s.GetByID(yID)
	if !ok {
		t.Fatal("y.com not found after rebuild")
	}
	if yRec.Status != cert.StatusActive {
		t.Errorf("y.com status = %q, want active", yRec.Status)
	}
}

func TestEvictionOnMaxCerts(t *testing.T) {
	// maxCerts=2; add 3 certs and revoke 2. Store should evict oldest revoked.
	s := cert.NewStore(2)
	id := newID(t)
	genesis := chain.GenesisBlock()

	blk1 := publishBlock(t, genesis, id, 1, "e1.com", 1000, 2000, 1500)
	_ = s.ApplyBlock(blk1)
	blk2 := publishBlock(t, blk1, id, 2, "e2.com", 1000, 2000, 1500)
	_ = s.ApplyBlock(blk2)

	// At this point count=2, at limit. Revoke e1 to make room.
	e1ID := sha256.Sum256([]byte("e1.com"))
	blk3 := revokeBlock(t, blk2, id, 3, e1ID, 1600)
	_ = s.ApplyBlock(blk3)

	// Add a 3rd cert. Total would be 3 → evict oldest revoked (e1).
	blk4 := publishBlock(t, blk3, id, 4, "e3.com", 1000, 2000, 1500)
	_ = s.ApplyBlock(blk4)

	if s.Count() > 2 {
		t.Errorf("Count = %d after eviction, want ≤ 2", s.Count())
	}
}
