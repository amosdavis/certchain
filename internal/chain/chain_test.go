package chain_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/amosdavis/certchain/internal/chain"
	"github.com/amosdavis/certchain/internal/crypto"
)

// ---- helpers ----

func newIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}

func buildPublishTx(t *testing.T, id *crypto.Identity, nonce uint32, cn string) chain.Transaction {
	t.Helper()
	certID := sha256.Sum256([]byte(cn))
	payload, err := chain.MarshalPublish(&chain.CertPublishPayload{
		CertID:    certID,
		CN:        cn,
		AVXCertID: "AVX-" + cn,
		NotBefore: 1000,
		NotAfter:  2000,
		SANs:      []string{cn},
		Serial:    "01",
	})
	if err != nil {
		t.Fatalf("MarshalPublish: %v", err)
	}
	tx := chain.Transaction{
		Type:       chain.TxCertPublish,
		NodePubkey: id.PublicKey,
		Timestamp:  chain.Now(),
		Nonce:      nonce,
		Payload:    payload,
	}
	chain.Sign(&tx, id)
	return tx
}

func buildBlock(t *testing.T, prev chain.Block, txs []chain.Transaction) chain.Block {
	t.Helper()
	b := chain.Block{
		Index:     prev.Index + 1,
		Timestamp: chain.Now(),
		PrevHash:  prev.Hash,
		Txs:       txs,
	}
	b.Hash = chain.ComputeHash(&b)
	return b
}

// ---- tests ----

func TestGenesisBlockDeterministic(t *testing.T) {
	g1 := chain.GenesisBlock()
	g2 := chain.GenesisBlock()
	if g1.Hash != g2.Hash {
		t.Error("genesis block hash is not deterministic")
	}
	if g1.Index != 0 {
		t.Errorf("genesis index = %d, want 0", g1.Index)
	}
}

func TestAddValidBlock(t *testing.T) {
	c := chain.New()
	id := newIdentity(t)
	tx := buildPublishTx(t, id, 1, "example.com")
	prev := c.Tip()
	blk := buildBlock(t, prev, []chain.Transaction{tx})

	if err := c.AddBlock(blk); err != nil {
		t.Fatalf("AddBlock: %v", err)
	}
	if c.Len() != 2 {
		t.Errorf("chain length = %d, want 2", c.Len())
	}
}

func TestAddBlockBadPrevHash(t *testing.T) {
	c := chain.New()
	id := newIdentity(t)
	tx := buildPublishTx(t, id, 1, "example.com")
	blk := chain.Block{
		Index:     1,
		Timestamp: chain.Now(),
		PrevHash:  [32]byte{0xFF}, // wrong
		Txs:       []chain.Transaction{tx},
	}
	blk.Hash = chain.ComputeHash(&blk)
	if err := c.AddBlock(blk); err == nil {
		t.Error("expected error for bad prev_hash, got nil")
	}
}

func TestAddBlockBadSig(t *testing.T) {
	c := chain.New()
	id := newIdentity(t)
	tx := buildPublishTx(t, id, 1, "example.com")
	tx.Signature[0] ^= 0xFF // corrupt signature
	prev := c.Tip()
	blk := buildBlock(t, prev, []chain.Transaction{tx})
	if err := c.AddBlock(blk); err == nil {
		t.Error("expected signature error, got nil")
	}
}

func TestAddBlockReplayNonce(t *testing.T) {
	c := chain.New()
	id := newIdentity(t)

	tx1 := buildPublishTx(t, id, 1, "first.com")
	blk1 := buildBlock(t, c.Tip(), []chain.Transaction{tx1})
	if err := c.AddBlock(blk1); err != nil {
		t.Fatalf("AddBlock blk1: %v", err)
	}

	tx2 := buildPublishTx(t, id, 1, "second.com") // same nonce — replay
	blk2 := buildBlock(t, c.Tip(), []chain.Transaction{tx2})
	if err := c.AddBlock(blk2); err == nil {
		t.Error("expected replay nonce error, got nil")
	}
}

func TestRateLimit(t *testing.T) {
	c := chain.New()
	id := newIdentity(t)

	var nonce uint32
	// Place 20 txs across 2 blocks (10 per block). The rate window
	// (cutoff = blockIndex - 10) includes ALL preceding blocks when
	// blockIndex <= 10, so all 20 txs are active when block 3 is validated.
	build10 := func() []chain.Transaction {
		txs := make([]chain.Transaction, 10)
		for i := range txs {
			nonce++
			txs[i] = buildPublishTx(t, id, nonce, fmt.Sprintf("r%d.com", nonce))
		}
		return txs
	}

	blk1 := buildBlock(t, c.Tip(), build10())
	if err := c.AddBlock(blk1); err != nil {
		t.Fatalf("AddBlock blk1: %v", err)
	}
	blk2 := buildBlock(t, c.Tip(), build10())
	if err := c.AddBlock(blk2); err != nil {
		t.Fatalf("AddBlock blk2: %v", err)
	}

	// 21st transaction from the same node should be rate-limited.
	nonce++
	txOver := buildPublishTx(t, id, nonce, fmt.Sprintf("r%d.com", nonce))
	blkOver := buildBlock(t, c.Tip(), []chain.Transaction{txOver})
	if err := c.AddBlock(blkOver); err == nil {
		t.Error("expected rate limit error, got nil")
	}
}

func TestReplaceLongerChain(t *testing.T) {
	c := chain.New()
	id := newIdentity(t)

	// Add one block to local chain.
	tx := buildPublishTx(t, id, 1, "local.com")
	blk := buildBlock(t, c.Tip(), []chain.Transaction{tx})
	_ = c.AddBlock(blk)

	// Build a longer candidate chain (3 blocks).
	id2 := newIdentity(t)
	genesis := chain.GenesisBlock()
	candidate := []chain.Block{genesis}
	var nonce uint32
	for i := 0; i < 3; i++ {
		nonce++
		tx := buildPublishTx(t, id2, nonce, "candidate.com"+string(rune('0'+i)))
		blk := buildBlock(t, candidate[len(candidate)-1], []chain.Transaction{tx})
		candidate = append(candidate, blk)
	}

	replaced, err := c.Replace(candidate)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if !replaced {
		t.Error("expected chain to be replaced by longer candidate")
	}
	if c.Len() != 4 {
		t.Errorf("chain length = %d, want 4", c.Len())
	}
}

func TestReplaceShorterChainRejected(t *testing.T) {
	c := chain.New()
	id := newIdentity(t)

	// Build a 3-block local chain.
	var nonce uint32
	for i := 0; i < 3; i++ {
		nonce++
		tx := buildPublishTx(t, id, nonce, "local.com"+string(rune('0'+i)))
		blk := buildBlock(t, c.Tip(), []chain.Transaction{tx})
		_ = c.AddBlock(blk)
	}

	// Attempt to replace with a 2-block candidate.
	id2 := newIdentity(t)
	genesis := chain.GenesisBlock()
	candidate := []chain.Block{genesis}
	nonce = 0
	for i := 0; i < 2; i++ {
		nonce++
		tx := buildPublishTx(t, id2, nonce, "short.com"+string(rune('0'+i)))
		blk := buildBlock(t, candidate[len(candidate)-1], []chain.Transaction{tx})
		candidate = append(candidate, blk)
	}

	replaced, err := c.Replace(candidate)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if replaced {
		t.Error("shorter chain should not replace longer local chain")
	}
}

func TestSignAndVerify(t *testing.T) {
	id := newIdentity(t)
	tx := buildPublishTx(t, id, 1, "test.com")
	if err := chain.Verify(&tx); err != nil {
		t.Errorf("Verify valid tx: %v", err)
	}
}

func TestVerifyBadSig(t *testing.T) {
	id := newIdentity(t)
	tx := buildPublishTx(t, id, 1, "test.com")
	tx.Signature[0] ^= 0xFF
	if err := chain.Verify(&tx); err == nil {
		t.Error("expected Verify to fail on bad signature")
	}
}

func TestCertPublishPayloadRoundtrip(t *testing.T) {
	certID := sha256.Sum256([]byte("roundtrip.com"))
	orig := &chain.CertPublishPayload{
		CertID:    certID,
		CN:        "roundtrip.com",
		AVXCertID: "AVX-999",
		NotBefore: 100,
		NotAfter:  200,
		SANs:      []string{"roundtrip.com", "www.roundtrip.com"},
		Serial:    "deadbeef",
	}
	raw, err := chain.MarshalPublish(orig)
	if err != nil {
		t.Fatalf("MarshalPublish: %v", err)
	}

	id := newIdentity(t)
	tx := chain.Transaction{
		Type:       chain.TxCertPublish,
		NodePubkey: id.PublicKey,
		Timestamp:  chain.Now(),
		Nonce:      1,
		Payload:    json.RawMessage(raw),
	}
	got, err := chain.UnmarshalPublish(&tx)
	if err != nil {
		t.Fatalf("UnmarshalPublish: %v", err)
	}
	if got.CN != orig.CN {
		t.Errorf("CN = %q, want %q", got.CN, orig.CN)
	}
	if got.CertID != orig.CertID {
		t.Error("CertID mismatch after roundtrip")
	}
}
