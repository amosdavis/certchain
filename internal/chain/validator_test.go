package chain_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/amosdavis/certchain/internal/chain"
	"github.com/amosdavis/certchain/internal/crypto"
)

func TestValidatorSetContainsNil(t *testing.T) {
	var vs *chain.ValidatorSet
	var pk [32]byte
	pk[0] = 0xAB
	if !vs.Contains(pk) {
		t.Error("nil ValidatorSet must accept any pubkey (accept-all)")
	}
	if vs.Len() != 0 {
		t.Errorf("nil ValidatorSet Len = %d, want 0", vs.Len())
	}
}

func TestNewValidatorSetInvalidHex(t *testing.T) {
	if _, err := chain.NewValidatorSet([]string{"not-hex"}); err == nil {
		t.Error("expected error for non-hex validator entry")
	}
	if _, err := chain.NewValidatorSet([]string{"abcd"}); err == nil {
		t.Error("expected error for wrong-length validator entry")
	}
}

// TestAddBlockRejectsUnknownSigner — CM-23: a block whose transaction is
// signed by a pubkey outside the configured ValidatorSet must be rejected
// with ErrUnauthorizedAuthor.
func TestAddBlockRejectsUnknownSigner(t *testing.T) {
	c := chain.New()
	authorized := newIdentity(t)
	stranger := newIdentity(t)

	vs, err := chain.NewValidatorSet([]string{hex.EncodeToString(authorized.PublicKey[:])})
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	c.SetValidators(vs)

	tx := buildPublishTx(t, stranger, 1, "stranger.com")
	blk := buildBlock(t, c.Tip(), []chain.Transaction{tx})

	err = c.AddBlock(blk)
	if err == nil {
		t.Fatal("expected ErrUnauthorizedAuthor, got nil")
	}
	if err != chain.ErrUnauthorizedAuthor {
		t.Errorf("expected ErrUnauthorizedAuthor, got %v", err)
	}
}

// TestAddBlockAcceptsKnownSigner — CM-23: a block signed by a pubkey in
// the ValidatorSet must be accepted.
func TestAddBlockAcceptsKnownSigner(t *testing.T) {
	c := chain.New()
	authorized := newIdentity(t)

	vs, err := chain.NewValidatorSet([]string{hex.EncodeToString(authorized.PublicKey[:])})
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	c.SetValidators(vs)

	tx := buildPublishTx(t, authorized, 1, "ok.com")
	blk := buildBlock(t, c.Tip(), []chain.Transaction{tx})

	if err := c.AddBlock(blk); err != nil {
		t.Fatalf("AddBlock with authorized signer: %v", err)
	}
	if c.Len() != 2 {
		t.Errorf("chain length = %d, want 2", c.Len())
	}
}

// TestReplaceRejectsUnauthorizedBlock — CM-23: chain replacement must
// reject candidate chains containing even a single block from an
// unauthorized signer.
func TestReplaceRejectsUnauthorizedBlock(t *testing.T) {
	c := chain.New()
	authorized := newIdentity(t)
	stranger := newIdentity(t)

	vs, err := chain.NewValidatorSet([]string{hex.EncodeToString(authorized.PublicKey[:])})
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	c.SetValidators(vs)

	genesis := chain.GenesisBlock()
	candidate := []chain.Block{genesis}
	// First block: authorized
	tx1 := buildPublishTx(t, authorized, 1, "one.com")
	candidate = append(candidate, buildBlock(t, candidate[len(candidate)-1], []chain.Transaction{tx1}))
	// Second block: unauthorized signer
	tx2 := buildPublishTx(t, stranger, 1, "two.com")
	candidate = append(candidate, buildBlock(t, candidate[len(candidate)-1], []chain.Transaction{tx2}))

	replaced, err := c.Replace(candidate)
	if err == nil {
		t.Fatal("expected ErrUnauthorizedAuthor from Replace, got nil")
	}
	if err != chain.ErrUnauthorizedAuthor {
		t.Errorf("expected ErrUnauthorizedAuthor, got %v", err)
	}
	if replaced {
		t.Error("chain must not be replaced with unauthorized candidate")
	}
}

// TestNilValidatorSetAcceptsAny — CM-23 backward compatibility: a chain
// with no validators configured must accept any signer.
func TestNilValidatorSetAcceptsAny(t *testing.T) {
	c := chain.New()
	// No SetValidators call — implicit nil.
	id := newIdentity(t)
	tx := buildPublishTx(t, id, 1, "any.com")
	blk := buildBlock(t, c.Tip(), []chain.Transaction{tx})

	if err := c.AddBlock(blk); err != nil {
		t.Fatalf("AddBlock with nil validators: %v", err)
	}
	if c.Validators() != nil {
		t.Error("Validators() should be nil when not configured")
	}
}

// TestLoadValidatorsFromFileMissing — missing file is not an error; the
// returned set is nil (accept-all, caller logs WARN per CM-23).
func TestLoadValidatorsFromFileMissing(t *testing.T) {
	vs, err := chain.LoadValidatorsFromFile(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vs != nil {
		t.Error("expected nil ValidatorSet for missing file")
	}
}

func TestLoadValidatorsFromFileRoundtrip(t *testing.T) {
	id1, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	id2, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	path := filepath.Join(t.TempDir(), "validators.json")
	body := []byte(`{"validators": ["` + hex.EncodeToString(id1.PublicKey[:]) + `", "` +
		hex.EncodeToString(id2.PublicKey[:]) + `"]}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	vs, err := chain.LoadValidatorsFromFile(path)
	if err != nil {
		t.Fatalf("LoadValidatorsFromFile: %v", err)
	}
	if vs == nil || vs.Len() != 2 {
		t.Fatalf("expected 2-validator set, got %+v", vs)
	}
	if !vs.Contains(id1.PublicKey) || !vs.Contains(id2.PublicKey) {
		t.Error("loaded set missing expected pubkeys")
	}

	var stranger [32]byte
	stranger[0] = 0xFF
	if vs.Contains(stranger) {
		t.Error("stranger pubkey should not be in loaded set")
	}
}

func TestLoadValidatorsFromFileMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := chain.LoadValidatorsFromFile(path); err == nil {
		t.Error("expected error for malformed JSON")
	}
}
