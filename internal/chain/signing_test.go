// signing_test.go — CM-29 domain-separator tests.
package chain_test

import (
	"crypto/sha256"
	"sync/atomic"
	"testing"

	"github.com/amosdavis/certchain/internal/chain"
	"github.com/amosdavis/certchain/internal/crypto"
)

// resetSigningDefault puts the signing context back to the chain-package
// defaults so tests that mutate it do not contaminate their neighbours.
func resetSigningDefault(t *testing.T) {
	t.Helper()
	if err := chain.SetSigningContext(chain.DefaultChainID, true); err != nil {
		t.Fatalf("reset signing: %v", err)
	}
	chain.SetLegacySigHook(nil)
}

func makePublishTx(t *testing.T, id *crypto.Identity, cn string) chain.Transaction {
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
	return chain.Transaction{
		Type:       chain.TxCertPublish,
		NodePubkey: id.PublicKey,
		Timestamp:  chain.Now(),
		Nonce:      1,
		Payload:    payload,
	}
}

// TestDomainSeparatorRoundTrip — a tx signed under the current chainID
// verifies cleanly.
func TestDomainSeparatorRoundTrip(t *testing.T) {
	resetSigningDefault(t)
	defer resetSigningDefault(t)

	id := newIdentity(t)
	tx := makePublishTx(t, id, "roundtrip.example")
	chain.Sign(&tx, id)

	if err := chain.Verify(&tx); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestDomainSeparatorWrongChainIDFails — a tx signed under chainID "A"
// must not verify under chainID "B".
func TestDomainSeparatorWrongChainIDFails(t *testing.T) {
	resetSigningDefault(t)
	defer resetSigningDefault(t)

	id := newIdentity(t)
	tx := makePublishTx(t, id, "cross.example")
	chain.SignFor(&tx, id, "network-A")

	if err := chain.VerifyFor(&tx, "network-B", false); err == nil {
		t.Fatal("expected verify to fail under a different chainID")
	}
	if err := chain.VerifyFor(&tx, "network-A", false); err != nil {
		t.Fatalf("verify under correct chainID: %v", err)
	}
}

// TestDomainSeparatorRejectsTamperedDomain — even if the signer used the
// "right" key, a verifier running with a different chainID must reject.
func TestDomainSeparatorRejectsTamperedDomain(t *testing.T) {
	resetSigningDefault(t)
	defer resetSigningDefault(t)

	id := newIdentity(t)
	tx := makePublishTx(t, id, "tamper.example")
	// Configure the process to chainID "prod" and sign.
	if err := chain.SetSigningContext("prod", false); err != nil {
		t.Fatalf("set ctx: %v", err)
	}
	chain.Sign(&tx, id)

	// Flip to "test" chainID — verification must fail (no legacy fallback).
	if err := chain.SetSigningContext("test", false); err != nil {
		t.Fatalf("set ctx: %v", err)
	}
	if err := chain.Verify(&tx); err == nil {
		t.Fatal("expected Verify to reject signature crafted for a different chainID")
	}
}

// TestLegacySigAcceptanceAndCounter — a legacy-format signature verifies
// under acceptLegacy=true, fires the hook exactly once, and is rejected
// under acceptLegacy=false.
func TestLegacySigAcceptanceAndCounter(t *testing.T) {
	resetSigningDefault(t)
	defer resetSigningDefault(t)

	var legacyHits atomic.Int64
	chain.SetLegacySigHook(func() { legacyHits.Add(1) })

	id := newIdentity(t)
	tx := makePublishTx(t, id, "legacy.example")

	// Produce a legacy signature (no domain prefix): sha256(signingPayload).
	legacyMsg := legacyDigest(t, &tx)
	tx.Signature = id.Sign(legacyMsg)

	// With acceptLegacy=false, verification must fail.
	if err := chain.VerifyFor(&tx, chain.DefaultChainID, false); err == nil {
		t.Fatal("legacy signature accepted with acceptLegacy=false")
	}
	if got := legacyHits.Load(); got != 0 {
		t.Fatalf("legacy hook should not fire on rejection, got %d", got)
	}

	// With acceptLegacy=true, verification succeeds and the hook fires.
	if err := chain.VerifyFor(&tx, chain.DefaultChainID, true); err != nil {
		t.Fatalf("legacy signature rejected under acceptLegacy=true: %v", err)
	}
	if got := legacyHits.Load(); got != 1 {
		t.Fatalf("legacy hook fire count = %d, want 1", got)
	}

	// A second successful legacy verification increments the counter again.
	if err := chain.VerifyFor(&tx, chain.DefaultChainID, true); err != nil {
		t.Fatalf("legacy second verify: %v", err)
	}
	if got := legacyHits.Load(); got != 2 {
		t.Fatalf("legacy hook fire count = %d, want 2", got)
	}
}

// TestLegacyHookNotFiredForNewSig — the hook must only fire on the legacy
// path, never for signatures produced under the new domain-separated format.
func TestLegacyHookNotFiredForNewSig(t *testing.T) {
	resetSigningDefault(t)
	defer resetSigningDefault(t)

	var legacyHits atomic.Int64
	chain.SetLegacySigHook(func() { legacyHits.Add(1) })

	id := newIdentity(t)
	tx := makePublishTx(t, id, "new.example")
	chain.Sign(&tx, id)

	if err := chain.Verify(&tx); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := legacyHits.Load(); got != 0 {
		t.Fatalf("legacy hook fired on new-format sig: %d", got)
	}
}

// legacyDigest reproduces the pre-CM-29 signing digest — sha256 of the
// canonical bytes, with no domain prefix. Kept in the test package so the
// production code need not expose the legacy form as an API.
func legacyDigest(t *testing.T, tx *chain.Transaction) []byte {
	t.Helper()
	// Reconstruct the canonical bytes: type(1) + pubkey(32) + ts(8 LE) +
	// nonce(4 LE) + payload. Mirrors chain.signingPayload.
	buf := make([]byte, 0, 1+32+8+4+len(tx.Payload))
	buf = append(buf, byte(tx.Type))
	buf = append(buf, tx.NodePubkey[:]...)
	ts := tx.Timestamp
	for i := 0; i < 8; i++ {
		buf = append(buf, byte(ts>>(8*i)))
	}
	n := tx.Nonce
	for i := 0; i < 4; i++ {
		buf = append(buf, byte(n>>(8*i)))
	}
	buf = append(buf, tx.Payload...)
	h := sha256.Sum256(buf)
	return h[:]
}
