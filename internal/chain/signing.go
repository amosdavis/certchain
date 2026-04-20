// signing.go — signature domain separation for certchain transactions (CM-29).
//
// Transactions are signed over sha256(domain || canonical_bytes) where the
// domain is a fixed string plus a length-prefixed chainID. The domain string
// names the protocol version and the message type; the chainID disambiguates
// networks (e.g. test vs. prod) so a signature crafted for one chain cannot
// be replayed on another even if the payload bytes happen to coincide.
//
// Pre-CM-29 blocks signed bare sha256(canonical_bytes). A process-wide
// acceptLegacySigs flag enables a compat fallback during migration; each
// legacy verification increments the certchain_chain_legacy_sig_count
// counter (when wired via WithMetrics) and emits a WARN log line once per
// process startup so operators notice stragglers before flipping the flag
// to false.
package chain

import (
	"crypto/sha256"
	"errors"
	"log"
	"sync"
	"sync/atomic"

	"github.com/amosdavis/certchain/internal/crypto"
)

// SigningDomain is the fixed protocol-level prefix. It includes the project
// tag, a version, the message-type tag, and a null terminator so that the
// length of the prefix is unambiguous and cannot collide with arbitrary
// canonical-bytes content.
var SigningDomain = []byte("certchain/v1/tx\x00")

// DefaultChainID is the chainID used when a chain is constructed without an
// explicit WithChainID option.
const DefaultChainID = "certchain-default"

// maxChainIDLen bounds the chainID so its length fits in the single-byte
// length prefix. Values longer than this are rejected at configuration time.
const maxChainIDLen = 255

var (
	signingMu        sync.RWMutex
	currentChainID   = DefaultChainID
	acceptLegacySigs = true

	// legacySigCounter is invoked each time a transaction verifies only
	// under the legacy (no-prefix) format. nil means metrics are not wired.
	legacySigCounter func()

	// legacyWarnLogged ensures the one-shot WARN log line is emitted at
	// most once per process startup.
	legacyWarnLogged atomic.Bool
)

// SetSigningContext updates the process-wide signing context. It is safe
// to call concurrently but is intended to be invoked once at startup, from
// chain.New options or test setup helpers.
func SetSigningContext(chainID string, acceptLegacy bool) error {
	if len(chainID) > maxChainIDLen {
		return errors.New("chainID exceeds 255 bytes")
	}
	if chainID == "" {
		chainID = DefaultChainID
	}
	signingMu.Lock()
	currentChainID = chainID
	acceptLegacySigs = acceptLegacy
	signingMu.Unlock()
	return nil
}

// CurrentSigningContext returns the active chainID and acceptLegacySigs
// flag. Exported for diagnostics and tests.
func CurrentSigningContext() (chainID string, acceptLegacy bool) {
	signingMu.RLock()
	defer signingMu.RUnlock()
	return currentChainID, acceptLegacySigs
}

// SetLegacySigHook wires a callback that is invoked each time a signature
// verifies only under the legacy (pre-CM-29) format. Pass nil to clear.
func SetLegacySigHook(f func()) {
	signingMu.Lock()
	legacySigCounter = f
	signingMu.Unlock()
}

// domainPrefix returns SigningDomain || uint8(len(chainID)) || chainID.
func domainPrefix(chainID string) []byte {
	p := make([]byte, 0, len(SigningDomain)+1+len(chainID))
	p = append(p, SigningDomain...)
	p = append(p, byte(len(chainID)))
	p = append(p, chainID...)
	return p
}

// signingMessageFor returns the digest signed for tx under the given chainID.
func signingMessageFor(tx *Transaction, chainID string) []byte {
	h := sha256.New()
	h.Write(domainPrefix(chainID))
	h.Write(signingPayload(tx))
	return h.Sum(nil)
}

// legacySigningMessage returns the pre-CM-29 digest: sha256(canonical_bytes)
// with no domain prefix.
func legacySigningMessage(tx *Transaction) []byte {
	raw := signingPayload(tx)
	s := sha256.Sum256(raw)
	return s[:]
}

// SigningMessage returns the digest that is signed/verified for tx under the
// currently configured chainID. Tests and low-level tooling may use this;
// normal code should call Sign/Verify.
func SigningMessage(tx *Transaction) []byte {
	chainID, _ := CurrentSigningContext()
	return signingMessageFor(tx, chainID)
}

// Sign signs a transaction with the current signing context.
func Sign(tx *Transaction, id *crypto.Identity) {
	chainID, _ := CurrentSigningContext()
	SignFor(tx, id, chainID)
}

// SignFor signs a transaction under an explicit chainID. Exported to allow
// tests to cross-check domain-separation behaviour without mutating process
// state.
func SignFor(tx *Transaction, id *crypto.Identity, chainID string) {
	msg := signingMessageFor(tx, chainID)
	tx.Signature = id.Sign(msg)
}

// Verify verifies the Ed25519 signature on tx against the current signing
// context. When acceptLegacySigs is true it falls back to the pre-CM-29
// format and records the event via the legacy-sig hook.
func Verify(tx *Transaction) error {
	chainID, acceptLegacy := CurrentSigningContext()
	return VerifyFor(tx, chainID, acceptLegacy)
}

// VerifyFor verifies tx under an explicit chainID / acceptLegacy policy.
// Exported for tests and multi-chain tooling.
func VerifyFor(tx *Transaction, chainID string, acceptLegacy bool) error {
	msg := signingMessageFor(tx, chainID)
	if crypto.Verify(tx.NodePubkey, msg, tx.Signature) {
		return nil
	}
	if acceptLegacy {
		if crypto.Verify(tx.NodePubkey, legacySigningMessage(tx), tx.Signature) {
			onLegacyVerify()
			return nil
		}
	}
	return errors.New("invalid transaction signature")
}

func onLegacyVerify() {
	signingMu.RLock()
	hook := legacySigCounter
	signingMu.RUnlock()
	if hook != nil {
		hook()
	}
	if legacyWarnLogged.CompareAndSwap(false, true) {
		log.Printf("chain: WARN accepted transaction signed under legacy (pre-CM-29) format; flip --accept-legacy-sigs=false after migration to block these")
	}
}
