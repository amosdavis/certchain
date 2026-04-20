// validator.go — validator allowlist for block authors (CM-23).
//
// A ValidatorSet is an immutable set of hex-encoded Ed25519 public keys
// (see internal/crypto). When a chain has a non-nil ValidatorSet, every
// transaction's NodePubkey — which is the signer/author of the block's
// content — must appear in the set or the block is rejected with
// ErrUnauthorizedAuthor. A nil ValidatorSet disables the check and
// preserves the legacy "accept any signer" behavior used by tests and
// single-node deployments that have not yet rolled out a validators.json.
package chain

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// ErrUnauthorizedAuthor is returned by AddBlock / Replace when a block
// contains a transaction signed by a public key that is not in the
// configured ValidatorSet (CM-23).
var ErrUnauthorizedAuthor = errors.New("unauthorized block author")

// ValidatorSet is an immutable allowlist of Ed25519 public keys that are
// permitted to author blocks on the chain.
type ValidatorSet struct {
	keys map[[32]byte]struct{}
}

// NewValidatorSet builds an immutable ValidatorSet from hex-encoded
// Ed25519 public keys (32 bytes / 64 hex chars each). Duplicate entries
// are collapsed silently. An empty slice produces a set that authorizes
// no signer — useful for tests but not for production.
func NewValidatorSet(hexKeys []string) (*ValidatorSet, error) {
	set := &ValidatorSet{keys: make(map[[32]byte]struct{}, len(hexKeys))}
	for i, h := range hexKeys {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("validator[%d]: invalid hex: %w", i, err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("validator[%d]: want 32 bytes, got %d", i, len(raw))
		}
		var k [32]byte
		copy(k[:], raw)
		set.keys[k] = struct{}{}
	}
	return set, nil
}

// Contains reports whether pubkey is authorized by the set. A nil
// receiver returns true (accept-all) to preserve backward compatibility.
func (v *ValidatorSet) Contains(pubkey [32]byte) bool {
	if v == nil {
		return true
	}
	_, ok := v.keys[pubkey]
	return ok
}

// Len returns the number of authorized validators. A nil receiver
// returns 0.
func (v *ValidatorSet) Len() int {
	if v == nil {
		return 0
	}
	return len(v.keys)
}

// validatorFile is the on-disk JSON schema for the validators allowlist.
type validatorFile struct {
	Validators []string `json:"validators"`
}

// LoadValidatorsFromFile reads a JSON file of the form
//
//	{"validators": ["<hex32>", "<hex32>", ...]}
//
// If the file does not exist, the returned ValidatorSet is nil and the
// returned error is nil — callers should treat this as "accept-all" and
// log a WARN pointing at CM-23. Any other read or parse error is
// returned verbatim.
func LoadValidatorsFromFile(path string) (*ValidatorSet, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var vf validatorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return NewValidatorSet(vf.Validators)
}
