// Package crypto provides Ed25519 identity management for certchain nodes.
//
// Node identity is an Ed25519 keypair. The public key serves as the node ID
// and is embedded in every transaction. The private key is stored on disk with
// 0600 permissions and loaded on startup.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

const (
	privKeyLen = ed25519.PrivateKeySize // 64 bytes
	pubKeyLen  = ed25519.PublicKeySize  // 32 bytes
	keyFile    = "identity.key"
)

// Identity holds an Ed25519 keypair for a certchain node.
type Identity struct {
	PublicKey  [pubKeyLen]byte
	privateKey ed25519.PrivateKey
}

// GenerateIdentity creates a new random Ed25519 keypair.
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id := &Identity{privateKey: priv}
	copy(id.PublicKey[:], pub)
	return id, nil
}

// LoadOrCreate loads an identity from configDir/identity.key, or generates and
// saves a new one if the file does not exist.
func LoadOrCreate(configDir string) (*Identity, error) {
	path := filepath.Join(configDir, keyFile)

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return generateAndSave(path)
	}
	if err != nil {
		return nil, err
	}
	if len(data) != privKeyLen {
		return nil, errors.New("identity key file has wrong length")
	}

	priv := ed25519.PrivateKey(data)
	id := &Identity{privateKey: priv}
	copy(id.PublicKey[:], priv.Public().(ed25519.PublicKey))
	return id, nil
}

func generateAndSave(path string) (*Identity, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	id, err := GenerateIdentity()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(id.privateKey), 0600); err != nil {
		return nil, err
	}
	return id, nil
}

// Sign signs msg with the node's private key and returns the 64-byte signature.
func (id *Identity) Sign(msg []byte) [64]byte {
	sig := ed25519.Sign(id.privateKey, msg)
	var out [64]byte
	copy(out[:], sig)
	return out
}

// Verify checks an Ed25519 signature against a public key.
func Verify(pubkey [pubKeyLen]byte, msg []byte, sig [64]byte) bool {
	return ed25519.Verify(pubkey[:], msg, sig[:])
}

// PubKeyHex returns the hex-encoded public key string.
func (id *Identity) PubKeyHex() string {
	return hex.EncodeToString(id.PublicKey[:])
}
