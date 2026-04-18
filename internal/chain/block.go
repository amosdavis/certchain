// Package chain defines the block and transaction types for certchain.
package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"
)

// TxType identifies the kind of certificate transaction.
type TxType byte

const (
	TxCertPublish TxType = 0x01 // publish cert hash + metadata
	TxCertRevoke  TxType = 0x02 // revoke a certificate (AVX-driven)
	TxCertRenew   TxType = 0x03 // replace old cert_id with new cert_id
)

// Block is a single certchain block.
type Block struct {
	Index     uint32
	Timestamp int64 // unix seconds UTC
	PrevHash  [32]byte
	Hash      [32]byte
	Txs       []Transaction
}

// Transaction is a signed certificate transaction.
type Transaction struct {
	Type       TxType
	NodePubkey [32]byte
	Timestamp  int64
	Nonce      uint32
	Payload    json.RawMessage // JSON-encoded, type-specific
	Signature  [64]byte
}

// ---- Payload types ----

// CertPublishPayload is the JSON payload for TxCertPublish.
type CertPublishPayload struct {
	CertID    [32]byte `json:"cert_id"`
	CN        string   `json:"cn"`
	AVXCertID string   `json:"avx_cert_id"`
	NotBefore int64    `json:"not_before"`
	NotAfter  int64    `json:"not_after"`
	SANs      []string `json:"sans"`
	Serial    string   `json:"serial"`
}

// CertRevokePayload is the JSON payload for TxCertRevoke.
type CertRevokePayload struct {
	CertID    [32]byte `json:"cert_id"`
	Reason    uint8    `json:"reason"`
	RevokedAt int64    `json:"revoked_at"`
}

// CertRenewPayload is the JSON payload for TxCertRenew.
type CertRenewPayload struct {
	OldCertID [32]byte `json:"old_cert_id"`
	NewCertID [32]byte `json:"new_cert_id"`
}

// ---- Hashing ----

// ComputeHash computes the SHA-256 hash of a block.
// Input: index(4 LE) + timestamp(8 LE) + prevHash(32) + signing payload of each tx.
func ComputeHash(b *Block) [32]byte {
	h := sha256.New()

	var idx [4]byte
	binary.LittleEndian.PutUint32(idx[:], b.Index)
	h.Write(idx[:])

	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], uint64(b.Timestamp))
	h.Write(ts[:])

	h.Write(b.PrevHash[:])

	for i := range b.Txs {
		payload := signingPayload(&b.Txs[i])
		h.Write(payload)
	}

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// signingPayload builds the canonical bytes that are signed/verified for a tx.
// Format: type(1) + pubkey(32) + timestamp(8 LE) + nonce(4 LE) + payload(var)
func signingPayload(tx *Transaction) []byte {
	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], uint64(tx.Timestamp))

	var nonce [4]byte
	binary.LittleEndian.PutUint32(nonce[:], tx.Nonce)

	out := make([]byte, 0, 1+32+8+4+len(tx.Payload))
	out = append(out, byte(tx.Type))
	out = append(out, tx.NodePubkey[:]...)
	out = append(out, ts[:]...)
	out = append(out, nonce[:]...)
	out = append(out, tx.Payload...)
	return out
}

// ---- Transaction helpers ----

// SigningMessage returns the SHA-256 of the signing payload (what gets signed).
func SigningMessage(tx *Transaction) []byte {
	raw := signingPayload(tx)
	h := sha256.Sum256(raw)
	return h[:]
}

// Now returns the current unix timestamp in seconds.
func Now() int64 {
	return time.Now().UTC().Unix()
}

// ---- Payload marshalling ----

// MarshalPublish encodes a CertPublishPayload as JSON.
func MarshalPublish(p *CertPublishPayload) (json.RawMessage, error) {
	return json.Marshal(p)
}

// MarshalRevoke encodes a CertRevokePayload as JSON.
func MarshalRevoke(p *CertRevokePayload) (json.RawMessage, error) {
	return json.Marshal(p)
}

// MarshalRenew encodes a CertRenewPayload as JSON.
func MarshalRenew(p *CertRenewPayload) (json.RawMessage, error) {
	return json.Marshal(p)
}

// UnmarshalPublish decodes a CertPublishPayload from a transaction payload.
func UnmarshalPublish(tx *Transaction) (*CertPublishPayload, error) {
	if tx.Type != TxCertPublish {
		return nil, errors.New("not a CertPublish transaction")
	}
	var p CertPublishPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// UnmarshalRevoke decodes a CertRevokePayload from a transaction payload.
func UnmarshalRevoke(tx *Transaction) (*CertRevokePayload, error) {
	if tx.Type != TxCertRevoke {
		return nil, errors.New("not a CertRevoke transaction")
	}
	var p CertRevokePayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// UnmarshalRenew decodes a CertRenewPayload from a transaction payload.
func UnmarshalRenew(tx *Transaction) (*CertRenewPayload, error) {
	if tx.Type != TxCertRenew {
		return nil, errors.New("not a CertRenew transaction")
	}
	var p CertRenewPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
