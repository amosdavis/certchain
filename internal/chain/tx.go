// tx.go — transaction signing and verification for certchain.
package chain

import (
	"errors"

	"github.com/amosdavis/certchain/internal/crypto"
)

// Sign signs a transaction using the provided identity. The signature covers
// the SHA-256 of the signing payload (type + pubkey + timestamp + nonce + payload).
func Sign(tx *Transaction, id *crypto.Identity) {
	msg := SigningMessage(tx)
	tx.Signature = id.Sign(msg)
}

// Verify verifies the Ed25519 signature on a transaction.
// Returns nil if valid, an error otherwise.
func Verify(tx *Transaction) error {
	msg := SigningMessage(tx)
	if !crypto.Verify(tx.NodePubkey, msg, tx.Signature) {
		return errors.New("invalid transaction signature")
	}
	return nil
}

// ValidatePayload validates the type-specific fields of a transaction.
func ValidatePayload(tx *Transaction) error {
	switch tx.Type {
	case TxCertPublish:
		return validatePublish(tx)
	case TxCertRevoke:
		return validateRevoke(tx)
	case TxCertRenew:
		return validateRenew(tx)
	case TxCertRequest:
		return validateCertRequest(tx)
	default:
		return errors.New("unknown transaction type")
	}
}

func validatePublish(tx *Transaction) error {
	p, err := UnmarshalPublish(tx)
	if err != nil {
		return err
	}
	if isZero(p.CertID) {
		return errors.New("cert_id must not be zero")
	}
	if p.CN == "" {
		return errors.New("cn must not be empty")
	}
	if p.AVXCertID == "" {
		return errors.New("avx_cert_id must not be empty")
	}
	if p.NotBefore <= 0 {
		return errors.New("not_before must be positive")
	}
	if p.NotAfter <= 0 {
		return errors.New("not_after must be positive")
	}
	if p.NotBefore > p.NotAfter {
		return errors.New("not_before must be <= not_after")
	}
	if len(p.SANs) > 16 {
		return errors.New("too many SANs (max 16)")
	}
	return nil
}

func validateRevoke(tx *Transaction) error {
	p, err := UnmarshalRevoke(tx)
	if err != nil {
		return err
	}
	if isZero(p.CertID) {
		return errors.New("cert_id must not be zero")
	}
	if p.Reason > 10 || p.Reason == 7 {
		return errors.New("invalid RFC 5280 reason code")
	}
	if p.RevokedAt <= 0 {
		return errors.New("revoked_at must be positive")
	}
	return nil
}

func validateRenew(tx *Transaction) error {
	p, err := UnmarshalRenew(tx)
	if err != nil {
		return err
	}
	if isZero(p.OldCertID) {
		return errors.New("old_cert_id must not be zero")
	}
	if isZero(p.NewCertID) {
		return errors.New("new_cert_id must not be zero")
	}
	if p.OldCertID == p.NewCertID {
		return errors.New("old_cert_id and new_cert_id must differ")
	}
	return nil
}

func isZero(b [32]byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func validateCertRequest(tx *Transaction) error {
	p, err := UnmarshalCertRequest(tx)
	if err != nil {
		return err
	}
	if isZero(p.CSRHash) {
		return errors.New("csr_hash must not be zero")
	}
	if p.CN == "" {
		return errors.New("cn must not be empty")
	}
	if len(p.SANs) > 16 {
		return errors.New("too many SANs (max 16)")
	}
	return nil
}
