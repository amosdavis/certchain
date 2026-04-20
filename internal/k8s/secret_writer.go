// Package k8s provides Kubernetes integration for certchain.
// It writes active certificate metadata as K8s Secrets and watches
// CertificateSigningRequest objects to drive AVX-based issuance.
package k8s

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/amosdavis/certchain/internal/cert"
)

const (
	// LabelCertID is the K8s label key holding the hex cert-id of the owning record.
	LabelCertID    = "certchain.io/cert-id"
	labelAVXCertID = "certchain.io/avx-cert-id"

	backoffBase = 5 * time.Second
	backoffMax  = 10 * time.Minute
)

// SecretWriter upserts Kubernetes Opaque Secrets that carry the PEM-encoded
// public certificate for each active certchain record.
//
// certchain does not hold private keys (per CERTIFICATES.md); Secrets contain
// only the public certificate PEM in the "tls.crt" key.  Consumers that need
// the private key must obtain it directly from AppViewX.
//
// CM-16: exponential backoff when the K8s API is unreachable.
// CM-17: log + skip on RBAC Forbidden; certd never crashes.
type SecretWriter struct {
	client    kubernetes.Interface
	namespace string
	prefix    string
}

// NewSecretWriter creates a SecretWriter.
func NewSecretWriter(client kubernetes.Interface, namespace, prefix string) *SecretWriter {
	return &SecretWriter{
		client:    client,
		namespace: namespace,
		prefix:    prefix,
	}
}

// Sync reconciles K8s Secrets against the provided cert records:
//   - Active records get a Secret upserted (create or update).
//   - Revoked/replaced records have their Secret deleted, but only if the
//     Secret's cert-id label still matches the record being removed (prevents
//     a delete from racing a renewal that reused the same CN-derived name).
//
// DER bytes are read from <configDir>/certs/<certID_hex>.der.  Records whose
// DER file is absent are skipped with a WARN (CM-12 — DER not locally cached).
//
// On K8s API errors: CM-16 backoff / CM-17 skip.
func (sw *SecretWriter) Sync(ctx context.Context, records []*cert.Record, configDir string) error {
	for _, rec := range records {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		name := SecretName(sw.prefix, rec.CN)

		switch rec.Status {
		case cert.StatusActive, cert.StatusNotYetValid:
			if err := sw.upsert(ctx, rec, name, configDir); err != nil {
				return err
			}
		case cert.StatusRevoked, cert.StatusReplaced, cert.StatusExpired:
			if err := sw.deleteIfOwned(ctx, name, rec); err != nil {
				return err
			}
		}
	}
	return nil
}

// upsert creates or updates the Secret for an active cert record.
func (sw *SecretWriter) upsert(ctx context.Context, rec *cert.Record, name, configDir string) error {
	certPEM, err := sw.loadCertPEM(rec, configDir)
	if err != nil {
		// CM-12: DER not locally available — skip this record gracefully.
		log.Printf("k8s secret-writer: WARN cert %x DER unavailable, skipping Secret %s: %v",
			rec.CertID, name, err)
		return nil
	}

	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: sw.namespace,
			Labels: map[string]string{
				LabelCertID:    fmt.Sprintf("%x", rec.CertID),
				labelAVXCertID: rec.AVXCertID,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"tls.crt": certPEM,
		},
	}

	return sw.withBackoff(ctx, func() error {
		existing, err := sw.client.CoreV1().Secrets(sw.namespace).Get(ctx, name, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			_, createErr := sw.client.CoreV1().Secrets(sw.namespace).Create(ctx, desired, metav1.CreateOptions{})
			if isForbidden(createErr) {
				log.Printf("k8s secret-writer: ERROR Secret create forbidden — check RBAC; Secret %s not updated", name)
				return nil
			}
			return createErr
		}
		if err != nil {
			return err
		}
		// Only update if the cert-id has changed to avoid spurious writes.
		if existing.Labels[LabelCertID] == desired.Labels[LabelCertID] {
			return nil
		}
		existing.Labels = desired.Labels
		existing.Data = desired.Data
		existing.Type = desired.Type
		_, updateErr := sw.client.CoreV1().Secrets(sw.namespace).Update(ctx, existing, metav1.UpdateOptions{})
		if isForbidden(updateErr) {
			log.Printf("k8s secret-writer: ERROR Secret update forbidden — check RBAC; Secret %s not updated", name)
			return nil
		}
		return updateErr
	})
}

// deleteIfOwned deletes the Secret only when its cert-id label matches the
// record being removed, preventing a deletion from racing a renewal.
func (sw *SecretWriter) deleteIfOwned(ctx context.Context, name string, rec *cert.Record) error {
	return sw.withBackoff(ctx, func() error {
		existing, err := sw.client.CoreV1().Secrets(sw.namespace).Get(ctx, name, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if existing.Labels[LabelCertID] != fmt.Sprintf("%x", rec.CertID) {
			// A newer cert (e.g. renewal) already owns this Secret name.
			return nil
		}
		deleteErr := sw.client.CoreV1().Secrets(sw.namespace).Delete(ctx, name, metav1.DeleteOptions{})
		if k8serrors.IsNotFound(deleteErr) {
			return nil
		}
		if isForbidden(deleteErr) {
			log.Printf("k8s secret-writer: ERROR Secret delete forbidden — check RBAC; Secret %s not deleted", name)
			return nil
		}
		return deleteErr
	})
}

// withBackoff retries op with exponential backoff (CM-16).
// Returns nil on success, the last error after exhausting retries,
// or ctx.Err() if the context is cancelled.
func (sw *SecretWriter) withBackoff(ctx context.Context, op func() error) error {
	sleep := backoffBase
	for {
		err := op()
		if err == nil {
			return nil
		}
		if isForbidden(err) {
			// CM-17: already logged inside op; do not retry.
			return nil
		}
		log.Printf("k8s secret-writer: WARN K8s API error (retry in %v): %v", sleep, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
		sleep *= 2
		if sleep > backoffMax {
			sleep = backoffMax
		}
	}
}

// loadCertPEM reads the cached DER file and converts it to PEM.
func (sw *SecretWriter) loadCertPEM(rec *cert.Record, configDir string) ([]byte, error) {
	hexID := fmt.Sprintf("%x", rec.CertID)
	derPath := filepath.Join(configDir, "certs", hexID+".der")
	der, err := os.ReadFile(derPath)
	if err != nil {
		return nil, err
	}
	// Validate DER is parseable before encoding.
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, fmt.Errorf("parse DER: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// SecretName returns the K8s Secret name for the given prefix and CN.
// The name is lowercased, DNS-label-safe (alphanumeric + hyphens + dots),
// and capped at 253 characters.
func SecretName(prefix, cn string) string {
	sanitized := dnsLabelRE.ReplaceAllString(strings.ToLower(cn), "-")
	sanitized = strings.Trim(sanitized, "-.")
	name := prefix + "-" + sanitized
	if len(name) > 253 {
		name = name[:253]
	}
	return name
}

// dnsLabelRE matches any character that is not a lowercase letter, digit, hyphen, or dot.
var dnsLabelRE = regexp.MustCompile(`[^a-z0-9\-.]`)

func isForbidden(err error) bool {
	return k8serrors.IsForbidden(err) || k8serrors.IsUnauthorized(err)
}
