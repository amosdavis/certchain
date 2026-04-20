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

	// LabelManagedBy marks Secrets owned by certd. The sweep logic only
	// considers (and deletes) Secrets bearing this label, so it can never
	// touch operator-owned resources that happen to share a name (CM-25).
	LabelManagedBy      = "certchain.io/managed-by"
	LabelManagedByValue = "certd"

	// LabelCN records the CN of the cert whose PEM the Secret holds. The
	// sweep uses it to build a human-readable Event message without having
	// to re-parse the Secret's DER payload.
	LabelCN = "certchain.io/cn"

	// EventReasonRevoked is the reason emitted on the Kubernetes Event when
	// certd deletes a Secret in response to an on-chain revocation or
	// replacement (CM-25: Revoked Cert Still Served).
	EventReasonRevoked = "CertchainRevoked"

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
//   - Records is treated as the complete view. Any Secret in the namespace
//     that is labelled as managed by certd but whose name is not part of the
//     active set gets deleted, and a Kubernetes Event of reason
//     CertchainRevoked is emitted referencing the cert_id and CN (CM-25).
//
// DER bytes are read from <configDir>/certs/<certID_hex>.der.  Records whose
// DER file is absent are skipped with a WARN (CM-12 — DER not locally cached).
//
// On K8s API errors: CM-16 backoff / CM-17 skip.
func (sw *SecretWriter) Sync(ctx context.Context, records []*cert.Record, configDir string) error {
	// expected is the set of Secret names that correspond to *any* record in
	// the input batch, regardless of status. A Secret that falls outside this
	// set is considered orphaned — the cert record backing it is no longer
	// in the authoritative view — and must be swept (CM-25).
	expected := make(map[string]struct{}, len(records))
	for _, rec := range records {
		expected[SecretName(sw.prefix, rec.CN)] = struct{}{}
	}

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

	// Sweep: delete any certd-managed Secret not referenced by this active
	// set and emit an Event per deletion (CM-25).
	if err := sw.sweep(ctx, expected); err != nil {
		return err
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
				LabelManagedBy: LabelManagedByValue,
				LabelCN:        sanitizeLabelValue(rec.CN),
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
// record being removed, preventing a deletion from racing a renewal. When a
// deletion is actually performed, a Kubernetes Event of reason
// CertchainRevoked is emitted (CM-25).
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
		if deleteErr != nil {
			return deleteErr
		}
		sw.emitRevokedEvent(ctx, existing, fmt.Sprintf("%x", rec.CertID), rec.CN)
		return nil
	})
}

// sweep removes any certd-managed Secret whose name is not in `expected`.
// Each deleted Secret triggers a CertchainRevoked Event so downstream
// operators see that certd intentionally removed the material (CM-25).
// IsNotFound on delete is swallowed to keep the operation idempotent.
func (sw *SecretWriter) sweep(ctx context.Context, expected map[string]struct{}) error {
	return sw.withBackoff(ctx, func() error {
		list, err := sw.client.CoreV1().Secrets(sw.namespace).List(ctx, metav1.ListOptions{
			LabelSelector: LabelManagedBy + "=" + LabelManagedByValue,
		})
		if isForbidden(err) {
			log.Printf("k8s secret-writer: ERROR Secret list forbidden — check RBAC; sweep skipped")
			return nil
		}
		if err != nil {
			return err
		}
		for i := range list.Items {
			s := &list.Items[i]
			if _, keep := expected[s.Name]; keep {
				continue
			}
			delErr := sw.client.CoreV1().Secrets(sw.namespace).Delete(ctx, s.Name, metav1.DeleteOptions{})
			if k8serrors.IsNotFound(delErr) {
				continue
			}
			if isForbidden(delErr) {
				log.Printf("k8s secret-writer: ERROR Secret delete forbidden during sweep — check RBAC; Secret %s not deleted", s.Name)
				continue
			}
			if delErr != nil {
				return delErr
			}
			cn := s.Labels[LabelCN]
			if cn == "" {
				cn = s.Name
			}
			sw.emitRevokedEvent(ctx, s, s.Labels[LabelCertID], cn)
		}
		return nil
	})
}

// emitRevokedEvent records a core/v1 Event of type Normal with reason
// CertchainRevoked referencing the deleted Secret. The Event's message
// includes the hex cert-id and CN so operators can trace the revocation
// (CM-25). Errors creating the Event are logged but never propagated:
// losing an Event must not cause the revocation to be retried indefinitely.
func (sw *SecretWriter) emitRevokedEvent(ctx context.Context, secret *corev1.Secret, certIDHex, cn string) {
	now := metav1.NewTime(time.Now())
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "certchain-revoked-",
			Namespace:    sw.namespace,
			Labels: map[string]string{
				LabelManagedBy: LabelManagedByValue,
			},
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Secret",
			Namespace: secret.Namespace,
			Name:      secret.Name,
			UID:       secret.UID,
			APIVersion: "v1",
		},
		Reason:         EventReasonRevoked,
		Message:        fmt.Sprintf("Secret %s deleted: cert_id=%s CN=%s revoked/replaced on certchain", secret.Name, certIDHex, cn),
		Type:           corev1.EventTypeNormal,
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
		Source:         corev1.EventSource{Component: "certd-secret-writer"},
	}
	if _, err := sw.client.CoreV1().Events(sw.namespace).Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		if isForbidden(err) {
			log.Printf("k8s secret-writer: ERROR Event create forbidden — check RBAC; revocation event for Secret %s not recorded", secret.Name)
			return
		}
		log.Printf("k8s secret-writer: WARN failed to record revocation Event for Secret %s: %v", secret.Name, err)
	}
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

// labelValueRE matches any character that is not permitted in a Kubernetes
// label value (alphanumeric, '-', '_', '.'). Label values are also capped at
// 63 characters. We sanitize CNs before attaching them as the certchain.io/cn
// label so that arbitrary CNs (e.g. wildcards) never break object creation.
var labelValueRE = regexp.MustCompile(`[^A-Za-z0-9\-_.]`)

// sanitizeLabelValue returns a value safe to use as a K8s label value for
// the supplied CN. It lowercases, replaces invalid characters with '-',
// trims leading/trailing separators, and caps at 63 characters.
func sanitizeLabelValue(cn string) string {
	v := labelValueRE.ReplaceAllString(strings.ToLower(cn), "-")
	v = strings.Trim(v, "-_.")
	if len(v) > 63 {
		v = v[:63]
	}
	return v
}

func isForbidden(err error) bool {
	return k8serrors.IsForbidden(err) || k8serrors.IsUnauthorized(err)
}
