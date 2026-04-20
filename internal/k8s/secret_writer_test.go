package k8s_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/amosdavis/certchain/internal/cert"
	certk8s "github.com/amosdavis/certchain/internal/k8s"
)

// generateDER creates a minimal self-signed X.509 DER for the given CN.
// It uses crypto/ecdsa so the result is a valid DER accepted by x509.ParseCertificate.
func generateDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generateDER key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("generateDER create: %v", err)
	}
	return der
}

// writeFakeDER writes a valid self-signed DER for the given certID and returns
// the path.  The DER is generated via ecdsa P-256 so that x509.ParseCertificate
// accepts it.
func writeFakeDER(t *testing.T, configDir string, certID [32]byte) string {
	t.Helper()
	derDir := filepath.Join(configDir, "certs")
	if err := os.MkdirAll(derDir, 0700); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	// Use hex-encoded ID as a unique CN so each cert is distinct.
	cn := fmt.Sprintf("%x", certID[:8])
	der := generateDER(t, cn)
	hexID := fmt.Sprintf("%x", certID)
	path := filepath.Join(derDir, hexID+".der")
	if err := os.WriteFile(path, der, 0600); err != nil {
		t.Fatalf("write DER: %v", err)
	}
	return path
}

// writeFakePEM writes the same DER as PEM for use where PEM bytes are needed.
func writeFakePEM(t *testing.T, configDir string, certID [32]byte) string {
	t.Helper()
	// Re-use writeFakeDER path to get the DER bytes, then encode as PEM.
	path := writeFakeDER(t, configDir, certID)
	der, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read DER: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pemPath := path[:len(path)-4] + ".pem"
	if err := os.WriteFile(pemPath, pemBytes, 0600); err != nil {
		t.Fatalf("write PEM: %v", err)
	}
	return pemPath
}

// makeRecord returns a cert.Record with the provided CN and status.
func makeRecord(cn string, status cert.Status) *cert.Record {
	var id [32]byte
	copy(id[:], []byte(cn))
	return &cert.Record{
		CertID:    id,
		CN:        cn,
		AVXCertID: "AVX-" + cn,
		Status:    status,
	}
}

// TestSecretWriterUpsertCreatesSecret verifies that an active record results in
// a K8s Secret being created with the expected labels and data.
func TestSecretWriterUpsertCreatesSecret(t *testing.T) {
	fakeClient := k8sfake.NewSimpleClientset()
	//lint:ignore SA1019 transitional callsite for legacy writer
	//lint:ignore SA1019 transitional callsite for legacy writer
	sw := certk8s.NewSecretWriter(fakeClient, "certchain", "cc")

	rec := makeRecord("api.example.com", cert.StatusActive)
	configDir := t.TempDir()
	writeFakeDER(t, configDir, rec.CertID)

	ctx := context.Background()
	if err := sw.Sync(ctx, []*cert.Record{rec}, configDir); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	name := certk8s.SecretName("cc", "api.example.com")
	secret, err := fakeClient.CoreV1().Secrets("certchain").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get Secret: %v", err)
	}
	if secret.Type != corev1.SecretTypeOpaque {
		t.Errorf("Secret type = %v, want Opaque", secret.Type)
	}
	if _, ok := secret.Data["tls.crt"]; !ok {
		t.Error("Secret missing tls.crt key")
	}
	if secret.Labels["certchain.io/cert-id"] != fmt.Sprintf("%x", rec.CertID) {
		t.Errorf("cert-id label mismatch")
	}
	if secret.Labels["certchain.io/avx-cert-id"] != rec.AVXCertID {
		t.Errorf("avx-cert-id label mismatch")
	}
}

// TestSecretWriterRevokedDeletesOwnedSecret verifies that a revoked cert's
// Secret is deleted when the cert-id label matches.
func TestSecretWriterRevokedDeletesOwnedSecret(t *testing.T) {
	fakeClient := k8sfake.NewSimpleClientset()
	//lint:ignore SA1019 transitional callsite for legacy writer
	//lint:ignore SA1019 transitional callsite for legacy writer
	sw := certk8s.NewSecretWriter(fakeClient, "certchain", "cc")

	rec := makeRecord("old.example.com", cert.StatusActive)
	configDir := t.TempDir()
	writeFakeDER(t, configDir, rec.CertID)

	ctx := context.Background()
	// First create the secret.
	if err := sw.Sync(ctx, []*cert.Record{rec}, configDir); err != nil {
		t.Fatalf("Sync (create): %v", err)
	}

	// Now revoke and sync.
	rec.Status = cert.StatusRevoked
	if err := sw.Sync(ctx, []*cert.Record{rec}, configDir); err != nil {
		t.Fatalf("Sync (revoke): %v", err)
	}

	name := certk8s.SecretName("cc", "old.example.com")
	_, err := fakeClient.CoreV1().Secrets("certchain").Get(ctx, name, metav1.GetOptions{})
	if !k8serrors.IsNotFound(err) {
		t.Errorf("expected Secret to be deleted, got err=%v", err)
	}
}

// TestSecretWriterRenewalDoesNotDeleteNewSecret verifies CM-17 protection:
// when a revoked record's cert-id does not match the existing Secret's label
// (because a renewal already replaced it), the Secret is not deleted.
func TestSecretWriterRenewalDoesNotDeleteNewSecret(t *testing.T) {
	fakeClient := k8sfake.NewSimpleClientset()
	//lint:ignore SA1019 transitional callsite for legacy writer
	//lint:ignore SA1019 transitional callsite for legacy writer
	sw := certk8s.NewSecretWriter(fakeClient, "certchain", "cc")
	ctx := context.Background()

	oldRec := makeRecord("shared.example.com", cert.StatusActive)
	configDir := t.TempDir()
	writeFakeDER(t, configDir, oldRec.CertID)

	// Create secret for the old cert.
	if err := sw.Sync(ctx, []*cert.Record{oldRec}, configDir); err != nil {
		t.Fatalf("Sync (old): %v", err)
	}

	// Simulate renewal: create a new record with same CN but different cert-id.
	newRec := makeRecord("shared.example.com", cert.StatusActive)
	newRec.CertID[0] = 0xFF // different cert-id
	newRec.AVXCertID = "AVX-new"
	writeFakeDER(t, configDir, newRec.CertID)

	// Upsert new cert (overwrites Secret label with new cert-id).
	if err := sw.Sync(ctx, []*cert.Record{newRec}, configDir); err != nil {
		t.Fatalf("Sync (new): %v", err)
	}

	// Now try to delete using the old cert-id; should be a no-op.
	oldRec.Status = cert.StatusReplaced
	if err := sw.Sync(ctx, []*cert.Record{oldRec}, configDir); err != nil {
		t.Fatalf("Sync (delete old): %v", err)
	}

	name := certk8s.SecretName("cc", "shared.example.com")
	secret, err := fakeClient.CoreV1().Secrets("certchain").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get Secret: %v", err)
	}
	if secret.Labels["certchain.io/cert-id"] != fmt.Sprintf("%x", newRec.CertID) {
		t.Errorf("expected new cert-id in Secret, got %q", secret.Labels["certchain.io/cert-id"])
	}
}

// TestSecretWriterRBACForbiddenSkips verifies CM-17: a 403 Forbidden response
// from K8s causes a log + skip; Sync returns nil and certd keeps running.
func TestSecretWriterRBACForbiddenSkips(t *testing.T) {
	fakeClient := k8sfake.NewSimpleClientset()
	fakeClient.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "cc-api.example.com", fmt.Errorf("forbidden"))
	})
	//lint:ignore SA1019 transitional callsite for legacy writer
	//lint:ignore SA1019 transitional callsite for legacy writer
	sw := certk8s.NewSecretWriter(fakeClient, "certchain", "cc")

	rec := makeRecord("api.example.com", cert.StatusActive)
	configDir := t.TempDir()
	writeFakeDER(t, configDir, rec.CertID)

	ctx := context.Background()
	// Should not return an error — CM-17 log + skip.
	if err := sw.Sync(ctx, []*cert.Record{rec}, configDir); err != nil {
		t.Errorf("expected nil from Sync on RBAC error, got: %v", err)
	}
}

// TestSecretWriterMissingDERSkips verifies that a record whose DER file is not
// cached locally is skipped gracefully (CM-12).
func TestSecretWriterMissingDERSkips(t *testing.T) {
	fakeClient := k8sfake.NewSimpleClientset()
	//lint:ignore SA1019 transitional callsite for legacy writer
	//lint:ignore SA1019 transitional callsite for legacy writer
	sw := certk8s.NewSecretWriter(fakeClient, "certchain", "cc")

	rec := makeRecord("nodecache.example.com", cert.StatusActive)
	configDir := t.TempDir() // no DER written

	ctx := context.Background()
	if err := sw.Sync(ctx, []*cert.Record{rec}, configDir); err != nil {
		t.Errorf("expected nil when DER missing, got: %v", err)
	}
	// Secret must not exist.
	name := certk8s.SecretName("cc", "nodecache.example.com")
	_, err := fakeClient.CoreV1().Secrets("certchain").Get(ctx, name, metav1.GetOptions{})
	if !k8serrors.IsNotFound(err) {
		t.Errorf("expected Secret to be absent when DER missing, got err=%v", err)
	}
}

// TestSecretWriterRevokedSecretDeleted verifies CM-25: when a cert drops out
// of the active set (because it was revoked on-chain and is no longer passed
// to Sync), its Secret is deleted and a CertchainRevoked Event is emitted.
func TestSecretWriterRevokedSecretDeleted(t *testing.T) {
	fakeClient := k8sfake.NewSimpleClientset()
	//lint:ignore SA1019 transitional callsite for legacy writer
	//lint:ignore SA1019 transitional callsite for legacy writer
	sw := certk8s.NewSecretWriter(fakeClient, "certchain", "cc")
	ctx := context.Background()

	recA := makeRecord("a.example.com", cert.StatusActive)
	recB := makeRecord("b.example.com", cert.StatusActive)
	configDir := t.TempDir()
	writeFakeDER(t, configDir, recA.CertID)
	writeFakeDER(t, configDir, recB.CertID)

	// First Sync: both certs active -> both Secrets written.
	if err := sw.Sync(ctx, []*cert.Record{recA, recB}, configDir); err != nil {
		t.Fatalf("Sync (initial): %v", err)
	}
	nameA := certk8s.SecretName("cc", "a.example.com")
	nameB := certk8s.SecretName("cc", "b.example.com")
	for _, n := range []string{nameA, nameB} {
		if _, err := fakeClient.CoreV1().Secrets("certchain").Get(ctx, n, metav1.GetOptions{}); err != nil {
			t.Fatalf("expected Secret %s to exist after initial Sync: %v", n, err)
		}
	}

	// Second Sync: only cert-B in the active set. cert-A was revoked and
	// the chain no longer emits it as an active record.
	if err := sw.Sync(ctx, []*cert.Record{recB}, configDir); err != nil {
		t.Fatalf("Sync (after revocation): %v", err)
	}

	// Secret A must be gone, Secret B must still exist.
	if _, err := fakeClient.CoreV1().Secrets("certchain").Get(ctx, nameA, metav1.GetOptions{}); !k8serrors.IsNotFound(err) {
		t.Errorf("expected Secret %s to be deleted, got err=%v", nameA, err)
	}
	if _, err := fakeClient.CoreV1().Secrets("certchain").Get(ctx, nameB, metav1.GetOptions{}); err != nil {
		t.Errorf("expected Secret %s to still exist, got err=%v", nameB, err)
	}

	// A CertchainRevoked Event must have been emitted referencing Secret A.
	events, err := fakeClient.CoreV1().Events("certchain").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	var found *corev1.Event
	for i := range events.Items {
		ev := &events.Items[i]
		if ev.Reason == certk8s.EventReasonRevoked && ev.InvolvedObject.Name == nameA {
			found = ev
			break
		}
	}
	if found == nil {
		t.Fatalf("expected a %s Event for Secret %s; got %d events", certk8s.EventReasonRevoked, nameA, len(events.Items))
	}
	if found.Type != corev1.EventTypeNormal {
		t.Errorf("Event type = %q, want Normal", found.Type)
	}
	if found.InvolvedObject.Kind != "Secret" {
		t.Errorf("Event involvedObject.Kind = %q, want Secret", found.InvolvedObject.Kind)
	}
	certIDHex := fmt.Sprintf("%x", recA.CertID)
	if !strings.Contains(found.Message, certIDHex) {
		t.Errorf("Event message %q missing cert_id %s", found.Message, certIDHex)
	}
	if !strings.Contains(found.Message, recA.CN) {
		t.Errorf("Event message %q missing CN %s", found.Message, recA.CN)
	}

	// Idempotency: re-syncing the same active set must not error and must
	// not delete Secret B or emit a second Event for the already-gone A.
	if err := sw.Sync(ctx, []*cert.Record{recB}, configDir); err != nil {
		t.Fatalf("Sync (idempotent): %v", err)
	}
	events2, _ := fakeClient.CoreV1().Events("certchain").List(ctx, metav1.ListOptions{})
	countFor := func(list *corev1.EventList, name string) int {
		n := 0
		for i := range list.Items {
			if list.Items[i].InvolvedObject.Name == name && list.Items[i].Reason == certk8s.EventReasonRevoked {
				n++
			}
		}
		return n
	}
	if got := countFor(events2, nameA); got != 1 {
		t.Errorf("expected exactly 1 CertchainRevoked Event for %s after idempotent re-sync, got %d", nameA, got)
	}
}

// TestSecretNameSanitization verifies that SecretName produces valid DNS-safe names.
func TestSecretNameSanitization(t *testing.T) {
	tests := []struct {
		prefix string
		cn     string
		want   string
	}{
		{"cc", "api.example.com", "cc-api.example.com"},
		{"cc", "API.Example.COM", "cc-api.example.com"},
		{"cc", "*.wildcard.example.com", "cc-wildcard.example.com"},
		{"cc", "with spaces", "cc-with-spaces"},
	}
	for _, tt := range tests {
		got := certk8s.SecretName(tt.prefix, tt.cn)
		if got != tt.want {
			t.Errorf("SecretName(%q, %q) = %q, want %q", tt.prefix, tt.cn, got, tt.want)
		}
	}
}
