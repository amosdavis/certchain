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
