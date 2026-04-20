// Package issuer provides helpers for creating, approving, and polling
// Kubernetes CertificateSigningRequest objects on behalf of the certchain-issuer
// external issuer controller.
package issuer

import (
	"context"
	"fmt"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CreateCSR creates a K8s CertificateSigningRequest with the given signerName
// and PKCS#10 DER bytes. The usages are set to match standard TLS server auth.
// Returns nil if a CSR with the same name already exists (idempotent).
func CreateCSR(ctx context.Context, client kubernetes.Interface, name, signerName string, csrDER []byte) error {
	desired := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    csrDER,
			SignerName: signerName,
			Usages: []certificatesv1.KeyUsage{
				certificatesv1.UsageDigitalSignature,
				certificatesv1.UsageKeyEncipherment,
				certificatesv1.UsageServerAuth,
			},
		},
	}
	_, err := client.CertificatesV1().CertificateSigningRequests().Create(ctx, desired, metav1.CreateOptions{})
	if k8serrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// ApproveCSR adds an Approved condition to the K8s CSR so that the certchain
// CSR watcher (signer) picks it up. certchain-issuer auto-approves CSRs it
// creates; trust is enforced by who can create CertchainClusterIssuer objects.
func ApproveCSR(ctx context.Context, client kubernetes.Interface, name string) error {
	csr, err := client.CertificatesV1().CertificateSigningRequests().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	// Already approved — nothing to do.
	for _, c := range csr.Status.Conditions {
		if c.Type == certificatesv1.CertificateApproved {
			return nil
		}
	}
	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:               certificatesv1.CertificateApproved,
		Status:             corev1.ConditionTrue,
		Reason:             "CertchainIssuerApproved",
		Message:            "Approved by certchain-issuer; trust enforced via CertchainClusterIssuer RBAC",
		LastUpdateTime:     metav1.Now(),
	})
	_, err = client.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, name, csr, metav1.UpdateOptions{})
	return err
}

// WaitForCert polls the K8s CSR until status.certificate is populated or ctx
// is cancelled. Returns the PEM-encoded certificate bytes.
func WaitForCert(ctx context.Context, client kubernetes.Interface, name string, pollInterval time.Duration) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}

		csr, err := client.CertificatesV1().CertificateSigningRequests().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get CSR %s: %w", name, err)
		}
		// Check for a Failed condition before checking for a cert.
		for _, c := range csr.Status.Conditions {
			if c.Type == certificatesv1.CertificateFailed {
				return nil, fmt.Errorf("CSR %s marked Failed: %s", name, c.Message)
			}
		}
		if len(csr.Status.Certificate) > 0 {
			return csr.Status.Certificate, nil
		}
	}
}
