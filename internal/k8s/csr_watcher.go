// csr_watcher.go — watches Kubernetes CertificateSigningRequest objects and
// drives AVX-based certificate issuance.
//
// When a CSR with the configured signerName is Approved, the watcher:
//  1. Annotates the CSR to claim it (annotation-based deduplication across replicas).
//  2. Submits the CSR DER to AppViewX and stores the AVX request ID in an annotation.
//  3. Writes an immutable TxCertRequest block to the certchain (audit trail).
//  4. Polls AVX until the cert is issued (with exponential backoff; CM-19).
//  5. Writes the issued certificate PEM back to status.certificate on the CSR.
//
// On permanent failure (max retries exceeded): adds a "Failed" condition to the
// K8s CSR and logs at ERROR level (CM-19 mitigation).
package k8s

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"log"
	"sync"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	"github.com/amosdavis/certchain/internal/avx"
	"github.com/amosdavis/certchain/internal/chain"
	"github.com/amosdavis/certchain/internal/crypto"
)

const (
	annotationAVXRequestID = "certchain.io/avx-request-id"
	annotationSubmitted    = "pending"

	defaultCSRPollInterval = 15 * time.Second
	defaultCSRMaxRetries   = 10
)

// BlockSubmitFunc is a function that creates and commits a signed block to the
// chain.  certd passes a closure that holds the mutex protecting nonce/chain
// state, so the CSR watcher never races with the AVX poll loop.
type BlockSubmitFunc func(tx chain.Transaction) error

// CSRWatcher watches Kubernetes CertificateSigningRequest objects for the
// configured signerName and drives AVX certificate issuance.
type CSRWatcher struct {
	k8sClient   kubernetes.Interface
	avxClient   *avx.Client
	identity    *crypto.Identity
	signerName  string
	submitBlock BlockSubmitFunc

	// Configurable timing — override with WithXxx methods in tests.
	pollInterval time.Duration
	backoffSleep time.Duration
	maxRetries   int

	stop chan struct{}
	wg   sync.WaitGroup
}

// NewCSRWatcher creates a CSRWatcher.
// submitBlock must be concurrency-safe; certd provides a mutex-protected closure.
func NewCSRWatcher(
	k8sClient kubernetes.Interface,
	avxClient *avx.Client,
	identity *crypto.Identity,
	signerName string,
	submitBlock BlockSubmitFunc,
) *CSRWatcher {
	return &CSRWatcher{
		k8sClient:    k8sClient,
		avxClient:    avxClient,
		identity:     identity,
		signerName:   signerName,
		submitBlock:  submitBlock,
		pollInterval: defaultCSRPollInterval,
		backoffSleep: backoffBase,
		maxRetries:   defaultCSRMaxRetries,
		stop:         make(chan struct{}),
	}
}

// WithPollInterval overrides the AVX status poll interval (default 15 s).
// Used in tests to avoid long waits.
func (w *CSRWatcher) WithPollInterval(d time.Duration) *CSRWatcher {
	w.pollInterval = d
	return w
}

// WithBackoffBase overrides the retry backoff base duration (default 5 s).
// Used in tests to avoid long waits.
func (w *CSRWatcher) WithBackoffBase(d time.Duration) *CSRWatcher {
	w.backoffSleep = d
	return w
}

// WithMaxRetries overrides the maximum number of AVX submit retries (default 10).
// Used in tests to fail fast.
func (w *CSRWatcher) WithMaxRetries(n int) *CSRWatcher {
	w.maxRetries = n
	return w
}

// Start begins watching for CertificateSigningRequests in the background.
func (w *CSRWatcher) Start() {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.watchLoop()
	}()
}

// Stop shuts down the watcher and waits for the background goroutine to exit.
func (w *CSRWatcher) Stop() {
	close(w.stop)
	w.wg.Wait()
}

// HandleCSR processes a single approved CSR synchronously.
// This is exported for use in BDD tests that need deterministic behaviour
// without starting the background watch goroutine.
// It applies the same guard checks as the watch loop: signer name, annotation,
// and status.certificate presence.
func (w *CSRWatcher) HandleCSR(csr *certificatesv1.CertificateSigningRequest) {
	if csr.Spec.SignerName != w.signerName {
		return
	}
	if !isApproved(csr) {
		return
	}
	if _, claimed := csr.Annotations[annotationAVXRequestID]; claimed {
		return
	}
	if len(csr.Status.Certificate) > 0 {
		return
	}
	w.handleCSR(csr)
}

// watchLoop establishes a K8s watch and processes events.  It reconnects on
// transient errors with exponential backoff.
func (w *CSRWatcher) watchLoop() {
	sleep := backoffBase
	for {
		if err := w.runWatch(); err != nil {
			select {
			case <-w.stop:
				return
			default:
			}
			log.Printf("k8s csr-watcher: WARN watch error (retry in %v): %v", sleep, err)
			select {
			case <-time.After(sleep):
			case <-w.stop:
				return
			}
			sleep *= 2
			if sleep > backoffMax {
				sleep = backoffMax
			}
			continue
		}
		select {
		case <-w.stop:
			return
		default:
			sleep = backoffBase
		}
	}
}

// runWatch establishes one watch session and handles events until the watch
// channel closes or the watcher is stopped.
func (w *CSRWatcher) runWatch() error {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-w.stop
		cancel()
	}()
	defer cancel()

	watcher, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Watch(
		ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("create watch: %w", err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-w.stop:
			return nil
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("watch channel closed")
			}
			if event.Type != watch.Added && event.Type != watch.Modified {
				continue
			}
			csr, ok := event.Object.(*certificatesv1.CertificateSigningRequest)
			if !ok {
				continue
			}
			if csr.Spec.SignerName != w.signerName {
				continue
			}
			if !isApproved(csr) {
				continue
			}
			// Skip if already being processed or completed.
			if _, claimed := csr.Annotations[annotationAVXRequestID]; claimed {
				continue
			}
			// status.certificate is set when issuance has completed.
			if len(csr.Status.Certificate) > 0 {
				continue
			}
			go w.handleCSR(csr)
		}
	}
}

// handleCSR processes a single approved CSR: submits to AVX, writes on-chain
// audit record, polls for issuance, and writes the cert back to K8s.
func (w *CSRWatcher) handleCSR(csr *certificatesv1.CertificateSigningRequest) {
	ctx := context.Background()
	name := csr.Name

	// Claim the CSR atomically via optimistic locking (resourceVersion).
	claimed, err := w.claimCSR(ctx, csr)
	if err != nil || !claimed {
		return
	}

	csrDER := csr.Spec.Request

	// Submit CSR to AVX (CM-19 backoff).
	avxRequestID, err := w.submitToAVX(ctx, csrDER)
	if err != nil {
		log.Printf("k8s csr-watcher: ERROR AVX CSR submission failed for %s after retries: %v", name, err)
		w.markFailed(ctx, name, "AVX CSR submission failed: "+err.Error())
		return
	}

	// Persist AVX request ID in annotation so other replicas skip this CSR.
	if err := w.updateAnnotation(ctx, name, avxRequestID); err != nil {
		log.Printf("k8s csr-watcher: WARN could not update AVX request ID annotation for %s: %v", name, err)
	}

	// Write immutable audit record on-chain.
	cn, sans := cnAndSANs(csr)
	csrHash := sha256.Sum256(csrDER)
	payload, err := chain.MarshalCertRequest(&chain.CertRequestPayload{
		CSRHash: csrHash,
		CN:      cn,
		SANs:    sans,
	})
	if err != nil {
		log.Printf("k8s csr-watcher: WARN marshal TxCertRequest for %s: %v", name, err)
	} else {
		tx := chain.Transaction{
			Type:       chain.TxCertRequest,
			NodePubkey: w.identity.PublicKey,
			Timestamp:  chain.Now(),
			Payload:    payload,
		}
		chain.Sign(&tx, w.identity)
		if err := w.submitBlock(tx); err != nil {
			log.Printf("k8s csr-watcher: WARN submit TxCertRequest for %s: %v", name, err)
		}
	}

	// Poll AVX until issued or max retries (CM-19).
	certPEM, err := w.pollUntilIssued(ctx, avxRequestID)
	if err != nil {
		log.Printf("k8s csr-watcher: ERROR cert issuance failed for %s: %v", name, err)
		w.markFailed(ctx, name, "AVX cert issuance failed: "+err.Error())
		return
	}

	// Write issued cert PEM back to K8s CSR status.certificate.
	if err := w.writeCertificate(ctx, name, certPEM); err != nil {
		log.Printf("k8s csr-watcher: ERROR write certificate status for %s: %v", name, err)
	}
}

// claimCSR annotates the CSR with a "pending" AVX request ID to prevent other
// replicas from resubmitting the same CSR.  Uses optimistic locking via
// resourceVersion.  Returns (true, nil) if the claim succeeded.
func (w *CSRWatcher) claimCSR(ctx context.Context, csr *certificatesv1.CertificateSigningRequest) (bool, error) {
	updated := csr.DeepCopy()
	if updated.Annotations == nil {
		updated.Annotations = make(map[string]string)
	}
	updated.Annotations[annotationAVXRequestID] = annotationSubmitted

	_, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Update(
		ctx, updated, metav1.UpdateOptions{})
	if k8serrors.IsConflict(err) {
		// Another replica claimed it first.
		return false, nil
	}
	return err == nil, err
}

// submitToAVX submits the PKCS#10 DER to AppViewX with exponential backoff (CM-19).
func (w *CSRWatcher) submitToAVX(ctx context.Context, csrDER []byte) (string, error) {
	sleep := w.backoffSleep
	for i := 0; i < w.maxRetries; i++ {
		reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		id, err := w.avxClient.SubmitCSR(reqCtx, csrDER)
		cancel()
		if err == nil {
			return id, nil
		}
		log.Printf("k8s csr-watcher: WARN AVX CSR submit attempt %d/%d failed (retry in %v): %v",
			i+1, w.maxRetries, sleep, err)
		select {
		case <-time.After(sleep):
		case <-w.stop:
			return "", fmt.Errorf("watcher stopped")
		}
		sleep *= 2
		if sleep > backoffMax {
			sleep = backoffMax
		}
	}
	return "", fmt.Errorf("max retries (%d) exceeded", w.maxRetries)
}

// pollUntilIssued polls AVX for request status until it transitions to ISSUED
// or a terminal failure state.
func (w *CSRWatcher) pollUntilIssued(ctx context.Context, avxRequestID string) ([]byte, error) {
	for i := 0; i < w.maxRetries*3; i++ {
		select {
		case <-time.After(w.pollInterval):
		case <-w.stop:
			return nil, fmt.Errorf("watcher stopped")
		}

		pollCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		status, err := w.avxClient.GetRequestStatus(pollCtx, avxRequestID)
		cancel()
		if err != nil {
			log.Printf("k8s csr-watcher: WARN AVX status poll failed (will retry): %v", err)
			continue
		}

		switch status.Status {
		case "ISSUED":
			derCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			der, err := w.avxClient.GetDER(derCtx, status.CertID)
			cancel()
			if err != nil {
				return nil, fmt.Errorf("download issued cert DER: %w", err)
			}
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			return pemBytes, nil
		case "REJECTED", "FAILED":
			return nil, fmt.Errorf("AVX rejected CSR: status=%s", status.Status)
		}
		// PENDING — keep polling
	}
	return nil, fmt.Errorf("timed out waiting for AVX to issue certificate")
}

// updateAnnotation patches the AVX request ID annotation on the CSR.
func (w *CSRWatcher) updateAnnotation(ctx context.Context, name, avxRequestID string) error {
	csr, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Get(
		ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if csr.Annotations == nil {
		csr.Annotations = make(map[string]string)
	}
	csr.Annotations[annotationAVXRequestID] = avxRequestID
	_, err = w.k8sClient.CertificatesV1().CertificateSigningRequests().Update(
		ctx, csr, metav1.UpdateOptions{})
	return err
}

// writeCertificate sets status.certificate on the K8s CSR object.
func (w *CSRWatcher) writeCertificate(ctx context.Context, name string, certPEM []byte) error {
	csr, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Get(
		ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	csr.Status.Certificate = certPEM
	_, err = w.k8sClient.CertificatesV1().CertificateSigningRequests().UpdateStatus(
		ctx, csr, metav1.UpdateOptions{})
	return err
}

// markFailed adds a Failed condition to the K8s CSR (CM-19).
func (w *CSRWatcher) markFailed(ctx context.Context, name, reason string) {
	csr, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Get(
		ctx, name, metav1.GetOptions{})
	if err != nil {
		log.Printf("k8s csr-watcher: could not get CSR %s to mark failed: %v", name, err)
		return
	}
	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:               certificatesv1.CertificateFailed,
		Status:             corev1.ConditionTrue,
		Reason:             "AVXIssuanceFailed",
		Message:            reason,
		LastUpdateTime:     metav1.Now(),
	})
	if _, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().UpdateStatus(
		ctx, csr, metav1.UpdateOptions{}); err != nil {
		log.Printf("k8s csr-watcher: could not update Failed status for %s: %v", name, err)
	}
}

// isApproved returns true if the CSR has an Approved condition.
func isApproved(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, c := range csr.Status.Conditions {
		if c.Type == certificatesv1.CertificateApproved && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// cnAndSANs extracts CN and SANs from the CSR metadata.
func cnAndSANs(csr *certificatesv1.CertificateSigningRequest) (string, []string) {
	cn := csr.Name // fallback: use K8s object name
	var sans []string
	// Prefer explicit username/groups as rough CN; real CN lives in the PKCS#10 DER.
	if csr.Spec.Username != "" {
		cn = csr.Spec.Username
	}
	return cn, sans
}
