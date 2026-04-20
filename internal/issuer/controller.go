// Package issuer implements the certchain external issuer controller.
//
// The controller watches cert-manager CertificateRequest objects (via the
// Kubernetes dynamic client — no cert-manager Go dependency required) and
// bridges them to K8s CertificateSigningRequest objects processed by certd's
// existing CSR watcher.
//
// Reconcile loop per CertificateRequest:
//  1. Skip if issuerRef.group != "certchain.io" or status.certificate is set.
//  2. Resolve the CertchainClusterIssuer / CertchainIssuer; skip if not Ready.
//  3. Create a K8s CSR named "certchain-<cr-uid>" with spec.request from the CR.
//  4. Auto-approve the K8s CSR (trust enforced by RBAC on CertchainClusterIssuer).
//  5. Poll until certd's CSR watcher writes status.certificate.
//  6. Patch the CertificateRequest status with the issued cert.
package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/amosdavis/certchain/internal/logging"
	"github.com/amosdavis/certchain/internal/metrics"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var (
	certificateRequestGVR = schema.GroupVersionResource{
		Group:    "cert-manager.io",
		Version:  "v1",
		Resource: "certificaterequests",
	}
	clusterIssuerGVR = schema.GroupVersionResource{
		Group:    "certchain.io",
		Version:  "v1alpha1",
		Resource: "certchainclusterissuers",
	}
	issuerGVR = schema.GroupVersionResource{
		Group:    "certchain.io",
		Version:  "v1alpha1",
		Resource: "certchainissuers",
	}
)

const (
	defaultPollInterval     = 5 * time.Second
	defaultCertWaitTimeout  = 10 * time.Minute
	defaultSignerName       = "certchain.io/appviewx"
)

// Controller reconciles cert-manager CertificateRequest objects.
type Controller struct {
	dynClient    dynamic.Interface
	k8sClient    kubernetes.Interface
	pollInterval time.Duration
	certTimeout  time.Duration
	logger       *slog.Logger
	metrics      *metrics.IssuerMetrics
}

// NewController creates a Controller.
func NewController(dynClient dynamic.Interface, k8sClient kubernetes.Interface) *Controller {
	return &Controller{
		dynClient:    dynClient,
		k8sClient:    k8sClient,
		pollInterval: defaultPollInterval,
		certTimeout:  defaultCertWaitTimeout,
		logger:       logging.Discard(),
	}
}

// WithLogger sets the logger. Must be called before Run.
func (c *Controller) WithLogger(l *slog.Logger) *Controller {
	if l != nil {
		c.logger = l.With("component", "issuer")
	}
	return c
}

// WithMetrics sets the metrics collector.
func (c *Controller) WithMetrics(m *metrics.IssuerMetrics) *Controller {
	c.metrics = m
	return c
}

// WithPollInterval overrides the K8s CSR status poll interval. Used in tests.
func (c *Controller) WithPollInterval(d time.Duration) *Controller {
	c.pollInterval = d
	return c
}

// WithCertTimeout overrides the maximum time to wait for cert issuance. Used in tests.
func (c *Controller) WithCertTimeout(d time.Duration) *Controller {
	c.certTimeout = d
	return c
}

// Run starts the watch loop and blocks until ctx is cancelled.
func (c *Controller) Run(ctx context.Context) error {
	// List all namespaces — use "" for cluster-wide watch.
	watcher, err := c.dynClient.Resource(certificateRequestGVR).Namespace("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("watch CertificateRequests: %w", err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("CertificateRequest watch channel closed")
			}
			if event.Type != watch.Added && event.Type != watch.Modified {
				continue
			}
			cr, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				continue
			}
			go c.reconcile(ctx, cr)
		}
	}
}

// reconcile processes a single CertificateRequest.
func (c *Controller) reconcile(ctx context.Context, cr *unstructured.Unstructured) {
	name := cr.GetName()
	ns := cr.GetNamespace()
	uid := string(cr.GetUID())

	// Guard: must be for certchain.io issuer group.
	issuerGroup, _, _ := unstructured.NestedString(cr.Object, "spec", "issuerRef", "group")
	if issuerGroup != "certchain.io" {
		return
	}

	// Guard: skip if cert is already set.
	existingCert, _, _ := unstructured.NestedString(cr.Object, "status", "certificate")
	if existingCert != "" {
		return
	}

	// Guard: skip if already failed (has a Failed condition).
	if hasCRCondition(cr, "Failed") {
		return
	}

	// Resolve issuer to get signerName.
	signerName, err := c.resolveSignerName(ctx, cr)
	if err != nil {
		c.logger.Info("skip CertificateRequest: cannot resolve issuer", "namespace", ns, "name", name, "err", err)
		c.recordOutcome("issuer_unresolved")
		return
	}

	// Extract PKCS#10 CSR DER from spec.request (base64-encoded in the CR).
	csrB64, _, _ := unstructured.NestedString(cr.Object, "spec", "request")
	csrDER, err := base64.StdEncoding.DecodeString(csrB64)
	if err != nil {
		// cert-manager base64-encodes the field; try URL encoding as fallback.
		csrDER, err = base64.URLEncoding.DecodeString(csrB64)
		if err != nil {
			c.logger.Error("CR spec.request is not valid base64", "namespace", ns, "name", name, "err", err)
			c.recordOutcome("invalid_csr_encoding")
			_ = c.patchFailed(ctx, ns, name, "spec.request is not valid base64")
			return
		}
	}

	// K8s CSR name derived from CR UID so it is globally unique and idempotent.
	csrName := "certchain-" + uid

	if err := CreateCSR(ctx, c.k8sClient, csrName, signerName, csrDER); err != nil {
		c.logger.Error("create K8s CSR failed", "namespace", ns, "name", name, "csr", csrName, "err", err)
		c.recordOutcome("create_csr_failed")
		return
	}

	if err := ApproveCSR(ctx, c.k8sClient, csrName); err != nil {
		c.logger.Error("approve K8s CSR failed", "namespace", ns, "name", name, "csr", csrName, "err", err)
		c.recordOutcome("approve_csr_failed")
		return
	}

	certCtx, cancel := context.WithTimeout(ctx, c.certTimeout)
	defer cancel()

	certPEM, err := WaitForCert(certCtx, c.k8sClient, csrName, c.pollInterval)
	if err != nil {
		c.logger.Error("wait for cert failed", "namespace", ns, "name", name, "csr", csrName, "err", err)
		c.recordOutcome("wait_cert_failed")
		_ = c.patchFailed(ctx, ns, name, err.Error())
		return
	}

	if err := c.patchApproved(ctx, ns, name, certPEM); err != nil {
		c.logger.Error("patch CertificateRequest failed", "namespace", ns, "name", name, "err", err)
		c.recordOutcome("patch_failed")
		return
	}
	c.recordOutcome("issued")
}

func (c *Controller) recordOutcome(outcome string) {
	if c.metrics != nil {
		c.metrics.RequestsTotal.WithLabelValues(outcome).Inc()
	}
}

// resolveSignerName looks up the CertchainClusterIssuer or CertchainIssuer
// referenced by the CertificateRequest and returns its spec.signerName.
// Returns the default signerName if the field is absent.
func (c *Controller) resolveSignerName(ctx context.Context, cr *unstructured.Unstructured) (string, error) {
	issuerKind, _, _ := unstructured.NestedString(cr.Object, "spec", "issuerRef", "kind")
	issuerName, _, _ := unstructured.NestedString(cr.Object, "spec", "issuerRef", "name")
	crNamespace := cr.GetNamespace()

	var issuerObj *unstructured.Unstructured
	var err error

	switch issuerKind {
	case "CertchainClusterIssuer", "":
		issuerObj, err = c.dynClient.Resource(clusterIssuerGVR).Get(ctx, issuerName, metav1.GetOptions{})
	case "CertchainIssuer":
		issuerObj, err = c.dynClient.Resource(issuerGVR).Namespace(crNamespace).Get(ctx, issuerName, metav1.GetOptions{})
	default:
		return "", fmt.Errorf("unknown issuer kind %q", issuerKind)
	}
	if err != nil {
		return "", fmt.Errorf("get issuer %s/%s: %w", issuerKind, issuerName, err)
	}

	signerName, _, _ := unstructured.NestedString(issuerObj.Object, "spec", "signerName")
	if signerName == "" {
		signerName = defaultSignerName
	}
	return signerName, nil
}

// patchApproved sets status.certificate and the Ready/Approved conditions on
// the CertificateRequest using a strategic merge patch.
func (c *Controller) patchApproved(ctx context.Context, ns, name string, certPEM []byte) error {
	patch := map[string]interface{}{
		"status": map[string]interface{}{
			"certificate": base64.StdEncoding.EncodeToString(certPEM),
			"conditions": []map[string]interface{}{
				{
					"type":               "Approved",
					"status":             "True",
					"reason":             "CertchainIssued",
					"message":            "Certificate issued by certchain via AppViewX",
					"lastTransitionTime": metav1.Now().UTC().Format(time.RFC3339),
				},
				{
					"type":               "Ready",
					"status":             "True",
					"reason":             "Issued",
					"message":            "Certificate is issued",
					"lastTransitionTime": metav1.Now().UTC().Format(time.RFC3339),
				},
			},
		},
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, err = c.dynClient.Resource(certificateRequestGVR).Namespace(ns).Patch(
		ctx, name, types.MergePatchType, data, metav1.PatchOptions{}, "status")
	return err
}

// patchFailed sets a Failed condition on the CertificateRequest.
func (c *Controller) patchFailed(ctx context.Context, ns, name, reason string) error {
	patch := map[string]interface{}{
		"status": map[string]interface{}{
			"conditions": []map[string]interface{}{
				{
					"type":               "Failed",
					"status":             "True",
					"reason":             "CertchainIssuanceFailed",
					"message":            reason,
					"lastTransitionTime": metav1.Now().UTC().Format(time.RFC3339),
				},
			},
		},
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, err = c.dynClient.Resource(certificateRequestGVR).Namespace(ns).Patch(
		ctx, name, types.MergePatchType, data, metav1.PatchOptions{}, "status")
	return err
}

// hasCRCondition returns true if the CertificateRequest has a condition of the
// given type with status "True".
func hasCRCondition(cr *unstructured.Unstructured, condType string) bool {
	conditions, _, _ := unstructured.NestedSlice(cr.Object, "status", "conditions")
	for _, raw := range conditions {
		c, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if c["type"] == condType && c["status"] == "True" {
			return true
		}
	}
	return false
}
