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
	"strings"
	"time"

	"github.com/amosdavis/certchain/internal/logging"
	"github.com/amosdavis/certchain/internal/metrics"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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

	// Resolve issuer and patch its Ready status condition.
	ri, err := c.resolveIssuer(ctx, cr)
	if err != nil {
		c.logger.Info("skip CertificateRequest: cannot resolve issuer", "namespace", ns, "name", name, "err", err)
		c.recordOutcome("issuer_unresolved")
		_ = c.patchIssuerStatus(ctx, ri, false, "NotReady", err.Error())
		return
	}
	_ = c.patchIssuerStatus(ctx, ri, true, "Available", "certchain-issuer is reconciling CertificateRequests")
	signerName := ri.signerName

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

	// M8: emit an auditable Event on the CertificateRequest recording that
	// certchain-issuer auto-approved the derived K8s CSR. Deterministic name
	// keeps reconciles idempotent.
	if err := c.emitApprovalEvent(ctx, cr, ri.kind, ri.name); err != nil {
		c.logger.Warn("emit approval event failed", "namespace", ns, "name", name, "err", err)
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

	if err := c.patchApproved(ctx, ns, name, certPEM, ri.kind, ri.name); err != nil {
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

// resolvedIssuer captures the coordinates of the CertchainClusterIssuer or
// CertchainIssuer referenced by a CertificateRequest along with the fetched
// object. The object and signerName are only populated on successful
// resolution; kind/name/namespace are best-effort and may be populated even on
// failure so callers can still patch the issuer's status.
type resolvedIssuer struct {
	kind       string
	name       string
	namespace  string // empty for cluster-scoped
	gvr        schema.GroupVersionResource
	obj        *unstructured.Unstructured
	signerName string
}

// resolveIssuer looks up the CertchainClusterIssuer or CertchainIssuer
// referenced by the CertificateRequest and returns the resolved coordinates
// plus signerName. Returns the partially populated resolvedIssuer (with
// kind/name set) on failure so callers can still report status.
func (c *Controller) resolveIssuer(ctx context.Context, cr *unstructured.Unstructured) (*resolvedIssuer, error) {
	issuerKind, _, _ := unstructured.NestedString(cr.Object, "spec", "issuerRef", "kind")
	issuerName, _, _ := unstructured.NestedString(cr.Object, "spec", "issuerRef", "name")
	crNamespace := cr.GetNamespace()

	ri := &resolvedIssuer{name: issuerName}

	switch issuerKind {
	case "CertchainClusterIssuer", "":
		ri.kind = "CertchainClusterIssuer"
		ri.gvr = clusterIssuerGVR
	case "CertchainIssuer":
		ri.kind = "CertchainIssuer"
		ri.gvr = issuerGVR
		ri.namespace = crNamespace
	default:
		ri.kind = issuerKind
		return ri, fmt.Errorf("unknown issuer kind %q", issuerKind)
	}

	var (
		obj *unstructured.Unstructured
		err error
	)
	if ri.namespace == "" {
		obj, err = c.dynClient.Resource(ri.gvr).Get(ctx, issuerName, metav1.GetOptions{})
	} else {
		obj, err = c.dynClient.Resource(ri.gvr).Namespace(ri.namespace).Get(ctx, issuerName, metav1.GetOptions{})
	}
	if err != nil {
		return ri, fmt.Errorf("get issuer %s/%s: %w", ri.kind, issuerName, err)
	}
	ri.obj = obj

	signerName, _, _ := unstructured.NestedString(obj.Object, "spec", "signerName")
	if signerName == "" {
		signerName = defaultSignerName
	}
	if !strings.HasPrefix(signerName, "certchain.io/") {
		return ri, fmt.Errorf("issuer %s/%s spec.signerName %q is invalid: must start with %q",
			ri.kind, issuerName, signerName, "certchain.io/")
	}
	ri.signerName = signerName
	return ri, nil
}

// patchIssuerStatus patches the issuer's status.conditions with a single
// Ready condition (True when ready, False otherwise). It avoids hot-looping
// by skipping the patch when the desired condition already matches the
// existing object. When ri is nil or has no kind/name the call is a no-op.
func (c *Controller) patchIssuerStatus(ctx context.Context, ri *resolvedIssuer, ready bool, reason, message string) error {
	if ri == nil || ri.name == "" || ri.gvr.Resource == "" {
		return nil
	}

	status := "False"
	if ready {
		status = "True"
	}

	if ri.obj != nil {
		conds, _, _ := unstructured.NestedSlice(ri.obj.Object, "status", "conditions")
		for _, raw := range conds {
			m, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			if m["type"] == "Ready" && m["status"] == status && m["reason"] == reason && m["message"] == message {
				return nil
			}
		}
	}

	patch := map[string]interface{}{
		"status": map[string]interface{}{
			"conditions": []map[string]interface{}{
				{
					"type":               "Ready",
					"status":             status,
					"reason":             reason,
					"message":            message,
					"lastTransitionTime": metav1.Now().UTC().Format(time.RFC3339),
				},
			},
		},
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	var client dynamic.ResourceInterface = c.dynClient.Resource(ri.gvr)
	if ri.namespace != "" {
		client = c.dynClient.Resource(ri.gvr).Namespace(ri.namespace)
	}
	if _, err := client.Patch(ctx, ri.name, types.MergePatchType, data, metav1.PatchOptions{}, "status"); err != nil {
		c.logger.Debug("patch issuer status failed", "kind", ri.kind, "name", ri.name, "err", err)
		return err
	}
	return nil
}

// emitApprovalEvent records a Normal event against the CertificateRequest
// documenting that certchain-issuer auto-approved the derived K8s CSR on
// behalf of the referenced issuer. The event name is derived from the CR UID
// so reconciles remain idempotent (AlreadyExists is treated as success).
func (c *Controller) emitApprovalEvent(ctx context.Context, cr *unstructured.Unstructured, issuerKind, issuerName string) error {
	if c.k8sClient == nil {
		return nil
	}
	uid := string(cr.GetUID())
	if uid == "" {
		return nil
	}
	ns := cr.GetNamespace()
	now := metav1.Now()
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "certchain-approved-" + uid,
			Namespace: ns,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:       "CertificateRequest",
			APIVersion: "cert-manager.io/v1",
			Namespace:  ns,
			Name:       cr.GetName(),
			UID:        cr.GetUID(),
		},
		Reason:         "CertchainApproved",
		Message:        fmt.Sprintf("approved by %s/%s (cr=%s/%s)", issuerKind, issuerName, ns, cr.GetName()),
		Type:           corev1.EventTypeNormal,
		Source:         corev1.EventSource{Component: "certchain-issuer"},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
	}
	_, err := c.k8sClient.CoreV1().Events(ns).Create(ctx, ev, metav1.CreateOptions{})
	if k8serrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// patchApproved sets status.certificate and the Ready/Approved conditions on
// the CertificateRequest using a strategic merge patch. The Approved
// condition message records the CR coordinates and authorizing issuer for
// audit purposes.
func (c *Controller) patchApproved(ctx context.Context, ns, name string, certPEM []byte, issuerKind, issuerName string) error {
	approvedMsg := fmt.Sprintf("approved by %s/%s (cr=%s/%s)", issuerKind, issuerName, ns, name)
	patch := map[string]interface{}{
		"status": map[string]interface{}{
			"certificate": base64.StdEncoding.EncodeToString(certPEM),
			"conditions": []map[string]interface{}{
				{
					"type":               "Approved",
					"status":             "True",
					"reason":             "CertchainIssued",
					"message":            approvedMsg,
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
