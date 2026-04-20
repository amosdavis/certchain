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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
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
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
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
	// defaultMaxRetries caps the number of workqueue retries for a single
	// CertificateRequest key before certchain-issuer emits a CertchainGiveUp
	// Event and drops the key (CM-31).
	defaultMaxRetries = 5
)

// Controller reconciles cert-manager CertificateRequest objects.
type Controller struct {
	dynClient    dynamic.Interface
	k8sClient    kubernetes.Interface
	pollInterval time.Duration
	certTimeout  time.Duration
	logger       *slog.Logger
	metrics      *metrics.IssuerMetrics

	// Workqueue + worker pool (H5 / CM-31). queue is created lazily by
	// Run or initQueue so tests that invoke reconcile directly still work.
	queueOnce sync.Once
	queue     workqueue.RateLimitingInterface

	// maxRetries caps rate-limited retries per key (default 5).
	maxRetries int

	// reconcileKeyFn is the worker callback; swappable in tests. When nil,
	// the controller's real reconcileKey is used.
	reconcileKeyFn func(ctx context.Context, key string) error

	// cachesSynced is flipped to true after the informer's WaitForCacheSync
	// (or the initial List on the dynamic watch) returns. P5 readiness
	// reads this via CachesSynced().
	cachesSynced atomic.Bool
}

// NewController creates a Controller.
func NewController(dynClient dynamic.Interface, k8sClient kubernetes.Interface) *Controller {
	return &Controller{
		dynClient:    dynClient,
		k8sClient:    k8sClient,
		pollInterval: defaultPollInterval,
		certTimeout:  defaultCertWaitTimeout,
		logger:       logging.Discard(),
		maxRetries:   defaultMaxRetries,
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

// WithMaxRetries overrides the workqueue give-up threshold (default 5).
func (c *Controller) WithMaxRetries(n int) *Controller {
	if n > 0 {
		c.maxRetries = n
	}
	return c
}

// WithReconcileKeyFunc overrides the per-key worker callback. Used in tests
// to exercise burst / retry / give-up paths without the full reconcile.
func (c *Controller) WithReconcileKeyFunc(fn func(ctx context.Context, key string) error) *Controller {
	c.reconcileKeyFn = fn
	return c
}

// CachesSynced reports whether the controller has finished its initial
// cache sync. Used by /readyz (P5 / CM-27) — always reads atomically, never
// blocks.
func (c *Controller) CachesSynced() bool {
	return c.cachesSynced.Load()
}

// Queue exposes the rate-limiting workqueue. Lazily created. Callers may
// use it to enqueue keys before Run (e.g. tests).
func (c *Controller) Queue() workqueue.RateLimitingInterface {
	c.initQueue()
	return c.queue
}

func (c *Controller) initQueue() {
	c.queueOnce.Do(func() {
		c.queue = workqueue.NewNamedRateLimitingQueue(
			workqueue.DefaultControllerRateLimiter(),
			"certchain-issuer",
		)
	})
}

// Run starts the workqueue + worker pool and blocks until ctx is cancelled.
// workers must be >= 1; values <=0 are clamped to 1 to preserve the legacy
// serial behaviour.
func (c *Controller) Run(ctx context.Context, workers int) error {
	if workers < 1 {
		workers = 1
	}
	c.initQueue()

	// Ensure ShutDown runs exactly once even on early-exit paths.
	var shutOnce sync.Once
	shutdown := func() { shutOnce.Do(func() { c.queue.ShutDown() }) }
	defer shutdown()

	// Establish the CertificateRequest watch. A full informer would be
	// preferable long-term, but the dynamic watch matches what the fake
	// dynamic client supports and what certchain-issuer has used since M1.
	watcher, err := c.dynClient.Resource(certificateRequestGVR).Namespace("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("watch CertificateRequests: %w", err)
	}
	defer watcher.Stop()

	// After the watch is established, caches are effectively synced for the
	// purposes of P5 readiness — an informer's WaitForCacheSync would be
	// the direct analogue.
	c.cachesSynced.Store(true)

	// Start the worker pool.
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for c.processNextItem(ctx) {
			}
		}(i)
	}

	// Enqueue loop: translate watch events into workqueue keys.
	enqueueDone := make(chan struct{})
	go func() {
		defer close(enqueueDone)
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-watcher.ResultChan():
				if !ok {
					return
				}
				if event.Type != watch.Added && event.Type != watch.Modified {
					continue
				}
				cr, ok := event.Object.(*unstructured.Unstructured)
				if !ok {
					continue
				}
				c.enqueueCR(cr)
			}
		}
	}()

	// Wait for shutdown signal, then drain workers.
	<-ctx.Done()
	shutdown()
	<-enqueueDone
	wg.Wait()

	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// enqueueCR adds a CertificateRequest namespaced-name key to the queue.
// Guard filters (wrong issuer group, already-issued, failed) are applied
// lazily in the worker so that late-arriving status updates are still
// processed.
func (c *Controller) enqueueCR(cr *unstructured.Unstructured) {
	key, err := cache.MetaNamespaceKeyFunc(cr)
	if err != nil {
		c.logger.Warn("cannot form workqueue key", "err", err)
		return
	}
	c.initQueue()
	c.queue.Add(key)
	if c.metrics != nil {
		c.metrics.WorkqueueAdds.Inc()
		c.metrics.WorkqueueDepth.Set(float64(c.queue.Len()))
	}
}

// processNextItem pulls one key, runs the reconcile, and handles retry /
// forget bookkeeping. Returns false when the queue has shut down so the
// worker loop can exit.
func (c *Controller) processNextItem(ctx context.Context) bool {
	c.initQueue()
	keyObj, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(keyObj)

	key, ok := keyObj.(string)
	if !ok {
		c.queue.Forget(keyObj)
		return true
	}

	start := time.Now()
	fn := c.reconcileKeyFn
	if fn == nil {
		fn = c.reconcileKey
	}
	err := fn(ctx, key)
	if c.metrics != nil {
		c.metrics.ReconcileDurationSecs.Observe(time.Since(start).Seconds())
		c.metrics.WorkqueueDepth.Set(float64(c.queue.Len()))
	}
	c.handleErr(ctx, err, key)
	return true
}

// handleErr implements the standard controller retry policy: Forget on
// success, AddRateLimited on error until NumRequeues exceeds maxRetries,
// then emit a CertchainGiveUp Event and Forget.
func (c *Controller) handleErr(ctx context.Context, err error, key string) {
	if err == nil {
		c.queue.Forget(key)
		return
	}
	if c.queue.NumRequeues(key) < c.maxRetries {
		c.logger.Info("requeue CertificateRequest after error",
			"key", key, "retries", c.queue.NumRequeues(key), "err", err)
		c.queue.AddRateLimited(key)
		if c.metrics != nil {
			c.metrics.WorkqueueRetries.Inc()
		}
		return
	}
	c.logger.Error("giving up on CertificateRequest after max retries",
		"key", key, "max_retries", c.maxRetries, "err", err)
	c.recordOutcome("give_up")
	if evErr := c.emitGiveUpEvent(ctx, key, err); evErr != nil {
		c.logger.Warn("emit give-up event failed", "key", key, "err", evErr)
	}
	c.queue.Forget(key)
}

// reconcileKey is the default per-key worker: it fetches the CR and
// dispatches to reconcile. A NotFound CR (already deleted) is treated as a
// success to drop the key from the queue.
func (c *Controller) reconcileKey(ctx context.Context, key string) error {
	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("split key %q: %w", key, err)
	}
	cr, err := c.dynClient.Resource(certificateRequestGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get CertificateRequest %s/%s: %w", ns, name, err)
	}
	return c.reconcile(ctx, cr)
}

// emitGiveUpEvent records a Warning Event on the CertificateRequest
// identified by key. Idempotent via deterministic Event name.
func (c *Controller) emitGiveUpEvent(ctx context.Context, key string, cause error) error {
	if c.k8sClient == nil {
		return nil
	}
	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	// Best-effort Get to recover UID; proceed with an empty UID rather than
	// failing the give-up signal.
	cr, getErr := c.dynClient.Resource(certificateRequestGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	uid := ""
	if getErr == nil && cr != nil {
		uid = string(cr.GetUID())
	}
	evName := "certchain-giveup-" + uid
	if uid == "" {
		evName = "certchain-giveup-" + name
	}
	now := metav1.Now()
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      evName,
			Namespace: ns,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:       "CertificateRequest",
			APIVersion: "cert-manager.io/v1",
			Namespace:  ns,
			Name:       name,
		},
		Reason:         "CertchainGiveUp",
		Message:        fmt.Sprintf("giving up after %d retries: %v", c.maxRetries, cause),
		Type:           corev1.EventTypeWarning,
		Source:         corev1.EventSource{Component: "certchain-issuer"},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
	}
	if getErr == nil && cr != nil {
		ev.InvolvedObject.UID = cr.GetUID()
	}
	_, cerr := c.k8sClient.CoreV1().Events(ns).Create(ctx, ev, metav1.CreateOptions{})
	if k8serrors.IsAlreadyExists(cerr) {
		return nil
	}
	return cerr
}

// reconcile processes a single CertificateRequest. Returns nil on success
// or a no-op skip; returns an error to signal a retry-worthy transient
// failure. Status patching for terminal outcomes (Failed condition) happens
// inline before the nil return so that a single success does not re-queue.
func (c *Controller) reconcile(ctx context.Context, cr *unstructured.Unstructured) error {
	name := cr.GetName()
	ns := cr.GetNamespace()
	uid := string(cr.GetUID())

	// Guard: must be for certchain.io issuer group.
	issuerGroup, _, _ := unstructured.NestedString(cr.Object, "spec", "issuerRef", "group")
	if issuerGroup != "certchain.io" {
		return nil
	}

	// Guard: skip if cert is already set.
	existingCert, _, _ := unstructured.NestedString(cr.Object, "status", "certificate")
	if existingCert != "" {
		return nil
	}

	// Guard: skip if already failed (has a Failed condition).
	if hasCRCondition(cr, "Failed") {
		return nil
	}

	// Resolve issuer and patch its Ready status condition.
	ri, err := c.resolveIssuer(ctx, cr)
	if err != nil {
		c.logger.Info("skip CertificateRequest: cannot resolve issuer", "namespace", ns, "name", name, "err", err)
		c.recordOutcome("issuer_unresolved")
		_ = c.patchIssuerStatus(ctx, ri, false, "NotReady", err.Error())
		// Unresolved issuer is terminal for this reconcile pass; the
		// workqueue will revisit on the next CR event.
		return nil
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
			return nil
		}
	}

	// K8s CSR name derived from CR UID so it is globally unique and idempotent.
	csrName := "certchain-" + uid

	if err := CreateCSR(ctx, c.k8sClient, csrName, signerName, csrDER); err != nil {
		c.logger.Error("create K8s CSR failed", "namespace", ns, "name", name, "csr", csrName, "err", err)
		c.recordOutcome("create_csr_failed")
		return fmt.Errorf("create K8s CSR %s: %w", csrName, err)
	}

	if err := ApproveCSR(ctx, c.k8sClient, csrName); err != nil {
		c.logger.Error("approve K8s CSR failed", "namespace", ns, "name", name, "csr", csrName, "err", err)
		c.recordOutcome("approve_csr_failed")
		return fmt.Errorf("approve K8s CSR %s: %w", csrName, err)
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
		return nil
	}

	if err := c.patchApproved(ctx, ns, name, certPEM, ri.kind, ri.name); err != nil {
		c.logger.Error("patch CertificateRequest failed", "namespace", ns, "name", name, "err", err)
		c.recordOutcome("patch_failed")
		return fmt.Errorf("patch CR %s/%s: %w", ns, name, err)
	}
	c.recordOutcome("issued")
	return nil
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
