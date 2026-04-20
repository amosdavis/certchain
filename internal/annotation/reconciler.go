package annotation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/amosdavis/certchain/internal/logging"
	"github.com/amosdavis/certchain/internal/metrics"
)

const (
	// AnnotationCertCN is the user-facing contract: set this to the
	// fully-qualified CN you want a TLS Secret for.
	AnnotationCertCN = "certchain.io/cert-cn"
	// AnnotationSecretName optionally overrides the generated Secret
	// name. When absent the reconciler falls back to
	// "certchain-<sanitized-cn>".
	AnnotationSecretName = "certchain.io/cert-secret-name"

	// LabelManagedBy marks Secrets this controller created. The sweep
	// (and the renewal scheduler) only ever consider Secrets carrying
	// this exact value, which is deliberately distinct from the legacy
	// certd writer's "certd" value so the two paths can never touch the
	// same Secret (CM-30, CM-33).
	LabelManagedBy      = "certchain.io/managed-by"
	LabelManagedByValue = "annotation-ctrl"
	LabelCN             = "certchain.io/cn"

	// EventReasonIssued / EventReasonRenewed / EventReasonError are the
	// reasons emitted on the annotated Pod/Service so `kubectl describe`
	// shows operators exactly what the controller did.
	EventReasonIssued  = "CertchainSecretIssued"
	EventReasonRenewed = "CertchainSecretRenewed"
	EventReasonError   = "CertchainSecretError"
	EventReasonDeleted = "CertchainSecretDeleted"

	// SecretNamePrefix is used when no explicit cert-secret-name
	// annotation is supplied. Chosen so humans can grep for
	// controller-managed Secrets easily.
	SecretNamePrefix = "certchain-"

	// KeyPlaceholder is written into tls.key until the renewal task
	// (native-ann-renewal, separate todo) wires real private-key
	// delivery. See CM-33 for the rationale.
	KeyPlaceholder = "# certchain: private key not yet provisioned (see CM-33 / native-ann-renewal)\n"
)

// RenewalNotifier is the integration surface the separate
// "native-ann-renewal" task will implement. The reconciler calls
// OnNearExpiry(cn) as part of every successful reconcile so the renewal
// scheduler can maintain its own deadline tracker without watching the
// Kubernetes API a second time.
//
// Implementations MUST be non-blocking: returning an error logs a WARN
// but never fails the reconcile. This keeps Secret provisioning robust
// to bugs in the renewal scheduler.
type RenewalNotifier interface {
	OnNearExpiry(ctx context.Context, cn string) error
}

// NopRenewalNotifier is the default RenewalNotifier used until the
// renewal scheduler is wired in. It intentionally does nothing so the
// main reconcile path continues to function in isolation.
type NopRenewalNotifier struct{}

// OnNearExpiry implements RenewalNotifier.
func (NopRenewalNotifier) OnNearExpiry(_ context.Context, _ string) error { return nil }

// Metrics bundles the Prometheus counters/gauges owned by this
// controller. They live on whatever registry the binary creates so
// annotation-ctrl shares the same /metrics endpoint as certd /
// certchain-issuer.
type Metrics struct {
	Reconciles         prometheus.Counter
	Errors             prometheus.Counter
	LastSuccessSeconds prometheus.Gauge
}

// NewMetrics registers the three metrics required by the task
// (certchain_annotation_reconciles_total,
//  certchain_annotation_errors_total,
//  certchain_annotation_last_success_seconds) on the provided registry.
func NewMetrics(r *metrics.Registry) *Metrics {
	m := &Metrics{
		Reconciles: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "certchain",
			Subsystem: "annotation",
			Name:      "reconciles_total",
			Help:      "Total annotation-ctrl reconciles (all outcomes).",
		}),
		Errors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "certchain",
			Subsystem: "annotation",
			Name:      "errors_total",
			Help:      "Annotation-ctrl reconciles that returned an error (excluding not-found which is expected during initial issuance).",
		}),
		LastSuccessSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "certchain",
			Subsystem: "annotation",
			Name:      "last_success_seconds",
			Help:      "Unix timestamp of the most recent successful reconcile.",
		}),
	}
	r.MustRegister(m.Reconciles, m.Errors, m.LastSuccessSeconds)
	return m
}

// Reconciler is the heart of annotation-ctrl. It is deliberately
// stateless beyond a few dependencies so tests can construct it
// directly against a fake clientset.
type Reconciler struct {
	client   kubernetes.Interface
	fetcher  CertFetcher
	logger   *slog.Logger
	metrics  *Metrics
	notifier RenewalNotifier
	// now is injected so tests can pin LastSuccessSeconds deterministically.
	now func() time.Time
	// reconciles is an internal counter exposed to tests when no real
	// prometheus registry is wired up.
	reconciles atomic.Int64
	errors     atomic.Int64
}

// NewReconciler constructs a Reconciler. A nil logger is replaced with
// logging.Discard(); a nil notifier defaults to NopRenewalNotifier.
// metrics may be nil in tests.
func NewReconciler(client kubernetes.Interface, fetcher CertFetcher, logger *slog.Logger, m *Metrics, notifier RenewalNotifier) *Reconciler {
	if logger == nil {
		logger = logging.Discard()
	}
	if notifier == nil {
		notifier = NopRenewalNotifier{}
	}
	return &Reconciler{
		client:   client,
		fetcher:  fetcher,
		logger:   logger.With("component", "annotation-ctrl"),
		metrics:  m,
		notifier: notifier,
		now:      time.Now,
	}
}

// ObjectRef is a narrow view of a Pod or Service the reconciler is
// asked to process. The controller constructs these from informer
// events; tests build them inline.
type ObjectRef struct {
	Kind        string // "Pod" or "Service"
	APIVersion  string // "v1"
	Namespace   string
	Name        string
	UID         types.UID
	Annotations map[string]string
}

// podRef / serviceRef are small helpers so the watch loop doesn't have
// to duplicate field extraction.
func podRef(p *corev1.Pod) ObjectRef {
	return ObjectRef{
		Kind:        "Pod",
		APIVersion:  "v1",
		Namespace:   p.Namespace,
		Name:        p.Name,
		UID:         p.UID,
		Annotations: p.Annotations,
	}
}

func serviceRef(s *corev1.Service) ObjectRef {
	return ObjectRef{
		Kind:        "Service",
		APIVersion:  "v1",
		Namespace:   s.Namespace,
		Name:        s.Name,
		UID:         s.UID,
		Annotations: s.Annotations,
	}
}

// Reconcile processes one Pod/Service. It is safe to call concurrently
// from different goroutines; Kubernetes' optimistic-concurrency ensures
// two reconciles racing on the same Secret cannot silently corrupt it.
//
// Return values:
//   - nil: reconcile succeeded (Secret created, updated, or already
//     in-sync), or the annotation is absent (the sweep ran and no work
//     was required).
//   - err: a non-recoverable error the caller should log; the reconcile
//     loop should retry after a backoff. err also increments the
//     errors_total metric.
func (r *Reconciler) Reconcile(ctx context.Context, ref ObjectRef) error {
	r.reconciles.Add(1)
	if r.metrics != nil {
		r.metrics.Reconciles.Inc()
	}

	cn := strings.TrimSpace(ref.Annotations[AnnotationCertCN])
	if cn == "" {
		// Annotation absent or removed. Make sure no Secret this
		// controller previously created for this object is left
		// behind. This is the sweep-on-revoke analogue for the
		// annotation path (scoped strictly to our managed-by label so
		// we can never touch a certd- or cert-manager-owned Secret;
		// CM-30).
		return r.sweepOrphans(ctx, ref)
	}

	bundle, err := r.fetcher.Fetch(ctx, cn)
	if err != nil {
		if errors.Is(err, ErrCertNotFound) {
			// Not an error: the cert has not been issued yet.
			// Emit an Event so operators can see the wait state,
			// but do not count it against errors_total.
			r.emitEvent(ctx, ref, corev1.EventTypeNormal, EventReasonIssued,
				fmt.Sprintf("waiting for certd to issue cert for CN=%s", cn))
			return nil
		}
		r.recordError(ctx, ref, err)
		return fmt.Errorf("fetch cert for CN %q: %w", cn, err)
	}

	secretName := strings.TrimSpace(ref.Annotations[AnnotationSecretName])
	if secretName == "" {
		secretName = DefaultSecretName(cn)
	}

	action, err := r.upsertSecret(ctx, ref, secretName, cn, bundle)
	if err != nil {
		r.recordError(ctx, ref, err)
		return fmt.Errorf("upsert secret %s/%s: %w", ref.Namespace, secretName, err)
	}

	switch action {
	case actionCreated:
		r.emitEvent(ctx, ref, corev1.EventTypeNormal, EventReasonIssued,
			fmt.Sprintf("created TLS Secret %q for CN=%s", secretName, cn))
	case actionUpdated:
		r.emitEvent(ctx, ref, corev1.EventTypeNormal, EventReasonRenewed,
			fmt.Sprintf("updated TLS Secret %q for CN=%s", secretName, cn))
	}

	if r.metrics != nil {
		r.metrics.LastSuccessSeconds.Set(float64(r.now().Unix()))
	}
	// Fire-and-forget: the renewal scheduler hook. Never fail reconcile
	// on notifier errors (see RenewalNotifier doc).
	if err := r.notifier.OnNearExpiry(ctx, cn); err != nil {
		r.logger.Warn("renewal notifier returned error", "cn", cn, "err", err)
	}
	return nil
}

type upsertAction int

const (
	actionNoop upsertAction = iota
	actionCreated
	actionUpdated
)

// upsertSecret creates or updates a kubernetes.io/tls Secret. The
// Secret is owned by the Pod/Service via an ownerReference so that
// deleting the annotated object garbage-collects the Secret (no sweep
// required in the common case). The label partition
// (managed-by=annotation-ctrl) scopes the controller's own GC
// behaviour and prevents overlap with certd / cert-manager.
func (r *Reconciler) upsertSecret(ctx context.Context, ref ObjectRef, name, cn string, bundle *CertBundle) (upsertAction, error) {
	data := map[string][]byte{
		corev1.TLSCertKey:       bundle.CertPEM,
		corev1.TLSPrivateKeyKey: []byte(KeyPlaceholder),
		"ca.crt":                bundle.ChainPEM,
	}
	labels := map[string]string{
		LabelManagedBy: LabelManagedByValue,
		LabelCN:        SanitizeLabelValue(cn),
	}
	ownerRef := metav1.OwnerReference{
		APIVersion:         ref.APIVersion,
		Kind:               ref.Kind,
		Name:               ref.Name,
		UID:                ref.UID,
		BlockOwnerDeletion: boolPtr(false),
		Controller:         boolPtr(false),
	}

	existing, err := r.client.CoreV1().Secrets(ref.Namespace).Get(ctx, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				Namespace:       ref.Namespace,
				Labels:          labels,
				OwnerReferences: []metav1.OwnerReference{ownerRef},
			},
			Type: corev1.SecretTypeTLS,
			Data: data,
		}
		if _, cerr := r.client.CoreV1().Secrets(ref.Namespace).Create(ctx, sec, metav1.CreateOptions{}); cerr != nil {
			return actionNoop, cerr
		}
		return actionCreated, nil
	}
	if err != nil {
		return actionNoop, err
	}

	// Refuse to hijack a Secret this controller does not already own.
	// This is the CM-30 label partition in practice: if a human or
	// another system put a Secret with this name in place first, we
	// must not overwrite it.
	if existing.Labels[LabelManagedBy] != LabelManagedByValue {
		return actionNoop, fmt.Errorf("secret %s/%s exists but is not managed by annotation-ctrl (managed-by=%q); refusing to overwrite",
			ref.Namespace, name, existing.Labels[LabelManagedBy])
	}

	// Fast path: nothing changed.
	if existing.Labels[LabelCN] == SanitizeLabelValue(cn) &&
		bytesEqual(existing.Data[corev1.TLSCertKey], bundle.CertPEM) &&
		bytesEqual(existing.Data["ca.crt"], bundle.ChainPEM) {
		return actionNoop, nil
	}

	updated := existing.DeepCopy()
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	for k, v := range labels {
		updated.Labels[k] = v
	}
	updated.Type = corev1.SecretTypeTLS
	updated.Data = data
	// Preserve existing ownerReferences but ensure ours is present.
	updated.OwnerReferences = mergeOwnerRefs(updated.OwnerReferences, ownerRef)
	if _, uerr := r.client.CoreV1().Secrets(ref.Namespace).Update(ctx, updated, metav1.UpdateOptions{}); uerr != nil {
		return actionNoop, uerr
	}
	return actionUpdated, nil
}

// sweepOrphans deletes any Secret in the object's namespace that (a)
// carries the annotation-ctrl managed-by label AND (b) is owned by the
// supplied object. This implements the "annotation removed -> Secret
// deleted" half of the contract without relying on the generic GC,
// which only fires on owner deletion.
func (r *Reconciler) sweepOrphans(ctx context.Context, ref ObjectRef) error {
	list, err := r.client.CoreV1().Secrets(ref.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: LabelManagedBy + "=" + LabelManagedByValue,
	})
	if err != nil {
		return fmt.Errorf("list managed secrets: %w", err)
	}
	for i := range list.Items {
		s := &list.Items[i]
		if !ownedBy(s.OwnerReferences, ref.UID) {
			continue
		}
		if derr := r.client.CoreV1().Secrets(ref.Namespace).Delete(ctx, s.Name, metav1.DeleteOptions{}); derr != nil && !k8serrors.IsNotFound(derr) {
			return fmt.Errorf("delete orphan secret %s: %w", s.Name, derr)
		}
		r.emitEvent(ctx, ref, corev1.EventTypeNormal, EventReasonDeleted,
			fmt.Sprintf("deleted TLS Secret %q (annotation removed)", s.Name))
	}
	return nil
}

// recordError increments errors_total, logs, and emits an Event on the
// annotated object so operators see failures without tailing controller
// logs.
func (r *Reconciler) recordError(ctx context.Context, ref ObjectRef, err error) {
	r.errors.Add(1)
	if r.metrics != nil {
		r.metrics.Errors.Inc()
	}
	r.logger.Warn("reconcile error", "ns", ref.Namespace, "name", ref.Name, "kind", ref.Kind, "err", err)
	r.emitEvent(ctx, ref, corev1.EventTypeWarning, EventReasonError, err.Error())
}

func (r *Reconciler) emitEvent(ctx context.Context, ref ObjectRef, eventType, reason, message string) {
	now := metav1.NewTime(r.now())
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "certchain-annotation-",
			Namespace:    ref.Namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:       ref.Kind,
			APIVersion: ref.APIVersion,
			Namespace:  ref.Namespace,
			Name:       ref.Name,
			UID:        ref.UID,
		},
		Reason:         reason,
		Message:        message,
		Type:           eventType,
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
		Source:         corev1.EventSource{Component: "annotation-ctrl"},
	}
	if _, err := r.client.CoreV1().Events(ref.Namespace).Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		// Never fail reconcile because we could not persist an Event.
		r.logger.Debug("emit event failed", "err", err, "reason", reason)
	}
}

// --- helpers ---

// DefaultSecretName returns "certchain-<sanitized-cn>" capped to the
// DNS-1123 subdomain length limit (253).
func DefaultSecretName(cn string) string {
	name := SecretNamePrefix + sanitizeDNS(cn)
	if len(name) > 253 {
		name = name[:253]
	}
	return strings.TrimRight(name, "-.")
}

var dnsRE = regexp.MustCompile(`[^a-z0-9\-.]`)
var labelRE = regexp.MustCompile(`[^A-Za-z0-9\-_.]`)

func sanitizeDNS(s string) string {
	v := dnsRE.ReplaceAllString(strings.ToLower(s), "-")
	return strings.Trim(v, "-.")
}

// SanitizeLabelValue lowercases and strips disallowed characters from a
// CN so it can be safely used as a Kubernetes label value. Capped at 63
// chars per the label-value spec.
func SanitizeLabelValue(cn string) string {
	v := labelRE.ReplaceAllString(strings.ToLower(cn), "-")
	v = strings.Trim(v, "-_.")
	if len(v) > 63 {
		v = v[:63]
	}
	return v
}

func boolPtr(b bool) *bool { return &b }

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ownedBy(refs []metav1.OwnerReference, uid types.UID) bool {
	for _, o := range refs {
		if o.UID == uid {
			return true
		}
	}
	return false
}

func mergeOwnerRefs(existing []metav1.OwnerReference, desired metav1.OwnerReference) []metav1.OwnerReference {
	for _, o := range existing {
		if o.UID == desired.UID {
			return existing
		}
	}
	return append(existing, desired)
}

// secretGVR / podGVR / serviceGVR are referenced by tests and
// documentation; keep them exported on the package for symmetry with
// internal/issuer.
var (
	PodGVR     = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	ServiceGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}
)
