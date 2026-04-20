package annotation

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"

	"github.com/amosdavis/certchain/internal/logging"
	"github.com/amosdavis/certchain/internal/metrics"
)

// RenewalScheduler watches Secrets managed by annotation-ctrl and
// schedules automatic renewal before NotAfter using workqueue AddAfter.
// Each secret gets a requeue scheduled at NotAfter - renewBefore.
type RenewalScheduler struct {
	client      kubernetes.Interface
	fetcher     CertFetcher
	queue       workqueue.RateLimitingInterface
	logger      *slog.Logger
	renewBefore time.Duration
	metrics     *metrics.AnnotationRenewalMetrics
	clock       clock
	stopOnce    sync.Once
	stopCh      chan struct{}
}

// clock is a small interface for time operations so tests can inject a fake.
type clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) timer
}

type timer interface {
	Stop() bool
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) timer {
	return time.AfterFunc(d, f)
}

// NewRenewalScheduler creates a scheduler with default settings.
// renewBefore is the duration before NotAfter when renewal is triggered.
func NewRenewalScheduler(client kubernetes.Interface, fetcher CertFetcher, renewBefore time.Duration, logger *slog.Logger, m *metrics.AnnotationRenewalMetrics) *RenewalScheduler {
	if logger == nil {
		logger = logging.Discard()
	}
	return &RenewalScheduler{
		client:      client,
		fetcher:     fetcher,
		queue:       workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		logger:      logger.With("component", "renewal-scheduler"),
		renewBefore: renewBefore,
		metrics:     m,
		clock:       realClock{},
		stopCh:      make(chan struct{}),
	}
}

// secretKey is the workqueue item type: namespace/name.
type secretKey struct {
	namespace string
	name      string
}

func (s secretKey) String() string {
	return s.namespace + "/" + s.name
}

// OnNearExpiry implements RenewalNotifier. It is called by the reconciler
// after each successful reconcile to schedule renewal for the secret.
func (s *RenewalScheduler) OnNearExpiry(ctx context.Context, cn string) error {
	// We need to find the secret for this CN. List all managed secrets
	// and pick the one with matching CN label.
	secrets, err := s.client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{
		LabelSelector: LabelManagedBy + "=" + LabelManagedByValue + "," + LabelCN + "=" + SanitizeLabelValue(cn),
	})
	if err != nil {
		return fmt.Errorf("list secrets for cn %q: %w", cn, err)
	}
	for i := range secrets.Items {
		sec := &secrets.Items[i]
		s.scheduleRenewal(ctx, sec)
	}
	return nil
}

// scheduleRenewal parses the cert from the secret, computes the renewal
// time, and adds the secret to the workqueue with AddAfter.
func (s *RenewalScheduler) scheduleRenewal(ctx context.Context, sec *corev1.Secret) {
	certPEM, ok := sec.Data[corev1.TLSCertKey]
	if !ok || len(certPEM) == 0 {
		s.logger.Warn("secret has no tls.crt", "key", sec.Namespace+"/"+sec.Name)
		return
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		s.logger.Warn("failed to decode PEM", "key", sec.Namespace+"/"+sec.Name)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.logger.Warn("failed to parse cert", "key", sec.Namespace+"/"+sec.Name, "err", err)
		return
	}

	now := s.clock.Now()
	notAfter := cert.NotAfter
	renewAt := notAfter.Add(-s.renewBefore)
	delay := renewAt.Sub(now)

	// Update expiry metric
	if s.metrics != nil {
		ttl := notAfter.Sub(now).Seconds()
		s.metrics.CertExpiry.WithLabelValues(sec.Namespace, sec.Name).Set(ttl)
	}

	key := secretKey{namespace: sec.Namespace, name: sec.Name}

	if delay <= 0 {
		// Already past renewal time or cert expired - requeue immediately
		s.logger.Info("cert needs immediate renewal", "key", key.String(), "notAfter", notAfter, "renewAt", renewAt)
		s.queue.AddRateLimited(key)
		return
	}

	s.logger.Info("scheduled renewal", "key", key.String(), "notAfter", notAfter, "renewAt", renewAt, "delay", delay.Truncate(time.Second))
	s.queue.AddAfter(key, delay)
}

// Run starts the renewal scheduler worker loop.
func (s *RenewalScheduler) Run(ctx context.Context, workers int) {
	defer s.queue.ShutDown()

	s.logger.Info("starting renewal scheduler", "workers", workers, "renewBefore", s.renewBefore)

	for i := 0; i < workers; i++ {
		go s.worker(ctx)
	}

	<-ctx.Done()
	s.logger.Info("renewal scheduler stopped")
}

// worker processes items from the workqueue.
func (s *RenewalScheduler) worker(ctx context.Context) {
	for s.processNextItem(ctx) {
	}
}

func (s *RenewalScheduler) processNextItem(ctx context.Context) bool {
	item, shutdown := s.queue.Get()
	if shutdown {
		return false
	}
	defer s.queue.Done(item)

	key, ok := item.(secretKey)
	if !ok {
		s.logger.Error("unexpected queue item type", "item", item)
		s.queue.Forget(item)
		return true
	}

	if err := s.renewSecret(ctx, key); err != nil {
		s.logger.Warn("renewal failed, will retry", "key", key.String(), "err", err)
		s.queue.AddRateLimited(key)
		if s.metrics != nil {
			s.metrics.RenewalsTotal.WithLabelValues("error").Inc()
		}
		return true
	}

	s.queue.Forget(key)
	if s.metrics != nil {
		s.metrics.RenewalsTotal.WithLabelValues("success").Inc()
	}
	return true
}

// renewSecret fetches a fresh cert from certd and updates the Secret.
func (s *RenewalScheduler) renewSecret(ctx context.Context, key secretKey) error {
	sec, err := s.client.CoreV1().Secrets(key.namespace).Get(ctx, key.name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		s.logger.Info("secret no longer exists, skipping renewal", "key", key.String())
		return nil
	}
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}

	// Verify this is still one of our managed secrets
	if sec.Labels[LabelManagedBy] != LabelManagedByValue {
		s.logger.Info("secret no longer managed by annotation-ctrl, skipping", "key", key.String())
		return nil
	}

	cn := sec.Labels[LabelCN]
	if cn == "" {
		return fmt.Errorf("secret missing CN label")
	}

	// Fetch fresh cert from certd
	bundle, err := s.fetcher.Fetch(ctx, cn)
	if err != nil {
		return fmt.Errorf("fetch cert for CN %q: %w", cn, err)
	}

	// Update Secret data
	updated := sec.DeepCopy()
	updated.Data[corev1.TLSCertKey] = bundle.CertPEM
	updated.Data["ca.crt"] = bundle.ChainPEM

	if _, err := s.client.CoreV1().Secrets(key.namespace).Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update secret: %w", err)
	}

	s.logger.Info("renewed cert", "key", key.String(), "cn", cn, "notAfter", bundle.NotAfter)

	// Emit Event on the owning Pod/Service if we can find it
	s.emitRenewalEvent(ctx, sec, cn)

	// Re-schedule for next renewal
	s.scheduleRenewal(ctx, updated)

	return nil
}

// emitRenewalEvent tries to emit a CertRenewed event on the owning object.
func (s *RenewalScheduler) emitRenewalEvent(ctx context.Context, sec *corev1.Secret, cn string) {
	if len(sec.OwnerReferences) == 0 {
		return
	}
	// Take the first owner
	owner := sec.OwnerReferences[0]

	now := metav1.NewTime(s.clock.Now())
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "certchain-annotation-",
			Namespace:    sec.Namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:       owner.Kind,
			APIVersion: owner.APIVersion,
			Namespace:  sec.Namespace,
			Name:       owner.Name,
			UID:        owner.UID,
		},
		Reason:         EventReasonRenewed,
		Message:        fmt.Sprintf("renewed TLS Secret %q for CN=%s", sec.Name, cn),
		Type:           corev1.EventTypeNormal,
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
		Source:         corev1.EventSource{Component: "annotation-ctrl"},
	}
	if _, err := s.client.CoreV1().Events(sec.Namespace).Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		s.logger.Debug("emit renewal event failed", "err", err, "key", sec.Namespace+"/"+sec.Name)
	}
}
