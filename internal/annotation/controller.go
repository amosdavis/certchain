package annotation

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	"github.com/amosdavis/certchain/internal/logging"
)

// Controller wires together a Kubernetes watch on Pods and Services
// with the Reconciler. It is intentionally thin: the interesting logic
// all lives in the Reconciler so it can be exercised without a running
// apiserver.
type Controller struct {
	client     kubernetes.Interface
	reconciler *Reconciler
	namespace  string // "" = cluster-wide
	logger     *slog.Logger
	// reconnectDelay is how long the watch loop waits before
	// reconnecting after a channel close or transient error.
	reconnectDelay time.Duration
}

// NewController constructs a Controller. Pass namespace="" to watch
// cluster-wide; otherwise the controller restricts itself to the named
// namespace.
func NewController(client kubernetes.Interface, reconciler *Reconciler, namespace string, logger *slog.Logger) *Controller {
	if logger == nil {
		logger = logging.Discard()
	}
	return &Controller{
		client:         client,
		reconciler:     reconciler,
		namespace:      namespace,
		logger:         logger.With("component", "annotation-ctrl"),
		reconnectDelay: 5 * time.Second,
	}
}

// WithReconnectDelay overrides the reconnect backoff. Used in tests.
func (c *Controller) WithReconnectDelay(d time.Duration) *Controller {
	c.reconnectDelay = d
	return c
}

// Run starts two watches (Pods, Services) and blocks until ctx is
// cancelled. Errors on individual watch connections are logged and
// retried after reconnectDelay; only ctx cancellation causes Run to
// return.
func (c *Controller) Run(ctx context.Context) error {
	c.logger.Info("starting annotation-ctrl watches", "namespace", orAllNamespaces(c.namespace))
	errCh := make(chan error, 2)
	go func() { errCh <- c.watchPods(ctx) }()
	go func() { errCh <- c.watchServices(ctx) }()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (c *Controller) watchPods(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		w, err := c.client.CoreV1().Pods(c.namespace).Watch(ctx, metav1.ListOptions{})
		if err != nil {
			c.logger.Warn("watch pods failed; will reconnect", "err", err)
			if werr := sleepCtx(ctx, c.reconnectDelay); werr != nil {
				return werr
			}
			continue
		}
		if err := c.drainPods(ctx, w); err != nil {
			w.Stop()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			c.logger.Warn("pod watch drained with error; will reconnect", "err", err)
			if werr := sleepCtx(ctx, c.reconnectDelay); werr != nil {
				return werr
			}
			continue
		}
		w.Stop()
	}
}

func (c *Controller) watchServices(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		w, err := c.client.CoreV1().Services(c.namespace).Watch(ctx, metav1.ListOptions{})
		if err != nil {
			c.logger.Warn("watch services failed; will reconnect", "err", err)
			if werr := sleepCtx(ctx, c.reconnectDelay); werr != nil {
				return werr
			}
			continue
		}
		if err := c.drainServices(ctx, w); err != nil {
			w.Stop()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			c.logger.Warn("service watch drained with error; will reconnect", "err", err)
			if werr := sleepCtx(ctx, c.reconnectDelay); werr != nil {
				return werr
			}
			continue
		}
		w.Stop()
	}
}

func (c *Controller) drainPods(ctx context.Context, w watch.Interface) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-w.ResultChan():
			if !ok {
				return fmt.Errorf("pod watch channel closed")
			}
			if ev.Type != watch.Added && ev.Type != watch.Modified && ev.Type != watch.Deleted {
				continue
			}
			p, ok := ev.Object.(*corev1.Pod)
			if !ok {
				continue
			}
			ref := podRef(p)
			if ev.Type == watch.Deleted {
				// The ownerReference on the Secret will cause the
				// apiserver to garbage-collect it; no-op here.
				continue
			}
			if err := c.reconciler.Reconcile(ctx, ref); err != nil {
				c.logger.Warn("pod reconcile error", "ns", ref.Namespace, "name", ref.Name, "err", err)
			}
		}
	}
}

func (c *Controller) drainServices(ctx context.Context, w watch.Interface) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-w.ResultChan():
			if !ok {
				return fmt.Errorf("service watch channel closed")
			}
			if ev.Type != watch.Added && ev.Type != watch.Modified && ev.Type != watch.Deleted {
				continue
			}
			s, ok := ev.Object.(*corev1.Service)
			if !ok {
				continue
			}
			ref := serviceRef(s)
			if ev.Type == watch.Deleted {
				continue
			}
			if err := c.reconciler.Reconcile(ctx, ref); err != nil {
				c.logger.Warn("service reconcile error", "ns", ref.Namespace, "name", ref.Name, "err", err)
			}
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func orAllNamespaces(ns string) string {
	if ns == "" {
		return "<all>"
	}
	return ns
}
