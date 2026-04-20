package issuer

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// TestWorkqueueBurst verifies that a burst of 50 CertificateRequest keys
// all reach terminal state under a bounded worker pool (H5 / CM-31).
func TestWorkqueueBurst(t *testing.T) {
	scheme, listKinds := newTestScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds)
	k8sClient := k8sfake.NewSimpleClientset()

	const n = 50
	var processed atomic.Int64
	seen := sync.Map{}

	ctrl := NewController(dyn, k8sClient).
		WithReconcileKeyFunc(func(_ context.Context, key string) error {
			// Simulate a tiny reconcile cost so work actually overlaps.
			time.Sleep(1 * time.Millisecond)
			if _, dup := seen.LoadOrStore(key, true); dup {
				t.Errorf("duplicate processing of key %q", key)
			}
			processed.Add(1)
			return nil
		})

	ctrl.initQueue()
	for i := 0; i < n; i++ {
		ctrl.Queue().Add(fmt.Sprintf("ns/cr-%d", i))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const workers = 4
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctrl.processNextItem(ctx) {
				if processed.Load() >= int64(n) {
					return
				}
			}
		}()
	}

	// Wait until all keys are processed, then shut the queue down so workers exit.
	deadline := time.Now().Add(5 * time.Second)
	for processed.Load() < int64(n) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	ctrl.Queue().ShutDown()
	wg.Wait()

	if got := processed.Load(); got != int64(n) {
		t.Fatalf("processed %d of %d keys", got, n)
	}
}

// TestWorkqueueRetryThenSuccess verifies the transient-error path: a key
// that fails twice then succeeds is rate-limited-requeued and ultimately
// forgotten on success.
func TestWorkqueueRetryThenSuccess(t *testing.T) {
	scheme, listKinds := newTestScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds)
	k8sClient := k8sfake.NewSimpleClientset()

	var attempts atomic.Int32
	ctrl := NewController(dyn, k8sClient).
		WithReconcileKeyFunc(func(_ context.Context, _ string) error {
			n := attempts.Add(1)
			if n < 3 {
				return fmt.Errorf("transient failure #%d", n)
			}
			return nil
		})
	ctrl.initQueue()
	q := ctrl.Queue()

	key := "default/my-cr"
	q.Add(key)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var retriesObserved []int
	// Drive up to 6 iterations; should succeed on the 3rd.
	for i := 0; i < 6; i++ {
		if q.Len() == 0 {
			// Rate limiter may delay re-adds; poll briefly.
			waitUntil := time.Now().Add(2 * time.Second)
			for q.Len() == 0 && time.Now().Before(waitUntil) {
				time.Sleep(5 * time.Millisecond)
			}
		}
		if !ctrl.processNextItem(ctx) {
			break
		}
		retriesObserved = append(retriesObserved, q.NumRequeues(key))
		if attempts.Load() >= 3 && q.NumRequeues(key) == 0 {
			break
		}
	}
	q.ShutDown()

	if got := attempts.Load(); got != 3 {
		t.Fatalf("expected 3 attempts (2 failures + 1 success); got %d", got)
	}
	if n := q.NumRequeues(key); n != 0 {
		t.Errorf("NumRequeues after success = %d, want 0 (Forget)", n)
	}
	t.Logf("retry progression: %v", retriesObserved)
}

// TestWorkqueueGiveUpEmitsEvent verifies that a key that keeps failing past
// the retry cap is Forget()-ed and generates a CertchainGiveUp Event on the
// underlying CertificateRequest.
func TestWorkqueueGiveUpEmitsEvent(t *testing.T) {
	scheme, listKinds := newTestScheme()

	const ns, name, uid = "team-a", "flaky-cr", "uid-flaky"
	cr := newCertificateRequest(ns, name, uid,
		"CertchainClusterIssuer", "some-issuer", []byte("pkcs10"))
	cr.SetUID(uid)

	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, cr)
	k8sClient := k8sfake.NewSimpleClientset()

	const maxRetries = 3
	var attempts atomic.Int32
	ctrl := NewController(dyn, k8sClient).
		WithMaxRetries(maxRetries).
		WithReconcileKeyFunc(func(_ context.Context, _ string) error {
			attempts.Add(1)
			return fmt.Errorf("permanent failure")
		})
	ctrl.initQueue()
	q := ctrl.Queue()

	key, err := cache.MetaNamespaceKeyFunc(cr)
	if err != nil {
		t.Fatalf("MetaNamespaceKeyFunc: %v", err)
	}
	q.Add(key)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Up to maxRetries+1 attempts = maxRetries+1 processNextItem calls:
	// attempts 1..maxRetries each AddRateLimited; attempt maxRetries+1
	// triggers the give-up path.
	for i := 0; i <= maxRetries+2; i++ {
		// Wait briefly for the rate-limited re-add to reappear.
		waitUntil := time.Now().Add(3 * time.Second)
		for q.Len() == 0 && time.Now().Before(waitUntil) {
			time.Sleep(5 * time.Millisecond)
		}
		if q.Len() == 0 {
			break
		}
		if !ctrl.processNextItem(ctx) {
			break
		}
	}
	q.ShutDown()

	if got := attempts.Load(); got != int32(maxRetries+1) {
		t.Fatalf("expected %d attempts before give-up; got %d", maxRetries+1, got)
	}
	if n := q.NumRequeues(key); n != 0 {
		t.Errorf("NumRequeues after give-up = %d, want 0 (Forget)", n)
	}

	evList, err := k8sClient.CoreV1().Events(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	var giveUp *corev1.Event
	for i := range evList.Items {
		if evList.Items[i].Reason == "CertchainGiveUp" {
			giveUp = &evList.Items[i]
			break
		}
	}
	if giveUp == nil {
		t.Fatalf("no CertchainGiveUp event emitted; got %d events", len(evList.Items))
	}
	if giveUp.Type != corev1.EventTypeWarning {
		t.Errorf("give-up event Type = %q, want Warning", giveUp.Type)
	}
	if giveUp.InvolvedObject.Name != name || giveUp.InvolvedObject.Namespace != ns {
		t.Errorf("involvedObject = %+v, want %s/%s", giveUp.InvolvedObject, ns, name)
	}
	if giveUp.Name != "certchain-giveup-"+uid {
		t.Errorf("event Name = %q, want certchain-giveup-%s", giveUp.Name, uid)
	}
}

// TestWorkqueueShutdownExitsWorker verifies workers exit cleanly on queue
// shutdown so ctx-cancel-based drain works.
func TestWorkqueueShutdownExitsWorker(t *testing.T) {
	ctrl := NewController(nil, k8sfake.NewSimpleClientset()).
		WithReconcileKeyFunc(func(_ context.Context, _ string) error { return nil })
	ctrl.initQueue()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctrl.processNextItem(context.Background()) {
		}
	}()
	ctrl.Queue().ShutDown()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after queue shutdown")
	}

	// Sanity: the lazily-created queue satisfies RateLimitingInterface.
	var _ workqueue.RateLimitingInterface = ctrl.queue
}
