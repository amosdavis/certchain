package annotation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// fakeFetcher is a deterministic CertFetcher for tests.
type fakeFetcher struct {
	mu      sync.Mutex
	bundles map[string]*CertBundle
	err     error
	calls   int
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{bundles: map[string]*CertBundle{}}
}

func (f *fakeFetcher) set(cn string, b *CertBundle) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bundles[cn] = b
}

func (f *fakeFetcher) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeFetcher) Fetch(_ context.Context, cn string) (*CertBundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.bundles[cn]
	if !ok {
		return nil, ErrCertNotFound
	}
	return b, nil
}

func annotatedPod(ns, name, cn string, extra map[string]string) *corev1.Pod {
	ann := map[string]string{AnnotationCertCN: cn}
	for k, v := range extra {
		ann[k] = v
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			UID:         types.UID("uid-" + name),
			Annotations: ann,
		},
	}
}

// TestReconcile_CreateSecret exercises the happy path: annotation
// present, certd returns a bundle, Secret gets created with the correct
// labels, type, and owner reference.
func TestReconcile_CreateSecret(t *testing.T) {
	t.Parallel()
	cn := "api.example.com"
	bundle := &CertBundle{
		CN:       cn,
		CertPEM:  []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		ChainPEM: []byte("-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"),
		NotAfter: time.Now().Add(24 * time.Hour),
	}
	fetcher := newFakeFetcher()
	fetcher.set(cn, bundle)

	client := k8sfake.NewSimpleClientset()
	r := NewReconciler(client, fetcher, nil, nil, nil)

	pod := annotatedPod("default", "app", cn, nil)
	if err := r.Reconcile(context.Background(), podRef(pod)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	wantName := DefaultSecretName(cn)
	got, err := client.CoreV1().Secrets("default").Get(context.Background(), wantName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("secret not created: %v", err)
	}
	if got.Type != corev1.SecretTypeTLS {
		t.Errorf("secret type = %q, want %q", got.Type, corev1.SecretTypeTLS)
	}
	if got.Labels[LabelManagedBy] != LabelManagedByValue {
		t.Errorf("managed-by label = %q, want %q", got.Labels[LabelManagedBy], LabelManagedByValue)
	}
	if got.Labels[LabelCN] != SanitizeLabelValue(cn) {
		t.Errorf("cn label = %q, want %q", got.Labels[LabelCN], SanitizeLabelValue(cn))
	}
	if string(got.Data[corev1.TLSCertKey]) != string(bundle.CertPEM) {
		t.Errorf("tls.crt mismatch")
	}
	if string(got.Data["ca.crt"]) != string(bundle.ChainPEM) {
		t.Errorf("ca.crt mismatch")
	}
	if len(got.OwnerReferences) != 1 || got.OwnerReferences[0].UID != pod.UID {
		t.Errorf("owner reference = %+v, want UID %q", got.OwnerReferences, pod.UID)
	}

	// An Event should have been emitted for Issued.
	evs, _ := client.CoreV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if len(evs.Items) == 0 {
		t.Errorf("expected an Issued event")
	}
}

// TestReconcile_AnnotationRemoved exercises the sweep half of the
// contract: once the CN annotation is gone, any Secret previously
// created by this controller for the object should be deleted. Secrets
// lacking the managed-by label are left alone.
func TestReconcile_AnnotationRemoved(t *testing.T) {
	t.Parallel()
	ns := "default"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: ns,
			UID:       types.UID("uid-app"),
			// NB: no annotation.
		},
	}
	managed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "certchain-api-example-com",
			Namespace: ns,
			Labels:    map[string]string{LabelManagedBy: LabelManagedByValue, LabelCN: "api-example-com"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID,
			}},
		},
		Type: corev1.SecretTypeTLS,
	}
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unrelated",
			Namespace: ns,
			Labels:    map[string]string{LabelManagedBy: "certd"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID,
			}},
		},
	}
	client := k8sfake.NewSimpleClientset(managed, foreign)
	r := NewReconciler(client, newFakeFetcher(), nil, nil, nil)

	if err := r.Reconcile(context.Background(), podRef(pod)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if _, err := client.CoreV1().Secrets(ns).Get(context.Background(), managed.Name, metav1.GetOptions{}); err == nil {
		t.Errorf("managed secret should have been deleted")
	}
	if _, err := client.CoreV1().Secrets(ns).Get(context.Background(), foreign.Name, metav1.GetOptions{}); err != nil {
		t.Errorf("foreign secret was touched: %v", err)
	}
}

// TestReconcile_CNMismatchUpdates verifies that when the annotation
// changes to a different CN (but the Secret name is sticky, e.g. the
// operator pinned cert-secret-name), the existing Secret is updated
// with the new cert material and CN label rather than being hijacked
// or left stale.
func TestReconcile_CNMismatchUpdates(t *testing.T) {
	t.Parallel()
	ns := "default"
	oldCN := "old.example.com"
	newCN := "new.example.com"
	pinnedSecretName := "app-tls"

	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pinnedSecretName,
			Namespace: ns,
			Labels: map[string]string{
				LabelManagedBy: LabelManagedByValue,
				LabelCN:        SanitizeLabelValue(oldCN),
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey: []byte("OLD"),
			"ca.crt":          []byte("OLD-CHAIN"),
		},
	}
	client := k8sfake.NewSimpleClientset(existing)
	fetcher := newFakeFetcher()
	fetcher.set(newCN, &CertBundle{CN: newCN, CertPEM: []byte("NEW"), ChainPEM: []byte("NEW-CHAIN")})
	r := NewReconciler(client, fetcher, nil, nil, nil)

	pod := annotatedPod(ns, "app", newCN, map[string]string{AnnotationSecretName: pinnedSecretName})
	if err := r.Reconcile(context.Background(), podRef(pod)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got, err := client.CoreV1().Secrets(ns).Get(context.Background(), pinnedSecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if string(got.Data[corev1.TLSCertKey]) != "NEW" {
		t.Errorf("tls.crt = %q, want NEW (not updated)", got.Data[corev1.TLSCertKey])
	}
	if got.Labels[LabelCN] != SanitizeLabelValue(newCN) {
		t.Errorf("cn label = %q, want %q", got.Labels[LabelCN], SanitizeLabelValue(newCN))
	}
	// OwnerReference to the pod should now be attached even though the
	// pre-existing Secret had none.
	if !ownedBy(got.OwnerReferences, pod.UID) {
		t.Errorf("owner reference for pod %q missing: %+v", pod.UID, got.OwnerReferences)
	}
}

// TestReconcile_FetcherUnreachable verifies the errors_total + error
// return contract when certd is down.
func TestReconcile_FetcherUnreachable(t *testing.T) {
	t.Parallel()
	fetcher := newFakeFetcher()
	fetcher.setErr(errors.New("connect: connection refused"))

	client := k8sfake.NewSimpleClientset()
	r := NewReconciler(client, fetcher, nil, nil, nil)

	pod := annotatedPod("default", "app", "api.example.com", nil)
	err := r.Reconcile(context.Background(), podRef(pod))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if r.errors.Load() != 1 {
		t.Errorf("errors counter = %d, want 1", r.errors.Load())
	}
	if r.reconciles.Load() != 1 {
		t.Errorf("reconciles counter = %d, want 1", r.reconciles.Load())
	}
	// No secret should have been created.
	list, _ := client.CoreV1().Secrets("default").List(context.Background(), metav1.ListOptions{})
	if len(list.Items) != 0 {
		t.Errorf("secret created despite fetch error: %+v", list.Items)
	}
	// A Warning event should have been emitted.
	evs, _ := client.CoreV1().Events("default").List(context.Background(), metav1.ListOptions{})
	foundWarn := false
	for _, e := range evs.Items {
		if e.Type == corev1.EventTypeWarning && e.Reason == EventReasonError {
			foundWarn = true
			break
		}
	}
	if !foundWarn {
		t.Errorf("expected warning event with reason %s; got %+v", EventReasonError, evs.Items)
	}
}

// TestReconcile_NotFoundIsNotAnError ensures ErrCertNotFound does NOT
// increment errors_total — it's the expected state during initial
// issuance, not a failure.
func TestReconcile_NotFoundIsNotAnError(t *testing.T) {
	t.Parallel()
	fetcher := newFakeFetcher() // empty
	client := k8sfake.NewSimpleClientset()
	r := NewReconciler(client, fetcher, nil, nil, nil)

	pod := annotatedPod("default", "app", "pending.example.com", nil)
	if err := r.Reconcile(context.Background(), podRef(pod)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if r.errors.Load() != 0 {
		t.Errorf("errors counter = %d, want 0 for not-found", r.errors.Load())
	}
	if r.reconciles.Load() != 1 {
		t.Errorf("reconciles counter = %d, want 1", r.reconciles.Load())
	}
}

// TestReconcile_RefusesForeignSecret verifies the CM-30/CM-33 label
// partition: a Secret with the same name but a different managed-by
// label must not be hijacked.
func TestReconcile_RefusesForeignSecret(t *testing.T) {
	t.Parallel()
	cn := "api.example.com"
	ns := "default"
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DefaultSecretName(cn),
			Namespace: ns,
			Labels:    map[string]string{LabelManagedBy: "certd"},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"tls.crt": []byte("FROM-CERTD")},
	}
	client := k8sfake.NewSimpleClientset(foreign)
	fetcher := newFakeFetcher()
	fetcher.set(cn, &CertBundle{CN: cn, CertPEM: []byte("NEW")})
	r := NewReconciler(client, fetcher, nil, nil, nil)

	pod := annotatedPod(ns, "app", cn, nil)
	err := r.Reconcile(context.Background(), podRef(pod))
	if err == nil {
		t.Fatal("expected refusal error, got nil")
	}
	got, _ := client.CoreV1().Secrets(ns).Get(context.Background(), foreign.Name, metav1.GetOptions{})
	if string(got.Data["tls.crt"]) != "FROM-CERTD" {
		t.Errorf("foreign secret was overwritten: %q", got.Data["tls.crt"])
	}
}

// TestDefaultSecretName / TestSanitizeLabelValue cover the two naming
// helpers exposed from the package.
func TestDefaultSecretName(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"api.example.com":    "certchain-api.example.com",
		"API.Example.COM":    "certchain-api.example.com",
		"weird name with ws": "certchain-weird-name-with-ws",
	}
	for in, want := range cases {
		if got := DefaultSecretName(in); got != want {
			t.Errorf("DefaultSecretName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeLabelValue(t *testing.T) {
	t.Parallel()
	if got := SanitizeLabelValue("API.Example.COM"); got != "api.example.com" {
		t.Errorf("got %q", got)
	}
	if got := SanitizeLabelValue("a*b"); got != "a-b" {
		t.Errorf("got %q", got)
	}
	// Longer than 63 chars truncates.
	long := ""
	for i := 0; i < 100; i++ {
		long += "a"
	}
	if got := SanitizeLabelValue(long); len(got) != 63 {
		t.Errorf("len = %d, want 63", len(got))
	}
}
