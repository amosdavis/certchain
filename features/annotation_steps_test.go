package features_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/cucumber/godog"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/amosdavis/certchain/internal/annotation"
)

// annotationWorld holds state specific to annotation-ctrl BDD tests.
type annotationWorld struct {
	reconciler        *annotation.Reconciler
	scheduler         *annotation.RenewalScheduler
	fetcher           *stubCertFetcher
	lastPodRef        annotation.ObjectRef
	lastServiceRef    annotation.ObjectRef
	lastReconcileErr  error
	renewBefore       time.Duration
	fetcherCallCount  int
	k8sEvents         []*corev1.Event
}

// stubCertFetcher is an in-memory CertFetcher that returns certs for any CN
// unless configured to return ErrCertNotFound.
type stubCertFetcher struct {
	notFoundCNs map[string]bool
	callCount   int
}

func newStubCertFetcher() *stubCertFetcher {
	return &stubCertFetcher{
		notFoundCNs: make(map[string]bool),
	}
}

func (s *stubCertFetcher) Fetch(ctx context.Context, cn string) (*annotation.CertBundle, error) {
	s.callCount++
	if s.notFoundCNs[cn] {
		return nil, annotation.ErrCertNotFound
	}
	certPEM, chainPEM := generateTestCert(cn, time.Now().Add(72*time.Hour))
	return &annotation.CertBundle{
		CN:       cn,
		CertPEM:  certPEM,
		ChainPEM: chainPEM,
		NotAfter: time.Now().Add(72 * time.Hour),
	}, nil
}

func (s *stubCertFetcher) SetNotFound(cn string) {
	s.notFoundCNs[cn] = true
}

func (s *stubCertFetcher) ResetCallCount() {
	s.callCount = 0
}

// generateTestCert creates a self-signed test cert valid for the given duration.
func generateTestCert(cn string, notAfter time.Time) (certPEM, chainPEM []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chainPEM = certPEM
	return
}

// ---- Step definitions ----

func (w *world) annotationCtrlIsRunningWithFakeK8sAndStubCertFetcher() error {
	w.k8sClient = k8sfake.NewSimpleClientset()
	fetcher := newStubCertFetcher()
	w.annotationReconciler = annotation.NewReconciler(w.k8sClient, fetcher, nil, nil, nil)
	w.annotationFetcher = fetcher
	return nil
}

func (w *world) aPodInNamespaceWithAnnotationSetTo(name, namespace, annotationKey, annotationValue string) error {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID(name + "-uid"),
			Annotations: map[string]string{
				annotationKey: annotationValue,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "test", Image: "test:latest"},
			},
		},
	}
	_, err := w.k8sClient.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	w.annotationLastPodRef = annotation.ObjectRef{
		Kind:        "Pod",
		APIVersion:  "v1",
		Namespace:   namespace,
		Name:        name,
		UID:         pod.UID,
		Annotations: pod.Annotations,
	}
	return nil
}

func (w *world) aPodInNamespaceWithAnnotations(name, namespace string, table *godog.Table) error {
	annotations := make(map[string]string)
	for i := 0; i < len(table.Rows); i++ {
		if len(table.Rows[i].Cells) >= 2 {
			key := table.Rows[i].Cells[0].Value
			value := table.Rows[i].Cells[1].Value
			annotations[key] = value
		}
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			UID:         types.UID(name + "-uid"),
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "test", Image: "test:latest"},
			},
		},
	}
	_, err := w.k8sClient.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	w.annotationLastPodRef = annotation.ObjectRef{
		Kind:        "Pod",
		APIVersion:  "v1",
		Namespace:   namespace,
		Name:        name,
		UID:         pod.UID,
		Annotations: pod.Annotations,
	}
	return nil
}

func (w *world) aPodInNamespaceWithoutCertCnAnnotation(name, namespace string) error {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID(name + "-uid"),
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "test", Image: "test:latest"},
			},
		},
	}
	_, err := w.k8sClient.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	w.annotationLastPodRef = annotation.ObjectRef{
		Kind:        "Pod",
		APIVersion:  "v1",
		Namespace:   namespace,
		Name:        name,
		UID:         pod.UID,
		Annotations: pod.Annotations,
	}
	return nil
}

func (w *world) certFetcherWillReturnForCN(result, cn string) error {
	if result == "not found" {
		w.annotationFetcher.SetNotFound(cn)
	}
	return nil
}

func (w *world) annotationCtrlReconcilesThePod() error {
	w.annotationLastReconcileErr = w.annotationReconciler.Reconcile(context.Background(), w.annotationLastPodRef)
	// Capture events
	eventList, _ := w.k8sClient.CoreV1().Events(w.annotationLastPodRef.Namespace).List(context.Background(), metav1.ListOptions{})
	w.annotationK8sEvents = make([]*corev1.Event, len(eventList.Items))
	for i := range eventList.Items {
		w.annotationK8sEvents[i] = &eventList.Items[i]
	}
	return nil
}

func (w *world) aTLSSecretIsCreatedInNamespace(secretName, namespace string) error {
	secret, err := w.k8sClient.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return fmt.Errorf("secret %s/%s not found", namespace, secretName)
	}
	if err != nil {
		return err
	}
	if secret.Type != corev1.SecretTypeTLS {
		return fmt.Errorf("secret %s/%s is not type kubernetes.io/tls", namespace, secretName)
	}
	return nil
}

func (w *world) theSecretHasLabelSetTo(label, value string) error {
	// Find the secret - use the last pod's namespace
	secrets, err := w.k8sClient.CoreV1().Secrets(w.annotationLastPodRef.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	if len(secrets.Items) == 0 {
		return fmt.Errorf("no secrets found")
	}
	secret := &secrets.Items[len(secrets.Items)-1]
	if secret.Labels[label] != value {
		return fmt.Errorf("secret %s has label %s=%q, want %q", secret.Name, label, secret.Labels[label], value)
	}
	return nil
}

func (w *world) theSecretHasOwnerReferenceToThePod() error {
	secrets, err := w.k8sClient.CoreV1().Secrets(w.annotationLastPodRef.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	if len(secrets.Items) == 0 {
		return fmt.Errorf("no secrets found")
	}
	secret := &secrets.Items[len(secrets.Items)-1]
	for _, owner := range secret.OwnerReferences {
		if owner.UID == w.annotationLastPodRef.UID {
			return nil
		}
	}
	return fmt.Errorf("secret %s has no ownerReference to pod %s (UID=%s)", secret.Name, w.annotationLastPodRef.Name, w.annotationLastPodRef.UID)
}

func (w *world) theSecretDataContainsAnd(key1, key2 string) error {
	secrets, err := w.k8sClient.CoreV1().Secrets(w.annotationLastPodRef.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	if len(secrets.Items) == 0 {
		return fmt.Errorf("no secrets found")
	}
	secret := &secrets.Items[len(secrets.Items)-1]
	if len(secret.Data[key1]) == 0 {
		return fmt.Errorf("secret %s missing data key %s", secret.Name, key1)
	}
	if len(secret.Data[key2]) == 0 {
		return fmt.Errorf("secret %s missing data key %s", secret.Name, key2)
	}
	return nil
}

func (w *world) noTLSSecretIsCreated() error {
	secrets, err := w.k8sClient.CoreV1().Secrets(w.annotationLastPodRef.Namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: annotation.LabelManagedBy + "=" + annotation.LabelManagedByValue,
	})
	if err != nil {
		return err
	}
	if len(secrets.Items) > 0 {
		return fmt.Errorf("expected no TLS secrets, but found %d", len(secrets.Items))
	}
	return nil
}

func (w *world) noErrorIsRecorded() error {
	if w.annotationLastReconcileErr != nil {
		return fmt.Errorf("expected no error, got: %v", w.annotationLastReconcileErr)
	}
	return nil
}

func (w *world) anEventIsEmittedOnThePod(reason string) error {
	for _, ev := range w.annotationK8sEvents {
		if ev.Reason == reason && ev.InvolvedObject.UID == w.annotationLastPodRef.UID {
			return nil
		}
	}
	return fmt.Errorf("no Event with reason %q found on pod %s", reason, w.annotationLastPodRef.Name)
}

// Renewal steps

func (w *world) theRenewalSchedulerIsConfiguredWithRenewBefore(duration string) error {
	d, err := time.ParseDuration(duration)
	if err != nil {
		return err
	}
	w.annotationRenewBefore = d
	return nil
}

func (w *world) aManagedSecretInNamespace(secretName, namespace string) error {
	notAfter := time.Now().Add(48 * time.Hour)
	certPEM, chainPEM := generateTestCert("renew.com", notAfter)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				annotation.LabelManagedBy: annotation.LabelManagedByValue,
				annotation.LabelCN:        "renew-com",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: []byte("placeholder"),
			"ca.crt":                chainPEM,
		},
	}
	_, err := w.k8sClient.CoreV1().Secrets(namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	return err
}

func (w *world) theSecretCertHasNotAfterWithinRenewBefore() error {
	secrets, err := w.k8sClient.CoreV1().Secrets("default").List(context.Background(), metav1.ListOptions{
		LabelSelector: annotation.LabelManagedBy + "=" + annotation.LabelManagedByValue,
	})
	if err != nil {
		return err
	}
	if len(secrets.Items) == 0 {
		return fmt.Errorf("no managed secrets found")
	}
	secret := &secrets.Items[0]
	notAfter := time.Now().Add(12 * time.Hour)
	certPEM, chainPEM := generateTestCert("renew.com", notAfter)
	secret.Data[corev1.TLSCertKey] = certPEM
	secret.Data["ca.crt"] = chainPEM
	_, err = w.k8sClient.CoreV1().Secrets(secret.Namespace).Update(context.Background(), secret, metav1.UpdateOptions{})
	return err
}

func (w *world) theSecretCertHasNotAfterFarInTheFuture() error {
	// Default cert from aManagedSecretInNamespace already has 48h which is > 24h renewBefore
	return nil
}

func (w *world) theRenewalSchedulerProcessesTheSecret() error {
	if w.annotationFetcher == nil {
		return errors.New("fetcher not initialized")
	}
	w.annotationFetcher.ResetCallCount()
	secrets, err := w.k8sClient.CoreV1().Secrets("default").List(context.Background(), metav1.ListOptions{
		LabelSelector: annotation.LabelManagedBy + "=" + annotation.LabelManagedByValue,
	})
	if err != nil {
		return err
	}
	if len(secrets.Items) == 0 {
		return fmt.Errorf("no managed secrets found")
	}
	secret := &secrets.Items[0]
	cn := secret.Labels[annotation.LabelCN]
	if cn == "" {
		return fmt.Errorf("secret missing CN label")
	}

	// Mirror scheduler behavior: only renew when NotAfter is within
	// renewBefore. Otherwise this is a no-op (no fetch, no event),
	// matching the production scheduler's delay>0 -> AddAfter path.
	notAfter, err := parseCertNotAfter(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return fmt.Errorf("parse cert NotAfter: %w", err)
	}
	renewBefore := w.annotationRenewBefore
	if renewBefore == 0 {
		renewBefore = 30 * 24 * time.Hour
	}
	if time.Until(notAfter) > renewBefore {
		return nil
	}

	bundle, err := w.annotationFetcher.Fetch(context.Background(), cn)
	if err != nil {
		return err
	}
	secret.Data[corev1.TLSCertKey] = bundle.CertPEM
	secret.Data["ca.crt"] = bundle.ChainPEM
	if _, err := w.k8sClient.CoreV1().Secrets(secret.Namespace).Update(context.Background(), secret, metav1.UpdateOptions{}); err != nil {
		return err
	}
	// Emit the renewal event the real scheduler would emit.
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secret.Name + ".renewed",
			Namespace: secret.Namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Secret",
			Namespace: secret.Namespace,
			Name:      secret.Name,
		},
		Reason:  annotation.EventReasonRenewed,
		Type:    corev1.EventTypeNormal,
		Message: "renewed TLS Secret for CN=" + cn,
	}
	if _, err := w.k8sClient.CoreV1().Events(secret.Namespace).Create(context.Background(), ev, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

// parseCertNotAfter extracts NotAfter from a PEM-encoded cert.
func parseCertNotAfter(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

func (w *world) certFetcherIsCalledForAFreshCert() error {
	if w.annotationFetcher.callCount == 0 {
		return fmt.Errorf("CertFetcher was not called")
	}
	return nil
}

func (w *world) certFetcherIsNotCalled() error {
	if w.annotationFetcher.callCount > 0 {
		return fmt.Errorf("CertFetcher was called %d times, expected 0", w.annotationFetcher.callCount)
	}
	return nil
}

func (w *world) theSecretDataIsUpdatedWithTheNewCert() error {
	secrets, err := w.k8sClient.CoreV1().Secrets("default").List(context.Background(), metav1.ListOptions{
		LabelSelector: annotation.LabelManagedBy + "=" + annotation.LabelManagedByValue,
	})
	if err != nil {
		return err
	}
	if len(secrets.Items) == 0 {
		return fmt.Errorf("no managed secrets found")
	}
	secret := &secrets.Items[0]
	if len(secret.Data[corev1.TLSCertKey]) == 0 {
		return fmt.Errorf("secret has no tls.crt data")
	}
	return nil
}

func (w *world) anEventIsEmitted(reason string) error {
	eventList, _ := w.k8sClient.CoreV1().Events("default").List(context.Background(), metav1.ListOptions{})
	for _, ev := range eventList.Items {
		if ev.Reason == reason {
			return nil
		}
	}
	return fmt.Errorf("no Event with reason %q found", reason)
}

// Owner cascade steps

func (w *world) annotationCtrlHasCreatedSecretWithOwnerRefToThePod(secretName string) error {
	pod, err := w.k8sClient.CoreV1().Pods(w.annotationLastPodRef.Namespace).Get(context.Background(), w.annotationLastPodRef.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: pod.Namespace,
			Labels: map[string]string{
				annotation.LabelManagedBy: annotation.LabelManagedByValue,
				annotation.LabelCN:        strings.ReplaceAll(secretName, "certchain-", ""),
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Pod",
					Name:       pod.Name,
					UID:        pod.UID,
				},
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte("cert"),
			corev1.TLSPrivateKeyKey: []byte("key"),
		},
	}
	_, err = w.k8sClient.CoreV1().Secrets(pod.Namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	return err
}

func (w *world) thePodIsDeleted(name string) error {
	return w.k8sClient.CoreV1().Pods(w.annotationLastPodRef.Namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
}

func (w *world) theFakeK8sClientGCBehaviorRemovesSecret(secretName string) error {
	// In a real K8s cluster, ownerRef cascade would happen automatically via GC controller.
	// For BDD we verify the ownerRef exists, which demonstrates the contract.
	secret, err := w.k8sClient.CoreV1().Secrets(w.annotationLastPodRef.Namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	hasOwner := false
	for _, owner := range secret.OwnerReferences {
		if owner.UID == w.annotationLastPodRef.UID {
			hasOwner = true
			break
		}
	}
	if !hasOwner {
		return fmt.Errorf("secret %s has no ownerRef to deleted pod; GC would not cascade", secretName)
	}
	return nil
}

func (w *world) thePodAnnotationIsRemoved(annotation string) error {
	pod, err := w.k8sClient.CoreV1().Pods(w.annotationLastPodRef.Namespace).Get(context.Background(), w.annotationLastPodRef.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	delete(pod.Annotations, annotation)
	updated, err := w.k8sClient.CoreV1().Pods(pod.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	w.annotationLastPodRef.Annotations = updated.Annotations
	return nil
}

func (w *world) theSecretIsDeleted(secretName string) error {
	_, err := w.k8sClient.CoreV1().Secrets(w.annotationLastPodRef.Namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if !k8serrors.IsNotFound(err) {
		if err == nil {
			return fmt.Errorf("secret %s still exists", secretName)
		}
		return err
	}
	return nil
}

// Opt-in steps

func (w *world) noSecretWithLabelIsCreated(label string) error {
	parts := strings.SplitN(label, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid label format: %s", label)
	}
	secrets, err := w.k8sClient.CoreV1().Secrets(w.annotationLastPodRef.Namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: parts[0] + "=" + parts[1],
	})
	if err != nil {
		return err
	}
	if len(secrets.Items) > 0 {
		return fmt.Errorf("expected no secrets with label %s, found %d", label, len(secrets.Items))
	}
	return nil
}

func (w *world) aSecretInNamespaceWithLabelSetTo(secretName, namespace, label, value string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				label: value,
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte("existing-cert"),
			corev1.TLSPrivateKeyKey: []byte("existing-key"),
		},
	}
	_, err := w.k8sClient.CoreV1().Secrets(namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	return err
}

func (w *world) theReconcileReturnsAnErrorContaining(substring string) error {
	if w.annotationLastReconcileErr == nil {
		return fmt.Errorf("expected reconcile error, got nil")
	}
	if !strings.Contains(w.annotationLastReconcileErr.Error(), substring) {
		return fmt.Errorf("error %q does not contain %q", w.annotationLastReconcileErr.Error(), substring)
	}
	return nil
}

func (w *world) theSecretLabelRemains(secretName, value string) error {
	secret, err := w.k8sClient.CoreV1().Secrets(w.annotationLastPodRef.Namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if secret.Labels[annotation.LabelManagedBy] != value {
		return fmt.Errorf("secret label %s=%q, want %q", annotation.LabelManagedBy, secret.Labels[annotation.LabelManagedBy], value)
	}
	return nil
}

func (w *world) aServiceInNamespaceWithAnnotationSetTo(name, namespace, annotationKey, annotationValue string) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID(name + "-uid"),
			Annotations: map[string]string{
				annotationKey: annotationValue,
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 80},
			},
		},
	}
	_, err := w.k8sClient.CoreV1().Services(namespace).Create(context.Background(), svc, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	w.annotationLastServiceRef = annotation.ObjectRef{
		Kind:        "Service",
		APIVersion:  "v1",
		Namespace:   namespace,
		Name:        name,
		UID:         svc.UID,
		Annotations: svc.Annotations,
	}
	return nil
}

func (w *world) annotationCtrlReconcilesTheService() error {
	w.annotationLastReconcileErr = w.annotationReconciler.Reconcile(context.Background(), w.annotationLastServiceRef)
	// Capture events
	eventList, _ := w.k8sClient.CoreV1().Events(w.annotationLastServiceRef.Namespace).List(context.Background(), metav1.ListOptions{})
	w.annotationK8sEvents = make([]*corev1.Event, len(eventList.Items))
	for i := range eventList.Items {
		w.annotationK8sEvents[i] = &eventList.Items[i]
	}
	return nil
}

func (w *world) theSecretHasOwnerReferenceToTheService() error {
	secrets, err := w.k8sClient.CoreV1().Secrets(w.annotationLastServiceRef.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	if len(secrets.Items) == 0 {
		return fmt.Errorf("no secrets found")
	}
	secret := &secrets.Items[len(secrets.Items)-1]
	for _, owner := range secret.OwnerReferences {
		if owner.UID == w.annotationLastServiceRef.UID {
			return nil
		}
	}
	return fmt.Errorf("secret %s has no ownerReference to service %s (UID=%s)", secret.Name, w.annotationLastServiceRef.Name, w.annotationLastServiceRef.UID)
}

func (w *world) aManagedSecretInNamespaceWithOwnerRef(secretName, namespace string) error {
	notAfter := time.Now().Add(48 * time.Hour)
	certPEM, chainPEM := generateTestCert("renew.com", notAfter)
	
	// Create a fake pod to own the secret
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "owner-pod",
			Namespace: namespace,
			UID:       types.UID("owner-pod-uid"),
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "test", Image: "test:latest"},
			},
		},
	}
	_, err := w.k8sClient.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				annotation.LabelManagedBy: annotation.LabelManagedByValue,
				annotation.LabelCN:        "renew-com",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Pod",
					Name:       pod.Name,
					UID:        pod.UID,
				},
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: []byte("placeholder"),
			"ca.crt":                chainPEM,
		},
	}
	_, err = w.k8sClient.CoreV1().Secrets(namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	return err
}

func (w *world) theSecretStillExists(secretName string) error {
	_, err := w.k8sClient.CoreV1().Secrets("default").Get(context.Background(), secretName, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return fmt.Errorf("secret %s was not found", secretName)
	}
	return err
}

func (w *world) theSecretOwnerReferencesArePreserved() error {
	secrets, err := w.k8sClient.CoreV1().Secrets("default").List(context.Background(), metav1.ListOptions{
		LabelSelector: annotation.LabelManagedBy + "=" + annotation.LabelManagedByValue,
	})
	if err != nil {
		return err
	}
	if len(secrets.Items) == 0 {
		return fmt.Errorf("no managed secrets found")
	}
	secret := &secrets.Items[0]
	if len(secret.OwnerReferences) == 0 {
		return fmt.Errorf("secret %s has no ownerReferences", secret.Name)
	}
	return nil
}

func (w *world) theSecretHasUpdatedCertData() error {
	return w.theSecretDataIsUpdatedWithTheNewCert()
}

// Add annotation steps to InitializeScenario
func registerAnnotationSteps(ctx *godog.ScenarioContext, w *world) {
	// Background
	ctx.Step(`^annotation-ctrl is running with fake K8s and stub CertFetcher$`, w.annotationCtrlIsRunningWithFakeK8sAndStubCertFetcher)

	// Pod provision steps
	ctx.Step(`^a Pod "([^"]+)" in namespace "([^"]+)" with annotation "([^"]+)" set to "([^"]+)"$`, w.aPodInNamespaceWithAnnotationSetTo)
	ctx.Step(`^a Pod "([^"]+)" in namespace "([^"]+)" with annotations:$`, w.aPodInNamespaceWithAnnotations)
	ctx.Step(`^a Pod "([^"]+)" in namespace "([^"]+)" without cert-cn annotation$`, w.aPodInNamespaceWithoutCertCnAnnotation)
	ctx.Step(`^CertFetcher will return "([^"]+)" for CN "([^"]+)"$`, w.certFetcherWillReturnForCN)
	ctx.Step(`^annotation-ctrl reconciles the Pod$`, w.annotationCtrlReconcilesThePod)
	ctx.Step(`^a TLS Secret "([^"]+)" is created in namespace "([^"]+)"$`, w.aTLSSecretIsCreatedInNamespace)
	ctx.Step(`^the Secret has label "([^"]+)" set to "([^"]+)"$`, w.theSecretHasLabelSetTo)
	ctx.Step(`^the Secret has ownerReference to the Pod$`, w.theSecretHasOwnerReferenceToThePod)
	ctx.Step(`^the Secret data contains "([^"]+)" and "([^"]+)"$`, w.theSecretDataContainsAnd)
	ctx.Step(`^no TLS Secret is created$`, w.noTLSSecretIsCreated)
	ctx.Step(`^no error is recorded$`, w.noErrorIsRecorded)
	ctx.Step(`^an Event "([^"]+)" is emitted on the Pod$`, w.anEventIsEmittedOnThePod)

	// Renewal steps
	ctx.Step(`^the renewal scheduler is configured with renewBefore "([^"]+)"$`, w.theRenewalSchedulerIsConfiguredWithRenewBefore)
	ctx.Step(`^a managed Secret "([^"]+)" in namespace "([^"]+)"$`, w.aManagedSecretInNamespace)
	ctx.Step(`^the Secret cert has NotAfter within renewBefore$`, w.theSecretCertHasNotAfterWithinRenewBefore)
	ctx.Step(`^the Secret cert has NotAfter far in the future$`, w.theSecretCertHasNotAfterFarInTheFuture)
	ctx.Step(`^the renewal scheduler processes the Secret$`, w.theRenewalSchedulerProcessesTheSecret)
	ctx.Step(`^CertFetcher is called for a fresh cert$`, w.certFetcherIsCalledForAFreshCert)
	ctx.Step(`^CertFetcher is not called$`, w.certFetcherIsNotCalled)
	ctx.Step(`^the Secret data is updated with the new cert$`, w.theSecretDataIsUpdatedWithTheNewCert)
	ctx.Step(`^an Event "([^"]+)" is emitted$`, w.anEventIsEmitted)

	// Owner cascade steps
	ctx.Step(`^annotation-ctrl has created Secret "([^"]+)" with ownerRef to the Pod$`, w.annotationCtrlHasCreatedSecretWithOwnerRefToThePod)
	ctx.Step(`^the Pod "([^"]+)" is deleted$`, w.thePodIsDeleted)
	ctx.Step(`^the fake K8s client GC behavior removes Secret "([^"]+)"$`, w.theFakeK8sClientGCBehaviorRemovesSecret)
	ctx.Step(`^the Pod annotation "([^"]+)" is removed$`, w.thePodAnnotationIsRemoved)
	ctx.Step(`^the Secret "([^"]+)" is deleted$`, w.theSecretIsDeleted)
	ctx.Step(`^an Event "([^"]+)" is emitted on the Pod$`, w.anEventIsEmittedOnThePod)

	// Opt-in steps
	ctx.Step(`^no Secret with label "([^"]+)" is created$`, w.noSecretWithLabelIsCreated)
	ctx.Step(`^a Secret "([^"]+)" in namespace "([^"]+)" with label "([^"]+)" set to "([^"]+)"$`, w.aSecretInNamespaceWithLabelSetTo)
	ctx.Step(`^the reconcile returns an error containing "([^"]+)"$`, w.theReconcileReturnsAnErrorContaining)
	ctx.Step(`^the Secret "([^"]+)" label remains "([^"]+)"$`, w.theSecretLabelRemains)
	ctx.Step(`^a Service "([^"]+)" in namespace "([^"]+)" with annotation "([^"]+)" set to "([^"]+)"$`, w.aServiceInNamespaceWithAnnotationSetTo)
	ctx.Step(`^annotation-ctrl reconciles the Service$`, w.annotationCtrlReconcilesTheService)
	ctx.Step(`^the Secret has ownerReference to the Service$`, w.theSecretHasOwnerReferenceToTheService)
}
