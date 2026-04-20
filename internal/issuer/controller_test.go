package issuer

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// newTestScheme registers list kinds for the GVRs the controller uses so the
// dynamic fake client knows how to serialize list responses.
func newTestScheme() (*runtime.Scheme, map[schema.GroupVersionResource]string) {
	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{
		certificateRequestGVR: "CertificateRequestList",
		clusterIssuerGVR:      "CertchainClusterIssuerList",
		issuerGVR:             "CertchainIssuerList",
	}
	return scheme, listKinds
}

func newClusterIssuer(name, signerName string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   clusterIssuerGVR.Group,
		Version: clusterIssuerGVR.Version,
		Kind:    "CertchainClusterIssuer",
	})
	u.SetName(name)
	spec := map[string]interface{}{}
	if signerName != "" {
		spec["signerName"] = signerName
	}
	_ = unstructured.SetNestedMap(u.Object, spec, "spec")
	return u
}

func newCertificateRequest(ns, name, uid, issuerKind, issuerName string, csrDER []byte) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   certificateRequestGVR.Group,
		Version: certificateRequestGVR.Version,
		Kind:    "CertificateRequest",
	})
	u.SetNamespace(ns)
	u.SetName(name)
	u.SetUID(k8stypes.UID(uid))
	_ = unstructured.SetNestedMap(u.Object, map[string]interface{}{
		"issuerRef": map[string]interface{}{
			"group": "certchain.io",
			"kind":  issuerKind,
			"name":  issuerName,
		},
		"request": base64.StdEncoding.EncodeToString(csrDER),
	}, "spec")
	return u
}

// helper: retrieve a cluster issuer's Ready condition from the fake client.
func getIssuerReady(t *testing.T, dyn *dynamicfake.FakeDynamicClient, name string) (status, reason, message string, found bool) {
	t.Helper()
	obj, err := dyn.Resource(clusterIssuerGVR).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get cluster issuer %s: %v", name, err)
	}
	conds, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	for _, raw := range conds {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if m["type"] == "Ready" {
			s, _ := m["status"].(string)
			r, _ := m["reason"].(string)
			msg, _ := m["message"].(string)
			return s, r, msg, true
		}
	}
	return "", "", "", false
}

func TestIssuerStatusReadyPatched(t *testing.T) {
	scheme, listKinds := newTestScheme()

	// Seed a valid cluster issuer and an invalid one (bad signerName prefix).
	good := newClusterIssuer("good-issuer", "certchain.io/test")
	bad := newClusterIssuer("bad-issuer", "other.example.com/signer")

	crGood := newCertificateRequest("app", "cr-good", "uid-good",
		"CertchainClusterIssuer", "good-issuer", []byte("pkcs10"))
	crGood.SetUID("uid-good")
	crBad := newCertificateRequest("app", "cr-bad", "uid-bad",
		"CertchainClusterIssuer", "bad-issuer", []byte("pkcs10"))
	crBad.SetUID("uid-bad")

	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds,
		good, bad, crGood, crBad)
	k8sClient := k8sfake.NewSimpleClientset()

	ctrl := NewController(dyn, k8sClient).
		WithPollInterval(10 * time.Millisecond).
		WithCertTimeout(50 * time.Millisecond)

	// --- Failure path: resolution fails, issuer patched Ready=False. ---
	ctrl.reconcile(context.Background(), crBad)

	status, reason, msg, found := getIssuerReady(t, dyn, "bad-issuer")
	if !found {
		t.Fatalf("expected Ready condition on bad-issuer, none found")
	}
	if status != "False" {
		t.Errorf("bad-issuer Ready status = %q, want False", status)
	}
	if reason != "NotReady" {
		t.Errorf("bad-issuer Ready reason = %q, want NotReady", reason)
	}
	if msg == "" {
		t.Errorf("bad-issuer Ready message is empty; expected error detail")
	}

	// --- Success path: resolution succeeds, issuer patched Ready=True. ---
	// Pre-create the derived K8s CSR with a populated certificate so
	// WaitForCert returns immediately (we only care about the issuer status).
	csrName := "certchain-" + string(crGood.GetUID())
	_, err := k8sClient.CertificatesV1().CertificateSigningRequests().Create(
		context.Background(),
		&certificatesv1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{Name: csrName},
			Status: certificatesv1.CertificateSigningRequestStatus{
				Certificate: []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"),
			},
		}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("seed CSR: %v", err)
	}

	ctrl.reconcile(context.Background(), crGood)

	status, reason, msg, found = getIssuerReady(t, dyn, "good-issuer")
	if !found {
		t.Fatalf("expected Ready condition on good-issuer, none found")
	}
	if status != "True" {
		t.Errorf("good-issuer Ready status = %q, want True", status)
	}
	if reason != "Available" {
		t.Errorf("good-issuer Ready reason = %q, want Available", reason)
	}
	if !strings.Contains(msg, "certchain-issuer is reconciling CertificateRequests") {
		t.Errorf("good-issuer Ready message = %q, want it to mention reconciliation", msg)
	}
}

func TestApprovalEventEmitted(t *testing.T) {
	scheme, listKinds := newTestScheme()

	issuer := newClusterIssuer("prod-issuer", "certchain.io/test")
	cr := newCertificateRequest("team-a", "my-cr", "uid-123",
		"CertchainClusterIssuer", "prod-issuer", []byte("pkcs10"))
	cr.SetUID("uid-123")

	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, issuer, cr)
	k8sClient := k8sfake.NewSimpleClientset()

	// Seed the K8s CSR with a pre-populated certificate so WaitForCert returns.
	csrName := "certchain-uid-123"
	_, err := k8sClient.CertificatesV1().CertificateSigningRequests().Create(
		context.Background(),
		&certificatesv1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{Name: csrName},
			Status: certificatesv1.CertificateSigningRequestStatus{
				Certificate: []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"),
			},
		}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("seed CSR: %v", err)
	}

	ctrl := NewController(dyn, k8sClient).
		WithPollInterval(10 * time.Millisecond).
		WithCertTimeout(2 * time.Second)

	ctrl.reconcile(context.Background(), cr)

	evList, err := k8sClient.CoreV1().Events("team-a").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	var approval *corev1.Event
	for i := range evList.Items {
		if evList.Items[i].Reason == "CertchainApproved" {
			approval = &evList.Items[i]
			break
		}
	}
	if approval == nil {
		t.Fatalf("no CertchainApproved event emitted; got %d events", len(evList.Items))
	}
	if approval.Type != corev1.EventTypeNormal {
		t.Errorf("event Type = %q, want Normal", approval.Type)
	}
	if approval.Name != "certchain-approved-uid-123" {
		t.Errorf("event Name = %q, want deterministic certchain-approved-uid-123", approval.Name)
	}
	if approval.InvolvedObject.Name != "my-cr" || approval.InvolvedObject.Namespace != "team-a" {
		t.Errorf("event involvedObject = %+v, want team-a/my-cr", approval.InvolvedObject)
	}
	wantSubs := []string{"CertchainClusterIssuer/prod-issuer", "cr=team-a/my-cr"}
	for _, sub := range wantSubs {
		if !strings.Contains(approval.Message, sub) {
			t.Errorf("event message %q missing %q", approval.Message, sub)
		}
	}

	// Idempotence: a second reconcile must not create a duplicate event
	// (AlreadyExists is swallowed). Re-seed CSR status so reconcile proceeds.
	ctrl.reconcile(context.Background(), cr)
	evList2, err := k8sClient.CoreV1().Events("team-a").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list events (2nd): %v", err)
	}
	approvals := 0
	for _, ev := range evList2.Items {
		if ev.Reason == "CertchainApproved" {
			approvals++
		}
	}
	if approvals != 1 {
		t.Errorf("expected exactly 1 CertchainApproved event after 2 reconciles, got %d", approvals)
	}
}
