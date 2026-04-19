// certchain-sync watches the certchain query API and writes kubernetes.io/tls
// Secrets for every active certificate. It also accepts webhook POSTs from
// certd so that renewals and revocations are reflected immediately.
//
// Usage:
//
//	certchain-sync [--certd-url <url>] [--namespaces <ns,...>] [--listen <addr>]
package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// certRecord mirrors query.certResponse from the certd HTTP API.
type certRecord struct {
	CertID   string   `json:"cert_id"`
	CN       string   `json:"cn"`
	NotAfter int64    `json:"not_after"`
	SANs     []string `json:"sans"`
	Serial   string   `json:"serial"`
	Status   string   `json:"status"`
}

// webhookEvent is the body POSTed by certd's notifyCertEvent.
type webhookEvent struct {
	Event     string `json:"event"`       // "renewed" or "revoked"
	CN        string `json:"cn"`
	OldCertID string `json:"old_cert_id"`
	NewCertID string `json:"new_cert_id"`
}

// Controller syncs certchain records to Kubernetes TLS Secrets.
type Controller struct {
	k8s        kubernetes.Interface
	certdURL   string
	namespaces []string
	http       *http.Client
}

func main() {
	certdURL   := flag.String("certd-url", "http://certchain-query.certchain.svc.cluster.local:9879", "certchain query API base URL")
	namespaces := flag.String("namespaces", "", "comma-separated namespaces to sync Secrets into (empty = all)")
	listen     := flag.String("listen", ":8080", "webhook/healthz listen address")
	reconcileInterval := flag.Duration("reconcile-interval", 5*time.Minute, "how often to reconcile all certs")
	kubeconfig := flag.String("kubeconfig", "", "path to kubeconfig file (empty = in-cluster)")
	flag.Parse()

	if v := os.Getenv("CERTD_URL"); v != "" && *certdURL == "http://certchain-query.certchain.svc.cluster.local:9879" {
		*certdURL = v
	}

	cfg, err := buildKubeConfig(*kubeconfig)
	if err != nil {
		log.Fatalf("certchain-sync: kubeconfig: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("certchain-sync: k8s client: %v", err)
	}

	var nsSlice []string
	if *namespaces != "" {
		nsSlice = strings.Split(*namespaces, ",")
	}

	ctrl := &Controller{
		k8s:        clientset,
		certdURL:   *certdURL,
		namespaces: nsSlice,
		http:       &http.Client{Timeout: 15 * time.Second},
	}

	log.Printf("certchain-sync: certd=%s namespaces=%v reconcile=%v", *certdURL, nsSlice, *reconcileInterval)

	ctx := context.Background()

	if err := ctrl.ReconcileAll(ctx); err != nil {
		log.Printf("certchain-sync: initial reconcile: %v", err)
	}

	go func() {
		ticker := time.NewTicker(*reconcileInterval)
		defer ticker.Stop()
		for range ticker.C {
			if err := ctrl.ReconcileAll(ctx); err != nil {
				log.Printf("certchain-sync: reconcile: %v", err)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", ctrl.handleWebhook)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	log.Printf("certchain-sync: listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

// ReconcileAll paginates GET /cert/list and upserts a Secret per active cert.
func (c *Controller) ReconcileAll(ctx context.Context) error {
	certs, err := c.listAllCerts(ctx)
	if err != nil {
		return fmt.Errorf("list certs: %w", err)
	}
	for _, cr := range certs {
		if err := c.syncCert(ctx, cr.CertID, cr.CN, cr.NotAfter); err != nil {
			log.Printf("certchain-sync: sync %s: %v", cr.CN, err)
		}
	}
	return nil
}

// syncCert fetches the DER for a cert and upserts a kubernetes.io/tls Secret.
func (c *Controller) syncCert(ctx context.Context, certIDHex, cn string, notAfter int64) error {
	der, err := c.fetchDER(ctx, certIDHex)
	if err != nil {
		return fmt.Errorf("fetch DER for %s: %w", cn, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName(cn),
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "certchain-sync",
				"certchain/cn":                 sanitizeLabel(cn),
			},
			Annotations: map[string]string{
				"certchain/cert-id":   certIDHex,
				"certchain/cn":        cn,
				"certchain/not-after": fmt.Sprint(notAfter),
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			// certchain does not store private keys; supply tls.key separately.
			corev1.TLSPrivateKeyKey: {},
		},
	}

	for _, ns := range c.targetNamespaces(ctx) {
		s := secret.DeepCopy()
		s.Namespace = ns
		if err := c.upsertSecret(ctx, s); err != nil {
			log.Printf("certchain-sync: upsert Secret %s/%s: %v", ns, s.Name, err)
		}
	}
	return nil
}

// deleteCertSecret removes the Secret for the given CN from all target namespaces.
func (c *Controller) deleteCertSecret(ctx context.Context, cn string) {
	name := secretName(cn)
	for _, ns := range c.targetNamespaces(ctx) {
		err := c.k8s.CoreV1().Secrets(ns).Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil && !k8serrors.IsNotFound(err) {
			log.Printf("certchain-sync: delete Secret %s/%s: %v", ns, name, err)
		}
	}
}

// handleWebhook handles POST /webhook events from certd.
func (c *Controller) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var ev webhookEvent
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	switch ev.Event {
	case "renewed":
		cr, err := c.getCertByCN(ctx, ev.CN)
		if err != nil {
			log.Printf("certchain-sync: webhook renewed: get cert %s: %v", ev.CN, err)
		} else {
			_ = c.syncCert(ctx, cr.CertID, cr.CN, cr.NotAfter)
		}
	case "revoked":
		c.deleteCertSecret(ctx, ev.CN)
	}
	w.WriteHeader(http.StatusNoContent)
}

// upsertSecret creates the Secret, or updates it if it already exists.
func (c *Controller) upsertSecret(ctx context.Context, s *corev1.Secret) error {
	_, err := c.k8s.CoreV1().Secrets(s.Namespace).Create(ctx, s, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		return err
	}
	existing, err := c.k8s.CoreV1().Secrets(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	s.ResourceVersion = existing.ResourceVersion
	_, err = c.k8s.CoreV1().Secrets(s.Namespace).Update(ctx, s, metav1.UpdateOptions{})
	return err
}

// fetchDER downloads the DER bytes for the given cert_id hex from the certd query API.
func (c *Controller) fetchDER(ctx context.Context, certIDHex string) ([]byte, error) {
	url := fmt.Sprintf("%s/cert/%s/der", c.certdURL, certIDHex)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// listAllCerts paginates GET /cert/list until all active certs are retrieved.
func (c *Controller) listAllCerts(ctx context.Context) ([]certRecord, error) {
	var all []certRecord
	page := 1
	const limit = 100
	for {
		url := fmt.Sprintf("%s/cert/list?page=%d&limit=%d", c.certdURL, page, limit)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		var result struct {
			Total int          `json:"total"`
			Certs []certRecord `json:"certs"`
		}
		err = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, result.Certs...)
		if len(all) >= result.Total || len(result.Certs) == 0 {
			break
		}
		page++
	}
	return all, nil
}

// getCertByCN fetches a single cert record by Common Name.
func (c *Controller) getCertByCN(ctx context.Context, cn string) (*certRecord, error) {
	url := fmt.Sprintf("%s/cert?cn=%s", c.certdURL, cn)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cr certRecord
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, err
	}
	return &cr, nil
}

// targetNamespaces returns the configured namespace list, or all namespaces if unconfigured.
func (c *Controller) targetNamespaces(ctx context.Context) []string {
	if len(c.namespaces) > 0 {
		return c.namespaces
	}
	list, err := c.k8s.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("certchain-sync: list namespaces: %v", err)
		return nil
	}
	ns := make([]string, len(list.Items))
	for i, n := range list.Items {
		ns[i] = n.Name
	}
	return ns
}

func secretName(cn string) string {
	r := strings.NewReplacer(".", "-", "*", "wildcard", " ", "-")
	return "certchain-" + strings.ToLower(r.Replace(cn))
}

func sanitizeLabel(s string) string {
	if len(s) > 63 {
		return s[:63]
	}
	return s
}

func buildKubeConfig(kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}
	return rest.InClusterConfig()
}
