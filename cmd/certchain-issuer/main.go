// certchain-issuer is a cert-manager external issuer controller.
//
// It bridges cert-manager CertificateRequest objects to Kubernetes
// CertificateSigningRequests, which certd's existing CSR watcher then signs
// via AppViewX.
//
// Prerequisites:
//   - cert-manager v1+ must be installed in the cluster.
//   - CertchainClusterIssuer / CertchainIssuer CRDs (deploy/k8s/base/crds.yaml).
//   - certd must be running with --k8s-enabled and an appropriate --k8s-signer-name.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/amosdavis/certchain/internal/issuer"
)

func main() {
	healthAddr := flag.String("health-addr", ":8081", "Address for liveness/readiness HTTP server")
	reconnectDelay := flag.Duration("reconnect-delay", 5*time.Second, "Delay before reconnecting the watch on error")
	flag.Parse()

	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("certchain-issuer: failed to load in-cluster config: %v", err)
	}

	k8sClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("certchain-issuer: failed to create k8s client: %v", err)
	}

	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("certchain-issuer: failed to create dynamic client: %v", err)
	}

	ctrl := issuer.NewController(dynClient, k8sClient)

	// Health / readiness server — liveness probe calls /healthz, readiness /readyz.
	startHealthServer(*healthAddr)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Println("certchain-issuer: starting")

	// Outer reconnect loop: if the watch channel closes, re-establish after delay.
	for {
		if err := ctrl.Run(ctx); err != nil {
			if ctx.Err() != nil {
				log.Println("certchain-issuer: shutting down")
				return
			}
			log.Printf("certchain-issuer: watch error (reconnecting in %v): %v", *reconnectDelay, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(*reconnectDelay):
			}
		}
	}
}

func startHealthServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("certchain-issuer: health server error: %v", err)
			os.Exit(1)
		}
	}()
}
