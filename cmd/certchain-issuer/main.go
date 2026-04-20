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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/amosdavis/certchain/internal/issuer"
	"github.com/amosdavis/certchain/internal/leader"
	"github.com/amosdavis/certchain/internal/logging"
	"github.com/amosdavis/certchain/internal/metrics"
)

func main() {
	healthAddr := flag.String("health-addr", ":8081", "Address for liveness/readiness HTTP server")
	metricsAddr := flag.String("metrics-addr", ":9880", "Address for Prometheus /metrics (H3)")
	reconnectDelay := flag.Duration("reconnect-delay", 5*time.Second, "Delay before reconnecting the watch on error")
	leaderElect := flag.Bool("leader-elect", true, "Enable leader election across replicas (C1; CM-22)")
	leaseName := flag.String("leader-lease-name", "certchain-issuer", "Lease resource name used for leader election")
	leaseNamespace := flag.String("leader-lease-namespace", "", "Namespace for the Lease (defaults to POD_NAMESPACE / certchain)")
	logFormat := flag.String("log-format", "json", "Log format: json|text")
	logLevel := flag.String("log-level", "info", "Log level: debug|info|warn|error")
	flag.Parse()

	logger := logging.New(logging.Options{
		Format: logging.ParseFormat(*logFormat),
		Level:  logging.ParseLevel(*logLevel),
	}).With("binary", "certchain-issuer")

	cfg, err := rest.InClusterConfig()
	if err != nil {
		logger.Error("failed to load in-cluster config", "err", err)
		os.Exit(1)
	}

	k8sClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Error("failed to create k8s client", "err", err)
		os.Exit(1)
	}

	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		logger.Error("failed to create dynamic client", "err", err)
		os.Exit(1)
	}

	registry := metrics.NewRegistry()
	issuerMetrics := metrics.NewIssuerMetrics(registry)

	ctrl := issuer.NewController(dynClient, k8sClient).
		WithLogger(logger).
		WithMetrics(issuerMetrics)

	startHealthServer(*healthAddr, logger)
	startMetricsServer(*metricsAddr, registry, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	run := func(ctx context.Context) error {
		return reconnectLoop(ctx, ctrl, *reconnectDelay, logger)
	}

	if !*leaderElect {
		logger.Warn("leader election disabled; run with a single replica to avoid split-brain (CM-22)")
		if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("run returned error", "err", err)
			os.Exit(1)
		}
		return
	}

	leaderCfg := leader.Config{
		LeaseName: *leaseName,
		Namespace: *leaseNamespace,
		Client:    k8sClient,
		Logger:    logger,
	}
	if err := leader.Run(ctx, leaderCfg, run); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("leader run returned error", "err", err)
		os.Exit(1)
	}
}

// reconnectLoop runs the controller's Watch loop, reconnecting after any
// non-fatal error. Blocks until ctx is cancelled.
func reconnectLoop(ctx context.Context, ctrl *issuer.Controller, delay time.Duration, logger *slog.Logger) error {
	logger.Info("starting CertificateRequest watch")
	for {
		if err := ctrl.Run(ctx); err != nil {
			if ctx.Err() != nil {
				logger.Info("shutting down")
				return nil
			}
			logger.Warn("watch error; reconnecting", "delay", delay, "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(delay):
			}
		}
	}
}

func startHealthServer(addr string, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("health server error", "err", err)
			os.Exit(1)
		}
	}()
}

func startMetricsServer(addr string, reg *metrics.Registry, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", reg.Handler())

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server error", "err", err)
		}
	}()
}
