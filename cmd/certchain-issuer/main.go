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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
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
	certdURL := flag.String("certd-url", "http://127.0.0.1:9879", "certd query API base URL used for readiness probing (CM-27); empty disables the probe")
	readinessMaxStaleness := flag.Duration("readiness-max-staleness", 60*time.Second, "Maximum age of the last successful certd probe before /readyz returns 503 (CM-27)")
	certdProbeInterval := flag.Duration("certd-probe-interval", 15*time.Second, "Background certd reachability probe interval for /readyz (CM-27)")
	workers := flag.Int("workers", 2, "Number of reconcile workers pulling from the issuer workqueue (H5 / CM-31)")
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

	// Readiness state (CM-27). Only the owning subsystem flips each signal
	// forward (false -> true) to avoid flapping during transient recovery.
	ready := newReadiness(*certdURL, *readinessMaxStaleness)
	if !*leaderElect {
		ready.SetLeader(true)
	}

	startHealthServer(*healthAddr, ready, logger)
	startMetricsServer(*metricsAddr, registry, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Background certd reachability probe (CM-27). The readiness handler is
	// a pure atomic read; no HTTP I/O happens inside the probe endpoint.
	if *certdURL != "" {
		go runCertdProbe(ctx, *certdURL, *certdProbeInterval, ready, logger)
	}

	run := func(ctx context.Context) error {
		// Controller setup is effectively complete as soon as Run establishes
		// its watch; expose that as the "caches synced" readiness signal.
		ready.SetCachesSynced(true)
		return reconnectLoop(ctx, ctrl, *workers, *reconnectDelay, logger)
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
	leaderRun := func(ctx context.Context) error {
		ready.SetLeader(true)
		return run(ctx)
	}
	if err := leader.Run(ctx, leaderCfg, leaderRun); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("leader run returned error", "err", err)
		os.Exit(1)
	}
}

// reconnectLoop runs the controller's Watch loop, reconnecting after any
// non-fatal error. Blocks until ctx is cancelled.
func reconnectLoop(ctx context.Context, ctrl *issuer.Controller, workers int, delay time.Duration, logger *slog.Logger) error {
	logger.Info("starting CertificateRequest watch", "workers", workers)
	for {
		if err := ctrl.Run(ctx, workers); err != nil {
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

// readiness tracks the three /readyz signals for certchain-issuer (CM-27):
// leader acquisition, controller cache sync, and recent successful certd
// reachability. Each signal is owned by one writer and only moves forward.
type readiness struct {
	leader       atomic.Bool
	cachesSynced atomic.Bool
	// certdLastOKNanos is the Unix-nanos timestamp of the most recent
	// successful certd probe; zero means "never succeeded". Stored atomically
	// so the /readyz handler never contends with the probe goroutine.
	certdLastOKNanos atomic.Int64
	certdURL         string
	maxStaleness     time.Duration
	now              func() time.Time
}

func newReadiness(certdURL string, maxStaleness time.Duration) *readiness {
	return &readiness{
		certdURL:     certdURL,
		maxStaleness: maxStaleness,
		now:          time.Now,
	}
}

func (r *readiness) SetLeader(v bool)       { r.leader.Store(v) }
func (r *readiness) SetCachesSynced(v bool) { r.cachesSynced.Store(v) }
func (r *readiness) MarkCertdOK(t time.Time) {
	r.certdLastOKNanos.Store(t.UnixNano())
}

// Snapshot returns human-readable per-signal states plus an overall ready
// bit. It never blocks.
func (r *readiness) Snapshot() (leader, caches, certd string, ok bool) {
	leaderOK := r.leader.Load()
	cachesOK := r.cachesSynced.Load()

	leader = "not_acquired"
	if leaderOK {
		leader = "ok"
	}
	caches = "syncing"
	if cachesOK {
		caches = "synced"
	}

	certdOK := true
	switch {
	case r.certdURL == "":
		certd = "disabled"
	default:
		lastNanos := r.certdLastOKNanos.Load()
		if lastNanos == 0 {
			certd = "never"
			certdOK = false
			break
		}
		age := r.now().Sub(time.Unix(0, lastNanos))
		if age > r.maxStaleness {
			certd = fmt.Sprintf("stale_%s", age.Truncate(time.Second))
			certdOK = false
			break
		}
		certd = "ok"
	}

	ok = leaderOK && cachesOK && certdOK
	return
}

// ServeReadyz is the /readyz handler. It performs only atomic reads so it
// responds in well under the 50 ms probe budget (CM-27).
func (r *readiness) ServeReadyz(w http.ResponseWriter, _ *http.Request) {
	leader, caches, certd, ok := r.Snapshot()
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"leader": leader,
		"caches": caches,
		"certd":  certd,
	})
}

// runCertdProbe ticks every interval, pings certdURL/status, and on any 2xx
// response updates the readiness timestamp. It must never block the probe
// endpoint; all network work happens here.
func runCertdProbe(ctx context.Context, certdURL string, interval time.Duration, ready *readiness, logger *slog.Logger) {
	client := &http.Client{Timeout: 5 * time.Second}
	probe := func() {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, certdURL+"/status", nil)
		if err != nil {
			logger.Warn("certd readiness probe: build request", "err", err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			logger.Debug("certd readiness probe: transport error", "err", err)
			return
		}
		defer func() {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			ready.MarkCertdOK(time.Now())
			return
		}
		logger.Debug("certd readiness probe: non-2xx", "status", resp.StatusCode)
	}

	probe()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			probe()
		}
	}
}

func startHealthServer(addr string, ready *readiness, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/readyz", ready.ServeReadyz)

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
