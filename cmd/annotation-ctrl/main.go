// annotation-ctrl is the native, annotation-driven TLS Secret
// controller for certchain (CM-33). It watches Pods and Services for
// the certchain.io/cert-cn annotation and provisions a kubernetes.io/tls
// Secret in the same namespace, sourced from certd's Bearer-protected
// query API (CM-28).
//
// It is an alternative to the cert-manager external-issuer path
// (cmd/certchain-issuer); the two must not be enabled for the same
// Secret. See spec/FAILURES.md CM-30 and CM-33.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/amosdavis/certchain/internal/annotation"
	"github.com/amosdavis/certchain/internal/leader"
	"github.com/amosdavis/certchain/internal/logging"
	"github.com/amosdavis/certchain/internal/metrics"
	"github.com/amosdavis/certchain/internal/tracing"
)

func main() {
	healthAddr := flag.String("health-addr", ":8082", "Address for liveness/readiness HTTP server")
	metricsAddr := flag.String("metrics-addr", ":9880", "Address for Prometheus /metrics")
	certdURL := flag.String("certd-url", "http://127.0.0.1:9879", "certd query API base URL (Bearer-protected per CM-28)")
	queryTokenFile := flag.String("query-token-file", "", "Path to file containing the Bearer token certd requires on its query API (CM-28)")
	queryToken := flag.String("query-token", "", "Bearer token required on certd's query API (prefer --query-token-file)")
	namespace := flag.String("namespace", "", "Namespace to watch; empty = all namespaces (cluster-wide)")
	kubeconfig := flag.String("kubeconfig", "", "Path to a kubeconfig file; empty = in-cluster config")
	leaderElect := flag.Bool("leader-elect", true, "Enable leader election across replicas (CM-22)")
	leaseName := flag.String("leader-lease-name", "annotation-ctrl", "Lease name used for leader election")
	leaseNamespace := flag.String("leader-lease-namespace", "", "Namespace for the Lease (defaults to POD_NAMESPACE / certchain)")
	logFormat := flag.String("log-format", "json", "Log format: json|text")
	logLevel := flag.String("log-level", "info", "Log level: debug|info|warn|error")
	reconnectDelay := flag.Duration("reconnect-delay", 5*time.Second, "Delay before reconnecting a watch after an error")
	readinessMaxStaleness := flag.Duration("readiness-max-staleness", 60*time.Second, "Maximum age of the last certd probe before /readyz returns 503 (CM-27)")
	certdProbeInterval := flag.Duration("certd-probe-interval", 15*time.Second, "Background certd reachability probe interval for /readyz (CM-27)")
	renewBefore := flag.Duration("renew-before", 30*24*time.Hour, "Renew certs this duration before NotAfter (default 30d)")
	otelEndpoint := flag.String("otel-endpoint", "", "OTLP/HTTP endpoint for distributed tracing (empty=no-op); overridden by OTEL_EXPORTER_OTLP_ENDPOINT (CM-38)")
	flag.Parse()

	logger := logging.New(logging.Options{
		Format: logging.ParseFormat(*logFormat),
		Level:  logging.ParseLevel(*logLevel),
	}).With("binary", "annotation-ctrl")

	// CM-38: Initialize OpenTelemetry tracing.
	shutdownTracing, err := tracing.Init(context.Background(), "annotation-ctrl", *otelEndpoint)
	if err != nil {
		logger.Error("init tracing", "err", err)
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(shutdownCtx); err != nil {
			logger.Warn("tracing shutdown", "err", err)
		}
	}()

	token, err := resolveToken(*queryTokenFile, *queryToken, "CERTD_QUERY_TOKEN")
	if err != nil {
		logger.Error("resolve query token", "err", err)
		os.Exit(1)
	}
	if len(token) == 0 {
		logger.Warn("certd query token not configured — certd is likely to reject our requests (CM-28); set --query-token-file in production")
	}

	cfg, err := loadRESTConfig(*kubeconfig)
	if err != nil {
		logger.Error("load kubeconfig", "err", err)
		os.Exit(1)
	}
	k8sClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Error("create k8s client", "err", err)
		os.Exit(1)
	}

	registry := metrics.NewRegistry()
	annMetrics := annotation.NewMetrics(registry)
	renewalMetrics := metrics.NewAnnotationRenewalMetrics(registry)

	fetcher := annotation.NewHTTPFetcher(*certdURL, string(token))
	scheduler := annotation.NewRenewalScheduler(k8sClient, fetcher, *renewBefore, logger, renewalMetrics)
	reconciler := annotation.NewReconciler(k8sClient, fetcher, logger, annMetrics, scheduler)
	controller := annotation.NewController(k8sClient, reconciler, *namespace, logger).
		WithReconnectDelay(*reconnectDelay)

	ready := newReadiness(*certdURL, *readinessMaxStaleness)
	if !*leaderElect {
		ready.SetLeader(true)
	}

	startHealthServer(*healthAddr, ready, logger)
	startMetricsServer(*metricsAddr, registry, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *certdURL != "" {
		go runCertdProbe(ctx, *certdURL, string(token), *certdProbeInterval, ready, logger)
	}

	run := func(ctx context.Context) error {
		ready.SetCachesSynced(true)
		// Start renewal scheduler in background
		go scheduler.Run(ctx, 1)
		return controller.Run(ctx)
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

// loadRESTConfig returns an in-cluster config when kubeconfig is empty,
// else a config loaded from the supplied file (resolving ~ when present).
func loadRESTConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig == "" {
		return rest.InClusterConfig()
	}
	if len(kubeconfig) > 0 && kubeconfig[0] == '~' {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, kubeconfig[1:])
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

// resolveToken mirrors certd's resolveSecret convention: file path
// first (preferred), then flag, then env var. Trailing CR/LF are
// trimmed so `echo "$TOKEN" > file` does not accidentally embed a
// newline in the credential (CM-28).
func resolveToken(path, flagValue, envKey string) ([]byte, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return bytes.TrimRight(data, "\r\n"), nil
	}
	if flagValue != "" {
		return []byte(flagValue), nil
	}
	if envKey != "" {
		if v := os.Getenv(envKey); v != "" {
			return []byte(v), nil
		}
	}
	return nil, nil
}

// readiness implements the three-signal /readyz contract (CM-27):
// leader, caches, certd reachability.
type readiness struct {
	leader           atomic.Bool
	cachesSynced     atomic.Bool
	certdLastOKNanos atomic.Int64
	certdURL         string
	maxStaleness     time.Duration
	now              func() time.Time
}

func newReadiness(certdURL string, maxStaleness time.Duration) *readiness {
	return &readiness{certdURL: certdURL, maxStaleness: maxStaleness, now: time.Now}
}

func (r *readiness) SetLeader(v bool)        { r.leader.Store(v) }
func (r *readiness) SetCachesSynced(v bool)  { r.cachesSynced.Store(v) }
func (r *readiness) MarkCertdOK(t time.Time) { r.certdLastOKNanos.Store(t.UnixNano()) }

func (r *readiness) Snapshot() (leaderS, cachesS, certdS string, ok bool) {
	leaderOK := r.leader.Load()
	cachesOK := r.cachesSynced.Load()

	leaderS = "not_acquired"
	if leaderOK {
		leaderS = "ok"
	}
	cachesS = "syncing"
	if cachesOK {
		cachesS = "synced"
	}
	certdOK := true
	switch {
	case r.certdURL == "":
		certdS = "disabled"
	default:
		lastNanos := r.certdLastOKNanos.Load()
		if lastNanos == 0 {
			certdS = "never"
			certdOK = false
			break
		}
		age := r.now().Sub(time.Unix(0, lastNanos))
		if age > r.maxStaleness {
			certdS = fmt.Sprintf("stale_%s", age.Truncate(time.Second))
			certdOK = false
			break
		}
		certdS = "ok"
	}
	ok = leaderOK && cachesOK && certdOK
	return
}

func (r *readiness) ServeReadyz(w http.ResponseWriter, _ *http.Request) {
	l, c, d, ok := r.Snapshot()
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"leader": l, "caches": c, "certd": d})
}

// runCertdProbe pings <certdURL>/status at every tick and updates the
// readiness timestamp on 2xx. Token is sent when non-empty so the
// middleware allowlist's /status bypass is not required.
func runCertdProbe(ctx context.Context, certdURL, token string, interval time.Duration, ready *readiness, logger *slog.Logger) {
	client := &http.Client{Timeout: 5 * time.Second}
	probe := func() {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, certdURL+"/status", nil)
		if err != nil {
			logger.Warn("certd probe: build request", "err", err)
			return
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			logger.Debug("certd probe: transport error", "err", err)
			return
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			ready.MarkCertdOK(time.Now())
		}
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
