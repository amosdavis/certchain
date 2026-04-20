package certd

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/amosdavis/certchain/internal/avx"
	"github.com/amosdavis/certchain/internal/cert"
	"github.com/amosdavis/certchain/internal/chain"
	"github.com/amosdavis/certchain/internal/crypto"
	certk8s "github.com/amosdavis/certchain/internal/k8s"
	"github.com/amosdavis/certchain/internal/metrics"
	"github.com/amosdavis/certchain/internal/peer"
	"github.com/amosdavis/certchain/internal/query"
	"github.com/amosdavis/certchain/internal/tracing"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Run is the main entry point for certd. It sets up all subsystems and
// runs until ctx is cancelled. The logger is used throughout; if nil,
// a default text logger writing to stderr is created.
func Run(ctx context.Context, cfg *Config) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// CM-38: Initialize OpenTelemetry tracing.
	shutdownTracing, err := tracing.Init(ctx, "certd", cfg.OTelEndpoint)
	if err != nil {
		return fmt.Errorf("init tracing: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(shutdownCtx); err != nil {
			log.Printf("certd: tracing shutdown: %v", err)
		}
	}()

	// CM-28: resolve peer-push HMAC secret and query-API bearer token.
	// File-based sources take precedence over flag values to keep secrets
	// off argv; env vars are last-resort so container platforms that wire
	// Secrets to env (but not files) still work.
	peerSecretBytes, err := resolveSecret(cfg.PeerSecretFile, cfg.PeerSecret, "CERTD_PEER_SECRET")
	if err != nil {
		return fmt.Errorf("read peer-secret-file: %w", err)
	}
	if len(peerSecretBytes) == 0 {
		log.Printf("certd: WARN peer block-push HMAC secret not configured — any host in the peer table can inject blocks (CM-28). Set --peer-secret-file in production.")
	}
	queryTokenBytes, err := resolveSecret(cfg.QueryTokenFile, cfg.QueryToken, "CERTD_QUERY_TOKEN")
	if err != nil {
		return fmt.Errorf("read query-token-file: %w", err)
	}
	if len(queryTokenBytes) == 0 {
		log.Printf("certd: WARN HTTP query API bearer token not configured — all query endpoints are unauthenticated (CM-28). Set --query-token-file in production.")
	}

	id, err := crypto.LoadOrCreate(cfg.ConfigDir)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	log.Printf("certd: node pubkey %s", id.PubKeyHex())

	// Admin metrics listener. Safe to start early — it has no dependencies.
	registry := metrics.NewRegistry()
	chainMetrics := metrics.NewChainMetrics(registry)
	_ = metrics.NewAVXMetrics(registry)
	// Readiness state (CM-27). certd has no leader election today so the
	// leader signal is reported as "disabled" and does not gate readiness.
	ready := NewReadiness()
	startMetricsServer(ctx, logger, cfg.MetricsAddr, registry, ready)

	// CM-36: open WAL for crash-safe chain persistence
	walPath := cfg.ChainWALPath
	if walPath == "" {
		walPath = filepath.Join(cfg.ConfigDir, "chain.wal")
	}
	wal, err := chain.OpenWAL(walPath, logger, true)
	if err != nil {
		return fmt.Errorf("open WAL: %w", err)
	}
	defer wal.Close()

	ch := chain.New(
		chain.WithChainID(cfg.ChainID),
		chain.WithAcceptLegacySigs(cfg.AcceptLegacySigs),
		chain.WithMetrics(registry),
		chain.WithWAL(wal),
	)
	certStore := cert.NewStore(cfg.MaxCerts)
	peerTable := peer.NewTable()

	// CM-23: load validator allowlist if configured. Missing file is a
	// WARN (accept-all) so single-node and pre-rollout deployments keep
	// working; a malformed file is fatal.
	validatorsPath := cfg.ValidatorsFile
	if validatorsPath == "" {
		validatorsPath = filepath.Join(cfg.ConfigDir, "validators.json")
	}
	vs, err := LoadValidators(ctx, logger, validatorsPath)
	if err != nil {
		return fmt.Errorf("load validators: %w", err)
	}
	if vs == nil {
		log.Printf("certd: WARN validators.json not found at %s — chain is running in accept-all mode (CM-23)", validatorsPath)
	} else {
		log.Printf("certd: loaded %d authorized validators from %s (CM-23)", vs.Len(), validatorsPath)
		ch.SetValidators(vs)
	}

	if cfg.StaticPeers != "" {
		seeder := peer.NewStaticPeerSeeder(peerTable, strings.Split(cfg.StaticPeers, ","))
		seeder.Start()
		defer seeder.Stop()
	}

	// Load persisted chain if present.
	if err := LoadChain(ctx, logger, ch, certStore, cfg.ConfigDir, walPath); err != nil {
		log.Printf("certd: load chain: %v (starting fresh)", err)
	}
	// Even if load failed (fresh start), persisted-state replay has finished
	// and the process now reflects its on-disk source of truth. The peer-sync
	// signal below is strictly stronger, but marking here means /readyz is
	// not held open forever on a single-node deployment with no peers.
	ready.SetChainLoaded(true)

	// Peer discovery.
	discoverer := peer.NewDiscoverer(peerTable, id.PublicKey, peer.SyncPort)
	if err := discoverer.Start(); err != nil {
		return fmt.Errorf("start discovery: %w", err)
	}
	defer discoverer.Stop()

	// Block sync — OnNewBlocks is set after K8s wiring so triggerK8sSync is ready.
	syncer := peer.NewSyncer(ch, peerTable, id.PublicKey, cfg.ConfigDir)
	syncer.SetBlockSecret(peerSecretBytes)

	// blockSubmitter batches all block submissions (avxPollLoop + CSRWatcher)
	// through chain.Batcher so bursts commit as a single multi-tx block and
	// the per-node nonce stays monotonically increasing (CM-32).
	bs := NewBlockSubmitter(ctx, logger, ch, certStore, id, syncer, cfg.ConfigDir, walPath, cfg.BatchMaxTxs, cfg.BatchMaxWait, chainMetrics.SaveErrorsTotal.WithLabelValues("snapshot"))
	defer bs.Stop()

	// AppViewX client — shared between poll loop and K8s CSR watcher.
	var avxClient *avx.Client
	if cfg.AVXURL != "" {
		avxClient = avx.NewClient(avx.Config{
			BaseURL: cfg.AVXURL,
			APIKey:  cfg.AVXKey,
		})
	} else {
		log.Printf("certd: no --avx-url set; AVX polling disabled")
	}

	// Kubernetes integration (CM-16–CM-19).
	// triggerK8sSync is a no-op until K8s is enabled; syncer.OnNewBlocks calls
	// it so it must be defined before the callback is assigned.
	triggerK8sSync := func() {}
	if cfg.K8sEnabled {
		k8sClient, err := certk8s.NewInClusterClient()
		if err != nil {
			return fmt.Errorf("k8s in-cluster config: %w", err)
		}

		// CM-30: the direct-write Secret path is deprecated in favour of the
		// cert-manager external issuer (cmd/certchain-issuer).  It is gated
		// behind --enable-legacy-secret-writer so that operators running both
		// paths concurrently cannot accidentally cause split-brain Secret
		// ownership.  See docs/MIGRATION-LEGACY-SECRETS.md.
		if cfg.EnableLegacySecretWriter {
			log.Printf("certd: WARN %s", certk8s.LegacyWriterStartupWarning)

			//lint:ignore SA1019 transitional callsite for legacy writer
			sw := certk8s.NewSecretWriter(k8sClient, cfg.K8sNamespace, cfg.K8sSecretPrefix)

			// Dedicate one goroutine to SecretWriter syncs; a buffered channel
			// prevents duplicate queued syncs without blocking the caller.
			k8sSyncTrigger := make(chan struct{}, 1)
			go func() {
				for range k8sSyncTrigger {
					syncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
					if err := sw.Sync(syncCtx, certStore.List(false), cfg.ConfigDir); err != nil {
						log.Printf("certd: k8s secret sync: %v", err)
					}
					cancel()
				}
			}()
			triggerK8sSync = func() {
				select {
				case k8sSyncTrigger <- struct{}{}:
				default: // a sync is already queued; skip
				}
			}

			// Trigger an initial sync so existing secrets are up-to-date at start-up.
			triggerK8sSync()

			// Drain the trigger channel on shutdown so the sync goroutine exits cleanly.
			defer close(k8sSyncTrigger)
		} else {
			// Legacy writer disabled (default).  The first caller that
			// would have scheduled a sync gets a one-shot Warn so the
			// operator sees why Secrets are no longer being written.
			var legacyWarnOnce sync.Once
			triggerK8sSync = func() {
				legacyWarnOnce.Do(func() {
					log.Printf("certd: WARN %s", certk8s.LegacyWriterDisabledWarning)
				})
			}
		}

		// CSR watcher requires AVX to submit certificates.  It does not
		// depend on the legacy Secret writer and runs whenever K8s
		// integration is enabled.
		if avxClient != nil {
			cw := certk8s.NewCSRWatcher(k8sClient, avxClient, id, cfg.K8sSignerName, bs.Submit)
			cw.Start()
			defer cw.Stop()
		} else {
			log.Printf("certd: K8s CSR watching disabled (--avx-url not set)")
		}
	}

	syncer.OnNewBlocks = func(candidate []chain.Block) {
		replaced, err := ch.Replace(candidate)
		if err != nil {
			log.Printf("certd: chain replace error: %v", err)
			return
		}
		if replaced {
			log.Printf("certd: chain replaced with candidate len=%d", len(candidate))
			if err := certStore.RebuildFrom(ch.GetBlocks()); err != nil {
				log.Printf("certd: cert store rebuild: %v", err)
			}
			_ = SaveChain(ctx, logger, ch, cfg.ConfigDir, walPath, chainMetrics.SaveErrorsTotal.WithLabelValues("snapshot"))
			triggerK8sSync()
		}
	}
	if err := syncer.Start(); err != nil {
		return fmt.Errorf("start syncer: %w", err)
	}
	defer syncer.Stop()

	// HTTP query API.
	qserver := query.NewServer(certStore, ch, peerTable, cfg.ConfigDir)
	qserver.SetDERFetcher(syncer)
	
	// CM-38: Wrap handler with otelhttp middleware for distributed tracing.
	handler := otelhttp.NewHandler(
		queryAuthMiddleware(qserver.Handler(), queryTokenBytes),
		"certd-query-api",
	)
	
	httpServer := &http.Server{
		Addr:         cfg.QueryAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		log.Printf("certd: query API on %s", cfg.QueryAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("certd: HTTP server error: %v", err)
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	// AppViewX polling loop.
	if avxClient != nil {
		go func() {
			// Give UDP discovery time to find peers, then sync before polling AVX.
			// This prevents re-publishing certs already on chain after a restart.
			time.Sleep(2 * time.Second)
			syncer.SyncFromPeersAndWait(10 * time.Second)

			// Pre-populate published set from the now-current cert store.
			for _, rec := range certStore.List(false) {
				avxClient.MarkPublished(rec.AVXCertID)
			}
			AVXPollLoop(ctx, logger, avxClient, bs, cfg.ConfigDir, cfg.RenewWindow, cfg.NotifyURL, cfg.KeyVaultMap, triggerK8sSync)
		}()
	}

	// Wait for shutdown signal.
	<-ctx.Done()
	log.Println("certd: shutting down")

	_ = SaveChain(ctx, logger, ch, cfg.ConfigDir, walPath, chainMetrics.SaveErrorsTotal.WithLabelValues("snapshot"))

	return nil
}

// startMetricsServer exposes /metrics on the admin port. Failures are
// logged but do not terminate the process; metrics are observability, not
// availability-critical (see CM-14 for related HTTP timeout policy).
// /readyz reflects real operational readiness per CM-27.
func startMetricsServer(ctx context.Context, logger *slog.Logger, addr string, reg *metrics.Registry, ready *Readiness) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", reg.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/readyz", ready.ServeReadyz)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("certd: metrics on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("certd: metrics server error: %v", err)
		}
	}()
}
