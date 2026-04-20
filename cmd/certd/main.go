// certd is the certchain daemon.
//
// It manages a certchain blockchain node: polls AppViewX for new or revoked
// certificates, maintains the local chain and cert store, syncs with peers,
// and exposes the HTTP query API on :9879.
//
// Usage:
//
//	certd [--config <dir>] [--avx-url <url>] [--avx-key <key>]
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/amosdavis/certchain/internal/avx"
	"github.com/amosdavis/certchain/internal/cert"
	"github.com/amosdavis/certchain/internal/chain"
	"github.com/amosdavis/certchain/internal/crypto"
	certk8s "github.com/amosdavis/certchain/internal/k8s"
	"github.com/amosdavis/certchain/internal/metrics"
	"github.com/amosdavis/certchain/internal/peer"
	"github.com/amosdavis/certchain/internal/query"
)

// keyVaultEntry is one entry in the --key-vault-map JSON file.
type keyVaultEntry struct {
	KeyVaultRef  string   `json:"key_vault_ref"`
	Environments []string `json:"environments"`
}

func main() {
	configDir       := flag.String("config", defaultConfigDir(), "config directory")
	avxURL          := flag.String("avx-url", "", "AppViewX base URL (e.g. https://avx.example.com)")
	avxKey          := flag.String("avx-key", "", "AppViewX API key")
	queryAddr       := flag.String("query-addr", ":9879", "HTTP query API listen address")
	maxCerts        := flag.Int("max-certs", 0, "maximum cert records (0=unlimited)")
	renewWindow     := flag.Duration("renew-window", 30*24*time.Hour, "trigger AVX proactive renewal this far before cert expiry (0=disabled)")
	notifyURL       := flag.String("notify-url", "", "webhook URL to POST on cert renewal or revocation")
	staticPeers     := flag.String("static-peers", "", "comma-separated host:port peers for cross-cluster sync")
	keyVaultMap     := flag.String("key-vault-map", "", "path to JSON file mapping CNs to key vault URIs and environments")
	k8sEnabled      := flag.Bool("k8s-enabled", false, "enable Kubernetes Secret and CSR integration")
	k8sNamespace    := flag.String("k8s-namespace", "", "Kubernetes namespace for Secrets (default: certchain)")
	k8sSecretPrefix := flag.String("k8s-secret-prefix", "", "prefix for K8s Secret names (default: cc)")
	k8sSignerName   := flag.String("k8s-signer-name", "", "CSR signerName to watch (default: certchain.io/appviewx)")
	enableLegacySecretWriter := flag.Bool("enable-legacy-secret-writer", false, "enable the deprecated certd direct-write Secret path (CM-30); the modern path is the cert-manager external issuer — see docs/MIGRATION-LEGACY-SECRETS.md")
	metricsAddr     := flag.String("metrics-addr", ":9880", "Address for Prometheus /metrics (H3)")
	validatorsFile  := flag.String("validators", "", "path to validators.json allowlist (default: <config>/validators.json, CM-23)")
	peerSecret      := flag.String("peer-secret", "", "shared cluster secret for HMAC-authenticating peer block pushes (CM-28; prefer --peer-secret-file)")
	peerSecretFile  := flag.String("peer-secret-file", "", "path to a file whose contents are the shared cluster peer-push HMAC secret (CM-28)")
	queryToken      := flag.String("query-token", "", "Bearer token required on HTTP query API (CM-28; prefer --query-token-file)")
	queryTokenFile  := flag.String("query-token-file", "", "path to a file whose contents are the Bearer token required on the HTTP query API (CM-28)")
	chainID          := flag.String("chain-id", chain.DefaultChainID, "chainID mixed into the signature domain separator (CM-29); must match across all peers in a network")
	acceptLegacySigs := flag.Bool("accept-legacy-sigs", true, "accept signatures in the pre-CM-29 no-domain-separator format; flip to false once all peers have re-signed (CM-29)")
	batchMaxTxs      := flag.Int("batch-max-txs", chain.DefaultBatchMaxTxs, "maximum transactions committed in a single block by the chain.Batcher (CM-32)")
	batchMaxWait     := flag.Duration("batch-max-wait", chain.DefaultBatchMaxWait, "maximum time the chain.Batcher will hold a partial batch before committing (CM-32)")
	flag.Parse()

	// Allow env-var overrides so k8s ConfigMaps/Secrets can drive configuration
	// without needing a shell to build the args list.
	if *avxURL == ""      { *avxURL = os.Getenv("AVX_URL") }
	if *avxKey == ""      { *avxKey = os.Getenv("AVX_KEY") }
	if *notifyURL == ""   { *notifyURL = os.Getenv("NOTIFY_URL") }
	if *staticPeers == "" { *staticPeers = os.Getenv("STATIC_PEERS") }
	if !*k8sEnabled {
		v := os.Getenv("K8S_ENABLED")
		*k8sEnabled = v == "true" || v == "1"
	}
	if *k8sNamespace == ""    { *k8sNamespace = os.Getenv("K8S_NAMESPACE") }
	if *k8sSecretPrefix == "" { *k8sSecretPrefix = os.Getenv("K8S_SECRET_PREFIX") }
	if *k8sSignerName == ""   { *k8sSignerName = os.Getenv("K8S_SIGNER_NAME") }
	if !*enableLegacySecretWriter {
		v := os.Getenv("ENABLE_LEGACY_SECRET_WRITER")
		*enableLegacySecretWriter = v == "true" || v == "1"
	}
	// Apply built-in defaults after env-var resolution.
	if *k8sNamespace == ""    { *k8sNamespace = "certchain" }
	if *k8sSecretPrefix == "" { *k8sSecretPrefix = "cc" }
	if *k8sSignerName == ""   { *k8sSignerName = "certchain.io/appviewx" }

	// CM-28: resolve peer-push HMAC secret and query-API bearer token.
	// File-based sources take precedence over flag values to keep secrets
	// off argv; env vars are last-resort so container platforms that wire
	// Secrets to env (but not files) still work.
	peerSecretBytes, err := resolveSecret(*peerSecretFile, *peerSecret, "CERTD_PEER_SECRET")
	if err != nil {
		log.Fatalf("certd: read peer-secret-file: %v", err)
	}
	if len(peerSecretBytes) == 0 {
		log.Printf("certd: WARN peer block-push HMAC secret not configured — any host in the peer table can inject blocks (CM-28). Set --peer-secret-file in production.")
	}
	queryTokenBytes, err := resolveSecret(*queryTokenFile, *queryToken, "CERTD_QUERY_TOKEN")
	if err != nil {
		log.Fatalf("certd: read query-token-file: %v", err)
	}
	if len(queryTokenBytes) == 0 {
		log.Printf("certd: WARN HTTP query API bearer token not configured — all query endpoints are unauthenticated (CM-28). Set --query-token-file in production.")
	}

	id, err := crypto.LoadOrCreate(*configDir)
	if err != nil {
		log.Fatalf("certd: load identity: %v", err)
	}
	log.Printf("certd: node pubkey %s", id.PubKeyHex())

	// Admin metrics listener. Safe to start early — it has no dependencies.
	registry := metrics.NewRegistry()
	_ = metrics.NewChainMetrics(registry)
	_ = metrics.NewAVXMetrics(registry)
	// Readiness state (CM-27). certd has no leader election today so the
	// leader signal is reported as "disabled" and does not gate readiness.
	ready := newCertdReadiness()
	startCertdMetricsServer(*metricsAddr, registry, ready)

	ch := chain.New(
		chain.WithChainID(*chainID),
		chain.WithAcceptLegacySigs(*acceptLegacySigs),
		chain.WithMetrics(registry),
	)
	certStore := cert.NewStore(*maxCerts)
	peerTable := peer.NewTable()

	// CM-23: load validator allowlist if configured. Missing file is a
	// WARN (accept-all) so single-node and pre-rollout deployments keep
	// working; a malformed file is fatal.
	validatorsPath := *validatorsFile
	if validatorsPath == "" {
		validatorsPath = filepath.Join(*configDir, "validators.json")
	}
	vs, err := chain.LoadValidatorsFromFile(validatorsPath)
	if err != nil {
		log.Fatalf("certd: load validators %s: %v", validatorsPath, err)
	}
	if vs == nil {
		log.Printf("certd: WARN validators.json not found at %s — chain is running in accept-all mode (CM-23)", validatorsPath)
	} else {
		log.Printf("certd: loaded %d authorized validators from %s (CM-23)", vs.Len(), validatorsPath)
		ch.SetValidators(vs)
	}

	if *staticPeers != "" {
		seeder := peer.NewStaticPeerSeeder(peerTable, strings.Split(*staticPeers, ","))
		seeder.Start()
		defer seeder.Stop()
	}

	// Load persisted chain if present.
	if err := loadChain(ch, certStore, *configDir); err != nil {
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
		log.Fatalf("certd: start discovery: %v", err)
	}
	defer discoverer.Stop()

	// Block sync — OnNewBlocks is set after K8s wiring so triggerK8sSync is ready.
	syncer := peer.NewSyncer(ch, peerTable, id.PublicKey, *configDir)
	syncer.SetBlockSecret(peerSecretBytes)

	// blockSubmitter batches all block submissions (avxPollLoop + CSRWatcher)
	// through chain.Batcher so bursts commit as a single multi-tx block and
	// the per-node nonce stays monotonically increasing (CM-32).
	bs := newBlockSubmitter(ch, certStore, id, syncer, *configDir, *batchMaxTxs, *batchMaxWait)
	defer bs.Stop()

	// AppViewX client — shared between poll loop and K8s CSR watcher.
	var avxClient *avx.Client
	if *avxURL != "" {
		avxClient = avx.NewClient(avx.Config{
			BaseURL: *avxURL,
			APIKey:  *avxKey,
		})
	} else {
		log.Printf("certd: no --avx-url set; AVX polling disabled")
	}

	// Kubernetes integration (CM-16–CM-19).
	// triggerK8sSync is a no-op until K8s is enabled; syncer.OnNewBlocks calls
	// it so it must be defined before the callback is assigned.
	triggerK8sSync := func() {}
	if *k8sEnabled {
		k8sClient, err := certk8s.NewInClusterClient()
		if err != nil {
			log.Fatalf("certd: k8s in-cluster config: %v", err)
		}

		// CM-30: the direct-write Secret path is deprecated in favour of the
		// cert-manager external issuer (cmd/certchain-issuer).  It is gated
		// behind --enable-legacy-secret-writer so that operators running both
		// paths concurrently cannot accidentally cause split-brain Secret
		// ownership.  See docs/MIGRATION-LEGACY-SECRETS.md.
		if *enableLegacySecretWriter {
			log.Printf("certd: WARN %s", certk8s.LegacyWriterStartupWarning)

			//lint:ignore SA1019 transitional callsite for legacy writer
			sw := certk8s.NewSecretWriter(k8sClient, *k8sNamespace, *k8sSecretPrefix)

			// Dedicate one goroutine to SecretWriter syncs; a buffered channel
			// prevents duplicate queued syncs without blocking the caller.
			k8sSyncTrigger := make(chan struct{}, 1)
			go func() {
				for range k8sSyncTrigger {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					if err := sw.Sync(ctx, certStore.List(false), *configDir); err != nil {
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
			cw := certk8s.NewCSRWatcher(k8sClient, avxClient, id, *k8sSignerName, bs.Submit)
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
			if err := saveChain(ch, *configDir); err != nil {
				log.Printf("certd: save chain: %v", err)
			}
			triggerK8sSync()
		}
	}
	if err := syncer.Start(); err != nil {
		log.Fatalf("certd: start syncer: %v", err)
	}
	defer syncer.Stop()

	// HTTP query API.
	qserver := query.NewServer(certStore, ch, peerTable, *configDir)
	qserver.SetDERFetcher(syncer)
	httpServer := &http.Server{
		Addr:         *queryAddr,
		Handler:      queryAuthMiddleware(qserver.Handler(), queryTokenBytes),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		log.Printf("certd: query API on %s", *queryAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("certd: HTTP server error: %v", err)
		}
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
			avxPollLoop(avxClient, bs, *configDir, *renewWindow, *notifyURL, *keyVaultMap, triggerK8sSync)
		}()
	}

	// Wait for shutdown signal.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("certd: shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)

	if err := saveChain(ch, *configDir); err != nil {
		log.Printf("certd: save chain on shutdown: %v", err)
	}
}

// startCertdMetricsServer exposes /metrics on the admin port. Failures are
// logged but do not terminate the process; metrics are observability, not
// availability-critical (see CM-14 for related HTTP timeout policy).
// /readyz reflects real operational readiness per CM-27.
func startCertdMetricsServer(addr string, reg *metrics.Registry, ready *certdReadiness) {
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

// certdReadiness tracks the /readyz signals for certd (CM-27). Only the
// owning subsystem moves each flag forward (false -> true).
//
// Today certd does not run leader election, so leaderElectionEnabled is
// false and the leader signal is reported as "disabled" and does not gate
// readiness. When leader election is added, set leaderElectionEnabled
// true at startup and call SetLeader(true) inside the OnStartedLeading
// callback.
type certdReadiness struct {
	chainLoaded            atomic.Bool
	leaderAcquired         atomic.Bool
	leaderElectionEnabled  atomic.Bool
}

func newCertdReadiness() *certdReadiness { return &certdReadiness{} }

func (r *certdReadiness) SetChainLoaded(v bool)  { r.chainLoaded.Store(v) }
func (r *certdReadiness) SetLeader(v bool)       { r.leaderAcquired.Store(v) }
func (r *certdReadiness) EnableLeader(v bool)    { r.leaderElectionEnabled.Store(v) }

// Snapshot returns the per-signal human strings plus an overall ready bit.
// It performs only atomic reads and never blocks.
func (r *certdReadiness) Snapshot() (leader, chainStr string, ok bool) {
	chainOK := r.chainLoaded.Load()
	chainStr = "loading"
	if chainOK {
		chainStr = "loaded"
	}

	leaderOK := true
	if r.leaderElectionEnabled.Load() {
		leaderOK = r.leaderAcquired.Load()
		leader = "not_acquired"
		if leaderOK {
			leader = "ok"
		}
	} else {
		leader = "disabled"
	}

	ok = chainOK && leaderOK
	return
}

// ServeReadyz handles /readyz. It performs only atomic reads so it responds
// in well under the 50 ms probe budget (CM-27).
func (r *certdReadiness) ServeReadyz(w http.ResponseWriter, _ *http.Request) {
	leader, chainStr, ok := r.Snapshot()
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"leader": leader,
		"chain":  chainStr,
	})
}

// blockSubmitter groups block submissions from concurrent goroutines
// (avxPollLoop and CSRWatcher) through a chain.Batcher so bursts commit
// as a single multi-tx block (CM-32). The Batcher drain goroutine is
// single-threaded, so SignTx assigns the per-node nonce without a mutex;
// per-batch rollback on a failed commit keeps the counter monotonic.
type blockSubmitter struct {
	nonce     uint32
	ch        *chain.Chain
	id        *crypto.Identity
	certStore *cert.Store
	syncer    *peer.Syncer
	configDir string
	batcher   *chain.Batcher
}

func newBlockSubmitter(ch *chain.Chain, certStore *cert.Store, id *crypto.Identity, syncer *peer.Syncer, configDir string, batchMaxTxs int, batchMaxWait time.Duration) *blockSubmitter {
	bs := &blockSubmitter{
		ch: ch, certStore: certStore, id: id, syncer: syncer, configDir: configDir,
	}
	// Resume nonce from chain to avoid replay (monotonic per-node).
	for _, blk := range ch.GetBlocks() {
		for _, tx := range blk.Txs {
			if tx.NodePubkey == id.PublicKey && tx.Nonce > bs.nonce {
				bs.nonce = tx.Nonce
			}
		}
	}
	bs.batcher = chain.NewBatcher(context.Background(), ch, chain.BatcherConfig{
		MaxTxs:  batchMaxTxs,
		MaxWait: batchMaxWait,
		Signer:  bs,
		OnBlock: bs.onBlockCommitted,
	})
	return bs
}

// SignTx implements chain.Signer. It assigns this node's pubkey, the
// current timestamp, and a monotonically increasing nonce, then signs
// the transaction under the chain's current signing context (CM-29).
// Called exclusively from the Batcher drain goroutine.
func (bs *blockSubmitter) SignTx(tx *chain.Transaction) {
	bs.nonce++
	tx.NodePubkey = bs.id.PublicKey
	tx.Timestamp = chain.Now()
	tx.Nonce = bs.nonce
	chain.Sign(tx, bs.id)
}

// OnBatchRollback implements chain.Signer. When BatchSubmit rejects the
// batch, every nonce advanced in SignTx is rolled back so the next batch
// reuses the same nonce range; without this the chain would forever
// reject this node's subsequent submissions for nonce-replay.
func (bs *blockSubmitter) OnBatchRollback(n int) {
	bs.nonce -= uint32(n)
}

// onBlockCommitted is the Batcher's post-commit hook. It mirrors the
// pre-CM-32 per-block side-effects: cert-store apply, peer push, and
// persistent save.
func (bs *blockSubmitter) onBlockCommitted(blk chain.Block) {
	if err := bs.certStore.ApplyBlock(blk); err != nil {
		log.Printf("certd: cert store apply block: %v", err)
	}
	bs.syncer.PushBlockToPeers(blk)
	_ = saveChain(bs.ch, bs.configDir)
}

// Submit adds a transaction to the chain via the Batcher. tx must have
// Type and Payload set; NodePubkey, Timestamp, Nonce, and Signature are
// filled in by SignTx inside the drain goroutine, preventing duplicate
// nonces when multiple goroutines submit concurrently. Submit blocks
// until the batch containing tx has been committed (or rejected).
func (bs *blockSubmitter) Submit(tx chain.Transaction) error {
	return bs.batcher.Submit(tx)
}

// Stop flushes any queued txs and releases the Batcher drain goroutine.
// Safe to call multiple times.
func (bs *blockSubmitter) Stop() {
	if bs.batcher != nil {
		bs.batcher.Stop()
	}
}

// avxPollLoop polls AppViewX and publishes new/revoked/renewed certs to the chain.
// It also enforces certificate expiry (CM-02): any active cert whose not_after
// has passed is auto-revoked via TxCertRevoke.
// When renewWindow > 0, it proactively calls the AVX renewal API for certs
// approaching expiry so that AVX issues a replacement before the cert expires.
// onPollDone is called after each successful poll cycle (used to trigger K8s sync).
func avxPollLoop(client *avx.Client, bs *blockSubmitter, configDir string, renewWindow time.Duration, notifyURL string, keyVaultMapFile string, onPollDone func()) {
	kvMap := loadKeyVaultMap(keyVaultMapFile)

	const (
		backoffBase = 5 * time.Second
		backoffMax  = 10 * time.Minute
	)
	consecutiveErrors := 0
	nextSleep := time.Duration(0) // no initial sleep; poll immediately on first iteration

	for {
		if nextSleep > 0 {
			time.Sleep(nextSleep)
		}

		// Reload key vault map each cycle so file edits take effect without restart.
		if keyVaultMapFile != "" {
			kvMap = loadKeyVaultMap(keyVaultMapFile)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		result, err := client.Poll(ctx)
		cancel()

		if err != nil {
			consecutiveErrors++
			sleep := backoffBase
			for i := 1; i < consecutiveErrors; i++ {
				sleep *= 2
				if sleep > backoffMax {
					sleep = backoffMax
					break
				}
			}
			var rateLimitErr *avx.ErrRateLimited
			if errors.As(err, &rateLimitErr) && rateLimitErr.RetryAfter > sleep {
				sleep = rateLimitErr.RetryAfter
			}
			log.Printf("certd: AVX poll error (retry in %v): %v", sleep, err)
			nextSleep = sleep
			continue
		}
		consecutiveErrors = 0
		nextSleep = client.PollIntervalWithJitter()

		// renewedOldAVXIDs tracks old AVX cert IDs superseded by a TxCertRenew this
		// cycle so that we do not also emit a separate TxCertRevoke for them.
		renewedOldAVXIDs := make(map[string]struct{})

		for _, c := range result.NewCerts {
			// Check if this is a renewal: same CN already has an active cert.
			oldRec, isRenewal := bs.certStore.GetByCN(c.CommonName)

			payload, certID, err := buildPublishPayload(c, configDir, client, kvMap)
			if err != nil {
				log.Printf("certd: build publish payload for %s: %v", c.CommonName, err)
				continue
			}
			if err := bs.Submit(chain.Transaction{Type: chain.TxCertPublish, Payload: payload}); err != nil {
				log.Printf("certd: submit publish for %s: %v", c.CommonName, err)
				continue
			}
			client.MarkPublished(c.AVXCertID)

			// If this is a renewal, emit TxCertRenew linking old → new cert_id.
			// TxCertRenew sets the old cert's status to "replaced", so no separate
			// TxCertRevoke is needed for the old cert.
			if isRenewal {
				renewPayload, err := chain.MarshalRenew(&chain.CertRenewPayload{
					OldCertID: oldRec.CertID,
					NewCertID: certID,
				})
				if err != nil {
					log.Printf("certd: marshal renew for %s: %v", c.CommonName, err)
					continue
				}
				if err := bs.Submit(chain.Transaction{Type: chain.TxCertRenew, Payload: renewPayload}); err != nil {
					log.Printf("certd: submit renew for %s: %v", c.CommonName, err)
					continue
				}
				client.MarkUnpublished(oldRec.AVXCertID)
				renewedOldAVXIDs[oldRec.AVXCertID] = struct{}{}
				if notifyURL != "" {
					go notifyCertEvent(notifyURL, "renewed", c.CommonName,
						fmt.Sprintf("%x", oldRec.CertID), fmt.Sprintf("%x", certID))
				}
			}
		}

		for _, c := range result.RevokedCerts {
			// Skip certs superseded by a TxCertRenew this cycle.
			if _, skip := renewedOldAVXIDs[c.AVXCertID]; skip {
				continue
			}
			certID := certIDFromAVX(bs.certStore, c.AVXCertID)
			if certID == nil {
				continue
			}
			var revokeCN string
			if rec, ok := bs.certStore.GetByID(*certID); ok {
				revokeCN = rec.CN
			}
			revokePayload, err := chain.MarshalRevoke(&chain.CertRevokePayload{
				CertID:    *certID,
				Reason:    0,
				RevokedAt: chain.Now(),
			})
			if err != nil {
				log.Printf("certd: marshal revoke: %v", err)
				continue
			}
			if err := bs.Submit(chain.Transaction{Type: chain.TxCertRevoke, Payload: revokePayload}); err != nil {
				log.Printf("certd: submit revoke: %v", err)
				continue
			}
			if notifyURL != "" {
				go notifyCertEvent(notifyURL, "revoked", revokeCN,
					fmt.Sprintf("%x", *certID), "")
			}
		}

		// CM-02: auto-revoke any active cert whose not_after has passed.
		// This is the local expiry enforcement fallback for when AVX is slow or
		// silent about an expiry.
		now := time.Now().Unix()
		for _, rec := range bs.certStore.List(true) {
			if rec.NotAfter > now {
				continue
			}
			revokePayload, err := chain.MarshalRevoke(&chain.CertRevokePayload{
				CertID:    rec.CertID,
				Reason:    0,
				RevokedAt: chain.Now(),
			})
			if err != nil {
				log.Printf("certd: marshal expiry revoke for %s: %v", rec.CN, err)
				continue
			}
			if err := bs.Submit(chain.Transaction{Type: chain.TxCertRevoke, Payload: revokePayload}); err != nil {
				log.Printf("certd: submit expiry revoke for %s: %v", rec.CN, err)
				continue
			}
			if notifyURL != "" {
				go notifyCertEvent(notifyURL, "revoked", rec.CN,
					fmt.Sprintf("%x", rec.CertID), "")
			}
		}

		// Proactive renewal: trigger AVX to issue a replacement cert for any
		// active cert within the renewal window. The new cert will appear in
		// the next poll cycle via result.NewCerts and be linked via TxCertRenew.
		// Idempotent: AVX returns HTTP 409 if a renewal is already in progress.
		if renewWindow > 0 {
			renewWindowSecs := int64(renewWindow.Seconds())
			renewCutoff := now + renewWindowSecs
			for _, rec := range bs.certStore.List(true) {
				if rec.NotAfter <= now || rec.NotAfter > renewCutoff {
					continue // already expired or not yet within window
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				if err := client.RenewCert(ctx, rec.AVXCertID); err != nil {
					log.Printf("certd: proactive renewal trigger for %s: %v", rec.CN, err)
				} else {
					log.Printf("certd: triggered AVX renewal for %s (expires in %ds)", rec.CN, rec.NotAfter-now)
				}
				cancel()
			}
		}

		onPollDone()
	}
}

// buildPublishPayload fetches the DER from AVX, caches it locally, and returns
// the serialised TxCertPublish payload together with the cert's SHA-256 certID.
func buildPublishPayload(c *avx.Cert, configDir string, client *avx.Client, kvMap map[string]keyVaultEntry) (json.RawMessage, [32]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	der, err := client.GetDER(ctx, c.AVXCertID)
	cancel()
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("get DER: %w", err)
	}

	certID := sha256.Sum256(der)

	// Cache DER locally.
	derDir := filepath.Join(configDir, "certs")
	if err := os.MkdirAll(derDir, 0700); err == nil {
		hexID := fmt.Sprintf("%x", certID)
		_ = os.WriteFile(filepath.Join(derDir, hexID+".der"), der, 0600)
	}

	// Parse DER to extract issuer and key algorithm metadata.
	var issuerDN, keyAlg string
	if parsed, parseErr := x509.ParseCertificate(der); parseErr == nil {
		issuerDN = parsed.Issuer.String()
		keyAlg = keyAlgorithmString(parsed.PublicKey)
	}

	// Look up key vault reference and environments for this CN.
	var kvRef string
	var envs []string
	if entry, ok := kvMap[c.CommonName]; ok {
		kvRef = entry.KeyVaultRef
		envs = entry.Environments
	}

	payload, err := chain.MarshalPublish(&chain.CertPublishPayload{
		CertID:       certID,
		CN:           c.CommonName,
		AVXCertID:    c.AVXCertID,
		NotBefore:    c.NotBefore.Unix(),
		NotAfter:     c.NotAfter.Unix(),
		SANs:         c.SANs,
		Serial:       c.Serial,
		IssuerDN:     issuerDN,
		KeyAlgorithm: keyAlg,
		Template:     c.Template,
		Requester:    c.Requester,
		KeyVaultRef:  kvRef,
		Environments: envs,
	})
	if err != nil {
		return nil, [32]byte{}, err
	}
	return payload, certID, nil
}

// keyAlgorithmString returns a human-readable algorithm+size string for a public key.
func keyAlgorithmString(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-P%d", k.Curve.Params().BitSize)
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	default:
		return "unknown"
	}
}

// loadKeyVaultMap reads the key-vault-map JSON file. Returns an empty map on error.
func loadKeyVaultMap(path string) map[string]keyVaultEntry {
	m := make(map[string]keyVaultEntry)
	if path == "" {
		return m
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("certd: read key-vault-map: %v", err)
		return m
	}
	if err := json.Unmarshal(data, &m); err != nil {
		log.Printf("certd: parse key-vault-map: %v", err)
	}
	return m
}

func certIDFromAVX(certStore *cert.Store, avxCertID string) *[32]byte {
	for _, rec := range certStore.List(false) {
		if rec.AVXCertID == avxCertID && rec.Status != cert.StatusReplaced {
			id := rec.CertID
			return &id
		}
	}
	return nil
}

// ---- persistence ----

type persistedChain struct {
	Blocks []chain.Block `json:"blocks"`
}

func saveChain(ch *chain.Chain, configDir string) error {
	data, err := json.Marshal(persistedChain{Blocks: ch.GetBlocks()})
	if err != nil {
		return err
	}
	path := filepath.Join(configDir, "chain.json")
	return os.WriteFile(path, data, 0600)
}

// resolveSecret returns the secret material from the first available
// source: a file (preferred, to keep secrets off argv and environment),
// then a flag value, then an environment variable. A missing file path
// produces no error (secret simply stays empty); an unreadable path is
// fatal because the caller explicitly asked for file-based config.
// Trailing CR/LF are trimmed so operators can `echo "$SECRET" > file`
// without accidentally embedding a newline in the credential. See CM-26.
func resolveSecret(path, flagValue, envKey string) ([]byte, error) {
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

// queryAuthMiddleware Bearer-token-protects the HTTP query API (CM-26).
//
// Requests to paths in the allowlist (/healthz, /readyz, /metrics) are
// always passed through so Kubernetes probes and Prometheus scrapes keep
// working without credentials. When token is empty the middleware is a
// no-op (legacy / dev mode); callers are expected to log a WARN at
// startup so operators notice the degraded posture.
//
// Tokens are compared with crypto/subtle.ConstantTimeCompare to close
// the timing side-channel on a per-byte string comparison.
func queryAuthMiddleware(next http.Handler, token []byte) http.Handler {
	allow := map[string]struct{}{
		"/healthz": {},
		"/readyz":  {},
		"/metrics": {},
	}
	const bearerPrefix = "Bearer "
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := allow[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}
		if len(token) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, bearerPrefix) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="certchain"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		provided := []byte(authz[len(bearerPrefix):])
		if subtle.ConstantTimeCompare(provided, token) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="certchain"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loadChain(ch *chain.Chain, certStore *cert.Store, configDir string) error {
	path := filepath.Join(configDir, "chain.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var p persistedChain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	if len(p.Blocks) == 0 {
		return nil
	}

	replaced, err := ch.Replace(p.Blocks)
	if err != nil {
		return fmt.Errorf("restore chain: %w", err)
	}
	if replaced {
		return certStore.RebuildFrom(ch.GetBlocks())
	}
	return nil
}

// notifyCertEvent POSTs a JSON event to notifyURL. Called in a goroutine; errors are logged only.
func notifyCertEvent(notifyURL, event, cn, oldCertID, newCertID string) {
	payload := map[string]string{
		"event":       event,
		"cn":          cn,
		"old_cert_id": oldCertID,
		"new_cert_id": newCertID,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, notifyURL, bytes.NewReader(data))
	if err != nil {
		log.Printf("certd: notify build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("certd: notify %s for %s: %v", event, cn, err)
		return
	}
	resp.Body.Close()
}

func defaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".certchain"
	}
	return filepath.Join(home, ".certchain")
}

