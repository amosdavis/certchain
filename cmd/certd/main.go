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
	"crypto/sha256"
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
	"syscall"
	"time"

	"github.com/amosdavis/certchain/internal/avx"
	"github.com/amosdavis/certchain/internal/cert"
	"github.com/amosdavis/certchain/internal/chain"
	"github.com/amosdavis/certchain/internal/crypto"
	"github.com/amosdavis/certchain/internal/csr"
	"github.com/amosdavis/certchain/internal/peer"
	"github.com/amosdavis/certchain/internal/query"
)

func main() {
	configDir := flag.String("config", defaultConfigDir(), "config directory")
	avxURL := flag.String("avx-url", "", "AppViewX base URL (e.g. https://avx.example.com)")
	avxKey := flag.String("avx-key", "", "AppViewX API key")
	queryAddr := flag.String("query-addr", ":9879", "HTTP query API listen address")
	maxCerts := flag.Int("max-certs", 0, "maximum cert records (0=unlimited)")
	renewWindow := flag.Duration("renew-window", 30*24*time.Hour, "trigger AVX proactive renewal this far before cert expiry (0=disabled)")
	notifyURL   := flag.String("notify-url", "", "webhook URL to POST on cert renewal or revocation")
	staticPeers := flag.String("static-peers", "", "comma-separated host:port peers for cross-cluster sync")
	csrDomains  := flag.String("csr-domains", "", "path to JSON file listing CNs/SANs to auto-request from AVX")
	flag.Parse()

	// Allow env-var overrides so k8s ConfigMaps/Secrets can drive configuration
	// without needing a shell to build the args list.
	if *avxURL == ""      { *avxURL = os.Getenv("AVX_URL") }
	if *avxKey == ""      { *avxKey = os.Getenv("AVX_KEY") }
	if *notifyURL == ""   { *notifyURL = os.Getenv("NOTIFY_URL") }
	if *staticPeers == "" { *staticPeers = os.Getenv("STATIC_PEERS") }

	id, err := crypto.LoadOrCreate(*configDir)
	if err != nil {
		log.Fatalf("certd: load identity: %v", err)
	}
	log.Printf("certd: node pubkey %s", id.PubKeyHex())

	ch := chain.New()
	certStore := cert.NewStore(*maxCerts)
	peerTable := peer.NewTable()

	if *staticPeers != "" {
		seeder := peer.NewStaticPeerSeeder(peerTable, strings.Split(*staticPeers, ","))
		seeder.Start()
		defer seeder.Stop()
	}

	// Load persisted chain if present.
	if err := loadChain(ch, certStore, *configDir); err != nil {
		log.Printf("certd: load chain: %v (starting fresh)", err)
	}

	// Peer discovery.
	discoverer := peer.NewDiscoverer(peerTable, id.PublicKey, peer.SyncPort)
	if err := discoverer.Start(); err != nil {
		log.Fatalf("certd: start discovery: %v", err)
	}
	defer discoverer.Stop()

	// Block sync.
	syncer := peer.NewSyncer(ch, peerTable, id.PublicKey, *configDir)
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
		Handler:      qserver.Handler(),
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
	if *avxURL != "" {
		avxClient := avx.NewClient(avx.Config{
			BaseURL: *avxURL,
			APIKey:  *avxKey,
		})
		go func() {
			// Give UDP discovery time to find peers, then sync before polling AVX.
			// This prevents re-publishing certs already on chain after a restart.
			time.Sleep(2 * time.Second)
			syncer.SyncFromPeersAndWait(10 * time.Second)

			// Pre-populate published set from the now-current cert store.
			for _, rec := range certStore.List(false) {
				avxClient.MarkPublished(rec.AVXCertID)
			}
			avxPollLoop(avxClient, ch, certStore, id, syncer, *configDir, *renewWindow, *notifyURL, *csrDomains)
		}()
	} else {
		log.Printf("certd: no --avx-url set; AVX polling disabled")
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

// avxPollLoop polls AppViewX and publishes new/revoked/renewed certs to the chain.
// It also enforces certificate expiry (CM-02): any active cert whose not_after
// has passed is auto-revoked via TxCertRevoke.
// When renewWindow > 0, it proactively calls the AVX renewal API for certs
// approaching expiry so that AVX issues a replacement before the cert expires.
func avxPollLoop(client *avx.Client, ch *chain.Chain, certStore *cert.Store, id *crypto.Identity, syncer *peer.Syncer, configDir string, renewWindow time.Duration, notifyURL string, csrDomainsFile string) {
	var nonce uint32
	// Resume nonce from chain to avoid replay (monotonic per-node).
	for _, blk := range ch.GetBlocks() {
		for _, tx := range blk.Txs {
			if tx.NodePubkey == id.PublicKey && tx.Nonce > nonce {
				nonce = tx.Nonce
			}
		}
	}

	// CSR store tracks submitted CSRs and associates private keys with issued certs.
	csrStore, err := csr.NewStore(configDir)
	if err != nil {
		log.Printf("certd: csr store init: %v (CSR generation disabled)", err)
		csrStore = nil
	}

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
			oldRec, isRenewal := certStore.GetByCN(c.CommonName)

			nonce++
			blk, certID, err := buildPublishBlock(ch, id, nonce, c, configDir, client)
			if err != nil {
				log.Printf("certd: build publish block for %s: %v", c.CommonName, err)
				nonce--
				continue
			}
			if err := ch.AddBlock(blk); err != nil {
				log.Printf("certd: add publish block for %s: %v", c.CommonName, err)
				nonce--
				continue
			}
			if err := certStore.ApplyBlock(blk); err != nil {
				log.Printf("certd: cert store apply publish: %v", err)
			}
			client.MarkPublished(c.AVXCertID)
			syncer.PushBlockToPeers(blk)
			_ = saveChain(ch, configDir)

			// If a CSR was submitted for this CN, link the private key to cert_id.
			if csrStore != nil {
				certIDHex := fmt.Sprintf("%x", certID)
				keyDir := filepath.Join(configDir, "keys")
				if _, linkErr := csrStore.LinkCert(c.CommonName, certIDHex, keyDir); linkErr != nil {
					log.Printf("certd: link CSR key for %s: %v", c.CommonName, linkErr)
				}
			}

			// If this is a renewal, emit TxCertRenew linking old → new cert_id.
			// TxCertRenew sets the old cert's status to "replaced", so no separate
			// TxCertRevoke is needed for the old cert.
			if isRenewal {
				nonce++
				renewBlk, err := buildRenewBlock(ch, id, nonce, oldRec.CertID, certID)
				if err != nil {
					log.Printf("certd: build renew block for %s: %v", c.CommonName, err)
					nonce--
					continue
				}
				if err := ch.AddBlock(renewBlk); err != nil {
					log.Printf("certd: add renew block for %s: %v", c.CommonName, err)
					nonce--
					continue
				}
				if err := certStore.ApplyBlock(renewBlk); err != nil {
					log.Printf("certd: cert store apply renew: %v", err)
				}
				client.MarkUnpublished(oldRec.AVXCertID)
				renewedOldAVXIDs[oldRec.AVXCertID] = struct{}{}
				syncer.PushBlockToPeers(renewBlk)
				_ = saveChain(ch, configDir)
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
			certID := certIDFromAVX(certStore, c.AVXCertID)
			if certID == nil {
				continue
			}
			var revokeCN string
			if rec, ok := certStore.GetByID(*certID); ok {
				revokeCN = rec.CN
			}
			nonce++
			blk, err := buildRevokeBlock(ch, id, nonce, *certID)
			if err != nil {
				log.Printf("certd: build revoke block: %v", err)
				nonce--
				continue
			}
			if err := ch.AddBlock(blk); err != nil {
				log.Printf("certd: add revoke block: %v", err)
				nonce--
				continue
			}
			if err := certStore.ApplyBlock(blk); err != nil {
				log.Printf("certd: cert store apply revoke: %v", err)
			}
			syncer.PushBlockToPeers(blk)
			_ = saveChain(ch, configDir)
			if notifyURL != "" {
				go notifyCertEvent(notifyURL, "revoked", revokeCN,
					fmt.Sprintf("%x", *certID), "")
			}
		}

		// CM-02: auto-revoke any active cert whose not_after has passed.
		// This is the local expiry enforcement fallback for when AVX is slow or
		// silent about an expiry.
		now := time.Now().Unix()
		for _, rec := range certStore.List(true) {
			if rec.NotAfter > now {
				continue
			}
			nonce++
			blk, err := buildRevokeBlock(ch, id, nonce, rec.CertID)
			if err != nil {
				log.Printf("certd: build expiry revoke for %s: %v", rec.CN, err)
				nonce--
				continue
			}
			if err := ch.AddBlock(blk); err != nil {
				log.Printf("certd: add expiry revoke for %s: %v", rec.CN, err)
				nonce--
				continue
			}
			if err := certStore.ApplyBlock(blk); err != nil {
				log.Printf("certd: cert store expiry revoke for %s: %v", rec.CN, err)
			}
			syncer.PushBlockToPeers(blk)
			_ = saveChain(ch, configDir)
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
			for _, rec := range certStore.List(true) {
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

		// CSR domain requests: for any domain listed in --csr-domains that has no
		// active cert and no pending CSR, generate a key pair and submit to AVX.
		if csrStore != nil && csrDomainsFile != "" {
			submitPendingCSRs(client, certStore, csrStore, csrDomainsFile)
		}
	}
}

// submitPendingCSRs reads the csr-domains file and submits a CSR to AVX for any
// domain that has neither an active cert on chain nor a pending CSR already.
func submitPendingCSRs(client *avx.Client, certStore *cert.Store, csrStore *csr.Store, domainsFile string) {
	data, err := os.ReadFile(domainsFile)
	if err != nil {
		log.Printf("certd: read csr-domains: %v", err)
		return
	}
	var domains []struct {
		CN   string   `json:"cn"`
		SANs []string `json:"sans"`
	}
	if err := json.Unmarshal(data, &domains); err != nil {
		log.Printf("certd: parse csr-domains: %v", err)
		return
	}
	for _, d := range domains {
		if _, ok := certStore.GetByCN(d.CN); ok {
			continue // already have an active cert
		}
		if csrStore.HasPending(d.CN) {
			continue // CSR already submitted, waiting for issuance
		}
		keyPEM, csrPEM, err := csr.Generate(d.CN, d.SANs)
		if err != nil {
			log.Printf("certd: generate CSR for %s: %v", d.CN, err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		requestID, err := client.SubmitCSR(ctx, d.CN, d.SANs, csrPEM, 0)
		cancel()
		if err != nil {
			log.Printf("certd: submit CSR for %s: %v", d.CN, err)
			continue
		}
		if err := csrStore.Add(d.CN, d.SANs, requestID, keyPEM); err != nil {
			log.Printf("certd: store CSR for %s: %v", d.CN, err)
			continue
		}
		log.Printf("certd: submitted CSR for %s (avx_request_id=%s)", d.CN, requestID)
	}
}

func buildPublishBlock(ch *chain.Chain, id *crypto.Identity, nonce uint32, c *avx.Cert, configDir string, client *avx.Client) (chain.Block, [32]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	der, err := client.GetDER(ctx, c.AVXCertID)
	cancel()
	if err != nil {
		return chain.Block{}, [32]byte{}, fmt.Errorf("get DER: %w", err)
	}

	certID := sha256.Sum256(der)

	// Cache DER locally.
	derDir := filepath.Join(configDir, "certs")
	if err := os.MkdirAll(derDir, 0700); err == nil {
		hexID := fmt.Sprintf("%x", certID)
		_ = os.WriteFile(filepath.Join(derDir, hexID+".der"), der, 0600)
	}

	payload, err := chain.MarshalPublish(&chain.CertPublishPayload{
		CertID:    certID,
		CN:        c.CommonName,
		AVXCertID: c.AVXCertID,
		NotBefore: c.NotBefore.Unix(),
		NotAfter:  c.NotAfter.Unix(),
		SANs:      c.SANs,
		Serial:    c.Serial,
	})
	if err != nil {
		return chain.Block{}, [32]byte{}, err
	}

	tx := chain.Transaction{
		Type:       chain.TxCertPublish,
		NodePubkey: id.PublicKey,
		Timestamp:  chain.Now(),
		Nonce:      nonce,
		Payload:    payload,
	}
	chain.Sign(&tx, id)

	tip := ch.Tip()
	blk := chain.Block{
		Index:     tip.Index + 1,
		Timestamp: chain.Now(),
		PrevHash:  tip.Hash,
		Txs:       []chain.Transaction{tx},
	}
	blk.Hash = chain.ComputeHash(&blk)
	return blk, certID, nil
}

func buildRenewBlock(ch *chain.Chain, id *crypto.Identity, nonce uint32, oldCertID, newCertID [32]byte) (chain.Block, error) {
	payload, err := chain.MarshalRenew(&chain.CertRenewPayload{
		OldCertID: oldCertID,
		NewCertID: newCertID,
	})
	if err != nil {
		return chain.Block{}, err
	}

	tx := chain.Transaction{
		Type:       chain.TxCertRenew,
		NodePubkey: id.PublicKey,
		Timestamp:  chain.Now(),
		Nonce:      nonce,
		Payload:    payload,
	}
	chain.Sign(&tx, id)

	tip := ch.Tip()
	blk := chain.Block{
		Index:     tip.Index + 1,
		Timestamp: chain.Now(),
		PrevHash:  tip.Hash,
		Txs:       []chain.Transaction{tx},
	}
	blk.Hash = chain.ComputeHash(&blk)
	return blk, nil
}

func buildRevokeBlock(ch *chain.Chain, id *crypto.Identity, nonce uint32, certID [32]byte) (chain.Block, error) {
	payload, err := chain.MarshalRevoke(&chain.CertRevokePayload{
		CertID:    certID,
		Reason:    0, // unspecified
		RevokedAt: chain.Now(),
	})
	if err != nil {
		return chain.Block{}, err
	}

	tx := chain.Transaction{
		Type:       chain.TxCertRevoke,
		NodePubkey: id.PublicKey,
		Timestamp:  chain.Now(),
		Nonce:      nonce,
		Payload:    payload,
	}
	chain.Sign(&tx, id)

	tip := ch.Tip()
	blk := chain.Block{
		Index:     tip.Index + 1,
		Timestamp: chain.Now(),
		PrevHash:  tip.Hash,
		Txs:       []chain.Transaction{tx},
	}
	blk.Hash = chain.ComputeHash(&blk)
	return blk, nil
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
