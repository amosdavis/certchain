package certd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/amosdavis/certchain/internal/avx"
	"github.com/amosdavis/certchain/internal/cert"
	"github.com/amosdavis/certchain/internal/chain"
	"github.com/amosdavis/certchain/internal/crypto"
	"github.com/amosdavis/certchain/internal/peer"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// BlockSubmitter groups block submissions from concurrent goroutines
// (avxPollLoop and CSRWatcher) through a chain.Batcher so bursts commit
// as a single multi-tx block (CM-32). The Batcher drain goroutine is
// single-threaded, so SignTx assigns the per-node nonce without a mutex;
// per-batch rollback on a failed commit keeps the counter monotonic.
type BlockSubmitter struct {
	nonce           uint32
	ch              *chain.Chain
	id              *crypto.Identity
	certStore       *cert.Store
	syncer          *peer.Syncer
	configDir       string
	walPath         string
	batcher         *chain.Batcher
	logger          *slog.Logger
	saveErrorsTotal prometheus.Counter
}

// NewBlockSubmitter creates a BlockSubmitter that batches transactions
// through a chain.Batcher. It resumes the nonce from the chain to avoid
// replay.
func NewBlockSubmitter(ctx context.Context, logger *slog.Logger, ch *chain.Chain, certStore *cert.Store, id *crypto.Identity, syncer *peer.Syncer, configDir, walPath string, batchMaxTxs int, batchMaxWait time.Duration, saveErrorsTotal prometheus.Counter) *BlockSubmitter {
	bs := &BlockSubmitter{
		ch:              ch,
		certStore:       certStore,
		id:              id,
		syncer:          syncer,
		configDir:       configDir,
		walPath:         walPath,
		logger:          logger,
		saveErrorsTotal: saveErrorsTotal,
	}
	// Resume nonce from chain to avoid replay (monotonic per-node).
	for _, blk := range ch.GetBlocks() {
		for _, tx := range blk.Txs {
			if tx.NodePubkey == id.PublicKey && tx.Nonce > bs.nonce {
				bs.nonce = tx.Nonce
			}
		}
	}
	bs.batcher = chain.NewBatcher(ctx, ch, chain.BatcherConfig{
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
func (bs *BlockSubmitter) SignTx(tx *chain.Transaction) {
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
func (bs *BlockSubmitter) OnBatchRollback(n int) {
	bs.nonce -= uint32(n)
}

// onBlockCommitted is the Batcher's post-commit hook. It mirrors the
// pre-CM-32 per-block side-effects: cert-store apply, peer push, and
// persistent save. CM-38: instrumented with tracing spans.
func (bs *BlockSubmitter) onBlockCommitted(blk chain.Block) {
	tracer := otel.Tracer("certd")
	_, span := tracer.Start(context.Background(), "BlockSubmitter.onBlockCommitted",
		trace.WithAttributes(
			attribute.Int("block.index", int(blk.Index)),
			attribute.Int("block.tx_count", len(blk.Txs)),
		))
	defer span.End()
	
	if err := bs.certStore.ApplyBlock(blk); err != nil {
		log.Printf("certd: cert store apply block: %v", err)
		span.RecordError(err)
	}
	
	// CM-38: Span for peer push operation.
	_, pushSpan := tracer.Start(context.Background(), "peer.PushBlockToPeers",
		trace.WithAttributes(attribute.Int("block.index", int(blk.Index))))
	bs.syncer.PushBlockToPeers(blk)
	pushSpan.End()
	
	_ = SaveChain(context.Background(), bs.logger, bs.ch, bs.configDir, bs.walPath, bs.saveErrorsTotal)
}

// Submit adds a transaction to the chain via the Batcher. tx must have
// Type and Payload set; NodePubkey, Timestamp, Nonce, and Signature are
// filled in by SignTx inside the drain goroutine, preventing duplicate
// nonces when multiple goroutines submit concurrently. Submit blocks
// until the batch containing tx has been committed (or rejected).
// CM-38: instrumented with tracing span.
func (bs *BlockSubmitter) Submit(tx chain.Transaction) error {
	tracer := otel.Tracer("certd")
	ctx, span := tracer.Start(context.Background(), "BlockSubmitter.Submit",
		trace.WithAttributes(
			attribute.String("tx.type", fmt.Sprintf("%d", tx.Type)),
		))
	defer span.End()
	
	err := bs.batcher.Submit(tx)
	if err != nil {
		span.RecordError(err)
	}
	_ = ctx
	return err
}

// Stop flushes any queued txs and releases the Batcher drain goroutine.
// Safe to call multiple times.
func (bs *BlockSubmitter) Stop() {
	if bs.batcher != nil {
		bs.batcher.Stop()
	}
}

// keyVaultEntry is one entry in the --key-vault-map JSON file.
type keyVaultEntry struct {
	KeyVaultRef  string   `json:"key_vault_ref"`
	Environments []string `json:"environments"`
}

// AVXPollLoop polls AppViewX and publishes new/revoked/renewed certs to the chain.
// It also enforces certificate expiry (CM-02): any active cert whose not_after
// has passed is auto-revoked via TxCertRevoke.
// When renewWindow > 0, it proactively calls the AVX renewal API for certs
// approaching expiry so that AVX issues a replacement before the cert expires.
// onPollDone is called after each successful poll cycle (used to trigger K8s sync).
func AVXPollLoop(ctx context.Context, logger *slog.Logger, client *avx.Client, bs *BlockSubmitter, configDir string, renewWindow time.Duration, notifyURL string, keyVaultMapFile string, onPollDone func()) {
	kvMap := loadKeyVaultMap(keyVaultMapFile)

	const (
		backoffBase = 5 * time.Second
		backoffMax  = 10 * time.Minute
	)
	consecutiveErrors := 0
	nextSleep := time.Duration(0) // no initial sleep; poll immediately on first iteration

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if nextSleep > 0 {
			time.Sleep(nextSleep)
		}

		// Reload key vault map each cycle so file edits take effect without restart.
		if keyVaultMapFile != "" {
			kvMap = loadKeyVaultMap(keyVaultMapFile)
		}

		pollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		result, err := client.Poll(pollCtx)
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
				renewCtx, cancelRenew := context.WithTimeout(ctx, 15*time.Second)
				if err := client.RenewCert(renewCtx, rec.AVXCertID); err != nil {
					log.Printf("certd: proactive renewal trigger for %s: %v", rec.CN, err)
				} else {
					log.Printf("certd: triggered AVX renewal for %s (expires in %ds)", rec.CN, rec.NotAfter-now)
				}
				cancelRenew()
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
