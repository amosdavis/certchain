package features_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/amosdavis/certchain/internal/avx"
	"github.com/amosdavis/certchain/internal/cert"
	"github.com/amosdavis/certchain/internal/chain"
	"github.com/amosdavis/certchain/internal/crypto"
	"github.com/cucumber/godog"
)

// ---- world holds test state for each scenario ----

type world struct {
	identity     *crypto.Identity
	ch           *chain.Chain
	certStore    *cert.Store
	nonce        uint32
	lastCertID   [32]byte
	lastCN       string
	lastErr      error
	pendingCert  *pendingCertSpec // cert staged but not yet published
	altCertID    [32]byte         // used for renew tests
	avxServer    *httptest.Server // mock AVX renewal server
	avxRenewCalls []string        // AVX cert IDs requested for renewal
}

type pendingCertSpec struct {
	cn        string
	notBefore int64
	notAfter  int64
}

func newWorld() *world {
	id, _ := crypto.GenerateIdentity()
	return &world{
		identity:  id,
		ch:        chain.New(),
		certStore: cert.NewStore(0),
	}
}

func (w *world) reset() {
	id, _ := crypto.GenerateIdentity()
	w.identity = id
	w.ch = chain.New()
	w.certStore = cert.NewStore(0)
	w.nonce = 0
	w.lastCertID = [32]byte{}
	w.lastCN = ""
	w.lastErr = nil
	w.pendingCert = nil
	w.altCertID = [32]byte{}
	if w.avxServer != nil {
		w.avxServer.Close()
		w.avxServer = nil
	}
	w.avxRenewCalls = nil
}

func (w *world) nextNonce() uint32 {
	w.nonce++
	return w.nonce
}

// buildAndApplyPublish creates a TxCertPublish block and applies it.
func (w *world) buildAndApplyPublish(cn string, notBefore, notAfter, blockTime int64) error {
	certID := sha256.Sum256([]byte(cn))
	payload, err := chain.MarshalPublish(&chain.CertPublishPayload{
		CertID:    certID,
		CN:        cn,
		AVXCertID: "AVX-" + cn,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		SANs:      []string{cn},
		Serial:    "01",
	})
	if err != nil {
		return err
	}
	tx := chain.Transaction{
		Type:       chain.TxCertPublish,
		NodePubkey: w.identity.PublicKey,
		Timestamp:  blockTime,
		Nonce:      w.nextNonce(),
		Payload:    payload,
	}
	chain.Sign(&tx, w.identity)

	tip := w.ch.Tip()
	blk := chain.Block{
		Index:     tip.Index + 1,
		Timestamp: blockTime,
		PrevHash:  tip.Hash,
		Txs:       []chain.Transaction{tx},
	}
	blk.Hash = chain.ComputeHash(&blk)

	if err := w.ch.AddBlock(blk); err != nil {
		return err
	}
	if err := w.certStore.ApplyBlock(blk); err != nil {
		return err
	}
	w.lastCertID = certID
	w.lastCN = cn
	return nil
}

func (w *world) buildAndApplyRevoke(certID [32]byte, blockTime int64) error {
	payload, err := chain.MarshalRevoke(&chain.CertRevokePayload{
		CertID:    certID,
		Reason:    0,
		RevokedAt: blockTime,
	})
	if err != nil {
		return err
	}
	tx := chain.Transaction{
		Type:       chain.TxCertRevoke,
		NodePubkey: w.identity.PublicKey,
		Timestamp:  blockTime,
		Nonce:      w.nextNonce(),
		Payload:    payload,
	}
	chain.Sign(&tx, w.identity)

	tip := w.ch.Tip()
	blk := chain.Block{
		Index:     tip.Index + 1,
		Timestamp: blockTime,
		PrevHash:  tip.Hash,
		Txs:       []chain.Transaction{tx},
	}
	blk.Hash = chain.ComputeHash(&blk)

	if err := w.ch.AddBlock(blk); err != nil {
		return err
	}
	return w.certStore.ApplyBlock(blk)
}

// ---- step definitions ----

func (w *world) aFreshCertchainWithANodeIdentity() {
	w.reset()
}

func (w *world) aCertificateWithCNValidFromTo(cn string, notBefore, notAfter int64) {
	w.pendingCert = &pendingCertSpec{cn: cn, notBefore: notBefore, notAfter: notAfter}
}

func (w *world) iPublishTheCertificateAtBlockTime(blockTime int64) {
	p := w.pendingCert
	if p == nil {
		w.lastErr = errors.New("no pending cert")
		return
	}
	w.lastErr = w.buildAndApplyPublish(p.cn, p.notBefore, p.notAfter, blockTime)
}

func (w *world) theChainHeightIs(expected int) error {
	if got := w.ch.Len(); got != expected {
		return fmt.Errorf("chain height = %d, want %d", got, expected)
	}
	return nil
}

func (w *world) theCertStoreContainsWithStatus(cn, expectedStatus string) error {
	rec, ok := w.certStore.GetByCN(cn)
	if !ok {
		// also check by ID (e.g. for revoked certs removed from CN index)
		certID := sha256.Sum256([]byte(cn))
		rec, ok = w.certStore.GetByID(certID)
		if !ok {
			return fmt.Errorf("cert %q not found in store", cn)
		}
	}
	if string(rec.Status) != expectedStatus {
		return fmt.Errorf("cert %q status = %q, want %q", cn, rec.Status, expectedStatus)
	}
	return nil
}

func (w *world) iPublishTheSameCertificateAgainAtBlockTime(blockTime int64) {
	p := w.pendingCert
	if p == nil {
		w.lastErr = errors.New("no pending cert")
		return
	}
	// Cert already published; try again — store should reject.
	certID := sha256.Sum256([]byte(p.cn))
	payload, _ := chain.MarshalPublish(&chain.CertPublishPayload{
		CertID:    certID,
		CN:        p.cn,
		AVXCertID: "AVX-" + p.cn,
		NotBefore: p.notBefore,
		NotAfter:  p.notAfter,
		SANs:      []string{p.cn},
		Serial:    "01",
	})
	tx := chain.Transaction{
		Type:       chain.TxCertPublish,
		NodePubkey: w.identity.PublicKey,
		Timestamp:  blockTime,
		Nonce:      w.nextNonce(),
		Payload:    payload,
	}
	chain.Sign(&tx, w.identity)
	tip := w.ch.Tip()
	blk := chain.Block{
		Index:     tip.Index + 1,
		Timestamp: blockTime,
		PrevHash:  tip.Hash,
		Txs:       []chain.Transaction{tx},
	}
	blk.Hash = chain.ComputeHash(&blk)

	// Validate against store before adding to chain.
	if err := w.certStore.ValidateBlock(blk); err != nil {
		w.lastErr = err
	}
}

func (w *world) theSecondPublishFailsWith(expectedMsg string) error {
	if w.lastErr == nil {
		return fmt.Errorf("expected error containing %q, got nil", expectedMsg)
	}
	if got := w.lastErr.Error(); got != expectedMsg {
		return fmt.Errorf("error = %q, want %q", got, expectedMsg)
	}
	return nil
}

func (w *world) theActiveCertListContains(cn string) error {
	for _, rec := range w.certStore.List(true) {
		if rec.CN == cn {
			return nil
		}
	}
	return fmt.Errorf("active cert list does not contain %q", cn)
}

func (w *world) theCertificateIsPublishedAtBlockTime(blockTime int64) {
	p := w.pendingCert
	if p == nil {
		return
	}
	w.lastErr = w.buildAndApplyPublish(p.cn, p.notBefore, p.notAfter, blockTime)
}

func (w *world) iRevokeTheCertificateAtBlockTime(blockTime int64) {
	w.lastErr = w.buildAndApplyRevoke(w.lastCertID, blockTime)
}

func (w *world) iPublishAndRevokeTheCertificateInTheSameBlockAtTime(blockTime int64) {
	p := w.pendingCert
	if p == nil {
		return
	}
	certID := sha256.Sum256([]byte(p.cn))

	pubPayload, _ := chain.MarshalPublish(&chain.CertPublishPayload{
		CertID:    certID,
		CN:        p.cn,
		AVXCertID: "AVX-" + p.cn,
		NotBefore: p.notBefore,
		NotAfter:  p.notAfter,
		SANs:      []string{p.cn},
		Serial:    "01",
	})
	revokePayload, _ := chain.MarshalRevoke(&chain.CertRevokePayload{
		CertID:    certID,
		Reason:    0,
		RevokedAt: blockTime,
	})

	id2, _ := crypto.GenerateIdentity()

	pubTx := chain.Transaction{
		Type:       chain.TxCertPublish,
		NodePubkey: w.identity.PublicKey,
		Timestamp:  blockTime,
		Nonce:      w.nextNonce(),
		Payload:    pubPayload,
	}
	chain.Sign(&pubTx, w.identity)

	revokeTx := chain.Transaction{
		Type:       chain.TxCertRevoke,
		NodePubkey: id2.PublicKey,
		Timestamp:  blockTime,
		Nonce:      1,
		Payload:    revokePayload,
	}
	chain.Sign(&revokeTx, id2)

	tip := w.ch.Tip()
	blk := chain.Block{
		Index:     tip.Index + 1,
		Timestamp: blockTime,
		PrevHash:  tip.Hash,
		Txs:       []chain.Transaction{pubTx, revokeTx},
	}
	blk.Hash = chain.ComputeHash(&blk)

	if err := w.ch.AddBlock(blk); err != nil {
		w.lastErr = err
		return
	}
	w.lastErr = w.certStore.ApplyBlock(blk)
	w.lastCertID = certID
	w.lastCN = p.cn
}

func (w *world) aCertIDThatIsNotOnTheChain() {
	w.lastCertID = sha256.Sum256([]byte("nonexistent-cert"))
}

func (w *world) iAttemptToApplyARevokeBlockForTheUnknownCert() {
	w.lastErr = w.buildAndApplyRevoke(w.lastCertID, 1500)
}

func (w *world) theStoreApplyReturnsAnError() error {
	if w.lastErr == nil {
		return errors.New("expected error from revoke of unknown cert, got nil")
	}
	return nil
}

func (w *world) aReplacementCertificateWithCNValidFromTo(cn string, notBefore, notAfter int64) {
	// Save alt cert spec without overwriting primary pending cert.
	w.altCertID = sha256.Sum256([]byte(fmt.Sprintf("new-%s", cn)))
	// Store the alt cert under a different key in the DER hash so it differs.
	// We use a distinct seed so old and new cert_ids differ.
}

func (w *world) theReplacementCertificateIsPublishedAtBlockTime(blockTime int64) {
	// Save old cert ID before publish overwrites w.lastCertID.
	oldCertID := w.lastCertID
	oldCN := w.lastCN

	newCN := fmt.Sprintf("new-%s", w.lastCN)
	err := w.buildAndApplyPublish(newCN, 1800, 4000, blockTime)
	if err != nil {
		w.lastErr = err
		return
	}
	w.altCertID = sha256.Sum256([]byte(newCN))
	// Restore so that iRenewTheOldCertWithTheNewCertAtBlockTime uses the old cert.
	w.lastCertID = oldCertID
	w.lastCN = oldCN
}

func (w *world) iRenewTheOldCertWithTheNewCertAtBlockTime(blockTime int64) {
	payload, err := chain.MarshalRenew(&chain.CertRenewPayload{
		OldCertID: w.lastCertID,
		NewCertID: w.altCertID,
	})
	if err != nil {
		w.lastErr = err
		return
	}
	tx := chain.Transaction{
		Type:       chain.TxCertRenew,
		NodePubkey: w.identity.PublicKey,
		Timestamp:  blockTime,
		Nonce:      w.nextNonce(),
		Payload:    payload,
	}
	chain.Sign(&tx, w.identity)
	tip := w.ch.Tip()
	blk := chain.Block{
		Index:     tip.Index + 1,
		Timestamp: blockTime,
		PrevHash:  tip.Hash,
		Txs:       []chain.Transaction{tx},
	}
	blk.Hash = chain.ComputeHash(&blk)

	if err := w.ch.AddBlock(blk); err != nil {
		w.lastErr = err
		return
	}
	w.lastErr = w.certStore.ApplyBlock(blk)
}

func (w *world) theOldCertHasStatus(expectedStatus string) error {
	rec, ok := w.certStore.GetByID(w.lastCertID)
	if !ok {
		return fmt.Errorf("old cert not found")
	}
	if string(rec.Status) != expectedStatus {
		return fmt.Errorf("old cert status = %q, want %q", rec.Status, expectedStatus)
	}
	return nil
}

func (w *world) theNewCertHasStatus(expectedStatus string) error {
	rec, ok := w.certStore.GetByID(w.altCertID)
	if !ok {
		return fmt.Errorf("new cert not found")
	}
	if string(rec.Status) != expectedStatus {
		return fmt.Errorf("new cert status = %q, want %q", rec.Status, expectedStatus)
	}
	return nil
}

func (w *world) iAttemptToRenewACertWithItsOwnCertID() {
	certID := sha256.Sum256([]byte("same.example.com"))
	payload, _ := chain.MarshalRenew(&chain.CertRenewPayload{
		OldCertID: certID,
		NewCertID: certID, // same — should fail validation
	})
	tx := chain.Transaction{
		Type:       chain.TxCertRenew,
		NodePubkey: w.identity.PublicKey,
		Timestamp:  1500,
		Nonce:      w.nextNonce(),
		Payload:    payload,
	}
	chain.Sign(&tx, w.identity)
	w.lastErr = chain.ValidatePayload(&tx)
}

func (w *world) theRenewTransactionPayloadIsInvalid() error {
	if w.lastErr == nil {
		return errors.New("expected payload validation error, got nil")
	}
	return nil
}

// Query steps.

func (w *world) iQueryTheCertStoreByCN(cn string) {
	rec, ok := w.certStore.GetByCN(cn)
	if !ok {
		certID := sha256.Sum256([]byte(cn))
		rec, ok = w.certStore.GetByID(certID)
		if !ok {
			w.lastErr = fmt.Errorf("not found: %s", cn)
			return
		}
	}
	w.lastErr = nil
	w.lastCN = cn
	w.lastCertID = rec.CertID
}

func (w *world) iQueryTheCertStoreByCertIDOf(cn string) {
	certID := sha256.Sum256([]byte(cn))
	_, ok := w.certStore.GetByID(certID)
	if !ok {
		w.lastErr = fmt.Errorf("cert not found: %s", cn)
		return
	}
	w.lastCertID = certID
	w.lastErr = nil
}

func (w *world) theResultHasStatus(expectedStatus string) error {
	if w.lastErr != nil {
		return fmt.Errorf("query error: %v", w.lastErr)
	}
	rec, ok := w.certStore.GetByID(w.lastCertID)
	if !ok {
		// try CN
		rec, ok = w.certStore.GetByCN(w.lastCN)
		if !ok {
			certID := sha256.Sum256([]byte(w.lastCN))
			rec, ok = w.certStore.GetByID(certID)
			if !ok {
				return fmt.Errorf("cert not found in store")
			}
		}
	}
	if string(rec.Status) != expectedStatus {
		return fmt.Errorf("status = %q, want %q", rec.Status, expectedStatus)
	}
	return nil
}

func (w *world) theResultCNIs(expectedCN string) error {
	rec, ok := w.certStore.GetByCN(w.lastCN)
	if !ok {
		certID := sha256.Sum256([]byte(w.lastCN))
		rec, ok = w.certStore.GetByID(certID)
	}
	if !ok {
		return fmt.Errorf("cert not found")
	}
	if rec.CN != expectedCN {
		return fmt.Errorf("CN = %q, want %q", rec.CN, expectedCN)
	}
	return nil
}

func (w *world) theCertIsNotFound() error {
	if w.lastErr == nil {
		return fmt.Errorf("expected not-found error, got nil")
	}
	return nil
}

// Auto-renewal steps.

// theExpiryMonitorRunsAtWallTime simulates the CM-02 expiry enforcement goroutine.
// For each active cert with not_after <= wallTime, it emits a TxCertRevoke block.
func (w *world) theExpiryMonitorRunsAtWallTime(wallTime int64) {
	for _, rec := range w.certStore.List(true) {
		if rec.NotAfter > wallTime {
			continue
		}
		if err := w.buildAndApplyRevoke(rec.CertID, wallTime); err != nil {
			w.lastErr = err
			return
		}
	}
}

// avxReportsARenewalForCNValidFromToAtBlockTime simulates the AVX renewal detection
// in avxPollLoop: detect same-CN cert, emit TxCertPublish (new cert) then TxCertRenew.
func (w *world) avxReportsARenewalForCNValidFromToAtBlockTime(cn string, notBefore, notAfter, blockTime int64) {
	oldRec, hasOld := w.certStore.GetByCN(cn)
	if !hasOld {
		w.lastErr = errors.New("no active cert for CN — cannot simulate AVX renewal")
		return
	}
	oldCertID := oldRec.CertID

	// New cert_id is seeded from renewal params so it differs from the old cert.
	newSeed := fmt.Sprintf("renewed-%s-%d-%d", cn, notBefore, notAfter)
	w.altCertID = sha256.Sum256([]byte(newSeed))

	pubPayload, err := chain.MarshalPublish(&chain.CertPublishPayload{
		CertID:    w.altCertID,
		CN:        cn,
		AVXCertID: fmt.Sprintf("AVX-renewed-%s", cn),
		NotBefore: notBefore,
		NotAfter:  notAfter,
		SANs:      []string{cn},
		Serial:    "02",
	})
	if err != nil {
		w.lastErr = err
		return
	}
	pubTx := chain.Transaction{
		Type:       chain.TxCertPublish,
		NodePubkey: w.identity.PublicKey,
		Timestamp:  blockTime,
		Nonce:      w.nextNonce(),
		Payload:    pubPayload,
	}
	chain.Sign(&pubTx, w.identity)
	tip := w.ch.Tip()
	pubBlk := chain.Block{
		Index:     tip.Index + 1,
		Timestamp: blockTime,
		PrevHash:  tip.Hash,
		Txs:       []chain.Transaction{pubTx},
	}
	pubBlk.Hash = chain.ComputeHash(&pubBlk)
	if err := w.ch.AddBlock(pubBlk); err != nil {
		w.lastErr = err
		return
	}
	if err := w.certStore.ApplyBlock(pubBlk); err != nil {
		w.lastErr = err
		return
	}

	renewPayload, err := chain.MarshalRenew(&chain.CertRenewPayload{
		OldCertID: oldCertID,
		NewCertID: w.altCertID,
	})
	if err != nil {
		w.lastErr = err
		return
	}
	renewTx := chain.Transaction{
		Type:       chain.TxCertRenew,
		NodePubkey: w.identity.PublicKey,
		Timestamp:  blockTime,
		Nonce:      w.nextNonce(),
		Payload:    renewPayload,
	}
	chain.Sign(&renewTx, w.identity)
	tip = w.ch.Tip()
	renewBlk := chain.Block{
		Index:     tip.Index + 1,
		Timestamp: blockTime,
		PrevHash:  tip.Hash,
		Txs:       []chain.Transaction{renewTx},
	}
	renewBlk.Hash = chain.ComputeHash(&renewBlk)
	if err := w.ch.AddBlock(renewBlk); err != nil {
		w.lastErr = err
		return
	}
	w.lastErr = w.certStore.ApplyBlock(renewBlk)
	// Save old cert ID for "the old cert has status" assertion.
	w.lastCertID = oldCertID
}

// theNewCertForHasStatus checks the status of the renewed cert for a given CN.
func (w *world) theNewCertForHasStatus(cn, expectedStatus string) error {
	// The renewed cert takes over the CN index entry.
	rec, ok := w.certStore.GetByCN(cn)
	if !ok {
		rec, ok = w.certStore.GetByID(w.altCertID)
		if !ok {
			return fmt.Errorf("new cert for %q not found", cn)
		}
	}
	if string(rec.Status) != expectedStatus {
		return fmt.Errorf("new cert for %q status = %q, want %q", cn, rec.Status, expectedStatus)
	}
	return nil
}

// aMockAVXRenewalServerIsConfigured starts a lightweight mock AVX server that
// records POST /avxapi/certificate/{avxCertID}/renew calls.
func (w *world) aMockAVXRenewalServerIsConfigured() {
	w.avxRenewCalls = nil
	w.avxServer = httptest.NewServer(http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		// Match POST /avxapi/certificate/{avxCertID}/renew
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/renew") {
			parts := strings.Split(r.URL.Path, "/")
			// path: /avxapi/certificate/{id}/renew — id is parts[3]
			if len(parts) >= 4 {
				w.avxRenewCalls = append(w.avxRenewCalls, parts[3])
			}
			wr.WriteHeader(http.StatusAccepted)
			return
		}
		http.NotFound(wr, r)
	}))
}

// theProactiveRenewalCheckRunsWithWindowSecondsAtWallTime simulates the proactive
// renewal scan from avxPollLoop: for each active cert with not_after within the
// renewal window, call the AVX renewal API.
func (w *world) theProactiveRenewalCheckRunsWithWindowSecondsAtWallTime(windowSecs, wallTime int64) {
	if w.avxServer == nil {
		w.lastErr = errors.New("mock AVX server not configured")
		return
	}
	avxClient := avx.NewClient(avx.Config{BaseURL: w.avxServer.URL, APIKey: "test-key"})
	renewCutoff := wallTime + windowSecs
	for _, rec := range w.certStore.List(true) {
		if rec.NotAfter <= wallTime || rec.NotAfter > renewCutoff {
			continue // already expired or outside window
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = avxClient.RenewCert(ctx, rec.AVXCertID)
		cancel()
	}
}

// theAVXRenewalAPIWasCalledFor checks that the mock server received a renewal call
// for the cert matching the given CN. AVX cert IDs follow the pattern "AVX-{cn}".
func (w *world) theAVXRenewalAPIWasCalledFor(cn string) error {
	expected := "AVX-" + cn
	for _, id := range w.avxRenewCalls {
		if id == expected {
			return nil
		}
	}
	return fmt.Errorf("AVX renewal API was not called for %q (calls: %v)", expected, w.avxRenewCalls)
}

// theAVXRenewalAPIWasNotCalled checks that the mock server received no renewal calls.
func (w *world) theAVXRenewalAPIWasNotCalled() error {
	if len(w.avxRenewCalls) > 0 {
		return fmt.Errorf("expected no AVX renewal calls, got: %v", w.avxRenewCalls)
	}
	return nil
}

// ---- godog wiring ----

func InitializeScenario(ctx *godog.ScenarioContext) {
	w := newWorld()

	ctx.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})

	// Background / shared.
	ctx.Step(`^a fresh certchain with a node identity$`, w.aFreshCertchainWithANodeIdentity)
	ctx.Step(`^a certificate with CN "([^"]+)" valid from (\d+) to (\d+)$`, w.aCertificateWithCNValidFromTo)
	ctx.Step(`^the certificate is published at block time (\d+)$`, w.theCertificateIsPublishedAtBlockTime)

	// Publish.
	ctx.Step(`^I publish the certificate at block time (\d+)$`, w.iPublishTheCertificateAtBlockTime)
	ctx.Step(`^the chain height is (\d+)$`, w.theChainHeightIs)
	ctx.Step(`^the cert store contains "([^"]+)" with status "([^"]+)"$`, w.theCertStoreContainsWithStatus)
	ctx.Step(`^I publish the same certificate again at block time (\d+)$`, w.iPublishTheSameCertificateAgainAtBlockTime)
	ctx.Step(`^the second publish fails with "([^"]+)"$`, w.theSecondPublishFailsWith)
	ctx.Step(`^the active cert list contains "([^"]+)"$`, w.theActiveCertListContains)

	// Revoke.
	ctx.Step(`^I revoke the certificate at block time (\d+)$`, w.iRevokeTheCertificateAtBlockTime)
	ctx.Step(`^I publish and revoke the certificate in the same block at time (\d+)$`, w.iPublishAndRevokeTheCertificateInTheSameBlockAtTime)
	ctx.Step(`^a cert_id that is not on the chain$`, w.aCertIDThatIsNotOnTheChain)
	ctx.Step(`^I attempt to apply a revoke block for the unknown cert$`, w.iAttemptToApplyARevokeBlockForTheUnknownCert)
	ctx.Step(`^the store apply returns an error$`, w.theStoreApplyReturnsAnError)

	// Renew.
	ctx.Step(`^a replacement certificate with CN "([^"]+)" valid from (\d+) to (\d+)$`, w.aReplacementCertificateWithCNValidFromTo)
	ctx.Step(`^the replacement certificate is published at block time (\d+)$`, w.theReplacementCertificateIsPublishedAtBlockTime)
	ctx.Step(`^I renew the old cert with the new cert at block time (\d+)$`, w.iRenewTheOldCertWithTheNewCertAtBlockTime)
	ctx.Step(`^the old cert has status "([^"]+)"$`, w.theOldCertHasStatus)
	ctx.Step(`^the new cert has status "([^"]+)"$`, w.theNewCertHasStatus)
	ctx.Step(`^I attempt to renew a cert with its own cert_id$`, w.iAttemptToRenewACertWithItsOwnCertID)
	ctx.Step(`^the renew transaction payload is invalid$`, w.theRenewTransactionPayloadIsInvalid)

	// Query.
	ctx.Step(`^I query the cert store by CN "([^"]+)"$`, w.iQueryTheCertStoreByCN)
	ctx.Step(`^I query the cert store by cert_id of "([^"]+)"$`, w.iQueryTheCertStoreByCertIDOf)
	ctx.Step(`^the result has status "([^"]+)"$`, w.theResultHasStatus)
	ctx.Step(`^the result CN is "([^"]+)"$`, w.theResultCNIs)
	// Auto-renewal.
	ctx.Step(`^the expiry monitor runs at wall time (\d+)$`, w.theExpiryMonitorRunsAtWallTime)
	ctx.Step(`^AVX reports a renewal for CN "([^"]+)" valid from (\d+) to (\d+) at block time (\d+)$`, w.avxReportsARenewalForCNValidFromToAtBlockTime)
	ctx.Step(`^the new cert for "([^"]+)" has status "([^"]+)"$`, w.theNewCertForHasStatus)
	// Proactive renewal.
	ctx.Step(`^a mock AVX renewal server is configured$`, w.aMockAVXRenewalServerIsConfigured)
	ctx.Step(`^the proactive renewal check runs with window (\d+) seconds at wall time (\d+)$`, w.theProactiveRenewalCheckRunsWithWindowSecondsAtWallTime)
	ctx.Step(`^the AVX renewal API was called for "([^"]+)"$`, w.theAVXRenewalAPIWasCalledFor)
	ctx.Step(`^the AVX renewal API was not called$`, w.theAVXRenewalAPIWasNotCalled)
}

func TestBDD(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"."},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("BDD scenarios failed")
	}
}

// TestMain allows running godog from "go test".
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
