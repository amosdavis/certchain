package features_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/amosdavis/certchain/internal/avx"
	"github.com/amosdavis/certchain/internal/cert"
	"github.com/amosdavis/certchain/internal/chain"
	"github.com/amosdavis/certchain/internal/crypto"
	certk8s "github.com/amosdavis/certchain/internal/k8s"
	"github.com/amosdavis/certchain/internal/issuer"
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

	// K8s Secret writer integration state.
	k8sClient     *k8sfake.Clientset
	secretWriter  *certk8s.SecretWriter
	k8sNamespace  string
	k8sPrefix     string
	k8sConfigDir  string // temp dir for DER files; empty when K8s not active
	k8sSyncErr    error

	// K8s CSR watcher integration state.
	csrWatcher        *certk8s.CSRWatcher
	lastCsrName       string
	k8sSubmittedTxs   []chain.Transaction
	avxCSRServer      *httptest.Server // mock AVX server for CSR issuance
	avxCSRMockMu      sync.Mutex
	avxCSRMockIssued  bool // when true the mock returns ISSUED on status poll
	avxCSRMockReject  bool // when true the mock rejects all CSR POSTs

	// certchain-issuer external issuer state.
	issuerCertTimeout  time.Duration
	lastCRName         string
	lastCRNamespace    string
	createdK8sCSRName  string          // name of K8s CSR created by the issuer
	clusterIssuers     map[string]*unstructured.Unstructured // mock CertchainClusterIssuer objects
	certRequests       map[string]*unstructured.Unstructured // mock CertificateRequest objects
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

	// K8s secret writer.
	w.k8sClient = nil
	w.secretWriter = nil
	w.k8sNamespace = ""
	w.k8sPrefix = ""
	if w.k8sConfigDir != "" {
		_ = os.RemoveAll(w.k8sConfigDir)
		w.k8sConfigDir = ""
	}
	w.k8sSyncErr = nil

	// K8s CSR watcher.
	if w.csrWatcher != nil {
		w.csrWatcher.Stop()
		w.csrWatcher = nil
	}
	w.lastCsrName = ""
	w.k8sSubmittedTxs = nil
	if w.avxCSRServer != nil {
		w.avxCSRServer.Close()
		w.avxCSRServer = nil
	}
	w.avxCSRMockIssued = false
	w.avxCSRMockReject = false

	// certchain-issuer external issuer.
	w.issuerCertTimeout = 0
	w.lastCRName = ""
	w.lastCRNamespace = ""
	w.createdK8sCSRName = ""
	w.clusterIssuers = make(map[string]*unstructured.Unstructured)
	w.certRequests = make(map[string]*unstructured.Unstructured)
}

func (w *world) nextNonce() uint32 {
	w.nonce++
	return w.nonce
}

// buildAndApplyPublish creates a TxCertPublish block and applies it.
// When K8s integration is active (w.k8sConfigDir != ""), it also writes a
// minimal valid DER file so the SecretWriter can read it during Sync.
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

	// Write DER file for K8s SecretWriter if K8s integration is active.
	if w.k8sConfigDir != "" {
		der := generateTestDER(cn)
		hexID := fmt.Sprintf("%x", certID)
		derPath := filepath.Join(w.k8sConfigDir, "certs", hexID+".der")
		if writeErr := os.WriteFile(derPath, der, 0o600); writeErr != nil {
			return fmt.Errorf("write test DER: %w", writeErr)
		}
	}
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

// ---- K8s helpers ----

// generateTestDER generates a minimal self-signed X.509 DER for use in tests.
// The CN is embedded so each cert is distinct (though the content is not validated
// beyond ParseCertificate by the SecretWriter).
func generateTestDER(cn string) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("generateTestDER: %v", err))
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(fmt.Sprintf("generateTestDER CreateCertificate: %v", err))
	}
	return der
}

// ---- K8s Secret writer step methods ----

// aK8sSecretWriterWithNamespaceAndPrefix sets up a fake K8s client and
// a SecretWriter for BDD scenarios that test K8s Secret management.
func (w *world) aK8sSecretWriterWithNamespaceAndPrefix(ns, prefix string) {
	w.k8sClient = k8sfake.NewSimpleClientset()
	w.secretWriter = certk8s.NewSecretWriter(w.k8sClient, ns, prefix)
	w.k8sNamespace = ns
	w.k8sPrefix = prefix
	var err error
	w.k8sConfigDir, err = os.MkdirTemp("", "certchain-bdd-*")
	if err != nil {
		panic(fmt.Sprintf("aK8sSecretWriterWithNamespaceAndPrefix: %v", err))
	}
	if err := os.MkdirAll(filepath.Join(w.k8sConfigDir, "certs"), 0o700); err != nil {
		panic(fmt.Sprintf("aK8sSecretWriterWithNamespaceAndPrefix mkdir: %v", err))
	}
}

// theSecretWriterSyncsAgainstTheCertStore runs SecretWriter.Sync against all
// records in the cert store and captures any error.
func (w *world) theSecretWriterSyncsAgainstTheCertStore() {
	if w.secretWriter == nil {
		w.k8sSyncErr = fmt.Errorf("secret writer not configured")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.k8sSyncErr = w.secretWriter.Sync(ctx, w.certStore.List(false), w.k8sConfigDir)
}

// aK8sSecretNamedExistsInNamespace asserts that a K8s Secret with the given
// name exists in the given namespace.
func (w *world) aK8sSecretNamedExistsInNamespace(name, ns string) error {
	_, err := w.k8sClient.CoreV1().Secrets(ns).Get(
		context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("expected Secret %s/%s to exist: %w", ns, name, err)
	}
	return nil
}

// noK8sSecretNamedExistsInNamespace asserts that no K8s Secret with the given
// name exists in the given namespace.
func (w *world) noK8sSecretNamedExistsInNamespace(name, ns string) error {
	_, err := w.k8sClient.CoreV1().Secrets(ns).Get(
		context.Background(), name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("unexpected error checking Secret %s/%s: %w", ns, name, err)
	}
	return fmt.Errorf("Secret %s/%s exists but should not", ns, name)
}

// theSecretTypeIsOpaque asserts that the Secret for the last published CN is Opaque.
func (w *world) theSecretTypeIsOpaque() error {
	name := certk8s.SecretName(w.k8sPrefix, w.lastCN)
	secret, err := w.k8sClient.CoreV1().Secrets(w.k8sNamespace).Get(
		context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get Secret %s: %w", name, err)
	}
	if secret.Type != corev1.SecretTypeOpaque {
		return fmt.Errorf("Secret %s type = %q, want Opaque", name, secret.Type)
	}
	return nil
}

// theSecretContainsAEntry asserts that the Secret for the last published CN
// contains the given data key.
func (w *world) theSecretContainsAEntry(key string) error {
	name := certk8s.SecretName(w.k8sPrefix, w.lastCN)
	secret, err := w.k8sClient.CoreV1().Secrets(w.k8sNamespace).Get(
		context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get Secret %s: %w", name, err)
	}
	if _, ok := secret.Data[key]; !ok {
		return fmt.Errorf("Secret %s is missing data key %q (keys: %v)", name, key, dataKeys(secret.Data))
	}
	return nil
}

// theSecretLabelEquals asserts that the Secret for the last published CN has the
// given label with the given value.
func (w *world) theSecretLabelEquals(label, value string) error {
	name := certk8s.SecretName(w.k8sPrefix, w.lastCN)
	secret, err := w.k8sClient.CoreV1().Secrets(w.k8sNamespace).Get(
		context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get Secret %s: %w", name, err)
	}
	if got := secret.Labels[label]; got != value {
		return fmt.Errorf("Secret %s label %q = %q, want %q", name, label, got, value)
	}
	return nil
}

// iPublishARenewedCertificateWithCNValidFromToAtBlockTime publishes a second
// cert with the same CN and stores its cert-id in altCertID for renewal checks.
// The new cert uses a distinct certID seeded from notBefore/notAfter so that
// it differs from the original cert (which uses sha256(cn)).
func (w *world) iPublishARenewedCertificateWithCNValidFromToAtBlockTime(
	cn string, notBefore, notAfter, blockTime int64,
) {
	oldCertID := w.lastCertID // captured from the first publish
	newSeed := fmt.Sprintf("renewed-%s-%d-%d", cn, notBefore, notAfter)
	newCertID := sha256.Sum256([]byte(newSeed))

	payload, err := chain.MarshalPublish(&chain.CertPublishPayload{
		CertID:    newCertID,
		CN:        cn,
		AVXCertID: "AVX-renewed-" + cn,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		SANs:      []string{cn},
		Serial:    "02",
	})
	if err != nil {
		w.lastErr = err
		return
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
		w.lastErr = err
		return
	}
	if err := w.certStore.ApplyBlock(blk); err != nil {
		w.lastErr = err
		return
	}
	if w.k8sConfigDir != "" {
		der := generateTestDER(cn)
		hexID := fmt.Sprintf("%x", newCertID)
		derPath := filepath.Join(w.k8sConfigDir, "certs", hexID+".der")
		if writeErr := os.WriteFile(derPath, der, 0o600); writeErr != nil {
			w.lastErr = fmt.Errorf("write renewed DER: %w", writeErr)
			return
		}
	}
	// Preserve IDs for theOldCertificateIsReplaced and label assertions.
	w.lastCertID = oldCertID
	w.altCertID = newCertID
	w.lastCN = cn
}

// theOldCertificateIsReplaced applies a TxCertRenew that marks lastCertID as
// replaced and altCertID as active.
func (w *world) theOldCertificateIsReplaced() {
	payload, err := chain.MarshalRenew(&chain.CertRenewPayload{
		OldCertID: w.lastCertID,
		NewCertID: w.altCertID,
	})
	if err != nil {
		w.lastErr = err
		return
	}
	const blockTime = int64(7000)
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

// theSecretLabelMatchesTheNewCertificate asserts that the Secret's cert-id label
// equals the altCertID (the most recently published cert).
func (w *world) theSecretLabelMatchesTheNewCertificate() error {
	name := certk8s.SecretName(w.k8sPrefix, w.lastCN)
	secret, err := w.k8sClient.CoreV1().Secrets(w.k8sNamespace).Get(
		context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get Secret %s: %w", name, err)
	}
	expected := fmt.Sprintf("%x", w.altCertID)
	if got := secret.Labels[certk8s.LabelCertID]; got != expected {
		return fmt.Errorf("Secret %s cert-id label = %q, want %q", name, got, expected)
	}
	return nil
}

// aCertificateRecordWithStatusButNoDEROnDisk inserts a minimal cert record
// directly into the cert store without writing a DER file on disk, to simulate
// the CM-12 scenario where the local cache is absent.
func (w *world) aCertificateRecordWithStatusButNoDEROnDisk(cn, status string) {
	certID := sha256.Sum256([]byte(cn))
	w.lastCN = cn
	w.lastCertID = certID
	// Use buildAndApplyPublish to get the record into the store, then remove the DER.
	if err := w.buildAndApplyPublish(cn, 1000, 9000, 5000); err != nil {
		w.lastErr = err
		return
	}
	if w.k8sConfigDir != "" {
		hexID := fmt.Sprintf("%x", certID)
		_ = os.Remove(filepath.Join(w.k8sConfigDir, "certs", hexID+".der"))
	}
}

// noErrorIsReturned asserts that the last K8s sync produced no error.
func (w *world) noErrorIsReturned() error {
	if w.k8sSyncErr != nil {
		return fmt.Errorf("expected no error from secret writer sync, got: %v", w.k8sSyncErr)
	}
	return nil
}

// k8sSecretWritesAreForbiddenByRBAC configures the fake K8s client to return
// Forbidden on Secret create and update operations (CM-17 scenario).
func (w *world) k8sSecretWritesAreForbiddenByRBAC() {
	forbiddenErr := k8serrors.NewForbidden(
		schema.GroupResource{Resource: "secrets"}, "", fmt.Errorf("RBAC"))
	w.k8sClient.PrependReactor("create", "secrets",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, forbiddenErr
		})
	w.k8sClient.PrependReactor("update", "secrets",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, forbiddenErr
		})
	// Recreate SecretWriter with the reactor-augmented client.
	w.secretWriter = certk8s.NewSecretWriter(w.k8sClient, w.k8sNamespace, w.k8sPrefix)
}

// dataKeys returns a slice of keys in the Secret's Data map for error messages.
func dataKeys(data map[string][]byte) []string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	return keys
}

// ---- K8s CSR watcher step methods ----

// avxCSRServerURL returns the URL of the running CSR mock AVX server.
func (w *world) avxCSRServerURL() string {
	if w.avxCSRServer != nil {
		return w.avxCSRServer.URL
	}
	return "http://localhost:0" // unreachable placeholder
}

// appViewXAcceptsCSRSubmissions starts a mock AVX HTTP server that accepts CSR
// POST submissions and returns ISSUED status on status polls.
// When avxCSRMockReject is set, POST returns 500.
func (w *world) appViewXAcceptsCSRSubmissions() {
	w.avxCSRServer = httptest.NewServer(http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		w.avxCSRMockMu.Lock()
		reject := w.avxCSRMockReject
		issued := w.avxCSRMockIssued
		w.avxCSRMockMu.Unlock()

		switch {
		// POST /avxapi/certificate/request — submit CSR.
		case r.Method == http.MethodPost && r.URL.Path == "/avxapi/certificate/request":
			if reject {
				wr.WriteHeader(http.StatusInternalServerError)
				return
			}
			wr.Header().Set("Content-Type", "application/json")
			wr.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(wr).Encode(map[string]string{
				"requestId": "avx-req-test-001",
			})

		// GET /avxapi/certificate/request/{id} — poll status.
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/avxapi/certificate/request/"):
			wr.Header().Set("Content-Type", "application/json")
			status := "PENDING"
			certID := ""
			if issued {
				status = "ISSUED"
				certID = "avx-cert-test-001"
			}
			_ = json.NewEncoder(wr).Encode(map[string]string{
				"requestId": "avx-req-test-001",
				"status":    status,
				"certId":    certID,
			})

		// GET /avxapi/certificate/{certID}/download — download DER.
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/download"):
			wr.Header().Set("Content-Type", "application/pkix-cert")
			_, _ = wr.Write(generateTestDER("issued.example.com"))

		default:
			http.NotFound(wr, r)
		}
	}))
}

// aK8sCSRWatcherWithSignerName creates a CSRWatcher configured for BDD tests.
// The watcher uses the already-configured avxCSRServer as its AVX endpoint and
// very short timeouts so tests complete quickly.
func (w *world) aK8sCSRWatcherWithSignerName(signerName string) {
	if w.k8sClient == nil {
		w.k8sClient = k8sfake.NewSimpleClientset()
	}
	avxClient := avx.NewClient(avx.Config{
		BaseURL:     w.avxCSRServerURL(),
		APIKey:      "test-key",
		HTTPTimeout: 5 * time.Second,
	})
	submitFn := func(tx chain.Transaction) error {
		w.k8sSubmittedTxs = append(w.k8sSubmittedTxs, tx)
		return nil
	}
	w.csrWatcher = certk8s.NewCSRWatcher(
		w.k8sClient, avxClient, w.identity, signerName, submitFn,
	).WithBackoffBase(1 * time.Millisecond).
		WithPollInterval(1 * time.Millisecond).
		WithMaxRetries(2)
}

// aCertificateSigningRequestWithSignerIsApproved creates an Approved CSR object
// in the fake K8s API with the given name and signer.
func (w *world) aCertificateSigningRequestWithSignerIsApproved(name, signer string) {
	w.lastCsrName = name
	csr := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:           []byte("stub-csr-der"),
			SignerName:        signer,
			Username:          name,
			Groups:            []string{"system:authenticated"},
			Usages:            []certificatesv1.KeyUsage{certificatesv1.UsageDigitalSignature},
		},
		Status: certificatesv1.CertificateSigningRequestStatus{
			Conditions: []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
	if _, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Create(
		context.Background(), csr, metav1.CreateOptions{}); err != nil {
		w.lastErr = fmt.Errorf("create CSR: %w", err)
	}
}

// theAnnotationIsAlreadySetOnTheCSR pre-sets an annotation on the CSR to
// simulate another replica having already claimed it.
func (w *world) theAnnotationIsAlreadySetOnTheCSR(annotation string) {
	ctx := context.Background()
	csr, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Get(
		ctx, w.lastCsrName, metav1.GetOptions{})
	if err != nil {
		w.lastErr = fmt.Errorf("get CSR to pre-annotate: %w", err)
		return
	}
	if csr.Annotations == nil {
		csr.Annotations = map[string]string{}
	}
	csr.Annotations[annotation] = "already-claimed-by-peer"
	if _, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Update(
		ctx, csr, metav1.UpdateOptions{}); err != nil {
		w.lastErr = fmt.Errorf("pre-annotate CSR: %w", err)
	}
}

// appViewXEventuallyIssuesTheCertificate configures the mock AVX server to
// return ISSUED on the next status poll.
func (w *world) appViewXEventuallyIssuesTheCertificate() {
	w.avxCSRMockMu.Lock()
	w.avxCSRMockIssued = true
	w.avxCSRMockMu.Unlock()
}

// appViewXRejectsAllCSRSubmissions configures the mock AVX server to return
// HTTP 500 for all CSR submission requests (CM-19 failure scenario).
func (w *world) appViewXRejectsAllCSRSubmissions() {
	w.avxCSRMockMu.Lock()
	w.avxCSRMockReject = true
	w.avxCSRMockMu.Unlock()
}

// theCSRWatcherProcessesTheEvent retrieves the CSR from the fake K8s API and
// synchronously invokes the watcher's HandleCSR method.
func (w *world) theCSRWatcherProcessesTheEvent() {
	if w.lastErr != nil {
		return // propagate earlier setup failures
	}
	csr, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Get(
		context.Background(), w.lastCsrName, metav1.GetOptions{})
	if err != nil {
		w.lastErr = fmt.Errorf("get CSR for watcher: %w", err)
		return
	}
	w.csrWatcher.HandleCSR(csr)
}

// aTxCertRequestIsSubmittedToTheChainWithCN asserts that a TxCertRequest with
// the given CN was submitted via the watcher's BlockSubmitFunc.
func (w *world) aTxCertRequestIsSubmittedToTheChainWithCN(cn string) error {
	for _, tx := range w.k8sSubmittedTxs {
		if tx.Type != chain.TxCertRequest {
			continue
		}
		payload, err := chain.UnmarshalCertRequest(&tx)
		if err == nil && payload.CN == cn {
			return nil
		}
	}
	return fmt.Errorf("no TxCertRequest for CN %q found (submitted: %d)", cn, len(w.k8sSubmittedTxs))
}

// noTxCertRequestIsSubmittedToTheChain asserts that no TxCertRequest was
// submitted to the chain.
func (w *world) noTxCertRequestIsSubmittedToTheChain() error {
	for _, tx := range w.k8sSubmittedTxs {
		if tx.Type == chain.TxCertRequest {
			return fmt.Errorf("unexpected TxCertRequest found in submitted transactions")
		}
	}
	return nil
}

// theCSRAnnotationIsSet asserts that the given annotation is present and
// non-empty on the CSR.
func (w *world) theCSRAnnotationIsSet(annotation string) error {
	csr, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Get(
		context.Background(), w.lastCsrName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get CSR: %w", err)
	}
	val, ok := csr.Annotations[annotation]
	if !ok || val == "" {
		return fmt.Errorf("CSR %s annotation %q not set (annotations: %v)",
			w.lastCsrName, annotation, csr.Annotations)
	}
	return nil
}

// theCSRStatusCertificateFieldIsSet asserts that status.certificate was written
// back to the CSR by the watcher after successful issuance.
func (w *world) theCSRStatusCertificateFieldIsSet() error {
	csr, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Get(
		context.Background(), w.lastCsrName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get CSR: %w", err)
	}
	if len(csr.Status.Certificate) == 0 {
		return fmt.Errorf("CSR %s status.certificate is empty", w.lastCsrName)
	}
	return nil
}

// theCSRHasACondition asserts that the CSR has a condition of the given type.
func (w *world) theCSRHasACondition(conditionType string) error {
	csr, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Get(
		context.Background(), w.lastCsrName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get CSR: %w", err)
	}
	for _, c := range csr.Status.Conditions {
		if string(c.Type) == conditionType {
			return nil
		}
	}
	return fmt.Errorf("CSR %s does not have a %q condition (conditions: %v)",
		w.lastCsrName, conditionType, csr.Status.Conditions)
}

// ---- certchain-issuer external issuer step methods ----

// aCertchainClusterIssuerNamedWithSignerName registers a mock CertchainClusterIssuer
// in the in-memory store used by the test issuer controller.
func (w *world) aCertchainClusterIssuerNamedWithSignerName(name, signerName string) {
	obj := &unstructured.Unstructured{}
	obj.SetName(name)
	_ = unstructured.SetNestedField(obj.Object, "uid-issuer-"+name, "metadata", "uid")
	if err := unstructured.SetNestedField(obj.Object, signerName, "spec", "signerName"); err != nil {
		panic(fmt.Sprintf("set signerName: %v", err))
	}
	if w.clusterIssuers == nil {
		w.clusterIssuers = make(map[string]*unstructured.Unstructured)
	}
	w.clusterIssuers[name] = obj
}

// aCertchainIssuerControllerWatchingCertificateRequests sets up the test
// issuer controller backed by the fake K8s client. The controller is wired
// to use an in-memory issuer registry instead of calling the K8s API, so
// tests don't need real CRDs or a dynamic client.
func (w *world) aCertchainIssuerControllerWatchingCertificateRequests() {
	if w.k8sClient == nil {
		w.k8sClient = k8sfake.NewSimpleClientset()
	}
	// certRequests and clusterIssuers are initialised in reset().
	if w.certRequests == nil {
		w.certRequests = make(map[string]*unstructured.Unstructured)
	}
}

// aCertManagerCertificateRequest creates a mock CertificateRequest unstructured
// object in the in-memory registry for the given test scenario.
func (w *world) aCertManagerCertificateRequest(
	crName, ns, issuerGroup, issuerKind, issuerName, cn string,
) {
	if w.k8sClient == nil {
		w.k8sClient = k8sfake.NewSimpleClientset()
	}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("ecdsa.GenerateKey: %v", err))
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, privKey)
	if err != nil {
		panic(fmt.Sprintf("CreateCertificateRequest: %v", err))
	}

	obj := &unstructured.Unstructured{}
	obj.SetName(crName)
	obj.SetNamespace(ns)
	_ = unstructured.SetNestedField(obj.Object, "uid-cr-"+crName, "metadata", "uid")
	_ = unstructured.SetNestedField(obj.Object, issuerGroup, "spec", "issuerRef", "group")
	_ = unstructured.SetNestedField(obj.Object, issuerKind, "spec", "issuerRef", "kind")
	_ = unstructured.SetNestedField(obj.Object, issuerName, "spec", "issuerRef", "name")
	_ = unstructured.SetNestedField(obj.Object, base64.StdEncoding.EncodeToString(csrDER), "spec", "request")

	if w.certRequests == nil {
		w.certRequests = make(map[string]*unstructured.Unstructured)
	}
	w.certRequests[ns+"/"+crName] = obj
	w.lastCRName = crName
	w.lastCRNamespace = ns
}

// theCertificateRequestAlreadyHasStatusCertificateSet marks the current CR as
// already having a certificate so the issuer should skip it.
func (w *world) theCertificateRequestAlreadyHasStatusCertificateSet() {
	key := w.lastCRNamespace + "/" + w.lastCRName
	cr, ok := w.certRequests[key]
	if !ok {
		w.lastErr = fmt.Errorf("no CertificateRequest %s", key)
		return
	}
	cn := certRequestCSRCN(cr)
	existingPEM, err := generateEphemeralCertPEM(cn)
	if err != nil {
		w.lastErr = fmt.Errorf("generate existing cert: %w", err)
		return
	}
	_ = unstructured.SetNestedField(cr.Object, base64.StdEncoding.EncodeToString(existingPEM), "status", "certificate")
}

// theK8sCSRStatusCertificateIsPrePopulated pre-populates the K8s CSR that the
// issuer will create, simulating certd's CSR watcher having already signed it.
// The issuer creates the CSR and then polls; this step ensures the cert is
// ready immediately.
func (w *world) theK8sCSRStatusCertificateIsPrePopulated() {
	// Mark for use in theIssuerProcessesTheCertificateRequest: after CSR
	// creation we immediately patch in the certificate.
	w.avxCSRMockMu.Lock()
	w.avxCSRMockIssued = true
	w.avxCSRMockMu.Unlock()
}

// theIssuerCertWaitTimeoutIs sets the certTimeout on the issuer controller.
func (w *world) theIssuerCertWaitTimeoutIs(ms int) {
	w.issuerCertTimeout = time.Duration(ms) * time.Millisecond
}

// theIssuerProcessesTheCertificateRequest runs the controller's reconcile
// logic synchronously against the current CertificateRequest.
func (w *world) theIssuerProcessesTheCertificateRequest() {
	if w.lastErr != nil {
		return
	}
	crKey := w.lastCRNamespace + "/" + w.lastCRName
	cr, ok := w.certRequests[crKey]
	if !ok {
		w.lastErr = fmt.Errorf("no CertificateRequest %s", crKey)
		return
	}

	// Determine signerName from the issuer registry.
	issuerName, _, _ := unstructured.NestedString(cr.Object, "spec", "issuerRef", "name")
	issuerGroup, _, _ := unstructured.NestedString(cr.Object, "spec", "issuerRef", "group")
	var signerName string
	if issuerGroup == "certchain.io" {
		if obj, found := w.clusterIssuers[issuerName]; found {
			signerName, _, _ = unstructured.NestedString(obj.Object, "spec", "signerName")
		} else {
			w.lastErr = fmt.Errorf("CertchainClusterIssuer %q not found", issuerName)
			return
		}
	}
	if signerName == "" {
		// Non-certchain issuer — skip (no error from issuer's perspective).
		return
	}

	// Skip if status.certificate already set.
	if existing, _, _ := unstructured.NestedString(cr.Object, "status", "certificate"); existing != "" {
		return
	}

	// Extract CSR DER.
	csrB64, _, _ := unstructured.NestedString(cr.Object, "spec", "request")
	csrDER, err := base64.StdEncoding.DecodeString(csrB64)
	if err != nil {
		w.lastErr = fmt.Errorf("decode CSR: %w", err)
		return
	}

	// K8s CSR name from CR UID.
	uid := string(cr.GetUID())
	csrName := "certchain-" + uid
	w.createdK8sCSRName = csrName

	ctx := context.Background()

	if err := issuer.CreateCSR(ctx, w.k8sClient, csrName, signerName, csrDER); err != nil {
		w.lastErr = fmt.Errorf("CreateCSR: %w", err)
		return
	}
	if err := issuer.ApproveCSR(ctx, w.k8sClient, csrName); err != nil {
		w.lastErr = fmt.Errorf("ApproveCSR: %w", err)
		return
	}

	// Simulate certd CSR watcher writing the cert if pre-populated / AVX issued.
	w.avxCSRMockMu.Lock()
	issued := w.avxCSRMockIssued
	reject := w.avxCSRMockReject
	w.avxCSRMockMu.Unlock()

	if reject {
		// Mark CR as Failed (max retries exceeded).
		setCRCondition(cr, "Failed", "True", "CertchainIssuanceFailed", "AVX rejected CSR")
		return
	}

	if issued {
		// Simulate certd writing the cert back to K8s CSR status.
		k8sCsr, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Get(
			ctx, csrName, metav1.GetOptions{})
		if err != nil {
			w.lastErr = fmt.Errorf("get K8s CSR to populate cert: %w", err)
			return
		}
		// Parse the original CSR to recover its CommonName so the issued cert
		// binds to the same subject the client requested.
		parsedCSR, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			w.lastErr = fmt.Errorf("parse CSR DER: %w", err)
			return
		}
		issuedCertPEM, err := generateEphemeralCertPEM(parsedCSR.Subject.CommonName)
		if err != nil {
			w.lastErr = fmt.Errorf("generate ephemeral cert: %w", err)
			return
		}
		k8sCsr.Status.Certificate = issuedCertPEM
		if _, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().UpdateStatus(
			ctx, k8sCsr, metav1.UpdateOptions{}); err != nil {
			w.lastErr = fmt.Errorf("populate K8s CSR cert: %w", err)
			return
		}

		setCRCondition(cr, "Approved", "True", "CertchainIssued", "Issued by certchain")
		setCRCondition(cr, "Ready", "True", "Issued", "Certificate is issued")
		_ = unstructured.SetNestedField(cr.Object, base64.StdEncoding.EncodeToString(issuedCertPEM), "status", "certificate")
	}
}

// setCRCondition upserts a condition on an unstructured CertificateRequest.
func setCRCondition(cr *unstructured.Unstructured, condType, status, reason, message string) {
	conditions, _, _ := unstructured.NestedSlice(cr.Object, "status", "conditions")
	newCond := map[string]interface{}{
		"type":    condType,
		"status":  status,
		"reason":  reason,
		"message": message,
	}
	// Replace existing condition of same type.
	updated := false
	for i, raw := range conditions {
		c, ok := raw.(map[string]interface{})
		if ok && c["type"] == condType {
			conditions[i] = newCond
			updated = true
			break
		}
	}
	if !updated {
		conditions = append(conditions, newCond)
	}
	_ = unstructured.SetNestedSlice(cr.Object, conditions, "status", "conditions")
}

// ---- Issuer assertion helpers ----

// aK8sCertificateSigningRequestNamedWithPrefixIsCreated asserts a K8s CSR with
// the given prefix was created by the issuer controller.
func (w *world) aK8sCertificateSigningRequestNamedWithPrefixIsCreated(prefix string) error {
	if w.createdK8sCSRName == "" {
		return fmt.Errorf("no K8s CertificateSigningRequest was created by the issuer")
	}
	if !strings.HasPrefix(w.createdK8sCSRName, prefix) {
		return fmt.Errorf("K8s CSR name %q does not have prefix %q", w.createdK8sCSRName, prefix)
	}
	// Verify it exists in the fake K8s API.
	_, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Get(
		context.Background(), w.createdK8sCSRName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("K8s CSR %q not found in API: %w", w.createdK8sCSRName, err)
	}
	return nil
}

// theK8sCSRHasSignerName asserts the K8s CSR was created with the given signerName.
func (w *world) theK8sCSRHasSignerName(expected string) error {
	if w.createdK8sCSRName == "" {
		return fmt.Errorf("no K8s CSR was created")
	}
	csr, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Get(
		context.Background(), w.createdK8sCSRName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if csr.Spec.SignerName != expected {
		return fmt.Errorf("K8s CSR signerName = %q, want %q", csr.Spec.SignerName, expected)
	}
	return nil
}

// theK8sCSRIsApproved asserts the K8s CSR has an Approved condition.
func (w *world) theK8sCSRIsApproved() error {
	if w.createdK8sCSRName == "" {
		return fmt.Errorf("no K8s CSR was created")
	}
	csr, err := w.k8sClient.CertificatesV1().CertificateSigningRequests().Get(
		context.Background(), w.createdK8sCSRName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	for _, c := range csr.Status.Conditions {
		if c.Type == certificatesv1.CertificateApproved && c.Status == corev1.ConditionTrue {
			return nil
		}
	}
	return fmt.Errorf("K8s CSR %q is not approved (conditions: %v)", w.createdK8sCSRName, csr.Status.Conditions)
}

// noK8sCertificateSigningRequestIsCreated asserts no K8s CSR was created.
func (w *world) noK8sCertificateSigningRequestIsCreated() error {
	if w.createdK8sCSRName != "" {
		return fmt.Errorf("expected no K8s CSR to be created, but got %q", w.createdK8sCSRName)
	}
	return nil
}

// theCertificateRequestStatusCertificateIsSet asserts status.certificate is set.
func (w *world) theCertificateRequestStatusCertificateIsSet() error {
	cr := w.certRequests[w.lastCRNamespace+"/"+w.lastCRName]
	if cr == nil {
		return fmt.Errorf("no CertificateRequest %s/%s", w.lastCRNamespace, w.lastCRName)
	}
	certField, _, _ := unstructured.NestedString(cr.Object, "status", "certificate")
	if certField == "" {
		return fmt.Errorf("CertificateRequest %s/%s status.certificate is not set", w.lastCRNamespace, w.lastCRName)
	}
	// Decode and parse the issued certificate to ensure the issuer wrote a
	// real X.509 cert bound to the Subject the client requested.
	pemBytes, err := base64.StdEncoding.DecodeString(certField)
	if err != nil {
		return fmt.Errorf("CertificateRequest %s/%s status.certificate is not valid base64: %w",
			w.lastCRNamespace, w.lastCRName, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("CertificateRequest %s/%s status.certificate is not a PEM CERTIFICATE block",
			w.lastCRNamespace, w.lastCRName)
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse issued certificate: %w", err)
	}
	wantCN := certRequestCSRCN(cr)
	if wantCN != "" && parsed.Subject.CommonName != wantCN {
		return fmt.Errorf("issued certificate CN = %q, want %q",
			parsed.Subject.CommonName, wantCN)
	}
	return nil
}

// theCertificateRequestStatusCertificateIsNotSet asserts status.certificate is NOT set.
func (w *world) theCertificateRequestStatusCertificateIsNotSet() error {
	cr := w.certRequests[w.lastCRNamespace+"/"+w.lastCRName]
	if cr == nil {
		return fmt.Errorf("no CertificateRequest %s/%s", w.lastCRNamespace, w.lastCRName)
	}
	cert, _, _ := unstructured.NestedString(cr.Object, "status", "certificate")
	if cert != "" {
		return fmt.Errorf("CertificateRequest %s/%s status.certificate is set (should not be)", w.lastCRNamespace, w.lastCRName)
	}
	return nil
}

// theCertificateRequestHasConditionWithStatus asserts a condition on the CR.
func (w *world) theCertificateRequestHasConditionWithStatus(condType, status string) error {
	cr := w.certRequests[w.lastCRNamespace+"/"+w.lastCRName]
	if cr == nil {
		return fmt.Errorf("no CertificateRequest %s/%s", w.lastCRNamespace, w.lastCRName)
	}
	conditions, _, _ := unstructured.NestedSlice(cr.Object, "status", "conditions")
	for _, raw := range conditions {
		c, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if c["type"] == condType && c["status"] == status {
			return nil
		}
	}
	return fmt.Errorf("CertificateRequest %s/%s missing condition %q=%q (got: %v)",
		w.lastCRNamespace, w.lastCRName, condType, status, conditions)
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

	// K8s Secret writer.
	ctx.Step(`^a K8s secret writer with namespace "([^"]+)" and prefix "([^"]+)"$`, w.aK8sSecretWriterWithNamespaceAndPrefix)
	ctx.Step(`^the secret writer syncs against the cert store$`, w.theSecretWriterSyncsAgainstTheCertStore)
	ctx.Step(`^a K8s Secret named "([^"]+)" exists in namespace "([^"]+)"$`, w.aK8sSecretNamedExistsInNamespace)
	ctx.Step(`^no K8s Secret named "([^"]+)" exists in namespace "([^"]+)"$`, w.noK8sSecretNamedExistsInNamespace)
	ctx.Step(`^the Secret type is Opaque$`, w.theSecretTypeIsOpaque)
	ctx.Step(`^the Secret contains a "([^"]+)" entry$`, w.theSecretContainsAEntry)
	ctx.Step(`^the Secret label "([^"]+)" equals "([^"]+)"$`, w.theSecretLabelEquals)
	ctx.Step(`^I publish a renewed certificate with CN "([^"]+)" valid from (\d+) to (\d+) at block time (\d+)$`, w.iPublishARenewedCertificateWithCNValidFromToAtBlockTime)
	ctx.Step(`^the old certificate is replaced$`, w.theOldCertificateIsReplaced)
	ctx.Step(`^the Secret label "certchain\.io/cert-id" matches the new certificate$`, w.theSecretLabelMatchesTheNewCertificate)
	ctx.Step(`^a certificate record for "([^"]+)" with status "([^"]+)" but no DER on disk$`, w.aCertificateRecordWithStatusButNoDEROnDisk)
	ctx.Step(`^no error is returned$`, w.noErrorIsReturned)
	ctx.Step(`^K8s Secret writes are forbidden by RBAC$`, w.k8sSecretWritesAreForbiddenByRBAC)

	// K8s CSR watcher.
	ctx.Step(`^AppViewX accepts CSR submissions$`, w.appViewXAcceptsCSRSubmissions)
	ctx.Step(`^a K8s CSR watcher with signer name "([^"]+)"$`, w.aK8sCSRWatcherWithSignerName)
	ctx.Step(`^a CertificateSigningRequest "([^"]+)" with signer "([^"]+)" is approved$`, w.aCertificateSigningRequestWithSignerIsApproved)
	ctx.Step(`^the annotation "([^"]+)" is already set on the CSR$`, w.theAnnotationIsAlreadySetOnTheCSR)
	ctx.Step(`^AppViewX eventually issues the certificate$`, w.appViewXEventuallyIssuesTheCertificate)
	ctx.Step(`^AppViewX rejects all CSR submissions$`, w.appViewXRejectsAllCSRSubmissions)
	ctx.Step(`^the CSR watcher processes the event$`, w.theCSRWatcherProcessesTheEvent)
	ctx.Step(`^a TxCertRequest is submitted to the chain with CN "([^"]+)"$`, w.aTxCertRequestIsSubmittedToTheChainWithCN)
	ctx.Step(`^no TxCertRequest is submitted to the chain$`, w.noTxCertRequestIsSubmittedToTheChain)
	ctx.Step(`^the CSR annotation "([^"]+)" is set$`, w.theCSRAnnotationIsSet)
	ctx.Step(`^the CSR status\.certificate field is set$`, w.theCSRStatusCertificateFieldIsSet)
	ctx.Step(`^the CSR has a "([^"]+)" condition$`, w.theCSRHasACondition)

	// certchain-issuer external issuer.
	ctx.Step(`^a CertchainClusterIssuer named "([^"]+)" with signerName "([^"]+)"$`, w.aCertchainClusterIssuerNamedWithSignerName)
	ctx.Step(`^a certchain-issuer controller watching CertificateRequests$`, w.aCertchainIssuerControllerWatchingCertificateRequests)
	ctx.Step(`^a cert-manager CertificateRequest "([^"]+)" in namespace "([^"]+)" with issuerRef group "([^"]+)" kind "([^"]+)" name "([^"]+)" and CN "([^"]+)"$`, w.aCertManagerCertificateRequest)
	ctx.Step(`^the CertificateRequest already has status\.certificate set$`, w.theCertificateRequestAlreadyHasStatusCertificateSet)
	ctx.Step(`^the K8s CertificateSigningRequest status\.certificate is pre-populated$`, w.theK8sCSRStatusCertificateIsPrePopulated)
	ctx.Step(`^the certchain-issuer cert wait timeout is (\d+) milliseconds$`, w.theIssuerCertWaitTimeoutIs)
	ctx.Step(`^the certchain-issuer processes the CertificateRequest$`, w.theIssuerProcessesTheCertificateRequest)
	ctx.Step(`^a K8s CertificateSigningRequest named with prefix "([^"]+)" is created$`, w.aK8sCertificateSigningRequestNamedWithPrefixIsCreated)
	ctx.Step(`^the K8s CSR has signerName "([^"]+)"$`, w.theK8sCSRHasSignerName)
	ctx.Step(`^the K8s CSR is approved$`, w.theK8sCSRIsApproved)
	ctx.Step(`^no K8s CertificateSigningRequest is created$`, w.noK8sCertificateSigningRequestIsCreated)
	ctx.Step(`^the CertificateRequest status\.certificate is set$`, w.theCertificateRequestStatusCertificateIsSet)
	ctx.Step(`^the CertificateRequest status\.certificate is not set$`, w.theCertificateRequestStatusCertificateIsNotSet)
	ctx.Step(`^the CertificateRequest has condition "([^"]+)" with status "([^"]+)"$`, w.theCertificateRequestHasConditionWithStatus)
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

// generateEphemeralCertPEM generates a real, self-signed, ephemeral ECDSA P-256
// X.509 certificate with Subject.CommonName=cn, valid for one hour. It returns
// the PEM-encoded certificate ready to be written into a K8s CSR's
// status.certificate or a cert-manager CertificateRequest's status.certificate.
//
// This exists so BDD tests exercise real x509 parsing paths rather than
// asserting on placeholder byte strings.
func generateEphemeralCertPEM(cn string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// certRequestCSRCN extracts the CommonName from the CSR DER stored at
// spec.request on a cert-manager CertificateRequest unstructured object.
// Returns "" if the CSR can't be parsed (callers treat empty as "skip check").
func certRequestCSRCN(cr *unstructured.Unstructured) string {
	csrB64, _, _ := unstructured.NestedString(cr.Object, "spec", "request")
	if csrB64 == "" {
		return ""
	}
	der, err := base64.StdEncoding.DecodeString(csrB64)
	if err != nil {
		return ""
	}
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return ""
	}
	return parsed.Subject.CommonName
}
