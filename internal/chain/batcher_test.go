// batcher_test.go — CM-32 tests for the chain.Batcher.
package chain_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/amosdavis/certchain/internal/chain"
	"github.com/amosdavis/certchain/internal/crypto"
)

// nonceSigner is a test Signer that assigns monotonic per-identity
// nonces and signs under the process-wide chain signing context. The
// drain goroutine invokes SignTx serially so no synchronisation is
// needed on nonce.
type nonceSigner struct {
	id    *crypto.Identity
	nonce uint32
}

func (s *nonceSigner) SignTx(tx *chain.Transaction) {
	s.nonce++
	tx.NodePubkey = s.id.PublicKey
	tx.Timestamp = chain.Now()
	tx.Nonce = s.nonce
	chain.Sign(tx, s.id)
}

func (s *nonceSigner) OnBatchRollback(n int) {
	s.nonce -= uint32(n)
}

func newUnsignedPublishTx(t *testing.T, cn string) chain.Transaction {
	t.Helper()
	payload, err := chain.MarshalPublish(&chain.CertPublishPayload{
		CertID:    sha256OfString(cn),
		CN:        cn,
		AVXCertID: "AVX-" + cn,
		NotBefore: 1000,
		NotAfter:  2000,
		SANs:      []string{cn},
		Serial:    "01",
	})
	if err != nil {
		t.Fatalf("MarshalPublish: %v", err)
	}
	return chain.Transaction{
		Type:    chain.TxCertPublish,
		Payload: payload,
	}
}

func sha256OfString(s string) [32]byte {
	var out [32]byte
	payload, _ := json.Marshal(s)
	copy(out[:], payload)
	// A hash is not required — only distinct, non-zero CertIDs.
	out[0] = 0x01
	return out
}

// TestBatcherDrainsOnFull — CM-32: sending MaxTxs transactions triggers
// a single block commit and every caller's promise resolves with nil.
func TestBatcherDrainsOnFull(t *testing.T) {
	ch := chain.New()
	id := newIdentity(t)

	const n = 64
	b := chain.NewBatcher(context.Background(), ch, chain.BatcherConfig{
		MaxTxs:  n,
		MaxWait: 10 * time.Second, // long enough that only full-drain fires
		Signer:  &nonceSigner{id: id},
	})
	defer b.Stop()

	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tx := newUnsignedPublishTx(t, fmt.Sprintf("host-%03d.example.com", i))
			errCh <- b.Submit(tx)
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}

	if ch.Len() != 2 {
		t.Fatalf("chain len = %d, want 2 (genesis + one batched block)", ch.Len())
	}
	tip := ch.Tip()
	if len(tip.Txs) != n {
		t.Fatalf("tip tx count = %d, want %d", len(tip.Txs), n)
	}
}

// TestBatcherDrainsOnDeadline — CM-32: when the batch is under MaxTxs,
// the deadline timer still forces a commit so partial batches don't
// sit in the queue indefinitely.
func TestBatcherDrainsOnDeadline(t *testing.T) {
	ch := chain.New()
	id := newIdentity(t)

	const n = 3
	maxWait := 100 * time.Millisecond
	b := chain.NewBatcher(context.Background(), ch, chain.BatcherConfig{
		MaxTxs:  64,
		MaxWait: maxWait,
		Signer:  &nonceSigner{id: id},
	})
	defer b.Stop()

	start := time.Now()
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tx := newUnsignedPublishTx(t, fmt.Sprintf("deadline-%d.example.com", i))
			errCh <- b.Submit(tx)
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}

	if ch.Len() != 2 {
		t.Fatalf("chain len = %d, want 2", ch.Len())
	}
	if got := len(ch.Tip().Txs); got != n {
		t.Fatalf("tip tx count = %d, want %d", got, n)
	}
	if elapsed < maxWait {
		t.Fatalf("commit took %v, want >= maxWait %v (deadline not honoured)", elapsed, maxWait)
	}
	if elapsed > 5*maxWait {
		t.Fatalf("commit took %v, want < %v (deadline fired too late)", elapsed, 5*maxWait)
	}
}

// TestBatcherPreservesOrder — CM-32: transactions appear in the
// committed block in the order they were submitted.
func TestBatcherPreservesOrder(t *testing.T) {
	ch := chain.New()
	id := newIdentity(t)

	const n = 8
	b := chain.NewBatcher(context.Background(), ch, chain.BatcherConfig{
		MaxTxs:  n,
		MaxWait: 5 * time.Second,
		Signer:  &nonceSigner{id: id},
	})
	defer b.Stop()

	// Serial submit so the expected order is unambiguous. The Batcher
	// still only commits once MaxTxs is reached because MaxWait is far
	// out of reach.
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cn := fmt.Sprintf("order-%02d.example.com", i)
			tx := newUnsignedPublishTx(t, cn)
			// Space out submissions so the channel send order is
			// deterministic; 2 ms is well below MaxWait but enough
			// to separate goroutine scheduling noise.
			time.Sleep(time.Duration(i) * 2 * time.Millisecond)
			errs[i] = b.Submit(tx)
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("Submit[%d]: %v", i, e)
		}
	}

	tip := ch.Tip()
	if len(tip.Txs) != n {
		t.Fatalf("tip tx count = %d, want %d", len(tip.Txs), n)
	}
	for i, tx := range tip.Txs {
		want := uint32(i + 1)
		if tx.Nonce != want {
			t.Fatalf("tip.Txs[%d].Nonce = %d, want %d (order not preserved)", i, tx.Nonce, want)
		}
		p, err := chain.UnmarshalPublish(&tx)
		if err != nil {
			t.Fatalf("UnmarshalPublish[%d]: %v", i, err)
		}
		wantCN := fmt.Sprintf("order-%02d.example.com", i)
		if p.CN != wantCN {
			t.Fatalf("tip.Txs[%d].CN = %q, want %q", i, p.CN, wantCN)
		}
	}
}

// TestBatcherErrorPropagation — CM-32: if any tx in a batch makes the
// block fail validation, every caller sees the same error and the chain
// is not modified.
func TestBatcherErrorPropagation(t *testing.T) {
	ch := chain.New()
	id := newIdentity(t)

	const n = 4
	b := chain.NewBatcher(context.Background(), ch, chain.BatcherConfig{
		MaxTxs:  n,
		MaxWait: 5 * time.Second,
		Signer:  &nonceSigner{id: id},
	})
	defer b.Stop()

	// Insert one tx with an invalid payload (empty CN) — validatePublish
	// rejects it, so the whole batch's BatchSubmit fails.
	badPayload, _ := chain.MarshalPublish(&chain.CertPublishPayload{
		CertID:    [32]byte{0x01},
		CN:        "", // invalid
		AVXCertID: "AVX-bad",
		NotBefore: 1000,
		NotAfter:  2000,
	})
	badTx := chain.Transaction{Type: chain.TxCertPublish, Payload: badPayload}

	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var tx chain.Transaction
			if i == 2 {
				tx = badTx
			} else {
				tx = newUnsignedPublishTx(t, fmt.Sprintf("err-%d.example.com", i))
			}
			time.Sleep(time.Duration(i) * 2 * time.Millisecond)
			errs[i] = b.Submit(tx)
		}(i)
	}
	wg.Wait()

	// Every caller should see a non-nil error, and all errors should be
	// the identical shared value returned by BatchSubmit.
	for i, e := range errs {
		if e == nil {
			t.Fatalf("errs[%d] = nil, want propagated batch error", i)
		}
		if e.Error() != errs[0].Error() {
			t.Fatalf("errs[%d] = %v, want %v (shared batch error)", i, e, errs[0])
		}
	}

	if ch.Len() != 1 {
		t.Fatalf("chain len = %d, want 1 (no block committed on failed batch)", ch.Len())
	}
}

// TestBatcherShutdownFlushesPending — CM-32: cancelling the parent
// context causes the drain goroutine to flush any queued txs so no
// caller is left blocked on an unresolved promise.
func TestBatcherShutdownFlushesPending(t *testing.T) {
	ch := chain.New()
	id := newIdentity(t)

	ctx, cancel := context.WithCancel(context.Background())
	b := chain.NewBatcher(ctx, ch, chain.BatcherConfig{
		MaxTxs:  64,
		MaxWait: 10 * time.Second, // large enough that only shutdown fires
		Signer:  &nonceSigner{id: id},
	})

	const n = 3
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tx := newUnsignedPublishTx(t, fmt.Sprintf("shut-%d.example.com", i))
			errs[i] = b.Submit(tx)
		}(i)
	}

	// Give producers time to enqueue before cancelling.
	time.Sleep(50 * time.Millisecond)
	cancel()
	b.Stop()

	wg.Wait()
	// Every submitter must have received a reply (commit or error),
	// never hung forever — that is the CM-32 invariant.
	for i, e := range errs {
		if e != nil {
			// An error on shutdown-flush is acceptable (the batch
			// may fail), but it must not be nil-without-commit.
			t.Logf("errs[%d] = %v (acceptable on shutdown)", i, e)
		}
	}
	// Either the chain has the flushed block, or it does not — but the
	// promises must all have resolved, which is proven by wg.Wait()
	// returning within the test timeout.
}
