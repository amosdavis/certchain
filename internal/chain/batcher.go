// batcher.go — time/size-bounded transaction batching (CM-32).
//
// Batcher accepts individual transactions from many producers and groups
// them into a single chain block once either:
//   - the pending queue reaches MaxTxs, or
//   - MaxWait has elapsed since the first pending tx was queued.
//
// Each producer receives a per-tx promise that resolves with the commit
// outcome (nil on success, the BatchSubmit error — shared by the whole
// batch — on failure). Ordering of txs in the committed block matches the
// order in which Submit was called.
//
// The Batcher's drain loop runs on a single goroutine, so an optional
// Signer hook observes transactions in commit order; nonce assignment and
// Ed25519 signing can therefore be done lock-free inside the hook.
package chain

import (
	"context"
	"errors"
	"sync"
	"time"
)

// DefaultBatchMaxTxs is the default upper bound on the number of txs per
// batched block. 64 matches the CLI default and is sized so a single
// block still fits comfortably under the peer-sync HTTP body budget.
const DefaultBatchMaxTxs = 64

// DefaultBatchMaxWait is the default upper bound on how long a tx may
// sit in the pending queue before it is committed. 250 ms is short
// enough that single-tx callers see no user-visible latency regression.
const DefaultBatchMaxWait = 250 * time.Millisecond

// ErrBatcherStopped is returned by Submit when the batcher has already
// been stopped and can no longer accept new work.
var ErrBatcherStopped = errors.New("chain.Batcher: stopped")

// Signer is an optional hook invoked from the Batcher's drain goroutine
// immediately before a batch is committed. Implementations may mutate
// each transaction (typically assigning NodePubkey, Timestamp, Nonce,
// and Signature). Because SignTx runs on a single goroutine in submit
// order, implementations need no internal synchronisation for
// monotonic-nonce assignment.
//
// OnBatchRollback is invoked when BatchSubmit returns an error for a
// batch that the Signer advanced state for (e.g., a nonce counter).
// n is the number of txs in the failed batch.
type Signer interface {
	SignTx(tx *Transaction)
	OnBatchRollback(n int)
}

// batchItem is one queued tx awaiting commit.
type batchItem struct {
	tx      Transaction
	promise chan error
}

// BatcherConfig controls Batcher construction. Zero or negative fields
// are replaced with their Default* equivalents.
type BatcherConfig struct {
	MaxTxs  int
	MaxWait time.Duration
	// OnBlock, if non-nil, is called with the committed block after a
	// successful chain.BatchSubmit. It runs on the drain goroutine so
	// it must not block for long; use a non-blocking send to a worker
	// channel if slow I/O (peer push, disk flush) is needed.
	OnBlock func(Block)
	// Signer is optional; pass nil for already-finalised txs (tests).
	Signer Signer
}

// Batcher groups single-tx submissions into multi-tx blocks.
type Batcher struct {
	ch      *Chain
	cfg     BatcherConfig
	queue   chan batchItem
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	stopped chan struct{}

	once sync.Once
}

// NewBatcher constructs and starts a Batcher. Call Stop (typically in
// main's shutdown path) to flush any pending work and release the drain
// goroutine. parent may be nil; in that case a background context is used.
func NewBatcher(parent context.Context, ch *Chain, cfg BatcherConfig) *Batcher {
	if parent == nil {
		parent = context.Background()
	}
	if cfg.MaxTxs <= 0 {
		cfg.MaxTxs = DefaultBatchMaxTxs
	}
	if cfg.MaxWait <= 0 {
		cfg.MaxWait = DefaultBatchMaxWait
	}

	ctx, cancel := context.WithCancel(parent)
	b := &Batcher{
		ch:      ch,
		cfg:     cfg,
		queue:   make(chan batchItem, cfg.MaxTxs*2),
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	go b.run()
	return b
}

// Submit enqueues tx and blocks until either the batch containing it is
// committed (returning nil) or the commit fails (returning the shared
// batch error). If the Batcher is stopped before tx can be enqueued,
// Submit returns ErrBatcherStopped.
func (b *Batcher) Submit(tx Transaction) error {
	promise := make(chan error, 1)
	select {
	case b.queue <- batchItem{tx: tx, promise: promise}:
	case <-b.stopped:
		return ErrBatcherStopped
	}
	// Once enqueued, the drain goroutine guarantees a reply on promise,
	// so we wait unconditionally — racing against stopped here would
	// risk a tx being committed with no caller listening for the result.
	return <-promise
}

// Stop drains any queued txs, attempts a final commit, and blocks until
// the drain goroutine has exited. Safe to call multiple times.
func (b *Batcher) Stop() {
	b.once.Do(func() {
		close(b.stopped)
		b.cancel()
	})
	<-b.done
}

// MaxTxs reports the configured batch size ceiling.
func (b *Batcher) MaxTxs() int { return b.cfg.MaxTxs }

// MaxWait reports the configured batch time ceiling.
func (b *Batcher) MaxWait() time.Duration { return b.cfg.MaxWait }

// run is the drain loop. It owns pending and the deadline timer.
func (b *Batcher) run() {
	defer close(b.done)

	pending := make([]batchItem, 0, b.cfg.MaxTxs)
	var timer *time.Timer
	var timerC <-chan time.Time

	resetTimer := func() {
		if timer != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		timer = nil
		timerC = nil
	}

	flushAll := func() {
		if len(pending) == 0 {
			return
		}
		b.commit(pending)
		pending = pending[:0]
		resetTimer()
	}

	for {
		select {
		case <-b.ctx.Done():
			// Drain anything already enqueued so no caller is
			// abandoned waiting on an unfulfilled promise.
		drain:
			for {
				select {
				case item := <-b.queue:
					pending = append(pending, item)
				default:
					break drain
				}
			}
			flushAll()
			return

		case item := <-b.queue:
			pending = append(pending, item)
			if len(pending) == 1 {
				timer = time.NewTimer(b.cfg.MaxWait)
				timerC = timer.C
			}
			if len(pending) >= b.cfg.MaxTxs {
				flushAll()
			}

		case <-timerC:
			flushAll()
		}
	}
}

// commit builds the tx slice in submit order, invokes Signer (if any),
// calls chain.BatchSubmit, and resolves every promise with the shared
// outcome. On error it asks the Signer to roll back its state.
func (b *Batcher) commit(items []batchItem) {
	txs := make([]Transaction, len(items))
	for i := range items {
		txs[i] = items[i].tx
		if b.cfg.Signer != nil {
			b.cfg.Signer.SignTx(&txs[i])
		}
	}

	blk, err := b.ch.BatchSubmit(b.ctx, txs)
	if err != nil {
		if b.cfg.Signer != nil {
			b.cfg.Signer.OnBatchRollback(len(items))
		}
		for _, it := range items {
			it.promise <- err
		}
		return
	}

	if b.cfg.OnBlock != nil {
		b.cfg.OnBlock(blk)
	}
	for _, it := range items {
		it.promise <- nil
	}
}
