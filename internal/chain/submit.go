// submit.go — chain-level transaction submission (CM-32).
//
// Before CM-32, every submitted transaction produced its own block. Under
// sustained load (e.g., a proactive-renewal sweep over several thousand
// certs) this inflated the chain to O(N) blocks per burst, blew the peer
// block-push fan-out, and made the persisted chain.json file grow linearly
// with the request rate rather than with the cert population.
//
// BatchSubmit atomically commits a new block containing an arbitrary
// number of transactions. The block's canonical bytes — and therefore the
// block hash (CM-29 / M7) — still cover every tx in the batch because
// ComputeHash folds each tx's signing payload into the digest. Single-tx
// Submit is preserved as a thin wrapper so existing callers keep working.
package chain

import (
	"context"
	"errors"
)

// ErrEmptyBatch is returned by BatchSubmit when called with no transactions.
// An empty batch would produce an empty block, which is valid structurally
// but wastes a block index and breaks the invariant that every non-genesis
// block commits at least one tx.
var ErrEmptyBatch = errors.New("chain.BatchSubmit: no transactions")

// Submit is a convenience wrapper around BatchSubmit for callers with a
// single transaction. Semantics are identical to BatchSubmit with a
// one-element slice.
func (c *Chain) Submit(ctx context.Context, tx Transaction) (Block, error) {
	return c.BatchSubmit(ctx, []Transaction{tx})
}

// BatchSubmit atomically builds a new block from the provided transactions
// and appends it to the chain. All txs either land in the same block or
// none are committed. The returned Block is a copy of the committed block.
//
// ctx is honoured as a pre-commit cancellation signal; once the chain
// mutex has been acquired and validation has started, ctx is no longer
// consulted so that partial state changes cannot occur.
func (c *Chain) BatchSubmit(ctx context.Context, txs []Transaction) (Block, error) {
	if len(txs) == 0 {
		return Block{}, ErrEmptyBatch
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return Block{}, err
		}
	}

	// Copy the tx slice so later caller mutations cannot racily rewrite
	// the committed block's contents.
	localTxs := make([]Transaction, len(txs))
	copy(localTxs, txs)

	c.mu.Lock()
	defer c.mu.Unlock()

	prev := c.blocks[len(c.blocks)-1]
	blk := Block{
		Index:     prev.Index + 1,
		Timestamp: Now(),
		PrevHash:  prev.Hash,
		Txs:       localTxs,
	}
	blk.Hash = ComputeHash(&blk)

	if err := c.validateBlock(blk, prev); err != nil {
		return Block{}, err
	}
	c.applySeqAndRate(blk)
	c.blocks = append(c.blocks, blk)
	return blk, nil
}
