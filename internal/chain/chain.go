// chain.go — blockchain engine for certchain.
//
// Thread-safe. All exported methods acquire c.mu before accessing state.
// Lock order: chain.mu → cert.Store.mu (never acquire in reverse).
package chain

import (
	"errors"
	"sync"
)

const (
	rateLimitWindow = 10 // blocks
	rateLimitMax    = 20 // transactions per node per window
)

// Chain is the thread-safe certchain blockchain.
type Chain struct {
	mu      sync.RWMutex
	blocks  []Block
	seqMap  map[[32]byte]uint32            // last seen nonce per node pubkey
	rateMap map[[32]byte][]int64           // block indices of recent txs per node
}

// New creates a Chain initialised with the genesis block.
func New() *Chain {
	genesis := GenesisBlock()
	return &Chain{
		blocks:  []Block{genesis},
		seqMap:  make(map[[32]byte]uint32),
		rateMap: make(map[[32]byte][]int64),
	}
}

// Len returns the number of blocks in the chain.
func (c *Chain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.blocks)
}

// Tip returns a copy of the last block.
func (c *Chain) Tip() Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blocks[len(c.blocks)-1]
}

// GenesisHash returns the hash of the genesis block.
func (c *Chain) GenesisHash() [32]byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blocks[0].Hash
}

// GetBlocks returns a copy of all blocks.
func (c *Chain) GetBlocks() []Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Block, len(c.blocks))
	copy(out, c.blocks)
	return out
}

// GetBlock returns a copy of the block at the given index, or an error if
// the index is out of range.
func (c *Chain) GetBlock(index uint32) (Block, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if int(index) >= len(c.blocks) {
		return Block{}, errors.New("block index out of range")
	}
	return c.blocks[index], nil
}

// AddBlock validates and appends a block to the chain.
func (c *Chain) AddBlock(b Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	prev := c.blocks[len(c.blocks)-1]
	if err := c.validateBlock(b, prev); err != nil {
		return err
	}
	c.applySeqAndRate(b)
	c.blocks = append(c.blocks, b)
	return nil
}

// Replace replaces the local chain with candidate if candidate wins the
// consensus comparison (longer, or same length with lower tip hash).
// Returns true if replaced, false if local chain was retained.
// The candidate slice must start with the genesis block.
func (c *Chain) Replace(candidate []Block) (bool, error) {
	if len(candidate) == 0 {
		return false, errors.New("candidate chain is empty")
	}

	if err := c.validateChain(candidate); err != nil {
		return false, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	localTip := c.blocks[len(c.blocks)-1]
	candTip := candidate[len(candidate)-1]

	if !ShouldReplace(&localTip, &candTip) {
		return false, nil
	}

	// Rebuild seq and rate maps from the candidate chain.
	newSeq := make(map[[32]byte]uint32)
	newRate := make(map[[32]byte][]int64)
	for _, blk := range candidate {
		for _, tx := range blk.Txs {
			newSeq[tx.NodePubkey] = tx.Nonce
			newRate[tx.NodePubkey] = append(newRate[tx.NodePubkey], int64(blk.Index))
		}
	}

	c.blocks = candidate
	c.seqMap = newSeq
	c.rateMap = newRate
	return true, nil
}

// Prune removes blocks before keepFrom, retaining all blocks from keepFrom
// onward. The genesis block is always kept (keepFrom is clamped to 1).
func (c *Chain) Prune(keepFrom uint32) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if keepFrom < 1 {
		keepFrom = 1
	}
	if int(keepFrom) >= len(c.blocks) {
		return 0
	}

	removed := int(keepFrom)
	c.blocks = c.blocks[keepFrom:]
	return removed
}

// ---- validation (called with lock held or from validateChain) ----

func (c *Chain) validateBlock(b, prev Block) error {
	if b.Index != prev.Index+1 {
		return errors.New("block index is not sequential")
	}
	if b.PrevHash != prev.Hash {
		return errors.New("prev_hash mismatch")
	}
	expected := ComputeHash(&b)
	if b.Hash != expected {
		return errors.New("block hash mismatch")
	}
	for i := range b.Txs {
		if err := c.validateTx(&b.Txs[i], b.Index); err != nil {
			return err
		}
	}
	return nil
}

func (c *Chain) validateTx(tx *Transaction, blockIndex uint32) error {
	if err := Verify(tx); err != nil {
		return err
	}
	if err := ValidatePayload(tx); err != nil {
		return err
	}

	// Replay protection: nonce must be greater than last seen for this node.
	last, seen := c.seqMap[tx.NodePubkey]
	if seen && tx.Nonce <= last {
		return errors.New("transaction nonce replay detected")
	}

	// Rate limiting: max rateLimitMax tx per node per rateLimitWindow blocks.
	indices := c.rateMap[tx.NodePubkey]
	cutoff := int64(blockIndex) - rateLimitWindow
	active := 0
	for _, idx := range indices {
		if idx > cutoff {
			active++
		}
	}
	if active >= rateLimitMax {
		return errors.New("rate limit exceeded")
	}

	return nil
}

func (c *Chain) applySeqAndRate(b Block) {
	for _, tx := range b.Txs {
		c.seqMap[tx.NodePubkey] = tx.Nonce
		c.rateMap[tx.NodePubkey] = append(c.rateMap[tx.NodePubkey], int64(b.Index))
	}
}

// validateChain validates a full candidate chain without holding c.mu.
// Used by Replace before acquiring the lock.
func (c *Chain) validateChain(blocks []Block) error {
	if blocks[0].Hash != GenesisBlock().Hash {
		return errors.New("genesis block hash mismatch")
	}

	seqMap := make(map[[32]byte]uint32)
	rateMap := make(map[[32]byte][]int64)

	// Temporarily swap maps for validation; restore after.
	orig := c
	tmp := &Chain{
		blocks:  blocks[:1],
		seqMap:  seqMap,
		rateMap: rateMap,
	}
	_ = orig

	for i := 1; i < len(blocks); i++ {
		if err := tmp.validateBlock(blocks[i], blocks[i-1]); err != nil {
			return err
		}
		tmp.applySeqAndRate(blocks[i])
	}
	return nil
}
