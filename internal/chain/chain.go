// chain.go — blockchain engine for certchain.
//
// Thread-safe. All exported methods acquire c.mu before accessing state.
// Lock order: chain.mu → cert.Store.mu (never acquire in reverse).
package chain

import (
	"errors"
	"sync"

	"github.com/amosdavis/certchain/internal/metrics"
)

const (
	rateLimitWindow = 10 // blocks
	rateLimitMax    = 20 // transactions per node per window
)

// Chain is the thread-safe certchain blockchain.
type Chain struct {
	mu         sync.RWMutex
	blocks     []Block
	seqMap     map[[32]byte]uint32  // last seen nonce per node pubkey
	rateMap    map[[32]byte][]int64 // block indices of recent txs per node
	validators *ValidatorSet        // nil = accept any signer (CM-23)

	// chainID and acceptLegacySigs reflect the signing context installed
	// by New (CM-29). They are recorded here so callers can introspect
	// the chain's configuration; the authoritative values that Sign /
	// Verify consult live in the signing package globals.
	chainID          string
	acceptLegacySigs bool
}

// Option configures a Chain at construction time.
type Option func(*Chain)

// WithChainID sets the chainID mixed into the signature domain separator
// (CM-29). An empty string is treated as DefaultChainID. Values longer
// than 255 bytes cause New to panic at startup.
func WithChainID(chainID string) Option {
	return func(c *Chain) {
		if chainID == "" {
			chainID = DefaultChainID
		}
		c.chainID = chainID
	}
}

// WithAcceptLegacySigs controls whether Verify falls back to the pre-CM-29
// (no domain prefix) signing format. Default true; flip to false after the
// legacy-block migration is complete so replays of pre-upgrade signatures
// are rejected network-wide.
func WithAcceptLegacySigs(accept bool) Option {
	return func(c *Chain) {
		c.acceptLegacySigs = accept
	}
}

// WithMetrics wires the chain's Prometheus counters, including the
// legacy-signature counter used by CM-29's compat path. Pass nil to leave
// metrics unwired (tests).
func WithMetrics(reg *metrics.Registry) Option {
	return func(c *Chain) {
		if reg == nil {
			return
		}
		counter := metrics.NewChainLegacySigCounter(reg)
		SetLegacySigHook(func() { counter.Inc() })
	}
}

// SetValidators installs an allowlist of authorized block authors. A nil
// argument disables the check, preserving the legacy accept-all behavior
// used by unit tests and pre-CM-23 deployments.
func (c *Chain) SetValidators(vs *ValidatorSet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.validators = vs
}

// Validators returns the currently installed ValidatorSet (may be nil).
func (c *Chain) Validators() *ValidatorSet {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.validators
}

// New creates a Chain initialised with the genesis block.
func New(opts ...Option) *Chain {
	genesis := GenesisBlock()
	c := &Chain{
		blocks:           []Block{genesis},
		seqMap:           make(map[[32]byte]uint32),
		rateMap:          make(map[[32]byte][]int64),
		chainID:          DefaultChainID,
		acceptLegacySigs: true,
	}
	for _, opt := range opts {
		opt(c)
	}
	// Install the process-wide signing context from the chain's settings.
	// A bad chainID length is a startup programmer error, not a runtime
	// recoverable condition, so panic loudly (CM-29).
	if err := SetSigningContext(c.chainID, c.acceptLegacySigs); err != nil {
		panic("chain.New: " + err.Error())
	}
	return c
}

// ChainID returns the chainID configured for this chain (CM-29).
func (c *Chain) ChainID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.chainID
}

// AcceptsLegacySigs reports whether this chain still accepts signatures in
// the pre-CM-29 no-domain-prefix format.
func (c *Chain) AcceptsLegacySigs() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.acceptLegacySigs
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

// validateBlockUnlocked validates a block against a snapshot of chain state
// (prev block, seqMap, rateMap) WITHOUT holding c.mu. The snapshot must be
// taken under RLock. This is used by BatchSubmit to validate outside the
// critical section (CM-34).
func (c *Chain) validateBlockUnlocked(b, prev Block) error {
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

	// Snapshot validator set and chain state for validation.
	c.mu.RLock()
	vs := c.validators
	seqMap := make(map[[32]byte]uint32, len(c.seqMap))
	for k, v := range c.seqMap {
		seqMap[k] = v
	}
	rateMap := make(map[[32]byte][]int64, len(c.rateMap))
	for k, v := range c.rateMap {
		rateMap[k] = append([]int64(nil), v...)
	}
	c.mu.RUnlock()

	// Validate each tx against the snapshot.
	for i := range b.Txs {
		tx := &b.Txs[i]
		if !vs.Contains(tx.NodePubkey) {
			return ErrUnauthorizedAuthor
		}
		if err := Verify(tx); err != nil {
			return err
		}
		if err := ValidatePayload(tx); err != nil {
			return err
		}

		// Replay protection.
		last, seen := seqMap[tx.NodePubkey]
		if seen && tx.Nonce <= last {
			return errors.New("transaction nonce replay detected")
		}

		// Rate limiting.
		indices := rateMap[tx.NodePubkey]
		cutoff := int64(b.Index) - rateLimitWindow
		active := 0
		for _, idx := range indices {
			if idx > cutoff {
				active++
			}
		}
		if active >= rateLimitMax {
			return errors.New("rate limit exceeded")
		}
	}
	return nil
}

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
		if !c.validators.Contains(b.Txs[i].NodePubkey) {
			return ErrUnauthorizedAuthor
		}
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

	// Snapshot the validator set under RLock so SetValidators cannot race
	// with in-flight chain validation.
	c.mu.RLock()
	vs := c.validators
	c.mu.RUnlock()

	seqMap := make(map[[32]byte]uint32)
	rateMap := make(map[[32]byte][]int64)

	tmp := &Chain{
		blocks:     blocks[:1],
		seqMap:     seqMap,
		rateMap:    rateMap,
		validators: vs,
	}

	for i := 1; i < len(blocks); i++ {
		if err := tmp.validateBlock(blocks[i], blocks[i-1]); err != nil {
			return err
		}
		tmp.applySeqAndRate(blocks[i])
	}
	return nil
}
