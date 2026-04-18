// consensus.go — genesis block and fork resolution for certchain.
package chain

import (
	"bytes"
	"crypto/sha256"
)

const genesisPayload = "certchain-v1-genesis"

// GenesisBlock returns the deterministic genesis block. All certchain nodes
// must start from this same block (CM-15).
func GenesisBlock() Block {
	b := Block{
		Index:     0,
		Timestamp: 0,
	}
	// PrevHash and Hash computed from fixed inputs.
	b.Hash = computeGenesisHash()
	return b
}

func computeGenesisHash() [32]byte {
	h := sha256.New()
	h.Write([]byte{0, 0, 0, 0})       // index LE
	h.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // timestamp LE
	h.Write(make([]byte, 32))          // prevHash zeros
	h.Write([]byte(genesisPayload))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ShouldReplace reports whether candidate should replace local according to
// consensus rules:
//  1. Candidate is longer (higher tip index) → replace.
//  2. Same length but candidate tip hash is lexicographically lower → replace.
//  3. Otherwise → keep local.
func ShouldReplace(localTip, candidateTip *Block) bool {
	if candidateTip.Index > localTip.Index {
		return true
	}
	if candidateTip.Index == localTip.Index {
		return bytes.Compare(candidateTip.Hash[:], localTip.Hash[:]) < 0
	}
	return false
}
