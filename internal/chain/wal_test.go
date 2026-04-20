package chain

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestWAL_AppendReplay(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "test.wal")
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create some test blocks
	genesis := GenesisBlock()
	blk1 := Block{
		Index:     1,
		Timestamp: 1000,
		PrevHash:  genesis.Hash,
		Txs:       []Transaction{},
	}
	blk1.Hash = ComputeHash(&blk1)

	blk2 := Block{
		Index:     2,
		Timestamp: 2000,
		PrevHash:  blk1.Hash,
		Txs:       []Transaction{},
	}
	blk2.Hash = ComputeHash(&blk2)

	// Write blocks
	wal, err := OpenWAL(walPath, logger, true)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := wal.Append(&blk1); err != nil {
		t.Fatalf("Append blk1: %v", err)
	}
	if err := wal.Append(&blk2); err != nil {
		t.Fatalf("Append blk2: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Replay and verify
	wal2, err := OpenWAL(walPath, logger, false)
	if err != nil {
		t.Fatalf("OpenWAL (replay): %v", err)
	}
	defer wal2.Close()

	var replayed []Block
	if err := wal2.Replay(func(b *Block) error {
		replayed = append(replayed, *b)
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if len(replayed) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(replayed))
	}
	if replayed[0].Index != 1 || replayed[0].Timestamp != 1000 {
		t.Errorf("block 1 mismatch: %+v", replayed[0])
	}
	if replayed[1].Index != 2 || replayed[1].Timestamp != 2000 {
		t.Errorf("block 2 mismatch: %+v", replayed[1])
	}
}

func TestWAL_TruncatedTail(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "test.wal")
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	genesis := GenesisBlock()
	blk1 := Block{
		Index:     1,
		Timestamp: 1000,
		PrevHash:  genesis.Hash,
		Txs:       []Transaction{},
	}
	blk1.Hash = ComputeHash(&blk1)

	wal, err := OpenWAL(walPath, logger, false)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := wal.Append(&blk1); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Truncate the file to simulate a torn write
	info, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	newSize := info.Size() - 5
	if err := os.Truncate(walPath, newSize); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	// Replay should stop at the truncated tail without error
	wal2, err := OpenWAL(walPath, logger, false)
	if err != nil {
		t.Fatalf("OpenWAL (replay): %v", err)
	}
	defer wal2.Close()

	var replayed []Block
	err = wal2.Replay(func(b *Block) error {
		replayed = append(replayed, *b)
		return nil
	})
	if err != nil {
		t.Fatalf("Replay on truncated file: %v", err)
	}
	// No blocks should be replayed since the only one is truncated
	if len(replayed) != 0 {
		t.Fatalf("expected 0 blocks on truncated tail, got %d", len(replayed))
	}
}

func TestWAL_CRCMismatch(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "test.wal")
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	genesis := GenesisBlock()
	blk1 := Block{
		Index:     1,
		Timestamp: 1000,
		PrevHash:  genesis.Hash,
		Txs:       []Transaction{},
	}
	blk1.Hash = ComputeHash(&blk1)

	wal, err := OpenWAL(walPath, logger, false)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := wal.Append(&blk1); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Corrupt the payload by flipping a byte
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) > 20 {
		data[20] ^= 0xFF // flip bits in the payload
	}
	if err := os.WriteFile(walPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Replay should skip the corrupted record
	wal2, err := OpenWAL(walPath, logger, false)
	if err != nil {
		t.Fatalf("OpenWAL (replay): %v", err)
	}
	defer wal2.Close()

	var replayed []Block
	err = wal2.Replay(func(b *Block) error {
		replayed = append(replayed, *b)
		return nil
	})
	if err != nil {
		t.Fatalf("Replay with CRC mismatch: %v", err)
	}
	if len(replayed) != 0 {
		t.Fatalf("expected 0 blocks (CRC mismatch skipped), got %d", len(replayed))
	}
}

func TestWAL_Rotate(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "test.wal")
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	genesis := GenesisBlock()
	blk1 := Block{
		Index:     1,
		Timestamp: 1000,
		PrevHash:  genesis.Hash,
		Txs:       []Transaction{},
	}
	blk1.Hash = ComputeHash(&blk1)

	wal, err := OpenWAL(walPath, logger, false)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := wal.Append(&blk1); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Rotate should truncate the file
	if err := wal.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Replay should return no blocks
	var replayed []Block
	err = wal.Replay(func(b *Block) error {
		replayed = append(replayed, *b)
		return nil
	})
	if err != nil {
		t.Fatalf("Replay after Rotate: %v", err)
	}
	if len(replayed) != 0 {
		t.Fatalf("expected 0 blocks after rotate, got %d", len(replayed))
	}

	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify file is empty
	info, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected 0 bytes after rotate, got %d", info.Size())
	}
}

func TestWAL_WithTransactions(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "test.wal")
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create a block with transactions
	genesis := GenesisBlock()
	payload := json.RawMessage(`{"cert_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","cn":"test.example.com","avx_cert_id":"123","not_before":1000,"not_after":2000}`)
	tx := Transaction{
		Type:       TxCertPublish,
		NodePubkey: [32]byte{1, 2, 3},
		Timestamp:  1000,
		Nonce:      1,
		Payload:    payload,
		Signature:  [64]byte{},
	}
	blk := Block{
		Index:     1,
		Timestamp: 1000,
		PrevHash:  genesis.Hash,
		Txs:       []Transaction{tx},
	}
	blk.Hash = ComputeHash(&blk)

	wal, err := OpenWAL(walPath, logger, false)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := wal.Append(&blk); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Replay and verify transaction is preserved
	wal2, err := OpenWAL(walPath, logger, false)
	if err != nil {
		t.Fatalf("OpenWAL (replay): %v", err)
	}
	defer wal2.Close()

	var replayed []Block
	if err := wal2.Replay(func(b *Block) error {
		replayed = append(replayed, *b)
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if len(replayed) != 1 {
		t.Fatalf("expected 1 block, got %d", len(replayed))
	}
	if len(replayed[0].Txs) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(replayed[0].Txs))
	}
	if replayed[0].Txs[0].Type != TxCertPublish {
		t.Errorf("tx type mismatch")
	}
}
