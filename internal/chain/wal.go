// wal.go — write-ahead log for crash-safe chain persistence (CM-35).
//
// Format: each record is framed as:
//   | len(4 LE) | crc32(4) | payload(JSON block) |
// On replay, short reads when reading len → stop (tail truncation OK).
// CRC mismatches → log warning + skip record.
package chain

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"os"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var (
	ErrWALClosed   = errors.New("wal: closed")
	ErrWALCorrupt  = errors.New("wal: corrupted record")
	crc32cTable    = crc32.MakeTable(crc32.Castagnoli)
)

type WAL struct {
	mu     sync.Mutex
	path   string
	file   *os.File
	logger *slog.Logger
	fsync  bool
	closed bool
}

type walRecord struct {
	Block Block `json:"block"`
}

// OpenWAL opens or creates the WAL file at path. If fsync is true (recommended
// for production), each Append will fsync before returning.
func OpenWAL(path string, logger *slog.Logger, fsync bool) (*WAL, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("wal.Open: %w", err)
	}
	w := &WAL{
		path:   path,
		file:   f,
		logger: logger,
		fsync:  fsync,
	}
	return w, nil
}

// Append writes a block to the WAL. Returns an error if the write or fsync
// fails, in which case the caller must treat the block as not durably committed.
// CM-38: instrumented with tracing span.
func (w *WAL) Append(b *Block) error {
	tracer := otel.Tracer("certd")
	ctx := context.Background()
	_, span := tracer.Start(ctx, "WAL.Append",
		trace.WithAttributes(
			attribute.Int("block.index", int(b.Index)),
			attribute.Bool("fsync", w.fsync),
		))
	defer span.End()
	
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		span.RecordError(ErrWALClosed)
		return ErrWALClosed
	}

	rec := walRecord{Block: *b}
	payload, err := json.Marshal(&rec)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("wal.Append: marshal: %w", err)
	}

	crc := crc32.Checksum(payload, crc32cTable)

	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(payload)))
	binary.LittleEndian.PutUint32(hdr[4:8], crc)

	if _, err := w.file.Write(hdr[:]); err != nil {
		span.RecordError(err)
		return fmt.Errorf("wal.Append: write header: %w", err)
	}
	if _, err := w.file.Write(payload); err != nil {
		span.RecordError(err)
		return fmt.Errorf("wal.Append: write payload: %w", err)
	}

	if w.fsync {
		if err := w.file.Sync(); err != nil {
			span.RecordError(err)
			return fmt.Errorf("wal.Append: sync: %w", err)
		}
	}
	return nil
}

// Replay reads the WAL file from start to end, calling fn for each valid
// record. Truncated tail records (short read when reading len) → log + stop.
// CRC mismatches → log warning + skip record + continue.
func (w *WAL) Replay(fn func(*Block) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return ErrWALClosed
	}

	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("wal.Replay: seek: %w", err)
	}

	for {
		var hdr [8]byte
		n, err := io.ReadFull(w.file, hdr[:])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			if n > 0 && w.logger != nil {
				w.logger.Warn("wal.Replay: truncated tail (partial header)", "bytes", n)
			}
			break
		}
		if err != nil {
			return fmt.Errorf("wal.Replay: read header: %w", err)
		}

		length := binary.LittleEndian.Uint32(hdr[0:4])
		expectedCRC := binary.LittleEndian.Uint32(hdr[4:8])

		payload := make([]byte, length)
		n, err = io.ReadFull(w.file, payload)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			if w.logger != nil {
				w.logger.Warn("wal.Replay: truncated tail (partial payload)", "expected", length, "got", n)
			}
			break
		}
		if err != nil {
			return fmt.Errorf("wal.Replay: read payload: %w", err)
		}

		actualCRC := crc32.Checksum(payload, crc32cTable)
		if actualCRC != expectedCRC {
			if w.logger != nil {
				w.logger.Warn("wal.Replay: CRC mismatch, skipping record", "expected", expectedCRC, "actual", actualCRC)
			}
			continue
		}

		var rec walRecord
		if err := json.Unmarshal(payload, &rec); err != nil {
			if w.logger != nil {
				w.logger.Warn("wal.Replay: unmarshal failed, skipping record", "error", err)
			}
			continue
		}

		if err := fn(&rec.Block); err != nil {
			return err
		}
	}
	return nil
}

// Rotate truncates the WAL file, resetting it to empty. Call this after a
// clean snapshot has been written so the WAL can be reset.
func (w *WAL) Rotate() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return ErrWALClosed
	}

	// Close the current file handle
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("wal.Rotate: close: %w", err)
	}

	// Truncate by reopening with O_TRUNC
	f, err := os.OpenFile(w.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("wal.Rotate: reopen: %w", err)
	}
	w.file = f
	return nil
}

// Close closes the WAL file. Subsequent operations return ErrWALClosed.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true
	return w.file.Close()
}
