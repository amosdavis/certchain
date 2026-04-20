package certd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/amosdavis/certchain/internal/cert"
	"github.com/amosdavis/certchain/internal/chain"
	"github.com/prometheus/client_golang/prometheus"
)

type persistedChain struct {
	Blocks []chain.Block `json:"blocks"`
}

// LoadChain loads the persisted chain from configDir/chain.json and
// replays the WAL on top if walPath is provided. It replaces the chain's
// blocks if the file exists and rebuilds the cert store from the loaded
// blocks. Returns nil if the snapshot file doesn't exist (fresh start).
func LoadChain(ctx context.Context, logger *slog.Logger, ch *chain.Chain, certStore *cert.Store, configDir, walPath string) error {
	// Load the snapshot
	path := filepath.Join(configDir, "chain.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// Fresh start; if WAL exists, replay it
		if walPath != "" {
			if err := replayWAL(ctx, logger, ch, walPath); err != nil {
				return err
			}
		}
		return certStore.RebuildFrom(ch.GetBlocks())
	}
	if err != nil {
		return err
	}
	var p persistedChain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	if len(p.Blocks) == 0 {
		return nil
	}

	replaced, err := ch.Replace(p.Blocks)
	if err != nil {
		return fmt.Errorf("restore chain: %w", err)
	}

	// Replay WAL entries on top of snapshot (CM-36)
	if walPath != "" {
		if err := replayWAL(ctx, logger, ch, walPath); err != nil {
			return err
		}
	}

	if replaced {
		return certStore.RebuildFrom(ch.GetBlocks())
	}
	return nil
}

func replayWAL(ctx context.Context, logger *slog.Logger, ch *chain.Chain, walPath string) error {
	wal, err := chain.OpenWAL(walPath, logger, false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open WAL: %w", err)
	}
	defer wal.Close()

	return wal.Replay(func(b *chain.Block) error {
		if err := ch.AddBlock(*b); err != nil {
			logger.Warn("wal replay: skip block", "index", b.Index, "error", err)
		}
		return nil
	})
}

// SaveChain persists the chain's blocks to configDir/chain.json and
// rotates the WAL if walPath is provided. Errors are logged with slog
// and counted via saveErrorsTotal metric (CM-37). Returns the error so
// callers can decide whether to stop or proceed.
func SaveChain(ctx context.Context, logger *slog.Logger, ch *chain.Chain, configDir, walPath string, saveErrorsTotal prometheus.Counter) error {
	data, err := json.Marshal(persistedChain{Blocks: ch.GetBlocks()})
	if err != nil {
		if saveErrorsTotal != nil {
			saveErrorsTotal.Inc()
		}
		logger.Error("chain save: marshal failed", "error", err)
		return err
	}
	path := filepath.Join(configDir, "chain.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		if saveErrorsTotal != nil {
			saveErrorsTotal.Inc()
		}
		logger.Error("chain save: write snapshot failed", "path", path, "error", err)
		return err
	}

	// Rotate WAL after successful snapshot (CM-36)
	if walPath != "" {
		wal, err := chain.OpenWAL(walPath, logger, false)
		if err != nil {
			if saveErrorsTotal != nil {
				saveErrorsTotal.Inc()
			}
			logger.Error("chain save: open WAL for rotate failed", "path", walPath, "error", err)
			return fmt.Errorf("open WAL for rotate: %w", err)
		}
		defer wal.Close()
		if err := wal.Rotate(); err != nil {
			if saveErrorsTotal != nil {
				saveErrorsTotal.Inc()
			}
			logger.Error("chain save: WAL rotate failed", "path", walPath, "error", err)
			return fmt.Errorf("rotate WAL: %w", err)
		}
	}
	return nil
}

// LoadValidators loads the validator allowlist from the specified path.
// If the file doesn't exist, returns (nil, nil) so the caller can log a
// WARN and continue in accept-all mode. Malformed files return an error.
func LoadValidators(ctx context.Context, logger *slog.Logger, validatorsPath string) (*chain.ValidatorSet, error) {
	vs, err := chain.LoadValidatorsFromFile(validatorsPath)
	if err != nil {
		return nil, fmt.Errorf("load validators %s: %w", validatorsPath, err)
	}
	return vs, nil
}
