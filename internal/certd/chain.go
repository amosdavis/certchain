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
)

type persistedChain struct {
	Blocks []chain.Block `json:"blocks"`
}

// LoadChain loads the persisted chain from configDir/chain.json and
// replaces the chain's blocks if the file exists. It rebuilds the cert
// store from the loaded blocks. Returns nil if the file doesn't exist
// (fresh start).
func LoadChain(ctx context.Context, logger *slog.Logger, ch *chain.Chain, certStore *cert.Store, configDir string) error {
	path := filepath.Join(configDir, "chain.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
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
	if replaced {
		return certStore.RebuildFrom(ch.GetBlocks())
	}
	return nil
}

// SaveChain persists the chain's blocks to configDir/chain.json.
func SaveChain(ctx context.Context, logger *slog.Logger, ch *chain.Chain, configDir string) error {
	data, err := json.Marshal(persistedChain{Blocks: ch.GetBlocks()})
	if err != nil {
		return err
	}
	path := filepath.Join(configDir, "chain.json")
	return os.WriteFile(path, data, 0600)
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
