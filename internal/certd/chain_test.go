package certd

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/amosdavis/certchain/internal/chain"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestSaveChainErrorMetric verifies that SaveChain increments the
// certchain_chain_save_errors_total metric when the write fails (CM-37).
func TestSaveChainErrorMetric(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ch := chain.New()

	tmpDir := t.TempDir()
	
	// Create a counter for tracking errors
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_save_errors_total",
		Help: "Test counter for save errors",
	})

	// Test 1: write to a non-existent directory should fail and increment metric
	badPath := filepath.Join(tmpDir, "nonexistent", "subdir")
	initialCount := testutil.ToFloat64(counter)
	
	err := SaveChain(context.Background(), logger, ch, badPath, "", counter)
	if err == nil {
		t.Fatal("expected error when writing to non-existent directory")
	}
	
	newCount := testutil.ToFloat64(counter)
	if newCount != initialCount+1 {
		t.Errorf("metric not incremented: got %f, want %f", newCount, initialCount+1)
	}

	// Test 2: write to a read-only directory should fail and increment metric
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	if err := os.Mkdir(readOnlyDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	
	// Make directory read-only (this works differently on Windows)
	// On Windows, we need to make the file read-only after creation
	// So we'll test with a read-only file instead
	testFile := filepath.Join(readOnlyDir, "chain.json")
	if err := os.WriteFile(testFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("create test file: %v", err)
	}
	if err := os.Chmod(testFile, 0444); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	
	beforeCount := testutil.ToFloat64(counter)
	err = SaveChain(context.Background(), logger, ch, readOnlyDir, "", counter)
	// On Windows, this might succeed due to different permission semantics
	// So we only check if there was an error
	if err != nil {
		afterCount := testutil.ToFloat64(counter)
		if afterCount != beforeCount+1 {
			t.Errorf("metric not incremented on read-only error: got %f, want %f", afterCount, beforeCount+1)
		}
	}

	// Test 3: successful write should NOT increment the metric
	goodDir := filepath.Join(tmpDir, "good")
	if err := os.Mkdir(goodDir, 0755); err != nil {
		t.Fatalf("mkdir good: %v", err)
	}
	
	beforeSuccess := testutil.ToFloat64(counter)
	err = SaveChain(context.Background(), logger, ch, goodDir, "", counter)
	if err != nil {
		t.Fatalf("unexpected error on valid write: %v", err)
	}
	
	afterSuccess := testutil.ToFloat64(counter)
	if afterSuccess != beforeSuccess {
		t.Errorf("metric incremented on success: got %f, want %f", afterSuccess, beforeSuccess)
	}
}

// TestSaveChainWALRotateError verifies that WAL rotate errors are counted (CM-37).
func TestSaveChainWALRotateError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ch := chain.New()
	tmpDir := t.TempDir()
	
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_wal_errors_total",
		Help: "Test counter for WAL errors",
	})

	// Point to a non-existent WAL file - should fail on rotate
	badWALPath := filepath.Join(tmpDir, "nonexistent", "chain.wal")
	
	beforeCount := testutil.ToFloat64(counter)
	err := SaveChain(context.Background(), logger, ch, tmpDir, badWALPath, counter)
	if err == nil {
		t.Fatal("expected error when rotating non-existent WAL")
	}
	
	afterCount := testutil.ToFloat64(counter)
	if afterCount != beforeCount+1 {
		t.Errorf("metric not incremented on WAL rotate error: got %f, want %f", afterCount, beforeCount+1)
	}
}
