package leader

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/amosdavis/certchain/internal/logging"

	"k8s.io/client-go/kubernetes/fake"
)

func TestRunValidatesRequiredFields(t *testing.T) {
	ctx := context.Background()
	run := func(context.Context) error { return nil }

	if err := Run(ctx, Config{}, run); err == nil {
		t.Errorf("expected error for missing LeaseName")
	}
	if err := Run(ctx, Config{LeaseName: "x"}, run); err == nil {
		t.Errorf("expected error for missing Client")
	}
	if err := Run(ctx, Config{LeaseName: "x", Client: fake.NewSimpleClientset()}, run); err == nil {
		t.Errorf("expected error for missing Logger")
	}
}

func TestRunRejectsImpossibleDurations(t *testing.T) {
	cfg := Config{
		LeaseName:     "x",
		Client:        fake.NewSimpleClientset(),
		Logger:        logging.Discard(),
		LeaseDuration: 1 * time.Second,
		RenewDeadline: 2 * time.Second,
	}
	err := Run(context.Background(), cfg, func(context.Context) error { return nil })
	if err == nil {
		t.Fatalf("expected error for RenewDeadline >= LeaseDuration")
	}
}

func TestRunExecutesLeaderFunction(t *testing.T) {
	// Use a fake clientset so the lease is "acquired" against an in-memory
	// store. This exercises OnStartedLeading without a real apiserver.
	client := fake.NewSimpleClientset()
	cfg := Config{
		LeaseName:     "cc-test",
		Namespace:     "certchain",
		Identity:      "test-0",
		Client:        client,
		Logger:        logging.Discard(),
		LeaseDuration: 5 * time.Second,
		RenewDeadline: 3 * time.Second,
		RetryPeriod:   500 * time.Millisecond,
	}

	ran := make(chan struct{}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := Run(ctx, cfg, func(ctx context.Context) error {
		select {
		case ran <- struct{}{}:
		default:
		}
		return errors.New("intentional-return")
	})
	if err == nil || err.Error() != "intentional-return" {
		t.Fatalf("expected intentional-return error, got %v", err)
	}
	select {
	case <-ran:
	default:
		t.Errorf("leader function did not execute")
	}
}
