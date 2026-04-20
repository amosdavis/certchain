// Package leader provides a thin helper around client-go's leaderelection
// package so that certd and certchain-issuer binaries can serialize
// singleton workloads (CSR watching, blockSubmitter, annotation-secret
// reconcile) across HA replicas.
//
// The helper uses a Kubernetes coordination.k8s.io/v1 Lease. Only the leader
// runs the Run function; followers block until they either become the leader
// or the context is cancelled. See CM-22 (split-brain reconciliation).
package leader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// Config configures a single leader-election cycle.
type Config struct {
	// LeaseName identifies the Lease object. Must be a valid DNS-1123 label.
	LeaseName string

	// Namespace holds the Lease object. Defaults to certchain namespace from
	// POD_NAMESPACE env var, then "certchain".
	Namespace string

	// Identity uniquely identifies this candidate. Defaults to POD_NAME env
	// var, then os.Hostname().
	Identity string

	// LeaseDuration controls how long a follower waits before trying to take
	// over after the leader has stopped renewing. Default 15s.
	LeaseDuration time.Duration

	// RenewDeadline controls how long the leader keeps trying to renew before
	// giving up. Must be < LeaseDuration. Default 10s.
	RenewDeadline time.Duration

	// RetryPeriod controls how often candidates try to become the leader.
	// Default 2s.
	RetryPeriod time.Duration

	// Client is the Kubernetes client used to manage the Lease.
	Client kubernetes.Interface

	// Logger is used for lifecycle events. Required.
	Logger *slog.Logger
}

// Run blocks until the provided Run function returns (if this replica became
// leader) or ctx is cancelled. If this replica loses leadership while Run is
// still executing, its context is cancelled and Run returns the cause as an
// error.
//
// The Run function MUST respect context cancellation; otherwise two replicas
// may briefly act as leader if the Lease is lost.
func Run(ctx context.Context, cfg Config, run func(ctx context.Context) error) error {
	if cfg.LeaseName == "" {
		return errors.New("leader: LeaseName is required")
	}
	if cfg.Client == nil {
		return errors.New("leader: Client is required")
	}
	if cfg.Logger == nil {
		return errors.New("leader: Logger is required")
	}
	if cfg.Namespace == "" {
		cfg.Namespace = firstNonEmpty(os.Getenv("POD_NAMESPACE"), "certchain")
	}
	if cfg.Identity == "" {
		host, _ := os.Hostname()
		cfg.Identity = firstNonEmpty(os.Getenv("POD_NAME"), host, "unknown")
	}
	if cfg.LeaseDuration == 0 {
		cfg.LeaseDuration = 15 * time.Second
	}
	if cfg.RenewDeadline == 0 {
		cfg.RenewDeadline = 10 * time.Second
	}
	if cfg.RetryPeriod == 0 {
		cfg.RetryPeriod = 2 * time.Second
	}
	if cfg.RenewDeadline >= cfg.LeaseDuration {
		return fmt.Errorf("leader: RenewDeadline (%v) must be < LeaseDuration (%v)", cfg.RenewDeadline, cfg.LeaseDuration)
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metaObject(cfg.Namespace, cfg.LeaseName),
		Client:    cfg.Client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: cfg.Identity,
		},
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	var runErr error
	logger := cfg.Logger.With("component", "leader", "lease", cfg.LeaseName, "identity", cfg.Identity)

	le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   cfg.LeaseDuration,
		RenewDeadline:   cfg.RenewDeadline,
		RetryPeriod:     cfg.RetryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				logger.Info("acquired leadership")
				if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
					runErr = err
					logger.Error("leader run returned error", "err", err)
				}
				cancelRun()
			},
			OnStoppedLeading: func() {
				logger.Warn("lost leadership; cancelling workload")
				cancelRun()
			},
			OnNewLeader: func(id string) {
				if id != cfg.Identity {
					logger.Info("new leader elected", "leader", id)
				}
			},
		},
	})
	if err != nil {
		return fmt.Errorf("leader: build elector: %w", err)
	}

	go le.Run(runCtx)
	<-runCtx.Done()

	if runErr != nil {
		return runErr
	}
	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
