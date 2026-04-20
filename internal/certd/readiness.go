package certd

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

// Readiness tracks the /readyz signals for certd (CM-27). Only the
// owning subsystem moves each flag forward (false -> true).
//
// Today certd does not run leader election, so leaderElectionEnabled is
// false and the leader signal is reported as "disabled" and does not gate
// readiness. When leader election is added, set leaderElectionEnabled
// true at startup and call SetLeader(true) inside the OnStartedLeading
// callback.
type Readiness struct {
	chainLoaded           atomic.Bool
	leaderAcquired        atomic.Bool
	leaderElectionEnabled atomic.Bool
}

// NewReadiness creates a new Readiness tracker with all signals unset.
func NewReadiness() *Readiness { return &Readiness{} }

// SetChainLoaded marks the chain-loaded signal as satisfied.
func (r *Readiness) SetChainLoaded(v bool) { r.chainLoaded.Store(v) }

// SetLeader marks the leader-acquired signal as satisfied.
func (r *Readiness) SetLeader(v bool) { r.leaderAcquired.Store(v) }

// EnableLeader enables the leader-election check in the readiness probe.
func (r *Readiness) EnableLeader(v bool) { r.leaderElectionEnabled.Store(v) }

// Snapshot returns the per-signal human strings plus an overall ready bit.
// It performs only atomic reads and never blocks.
func (r *Readiness) Snapshot() (leader, chainStr string, ok bool) {
	chainOK := r.chainLoaded.Load()
	chainStr = "loading"
	if chainOK {
		chainStr = "loaded"
	}

	leaderOK := true
	if r.leaderElectionEnabled.Load() {
		leaderOK = r.leaderAcquired.Load()
		leader = "not_acquired"
		if leaderOK {
			leader = "ok"
		}
	} else {
		leader = "disabled"
	}

	ok = chainOK && leaderOK
	return
}

// ServeReadyz handles /readyz. It performs only atomic reads so it responds
// in well under the 50 ms probe budget (CM-27).
func (r *Readiness) ServeReadyz(w http.ResponseWriter, _ *http.Request) {
	leader, chainStr, ok := r.Snapshot()
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"leader": leader,
		"chain":  chainStr,
	})
}
