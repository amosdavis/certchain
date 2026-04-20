// Package metrics exposes Prometheus metrics for certchain.
//
// Each subsystem creates metrics via New* helpers and registers them on the
// shared Registry. The /metrics HTTP handler is served on the admin listener
// (default :9880) by certd and certchain-issuer.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry is a thin wrapper around *prometheus.Registry that preregisters
// process and go runtime collectors. Use one Registry per binary.
type Registry struct {
	*prometheus.Registry
}

// NewRegistry creates a Registry with process + Go collectors preregistered.
func NewRegistry() *Registry {
	r := prometheus.NewRegistry()
	r.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return &Registry{Registry: r}
}

// Handler returns an http.Handler serving /metrics output from this registry.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.Registry, promhttp.HandlerOpts{Registry: r.Registry})
}

// ChainMetrics collects chain-level Prometheus metrics.
type ChainMetrics struct {
	BlockHeight         prometheus.Gauge
	BlocksAppendedTotal prometheus.Counter
	ChainReplacedTotal  prometheus.Counter
	ValidationFailTotal *prometheus.CounterVec
	SaveErrorsTotal     *prometheus.CounterVec
}

// NewChainMetrics registers and returns chain metrics.
func NewChainMetrics(r *Registry) *ChainMetrics {
	m := &ChainMetrics{
		BlockHeight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "certchain",
			Subsystem: "chain",
			Name:      "height",
			Help:      "Current chain tip index.",
		}),
		BlocksAppendedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "certchain",
			Subsystem: "chain",
			Name:      "blocks_appended_total",
			Help:      "Total blocks appended by this node.",
		}),
		ChainReplacedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "certchain",
			Subsystem: "chain",
			Name:      "replaced_total",
			Help:      "Number of times the chain was replaced by a peer's longer chain.",
		}),
		ValidationFailTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "certchain",
			Subsystem: "chain",
			Name:      "validation_fail_total",
			Help:      "Number of block validation failures, by reason.",
		}, []string{"reason"}),
		SaveErrorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "certchain",
			Subsystem: "chain",
			Name:      "save_errors_total",
			Help:      "Number of chain save/snapshot failures (CM-37), by operation.",
		}, []string{"op"}),
	}
	r.MustRegister(m.BlockHeight, m.BlocksAppendedTotal, m.ChainReplacedTotal, m.ValidationFailTotal, m.SaveErrorsTotal)
	return m
}

// NewChainLegacySigCounter registers and returns the counter that tracks
// the number of transactions that verify only under the legacy (pre-CM-29)
// signing format. Wired into the chain package via chain.WithMetrics.
func NewChainLegacySigCounter(r *Registry) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "certchain",
		Subsystem: "chain",
		Name:      "legacy_sig_count",
		Help:      "Total transactions that verified only under the legacy (pre-CM-29) no-domain-separator signing format.",
	})
	r.MustRegister(c)
	return c
}

// AVXMetrics collects AppViewX client metrics.
type AVXMetrics struct {
	RequestsTotal  *prometheus.CounterVec
	RequestSeconds *prometheus.HistogramVec
	LastSuccessTs  prometheus.Gauge
}

// NewAVXMetrics registers and returns AVX client metrics.
func NewAVXMetrics(r *Registry) *AVXMetrics {
	m := &AVXMetrics{
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "certchain",
			Subsystem: "avx",
			Name:      "requests_total",
			Help:      "Total AVX API requests by endpoint and outcome.",
		}, []string{"endpoint", "outcome"}),
		RequestSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "certchain",
			Subsystem: "avx",
			Name:      "request_seconds",
			Help:      "AVX API request latency.",
			Buckets:   prometheus.ExponentialBuckets(0.01, 2, 12),
		}, []string{"endpoint"}),
		LastSuccessTs: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "certchain",
			Subsystem: "avx",
			Name:      "last_success_timestamp_seconds",
			Help:      "Unix timestamp of last successful AVX poll.",
		}),
	}
	r.MustRegister(m.RequestsTotal, m.RequestSeconds, m.LastSuccessTs)
	return m
}

// IssuerMetrics collects cert-manager issuer controller metrics.
type IssuerMetrics struct {
	RequestsTotal       *prometheus.CounterVec
	ReconcileSecs       prometheus.Histogram
	PendingGauge        prometheus.Gauge
	WorkqueueDepth      prometheus.Gauge
	WorkqueueAdds       prometheus.Counter
	WorkqueueRetries    prometheus.Counter
	ReconcileDurationSecs prometheus.Histogram
}

// NewIssuerMetrics registers and returns issuer metrics.
func NewIssuerMetrics(r *Registry) *IssuerMetrics {
	m := &IssuerMetrics{
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "certchain",
			Subsystem: "issuer",
			Name:      "reconciles_total",
			Help:      "CertificateRequest reconcile outcomes.",
		}, []string{"outcome"}),
		ReconcileSecs: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "certchain",
			Subsystem: "issuer",
			Name:      "reconcile_seconds",
			Help:      "Time spent reconciling a CertificateRequest.",
			Buckets:   prometheus.ExponentialBuckets(0.01, 2, 10),
		}),
		PendingGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "certchain",
			Subsystem: "issuer",
			Name:      "pending_requests",
			Help:      "Current number of pending CertificateRequests observed.",
		}),
		WorkqueueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "certchain",
			Subsystem: "issuer",
			Name:      "workqueue_depth",
			Help:      "Current depth of the issuer workqueue (H5).",
		}),
		WorkqueueAdds: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "certchain",
			Subsystem: "issuer",
			Name:      "workqueue_adds_total",
			Help:      "Total number of adds to the issuer workqueue (H5).",
		}),
		WorkqueueRetries: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "certchain",
			Subsystem: "issuer",
			Name:      "workqueue_retries_total",
			Help:      "Total number of rate-limited retries on the issuer workqueue (H5).",
		}),
		ReconcileDurationSecs: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "certchain",
			Subsystem: "issuer",
			Name:      "reconcile_duration_seconds",
			Help:      "Duration of a single issuer reconcile attempt from the workqueue (H5).",
			Buckets:   prometheus.ExponentialBuckets(0.01, 2, 10),
		}),
	}
	r.MustRegister(
		m.RequestsTotal, m.ReconcileSecs, m.PendingGauge,
		m.WorkqueueDepth, m.WorkqueueAdds, m.WorkqueueRetries, m.ReconcileDurationSecs,
	)
	return m
}

// AnnotationRenewalMetrics collects annotation-ctrl renewal scheduler metrics.
type AnnotationRenewalMetrics struct {
	RenewalsTotal *prometheus.CounterVec
	CertExpiry    *prometheus.GaugeVec
}

// NewAnnotationRenewalMetrics registers renewal scheduler metrics.
func NewAnnotationRenewalMetrics(r *Registry) *AnnotationRenewalMetrics {
	m := &AnnotationRenewalMetrics{
		RenewalsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "certchain",
			Subsystem: "annotation",
			Name:      "renewals_total",
			Help:      "Total annotation-ctrl cert renewals by result (success or error).",
		}, []string{"result"}),
		CertExpiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "certchain",
			Subsystem: "annotation",
			Name:      "cert_expiry_seconds",
			Help:      "Seconds until certificate expiry for each managed secret.",
		}, []string{"namespace", "name"}),
	}
	r.MustRegister(m.RenewalsTotal, m.CertExpiry)
	return m
}
