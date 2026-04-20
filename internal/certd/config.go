package certd

import (
	"flag"
	"os"
	"path/filepath"
	"time"
)

// Config holds all certd configuration loaded from flags and env vars.
type Config struct {
	ConfigDir                string
	AVXURL                   string
	AVXKey                   string
	QueryAddr                string
	MaxCerts                 int
	RenewWindow              time.Duration
	NotifyURL                string
	StaticPeers              string
	KeyVaultMap              string
	K8sEnabled               bool
	K8sNamespace             string
	K8sSecretPrefix          string
	K8sSignerName            string
	EnableLegacySecretWriter bool
	MetricsAddr              string
	ValidatorsFile           string
	PeerSecret               string
	PeerSecretFile           string
	QueryToken               string
	QueryTokenFile           string
	ChainID                  string
	AcceptLegacySigs         bool
	BatchMaxTxs              int
	BatchMaxWait             time.Duration
}

// ParseFlags parses command-line flags and environment variables
// into a Config. It does not call os.Exit; the caller must handle
// validation errors.
func ParseFlags(args []string) *Config {
	fs := flag.NewFlagSet("certd", flag.ExitOnError)

	cfg := &Config{}
	fs.StringVar(&cfg.ConfigDir, "config", defaultConfigDir(), "config directory")
	fs.StringVar(&cfg.AVXURL, "avx-url", "", "AppViewX base URL (e.g. https://avx.example.com)")
	fs.StringVar(&cfg.AVXKey, "avx-key", "", "AppViewX API key")
	fs.StringVar(&cfg.QueryAddr, "query-addr", ":9879", "HTTP query API listen address")
	fs.IntVar(&cfg.MaxCerts, "max-certs", 0, "maximum cert records (0=unlimited)")
	fs.DurationVar(&cfg.RenewWindow, "renew-window", 30*24*time.Hour, "trigger AVX proactive renewal this far before cert expiry (0=disabled)")
	fs.StringVar(&cfg.NotifyURL, "notify-url", "", "webhook URL to POST on cert renewal or revocation")
	fs.StringVar(&cfg.StaticPeers, "static-peers", "", "comma-separated host:port peers for cross-cluster sync")
	fs.StringVar(&cfg.KeyVaultMap, "key-vault-map", "", "path to JSON file mapping CNs to key vault URIs and environments")
	fs.BoolVar(&cfg.K8sEnabled, "k8s-enabled", false, "enable Kubernetes Secret and CSR integration")
	fs.StringVar(&cfg.K8sNamespace, "k8s-namespace", "", "Kubernetes namespace for Secrets (default: certchain)")
	fs.StringVar(&cfg.K8sSecretPrefix, "k8s-secret-prefix", "", "prefix for K8s Secret names (default: cc)")
	fs.StringVar(&cfg.K8sSignerName, "k8s-signer-name", "", "CSR signerName to watch (default: certchain.io/appviewx)")
	fs.BoolVar(&cfg.EnableLegacySecretWriter, "enable-legacy-secret-writer", false, "enable the deprecated certd direct-write Secret path (CM-30); the modern path is the cert-manager external issuer — see docs/MIGRATION-LEGACY-SECRETS.md")
	fs.StringVar(&cfg.MetricsAddr, "metrics-addr", ":9880", "Address for Prometheus /metrics (H3)")
	fs.StringVar(&cfg.ValidatorsFile, "validators", "", "path to validators.json allowlist (default: <config>/validators.json, CM-23)")
	fs.StringVar(&cfg.PeerSecret, "peer-secret", "", "shared cluster secret for HMAC-authenticating peer block pushes (CM-28; prefer --peer-secret-file)")
	fs.StringVar(&cfg.PeerSecretFile, "peer-secret-file", "", "path to a file whose contents are the shared cluster peer-push HMAC secret (CM-28)")
	fs.StringVar(&cfg.QueryToken, "query-token", "", "Bearer token required on HTTP query API (CM-28; prefer --query-token-file)")
	fs.StringVar(&cfg.QueryTokenFile, "query-token-file", "", "path to a file whose contents are the Bearer token required on the HTTP query API (CM-28)")

	// CM-29: domain-separated signing
	const defaultChainID = "certchain-v1"
	fs.StringVar(&cfg.ChainID, "chain-id", defaultChainID, "chainID mixed into the signature domain separator (CM-29); must match across all peers in a network")
	fs.BoolVar(&cfg.AcceptLegacySigs, "accept-legacy-sigs", true, "accept signatures in the pre-CM-29 no-domain-separator format; flip to false once all peers have re-signed (CM-29)")

	// CM-32: batching
	const (
		defaultBatchMaxTxs  = 100
		defaultBatchMaxWait = 5 * time.Second
	)
	fs.IntVar(&cfg.BatchMaxTxs, "batch-max-txs", defaultBatchMaxTxs, "maximum transactions committed in a single block by the chain.Batcher (CM-32)")
	fs.DurationVar(&cfg.BatchMaxWait, "batch-max-wait", defaultBatchMaxWait, "maximum time the chain.Batcher will hold a partial batch before committing (CM-32)")

	_ = fs.Parse(args)

	// Allow env-var overrides so k8s ConfigMaps/Secrets can drive configuration
	// without needing a shell to build the args list.
	if cfg.AVXURL == "" {
		cfg.AVXURL = os.Getenv("AVX_URL")
	}
	if cfg.AVXKey == "" {
		cfg.AVXKey = os.Getenv("AVX_KEY")
	}
	if cfg.NotifyURL == "" {
		cfg.NotifyURL = os.Getenv("NOTIFY_URL")
	}
	if cfg.StaticPeers == "" {
		cfg.StaticPeers = os.Getenv("STATIC_PEERS")
	}
	if !cfg.K8sEnabled {
		v := os.Getenv("K8S_ENABLED")
		cfg.K8sEnabled = v == "true" || v == "1"
	}
	if cfg.K8sNamespace == "" {
		cfg.K8sNamespace = os.Getenv("K8S_NAMESPACE")
	}
	if cfg.K8sSecretPrefix == "" {
		cfg.K8sSecretPrefix = os.Getenv("K8S_SECRET_PREFIX")
	}
	if cfg.K8sSignerName == "" {
		cfg.K8sSignerName = os.Getenv("K8S_SIGNER_NAME")
	}
	if !cfg.EnableLegacySecretWriter {
		v := os.Getenv("ENABLE_LEGACY_SECRET_WRITER")
		cfg.EnableLegacySecretWriter = v == "true" || v == "1"
	}

	// Apply built-in defaults after env-var resolution.
	if cfg.K8sNamespace == "" {
		cfg.K8sNamespace = "certchain"
	}
	if cfg.K8sSecretPrefix == "" {
		cfg.K8sSecretPrefix = "cc"
	}
	if cfg.K8sSignerName == "" {
		cfg.K8sSignerName = "certchain.io/appviewx"
	}

	return cfg
}

func defaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".certchain"
	}
	return filepath.Join(home, ".certchain")
}
