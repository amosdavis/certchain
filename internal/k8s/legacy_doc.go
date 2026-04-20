// Package-level deprecation notice for the certd direct-write Secret path.
//
// The original certchain design had certd itself write TLS Secrets into every
// namespace that needed one (see SecretWriter in secret_writer.go).  The
// modern delivery path is the cert-manager external issuer under
// cmd/certchain-issuer, which issues Secrets on behalf of application-owned
// cert-manager Certificate custom resources.  Running both paths
// concurrently risks split-brain Secret ownership (see CM-30 in
// spec/FAILURES.md); the legacy path is therefore deprecated and kept only
// for migration and dev environments.
//
// New code MUST use the cert-manager external issuer.  See
// docs/MIGRATION-LEGACY-SECRETS.md for the migration procedure.
//
// Deprecated: the certd SecretWriter is scheduled for removal in certchain
// v2.  Gate it behind certd's --enable-legacy-secret-writer flag and migrate
// callers to the cert-manager external issuer.

package k8s

// LegacyWriterStartupWarning is the one-shot Warn message certd emits at
// startup when the legacy direct-write Secret path is enabled.  It is kept
// as an exported constant so operators can grep for it in logs and so that
// tests can assert on the exact wording.
const LegacyWriterStartupWarning = "legacy secret writer is enabled; this path is deprecated and will be removed in v2 — see docs/MIGRATION-LEGACY-SECRETS.md"

// LegacyWriterDisabledWarning is logged (once) the first time a code path
// attempts to trigger a legacy Secret sync while the feature flag is off.
// It tells the operator why Secrets are no longer being written and points
// at the migration document.
const LegacyWriterDisabledWarning = "legacy secret writer is disabled (default); direct-write Secret sync skipped — use the cert-manager external issuer, see docs/MIGRATION-LEGACY-SECRETS.md"
