// Package annotation implements the annotation-driven TLS Secret
// controller ("annotation-ctrl") described in CM-33.
//
// It is an opinionated, lightweight alternative to the cert-manager
// external-issuer bridge (cmd/certchain-issuer / internal/issuer). Rather
// than requiring cert-manager CRDs and CertificateRequest objects, this
// controller watches plain Pods and Services in the cluster: when a user
// adds the annotation
//
//	certchain.io/cert-cn: <fqdn>
//
// to a Pod or Service, the reconciler fetches the certificate material
// for that CN from certd's HTTP query API (Bearer-authenticated per
// CM-28) and upserts a kubernetes.io/tls Secret in the same namespace
// whose ownerReference points back at the annotated object.
//
// The Secret is labelled
//
//	certchain.io/managed-by: annotation-ctrl
//	certchain.io/cn:        <sanitized-cn>
//
// which both scopes this controller's sweep-on-revoke logic to Secrets
// it created and prevents it from touching Secrets owned by certd's
// legacy writer (certchain.io/managed-by=certd) or by cert-manager.
// That label partition is what keeps the two-path delivery story
// unambiguous (CM-30, CM-33).
//
// Private-key delivery: certd's query API currently returns only the
// public cert + chain. Production private-key material must be
// provisioned by the "native-ann-renewal" task, which will hook in via
// the RenewalNotifier interface defined here. For now the reconciler
// writes a well-known placeholder for tls.key and leaves a TODO marker
// so callers cannot mistake the Secret for a fully-provisioned TLS
// Secret.
package annotation
