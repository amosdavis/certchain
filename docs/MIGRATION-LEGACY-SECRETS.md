# Migrating from the Legacy certd Secret Writer

certchain historically shipped two paths for getting a TLS `Secret` into a
workload's namespace:

1. **Legacy** — `certd` watched the chain and directly created/updated
   `Opaque` Secrets (`tls.crt` only) in a configured namespace, owned via
   the `certchain.io/managed-by=certd` label (see
   [`internal/k8s/secret_writer.go`](../internal/k8s/secret_writer.go)).
2. **Modern** — the [certchain cert-manager external issuer](../cmd/certchain-issuer)
   answers cert-manager `CertificateRequest` objects, letting application
   teams manage Secrets via standard cert-manager `Certificate` CRs.

Running both paths against the same namespaces causes split-brain Secret
ownership (see **CM-30** in [`spec/FAILURES.md`](../spec/FAILURES.md)).
The legacy writer is therefore **deprecated** and gated behind
`--enable-legacy-secret-writer` on `certd` (default `false`).  It will be
removed in certchain **v2**.

This document is the migration runbook.

## 1. Inventory currently-managed Secrets

Every Secret written by the legacy path carries the
`certchain.io/managed-by=certd` label.  Export the inventory from each
cluster/namespace you run `certd` in **before** flipping any flags:

```sh
kubectl -n <certd-namespace> get secrets \
  -l certchain.io/managed-by=certd \
  -o custom-columns=NAME:.metadata.name,CN:.metadata.labels.certchain\\.io/cn,CERT_ID:.metadata.labels.certchain\\.io/cert-id \
  > legacy-secrets.csv
```

Keep `legacy-secrets.csv` as the source-of-truth list of workloads that
need a replacement cert-manager `Certificate`.

## 2. Install the cert-manager external issuer

The external issuer lives under [`cmd/certchain-issuer`](../cmd/certchain-issuer).
Install the CRDs and issuer Deployment from
[`deploy/k8s/base`](../deploy/k8s/base) and confirm the controller is
healthy:

```sh
kubectl apply -k deploy/k8s/base
kubectl -n certchain-system rollout status deploy/certchain-issuer
kubectl get clusterissuers,issuers -A
```

## 3. Create cert-manager Certificate CRs per workload

For each row in `legacy-secrets.csv`, author a cert-manager `Certificate`
that points at a certchain `Issuer` / `ClusterIssuer` and writes to the
**same Secret name** the legacy writer was producing.  Reusing the name
means downstream Deployments do not need to change their `volumeMounts` or
`tls.secretName` references during cutover:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: api-example-com
  namespace: team-api
spec:
  secretName: cc-api-example-com           # matches legacy writer's name
  commonName: api.example.com
  dnsNames:
    - api.example.com
  issuerRef:
    group: certchain.io
    kind: ClusterIssuer
    name: certchain-prod
```

Apply the CRs and wait for cert-manager to populate each Secret:

```sh
kubectl get certificate -A -w
```

Verify the new Secret carries `cert-manager.io/*` annotations rather than
`certchain.io/managed-by=certd`.

## 4. Flip clients over

Because the Secret name is unchanged, no client-side change is required.
Restart (or let cert-manager's Secret-rotation trigger) each consuming
workload so it picks up the cert-manager-issued material, and confirm TLS
handshakes still succeed end-to-end.

## 5. Disable the legacy writer

Once every workload in `legacy-secrets.csv` has a green cert-manager
`Certificate` and its Pods are serving on the cert-manager-issued Secret,
turn the legacy path off (this is also the default for new deployments):

```sh
# certd Deployment args / env
--enable-legacy-secret-writer=false
# or
ENABLE_LEGACY_SECRET_WRITER=false
```

With the flag off, `certd` logs one `WARN` the first time anything would
have triggered a legacy sync and otherwise performs no Secret writes or
deletes.  The CSR watcher and chain/peer subsystems are unaffected.

## 6. (Optional) Remove the `managed-by=certd` label from retained Secrets

If you chose to keep any of the legacy Secrets in place (e.g., during a
gradual cutover), strip the ownership label so a future re-enable of the
legacy writer cannot sweep them:

```sh
kubectl -n <ns> label secret <name> certchain.io/managed-by-
```

## Rollback

If the cert-manager path fails mid-migration, re-enable the legacy writer
(`--enable-legacy-secret-writer=true`).  certd will log the deprecation
`WARN` and resume upserting/sweeping Secrets as before.  Because the
Secret names are identical between paths, rollback does not require
client-side changes.

## Removal timeline

The legacy writer is scheduled for removal in certchain **v2**.  The
`NewSecretWriter` constructor is marked `// Deprecated:` so `staticcheck`
`SA1019` flags any new caller added after this migration doc lands.
