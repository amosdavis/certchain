# annotation-ctrl: Native Annotation-Driven TLS Secret Delivery

`annotation-ctrl` is certchain's lightweight, annotation-driven TLS Secret controller. It watches Pods and Services in Kubernetes for the `certchain.io/cert-cn` annotation, fetches the certificate material from certd's HTTP query API, and provisions a `kubernetes.io/tls` Secret in the same namespace — all without requiring cert-manager CRDs or CertificateRequest objects.

This is an alternative to the [cert-manager external issuer path](../ARCHITECTURE.md) (`certchain-issuer`). Choose whichever fits your workflow; the two must not be used for the same Secret (see [CM-30](../../spec/FAILURES.md#cm-30) and [CM-33](../../spec/FAILURES.md#cm-33)).

---

## When to Use annotation-ctrl

| Use annotation-ctrl when… | Use certchain-issuer when… |
|---------------------------|----------------------------|
| You want simple, annotation-driven cert delivery without installing cert-manager | You already use cert-manager and want to integrate certchain as an Issuer |
| Your workloads are plain Pods or Services that just need a TLS Secret mounted | You need cert-manager features like automated renewal, multiple Issuers, or ACME integration |
| You prefer explicit, per-object opt-in via annotations | You want declarative `Certificate` resources managed by cert-manager |
| You run in a cluster where CRDs are restricted or discouraged | You already have cert-manager installed and configured |

Both paths source certs from the same certd query API and certchain blockchain. The main difference is UX: annotations on existing resources vs. dedicated `Certificate` objects.

---

## Quick Start

### Prerequisites
1. A running certd instance with the HTTP query API enabled (default `:9879`)
2. A Bearer token for certd's query API (see [CM-28](../../spec/FAILURES.md#cm-28))
3. Kubernetes cluster with RBAC enabled

### 1. Deploy annotation-ctrl

```bash
# Create namespace
kubectl create namespace certchain

# Create the Bearer token Secret
kubectl create secret generic annotation-ctrl-token \
  --namespace=certchain \
  --from-literal=token=YOUR_BEARER_TOKEN_HERE

# Deploy annotation-ctrl and supporting resources
kubectl apply -f deploy/annotation-ctrl/
```

This deploys:
- `ServiceAccount` with cluster-wide Pod/Service/Secret permissions
- `ClusterRole` + `ClusterRoleBinding` for RBAC
- `Deployment` with leader election enabled (1 replica)
- Health and metrics endpoints (`:8082/healthz`, `:9880/metrics`)

### 2. Annotate a Pod or Service

Add the `certchain.io/cert-cn` annotation to any Pod or Service:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
  namespace: default
  annotations:
    certchain.io/cert-cn: "myapp.example.com"
spec:
  containers:
  - name: app
    image: nginx:latest
    volumeMounts:
    - name: tls
      mountPath: /etc/tls
      readOnly: true
  volumes:
  - name: tls
    secret:
      secretName: certchain-myapp-example-com
```

annotation-ctrl watches this Pod, fetches the certificate for `myapp.example.com` from certd, and creates a `kubernetes.io/tls` Secret named `certchain-myapp-example-com` in the `default` namespace with an ownerReference pointing back to the Pod.

### 3. Verify

```bash
# Check that the Secret was created
kubectl get secret certchain-myapp-example-com -o yaml

# View the Event on the Pod
kubectl describe pod example-pod | grep -A 5 Events
```

You should see an Event with reason `CertchainSecretIssued`.

---

## How It Works

```
┌──────────────────┐
│  annotated Pod   │ certchain.io/cert-cn: "foo.example.com"
│  or Service      │
└──────────────────┘
         │ (watch event)
         ▼
┌──────────────────────────────────────────────────────────┐
│  annotation-ctrl                                         │
│  ├─ Controller   (watches Pods & Services)               │
│  ├─ Reconciler   (fetches cert from certd query API)     │
│  └─ Scheduler    (renews before NotAfter - 30d)          │
└──────────────────────────────────────────────────────────┘
         │ (HTTP GET /cert?cn=foo.example.com)
         ▼
┌──────────────────┐
│  certd:9879      │ Bearer-protected query API
│  query API       │
└──────────────────┘
         │ (returns CertPEM + ChainPEM)
         ▼
┌──────────────────────────────────────────────────────────┐
│  kubernetes.io/tls Secret                                │
│  name: certchain-foo-example-com                         │
│  labels:                                                 │
│    certchain.io/managed-by: annotation-ctrl              │
│    certchain.io/cn: foo-example-com                      │
│  ownerReferences: [Pod/foo-example-com]                  │
│  data:                                                   │
│    tls.crt: <PEM cert>                                   │
│    ca.crt:  <PEM chain>                                  │
│    tls.key: <placeholder>                                │
└──────────────────────────────────────────────────────────┘
```

1. **Watch**: annotation-ctrl maintains watches on all Pods and Services across the cluster (or a single namespace if `--namespace` is set).
2. **Reconcile**: When a Pod/Service with `certchain.io/cert-cn` is added or modified, the reconciler fetches the cert from certd's `/cert?cn=<value>` endpoint.
3. **Upsert Secret**: The reconciler creates (or updates) a `kubernetes.io/tls` Secret with the cert material, owned by the annotated object.
4. **Renewal**: The scheduler parses the cert's NotAfter, schedules a workqueue requeue at `NotAfter - renewBefore`, fetches fresh material, and updates the Secret.
5. **Cleanup**: When the annotation is removed, the reconciler deletes any Secrets it created for that object (scoped to `certchain.io/managed-by=annotation-ctrl` to avoid touching Secrets owned by other systems).

---

## Configuration Flags

```
--health-addr=:8082
  Liveness (/healthz) and readiness (/readyz) HTTP server address.

--metrics-addr=:9880
  Prometheus /metrics endpoint address.

--certd-url=http://certchain-query.certchain.svc.cluster.local:9879
  certd query API base URL (Bearer-protected per CM-28).

--query-token-file=/var/run/secrets/certd-token/token
  Path to file containing the Bearer token certd requires.

--query-token=""
  Bearer token (prefer --query-token-file for production).

--namespace=""
  Namespace to watch; empty = cluster-wide.

--leader-elect=true
  Enable leader election across replicas (via coordination.k8s.io/v1 Lease).

--leader-lease-name=annotation-ctrl
  Lease name for leader election.

--leader-lease-namespace=""
  Lease namespace (defaults to POD_NAMESPACE or 'certchain').

--renew-before=30d
  Renew certs this duration before NotAfter.

--reconnect-delay=5s
  Delay before reconnecting a watch after an error.

--readiness-max-staleness=60s
  Maximum age of last certd probe before /readyz returns 503.

--certd-probe-interval=15s
  Background certd reachability probe interval for /readyz.

--log-format=json
  Log format: json|text.

--log-level=info
  Log level: debug|info|warn|error.
```

---

## Cluster-Wide vs. Namespaced

By default, annotation-ctrl watches **all namespaces** (requires ClusterRole with cluster-wide `pods`, `services`, `secrets` permissions). For production multi-tenant clusters, consider:

- **Single namespace mode**: `--namespace=my-namespace` restricts the controller to one namespace. Use a Role instead of ClusterRole.
- **Multiple controllers**: Deploy separate annotation-ctrl instances per namespace with different `--namespace` flags and separate ServiceAccounts.

---

## High Availability

annotation-ctrl supports **leader election** (enabled by default). Only the leader performs reconciles and renewals; followers remain idle until they acquire the lease. Deploy with `replicas: 1` and rely on Kubernetes to reschedule on node failure, or deploy with `replicas: 2+` for faster failover.

**Warning**: If you disable leader election (`--leader-elect=false`), run **only one replica** to avoid split-brain reconciliation.

---

## Observability

### Health Endpoints
- `GET /healthz` — Always returns 200 OK if the binary is running.
- `GET /readyz` — Returns 200 OK when:
  - Leader election lease acquired (or `--leader-elect=false`)
  - Watches synced
  - certd reachable within `--readiness-max-staleness`

### Metrics
Exposed on `--metrics-addr` (default `:9880`):

```
certchain_annotation_reconciles_total
  Total reconciles (all outcomes).

certchain_annotation_errors_total
  Reconciles that returned an error (excluding not-found during initial issuance).

certchain_annotation_last_success_seconds
  Unix timestamp of the most recent successful reconcile.

certchain_annotation_renewals_total{result="success|error"}
  Total cert renewals by result.

certchain_annotation_cert_expiry_seconds{namespace,name}
  Seconds until certificate expiry for each managed Secret.
```

Use `certchain_annotation_cert_expiry_seconds` to alert when a cert is within 7 days of expiry and renewal has not triggered.

### Events
annotation-ctrl emits Kubernetes Events on the annotated Pod/Service:

| Reason | Type | Message |
|--------|------|---------|
| `CertchainSecretIssued` | Normal | "created TLS Secret "certchain-foo" for CN=foo.example.com" |
| `CertchainSecretRenewed` | Normal | "updated TLS Secret "certchain-foo" for CN=foo.example.com" |
| `CertchainSecretDeleted` | Normal | "deleted TLS Secret "certchain-foo" (annotation removed)" |
| `CertchainSecretError` | Warning | Error message (e.g., "fetch cert for CN "foo": certd unreachable") |

Check with `kubectl describe pod <name>` or `kubectl get events --namespace=<ns>`.

---

## Private Key Delivery

**Current Status**: annotation-ctrl writes a **placeholder** for `tls.key`:

```
# certchain: private key not yet provisioned (see CM-33 / native-ann-renewal)
```

**Why**: certd's query API currently returns only the public cert + chain. Production private-key delivery is handled by the [native-ann-renewal](../../spec/FAILURES.md#cm-35) task.

**Workaround**: If your workload only needs the public cert for TLS verification (e.g., validating peer certs), the Secret is usable as-is. For server-side TLS, private keys must be provisioned separately or use the cert-manager issuer path, which integrates with cert-manager's CSR flow.

---

## Next Steps

- **[Annotations Reference](annotations.md)** — Full list of supported annotations and their semantics.
- **[Renewal Guide](renewal.md)** — How automatic renewal works, configuring `--renew-before`, and monitoring renewal metrics.
- **[Troubleshooting](troubleshooting.md)** — Common issues (bearer token, RBAC, certd unreachable, CN sanitization).
- **[Examples](examples/)** — Sample YAML for Pods, Services, and Ingress referencing annotated Secrets.

---

## Comparison to cert-manager Issuer

| Feature | annotation-ctrl | certchain-issuer |
|---------|----------------|------------------|
| Requires cert-manager | ❌ No | ✅ Yes |
| CRDs required | ❌ No | ✅ Yes (cert-manager CRDs) |
| Opt-in mechanism | Annotation on Pod/Service | `Certificate` resource |
| Secret ownership | ownerReference to Pod/Service | Managed by cert-manager |
| Automatic renewal | ✅ Built-in scheduler | ✅ cert-manager handles renewal |
| Private key delivery | ⚠️ Placeholder (see native-ann-renewal) | ✅ Full CSR flow with private key |
| Use case | Lightweight, annotation-driven | Full cert-manager integration |

Both paths are supported and source certs from the same certchain blockchain.
