# annotation-ctrl Deployment

Kubernetes manifests for the native, annotation-driven TLS Secret controller (`cmd/annotation-ctrl`). This controller watches Pods and Services for the `certchain.io/cert-cn` annotation and provisions `kubernetes.io/tls` Secrets sourced from certd's Bearer-protected query API (CM-28).

## Prerequisites

Create a Secret containing the Bearer token that certd requires on its query API (CM-28):

```bash
kubectl create secret generic annotation-ctrl-token \
  --namespace=certchain \
  --from-literal=token=YOUR_CERTD_BEARER_TOKEN
```

Replace `YOUR_CERTD_BEARER_TOKEN` with the actual token configured on certd.

## Deployment

Apply the manifests:

```bash
kubectl apply -k deploy/annotation-ctrl/
```

Dry-run validation:

```bash
kubectl apply --dry-run=client -k deploy/annotation-ctrl/
```

## Architecture

- **Replicas**: 1 (HA via leader election; workload is not HA-critical)
- **Leader election**: Enabled by default (CM-22) using coordination.k8s.io Leases
- **Security**: 
  - Pod security: `runAsNonRoot`, `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`, drop ALL capabilities (CM-31)
  - NetworkPolicy: Egress restricted to certd query service + kube-apiserver only
  - PodDisruptionBudget: `minAvailable: 0` (acceptable brief unavailability during drains)
- **Resources**: 
  - Requests: 50m CPU, 64Mi memory
  - Limits: 200m CPU, 256Mi memory

## Monitoring

- Health endpoint: `:8082/healthz` (liveness), `:8082/readyz` (readiness)
- Metrics: `:9880/metrics` (Prometheus format)

## RBAC

annotation-ctrl requires cluster-wide permissions:
- Pods/Services: GET, LIST, WATCH (to watch for annotations)
- Secrets: GET, LIST, WATCH, CREATE, UPDATE, PATCH (to provision TLS Secrets)
- Events: CREATE, PATCH (for diagnostic logging)
- Leases: GET, CREATE, UPDATE (for leader election)
