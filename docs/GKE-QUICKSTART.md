# GKE Quick Start

Goal: go from an empty GKE cluster to a Pod mounting a TLS cert issued by
certchain in ~10 minutes. See [ARCHITECTURE.md](ARCHITECTURE.md) for the
big picture.

## 1. Prereqs

- `gcloud` ≥ 450, authenticated (`gcloud auth login`).
- `kubectl` ≥ 1.27 with `gke-gcloud-auth-plugin`.
- A GKE cluster (Standard or Autopilot) and `kubectl` context pointed at it:
  ```bash
  gcloud container clusters get-credentials <cluster> --region <region>
  ```
- cert-manager **v1.13 or newer** installed:
  ```bash
  kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.3/cert-manager.yaml
  kubectl -n cert-manager rollout status deploy/cert-manager-webhook --timeout=120s
  ```
- An AppViewX account and API key reachable from the cluster.

## 2. Install certchain

Raw manifests:

```bash
git clone https://github.com/amosdavis/certchain && cd certchain
kubectl apply -f deploy/k8s/base/namespace.yaml
kubectl apply -f deploy/k8s/base/crds.yaml
kubectl apply -f deploy/k8s/base/
```

This creates:

- The `certchain` namespace.
- `CertchainClusterIssuer` + `CertchainIssuer` CRDs (v1alpha1, status
  subresource, `Ready`/`Age` printer columns — CM-26).
- The `certd` StatefulSet + headless/query/sync Services.
- RBAC for certd and certchain-issuer.

A Helm chart is on the roadmap; raw `kubectl apply` is the supported
install today.

## 3. Bootstrap the validator set and per-node config

certchain uses a static validator allowlist (CM-23). On every `certd`
replica, drop `validators.json` into the config dir (`/data/certchain`
by default):

```json
{
  "validators": [
    "2f1b...<hex32>",
    "9c4e...<hex32>"
  ]
}
```

Entries are the hex-encoded Ed25519 public keys of authorized block
authors. Missing file = accept-all (logs a WARN) — never run production
without it.

Edit `deploy/k8s/cluster-a/configmap.yaml` and `secret.yaml` for this
cluster's `STATIC_PEERS`, `NOTIFY_URL`, and `AVX_URL` / `AVX_KEY`, then:

```bash
kubectl apply -f deploy/k8s/cluster-a/
kubectl -n certchain rollout status statefulset/certchain --timeout=180s
```

## 4. Install the certchain-issuer

The issuer is already applied by step 2
(`deploy/k8s/base/certchain-issuer-deployment.yaml`). It runs with
2 replicas, leader-elected, and exposes `/healthz`, `/readyz`, and
`/metrics`:

```yaml
args:
  - --leader-elect=true
  - --health-addr=:8081
  - --metrics-addr=:9880
readinessProbe:
  httpGet: { path: /readyz, port: 8081 }
```

Confirm both replicas are up and exactly one is leader:

```bash
kubectl -n certchain get deploy/certchain-issuer
kubectl -n certchain get lease/certchain-issuer -o yaml | grep holderIdentity
```

## 5. Create a `CertchainClusterIssuer`

```bash
kubectl apply -f deploy/k8s/examples/clusterissuer-example.yaml
kubectl get certchainclusterissuer
# NAME          READY   AGE
# prod-issuer   True    12s
```

The `Ready` column comes from the status subresource added in M6 /
CM-26. If `Ready` stays `Unknown`, `kubectl describe
certchainclusterissuer prod-issuer` shows the reconcile reason.

See [`deploy/k8s/examples/clusterissuer-example.yaml`](../deploy/k8s/examples/clusterissuer-example.yaml).

## 6. Request a cert via cert-manager

```bash
kubectl create namespace team-a
kubectl apply -f deploy/k8s/examples/certificate-example.yaml
```

See [`deploy/k8s/examples/certificate-example.yaml`](../deploy/k8s/examples/certificate-example.yaml).
The `Certificate` references the cluster issuer and asks for
`app.example.com`. cert-manager will create a `CertificateRequest`,
which `certchain-issuer` picks up and turns into an on-chain CSR.

## 7. Mount the Secret in a Pod

```bash
kubectl apply -f deploy/k8s/examples/pod-example.yaml
```

See [`deploy/k8s/examples/pod-example.yaml`](../deploy/k8s/examples/pod-example.yaml).
The Pod mounts the `app-tls` Secret at `/tls` read-only. Renewals are
applied in place; restart or watch the mount to pick them up.

## 8. Verify

```bash
# Certificate Ready=True and not_after in the future
kubectl -n team-a get certificate app-tls
# NAME      READY   SECRET    AGE
# app-tls   True    app-tls   45s

# Issuer is healthy
kubectl get certchainclusterissuer prod-issuer
# NAME          READY   AGE
# prod-issuer   True    3m

# Inspect the cert inside the Pod
kubectl -n team-a exec -it app -- \
  openssl x509 -in /tls/tls.crt -noout -text | head -25
```

You should see `Subject: CN=app.example.com`, the SAN list from the
`Certificate`, and a validity window matching `duration`.

## 9. Troubleshooting

| Symptom | Check |
|---------|-------|
| `Certificate` stays `Ready=False` | `kubectl -n team-a describe certificate app-tls` — look at the latest `CertificateRequest` and its Events. |
| `CertchainClusterIssuer` `Ready=Unknown` | `kubectl describe certchainclusterissuer prod-issuer` — reconcile error is in the condition `message`. |
| Issuer Pod not Ready | `kubectl -n certchain exec deploy/certchain-issuer -- wget -qO- localhost:8081/readyz` — JSON body reports `leader`, `caches`, `certd` signals (CM-27). |
| certd Pod not Ready | `kubectl -n certchain exec statefulset/certchain -- wget -qO- localhost:9880/readyz` — `chain` must be `loaded`. |
| Nothing happens after `Certificate` apply | Verify `spec.signerName` on the issuer matches `--k8s-signer-name` on certd, and that certd's validator allowlist includes this node's public key. |
| Secret disappears unexpectedly | Expected on revocation (CM-25). Check `kubectl -n team-a get events --field-selector reason=CertRevoked`. |

For failure modes and design tenets see [`spec/FAILURES.md`](../spec/FAILURES.md).
