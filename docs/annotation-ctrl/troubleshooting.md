# Troubleshooting Guide

This guide covers common issues with annotation-ctrl, their symptoms, root causes, and fixes.

---

## Bearer Token Issues

### Symptom

annotation-ctrl starts but logs:

```
WARN certd query token not configured — certd is likely to reject our requests (CM-28); set --query-token-file in production
```

or:

```
WARN reconcile error ns=default name=web-server kind=Pod err="fetch cert for CN 'foo.example.com': certd status 401"
```

### Root Cause

certd's query API is Bearer-protected (see [CM-28](../../spec/FAILURES.md#cm-28)). annotation-ctrl must present a valid Bearer token in the `Authorization` header when calling `/cert?cn=<cn>`.

### Fix

1. **Create a Secret with the Bearer token**:

```bash
kubectl create secret generic annotation-ctrl-token \
  --namespace=certchain \
  --from-literal=token=YOUR_BEARER_TOKEN_HERE
```

2. **Mount the Secret in annotation-ctrl Deployment**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: annotation-ctrl
  namespace: certchain
spec:
  template:
    spec:
      containers:
      - name: annotation-ctrl
        args:
        - "--query-token-file=/var/run/secrets/certd-token/token"
        volumeMounts:
        - name: token
          mountPath: /var/run/secrets/certd-token
          readOnly: true
      volumes:
      - name: token
        secret:
          secretName: annotation-ctrl-token
```

3. **Restart annotation-ctrl**:

```bash
kubectl rollout restart deployment annotation-ctrl -n certchain
```

4. **Verify**:

```bash
kubectl logs -n certchain deployment/annotation-ctrl | grep "query token"
```

You should no longer see the warning. If you still get HTTP 401, verify:
- The token in the Secret matches the token certd expects (configured via `--query-token-file` or `--query-token` in certd)
- The Secret is mounted at the correct path (`/var/run/secrets/certd-token/token`)

---

## RBAC Permission Denied

### Symptom

annotation-ctrl logs:

```
WARN reconcile error ns=default name=web-server kind=Pod err="upsert secret default/certchain-foo: secrets is forbidden: User 'system:serviceaccount:certchain:annotation-ctrl' cannot create resource 'secrets' in API group '' in the namespace 'default'"
```

or:

```
WARN reconcile error ns=default name=web-server kind=Pod err="list managed secrets: secrets is forbidden: User 'system:serviceaccount:certchain:annotation-ctrl' cannot list resource 'secrets' in API group '' at the cluster scope"
```

### Root Cause

annotation-ctrl's ServiceAccount lacks RBAC permissions to manage Secrets. This happens when:
- The ClusterRole/ClusterRoleBinding was not applied
- The ClusterRole is missing verbs (`create`, `update`, `patch`, `list`)
- annotation-ctrl is running in a namespace-restricted environment and needs a Role instead of ClusterRole

### Fix

1. **Verify ClusterRole exists**:

```bash
kubectl get clusterrole annotation-ctrl -o yaml
```

Expected output:

```yaml
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "create", "update"]
```

2. **Verify ClusterRoleBinding**:

```bash
kubectl get clusterrolebinding annotation-ctrl -o yaml
```

Expected output:

```yaml
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: annotation-ctrl
subjects:
- kind: ServiceAccount
  name: annotation-ctrl
  namespace: certchain
```

3. **If missing, apply RBAC manifests**:

```bash
kubectl apply -f deploy/annotation-ctrl/rbac.yaml
```

4. **Restart annotation-ctrl**:

```bash
kubectl rollout restart deployment annotation-ctrl -n certchain
```

### Namespace-Scoped RBAC

If your cluster policy prohibits ClusterRole/ClusterRoleBinding, use a **Role** instead:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: annotation-ctrl
  namespace: default  # Repeat for each namespace
rules:
- apiGroups: [""]
  resources: ["pods", "services", "secrets", "events"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: annotation-ctrl
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: annotation-ctrl
subjects:
- kind: ServiceAccount
  name: annotation-ctrl
  namespace: certchain
```

Run annotation-ctrl with `--namespace=default` to restrict it to a single namespace.

---

## NetworkPolicy Egress Blocked

### Symptom

annotation-ctrl logs:

```
WARN reconcile error ns=default name=web-server kind=Pod err="fetch cert for CN 'foo.example.com': certd unreachable: dial tcp 10.0.0.1:9879: i/o timeout"
```

or `/readyz` returns 503:

```json
{"leader":"ok","caches":"synced","certd":"stale_65s"}
```

### Root Cause

A NetworkPolicy in the `certchain` namespace is blocking egress to certd's query API (port 9879).

### Fix

1. **Check for NetworkPolicy**:

```bash
kubectl get networkpolicy -n certchain
```

2. **Allow egress to certd**:

If you have a default-deny egress policy, add an exception for annotation-ctrl:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: annotation-ctrl-egress
  namespace: certchain
spec:
  podSelector:
    matchLabels:
      app: annotation-ctrl
  policyTypes:
  - Egress
  egress:
  # DNS (kube-dns / coredns)
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
  # certd query API
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: certchain
    - podSelector:
        matchLabels:
          app: certchain-query
    ports:
    - protocol: TCP
      port: 9879
  # Kubernetes API server (for watch, Secret management)
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 6443
```

3. **Apply the NetworkPolicy**:

```bash
kubectl apply -f annotation-ctrl-egress-netpol.yaml
```

4. **Verify connectivity**:

```bash
kubectl exec -n certchain deployment/annotation-ctrl -it -- sh
# Inside the pod:
curl -H "Authorization: Bearer $TOKEN" http://certchain-query.certchain.svc.cluster.local:9879/status
```

Expected: HTTP 200 OK.

---

## Secret Ownership Conflict

### Symptom

annotation-ctrl logs:

```
WARN reconcile error ns=default name=web-server kind=Pod err="upsert secret default/my-tls-secret: secret default/my-tls-secret exists but is not managed by annotation-ctrl (managed-by='certd'); refusing to overwrite"
```

### Root Cause

annotation-ctrl refuses to hijack a Secret that exists but is not labelled `certchain.io/managed-by=annotation-ctrl`. This prevents overlap with:
- certd's legacy writer (`managed-by=certd`)
- cert-manager (`managed-by=cert-manager` or no label)
- Manually created Secrets (no label)

See [CM-30](../../spec/FAILURES.md#cm-30) and [CM-33](../../spec/FAILURES.md#cm-33).

### Fix

**Option 1: Use a different Secret name**

Add `certchain.io/cert-secret-name` to the Pod/Service annotation:

```yaml
annotations:
  certchain.io/cert-cn: "foo.example.com"
  certchain.io/cert-secret-name: "my-tls-secret-v2"
```

**Option 2: Delete the existing Secret**

If the existing Secret is no longer managed by another system:

```bash
kubectl delete secret my-tls-secret -n default
```

annotation-ctrl will recreate it on the next reconcile.

**Option 3: Migrate the Secret**

Manually add the `certchain.io/managed-by=annotation-ctrl` label:

```bash
kubectl label secret my-tls-secret -n default certchain.io/managed-by=annotation-ctrl --overwrite
kubectl label secret my-tls-secret -n default certchain.io/cn=foo-example-com --overwrite
```

**Warning**: Only do this if you are **certain** no other system (certd, cert-manager) is managing the Secret. Violating the ownership partition can cause split-brain updates.

---

## CN Label Sanitization Issues

### Symptom

You annotate a Pod with `certchain.io/cert-cn: "*.example.com"` but the Secret is named `certchain--example-com` (leading `-`), and renewal fails with:

```
WARN renewal failed, will retry key=default/certchain--example-com err="secret missing CN label"
```

### Root Cause

annotation-ctrl sanitizes the CN for use in Secret names and label values:
- **Secret name**: lowercase, replace non-alphanumeric (except `-` `.`) with `-`, trim leading/trailing `-` `.`, truncate to 253 chars
- **Label value**: lowercase, replace non-alphanumeric (except `-` `_` `.`) with `-`, trim leading/trailing `-` `_` `.`, truncate to 63 chars

For CN `*.example.com`:
- Secret name: `certchain-*-example-com` → sanitized to `certchain--example-com` (asterisk replaced with `-`)
- Label value: `*-example-com` → sanitized to `example-com` (leading `-` trimmed)

If the Secret name and label value differ too much, the scheduler cannot find the Secret.

### Fix

**Option 1: Use `cert-secret-name` to force a clean name**:

```yaml
annotations:
  certchain.io/cert-cn: "*.example.com"
  certchain.io/cert-secret-name: "wildcard-example-com-tls"
```

**Option 2: Avoid special characters in CNs**

If possible, use a CN without `*` or other special characters. For wildcard certs, consider using the SAN field instead (though annotation-ctrl currently only supports CN-based lookups).

---

## Cert Not Found in certd

### Symptom

annotation-ctrl logs:

```
INFO reconcile ns=default name=web-server kind=Pod: waiting for certd to issue cert for CN=foo.example.com
```

and emits a Normal Event:

```
Reason: CertchainSecretIssued
Message: "waiting for certd to issue cert for CN=foo.example.com"
```

### Root Cause

certd's query API returned HTTP 404, meaning the cert for this CN does not exist on the certchain blockchain yet. This is **not an error** — it means:
- The cert has not been issued by AppViewX yet
- certd has not polled AppViewX since the cert was issued
- The cert is revoked and certd has removed it from its store

### Fix

1. **Verify the cert exists in AppViewX**:

Log into AppViewX and check that a certificate for `foo.example.com` exists and is active.

2. **Force certd to poll AppViewX immediately**:

```bash
# Option 1: Restart certd to trigger an immediate poll
kubectl rollout restart deployment certd -n certchain

# Option 2: Wait for the next scheduled poll (default 60s)
```

3. **Query certd directly**:

```bash
kubectl exec -n certchain deployment/annotation-ctrl -it -- sh
curl -H "Authorization: Bearer $TOKEN" http://certd-url:9879/cert?cn=foo.example.com
```

Expected:
- HTTP 404 → cert not on chain
- HTTP 200 → cert exists; annotation-ctrl should reconcile within seconds

4. **If the cert exists in certd but annotation-ctrl still logs "waiting"**:

Check for:
- Typo in the CN annotation (case-sensitive!)
- Bearer token mismatch
- Network partition between annotation-ctrl and certd

---

## Multiple Secrets for Same CN

### Symptom

You have two Pods in the same namespace, both annotated with the same CN:

```yaml
# Pod A
annotations:
  certchain.io/cert-cn: "shared.example.com"

# Pod B
annotations:
  certchain.io/cert-cn: "shared.example.com"
```

annotation-ctrl creates **two Secrets**:
- `certchain-shared-example-com` (owned by Pod A)
- `certchain-shared-example-com-<hash>` (Kubernetes appends a hash to avoid collision)

### Root Cause

Kubernetes Secret names must be unique per namespace. If two Pods in the same namespace request the same CN, annotation-ctrl tries to create two Secrets with the same name. Kubernetes detects the collision and either:
- Rejects the second create (if timing is right)
- Allows both if they have different owners (appends a hash)

### Fix

**Option 1: Use `cert-secret-name` to force a shared Secret**:

```yaml
# Pod A
annotations:
  certchain.io/cert-cn: "shared.example.com"
  certchain.io/cert-secret-name: "shared-tls"

# Pod B
annotations:
  certchain.io/cert-cn: "shared.example.com"
  certchain.io/cert-secret-name: "shared-tls"
```

annotation-ctrl will reconcile the **same Secret** for both Pods. The Secret will have two ownerReferences (one for Pod A, one for Pod B). Deleting either Pod does not delete the Secret (because the other owner still exists).

**Option 2: Annotate only one Pod**

Annotate only Pod A, and have Pod B reference the Secret created by Pod A's annotation:

```yaml
# Pod A
annotations:
  certchain.io/cert-cn: "shared.example.com"

# Pod B (no annotation)
spec:
  volumes:
  - name: tls
    secret:
      secretName: certchain-shared-example-com
```

Pod B will not own the Secret, so deleting Pod A will delete the Secret (which may break Pod B's mount).

**Option 3: Annotate a Service instead**

If Pods A and B are part of the same Service, annotate the **Service** instead:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
  annotations:
    certchain.io/cert-cn: "shared.example.com"
spec:
  selector:
    app: my-app
```

annotation-ctrl creates one Secret owned by the Service. All Pods selected by the Service can mount the Secret.

---

## Renewal Not Triggering

### Symptom

A Secret was created, but `certchain_annotation_cert_expiry_seconds` is decreasing toward zero and no renewal has occurred.

### Root Cause

Possible causes:
1. annotation-ctrl was restarted and the scheduler has not yet re-evaluated the Secret
2. The Secret is missing the `certchain.io/managed-by=annotation-ctrl` label
3. The cert's NotAfter is not parseable (malformed PEM)
4. certd is unreachable (renewal is retrying with exponential backoff)

### Fix

1. **Check Secret labels**:

```bash
kubectl get secret certchain-foo -o yaml | grep -A 5 labels
```

Ensure:
- `certchain.io/managed-by: annotation-ctrl`
- `certchain.io/cn: <sanitized-cn>`

If missing, re-annotate the Pod/Service to trigger a reconcile.

2. **Check logs**:

```bash
kubectl logs -n certchain deployment/annotation-ctrl | grep "scheduled renewal"
```

Look for:
```
INFO scheduled renewal key=default/certchain-foo notAfter=2026-06-01 renewAt=2026-05-02 delay=30d
```

If absent, the scheduler did not pick up the Secret. Restart annotation-ctrl to force re-evaluation:

```bash
kubectl rollout restart deployment annotation-ctrl -n certchain
```

3. **Check metrics**:

```bash
curl -s http://annotation-ctrl:9880/metrics | grep certchain_annotation_cert_expiry_seconds
```

If the metric is absent, the scheduler never parsed the Secret's cert. Check logs for parse errors.

4. **Check certd connectivity**:

```bash
kubectl exec -n certchain deployment/annotation-ctrl -it -- sh
curl -H "Authorization: Bearer $TOKEN" http://certd-url:9879/cert?cn=foo.example.com
```

If this fails, see [NetworkPolicy Egress Blocked](#networkpolicy-egress-blocked).

---

## Leader Election Issues

### Symptom

Multiple annotation-ctrl replicas are running, but logs show:

```
WARN leader election failed; this replica will not reconcile
```

or

```
INFO leader election: acquired lease name=annotation-ctrl
INFO leader election: lost lease name=annotation-ctrl
```

(rapid lease churn).

### Root Cause

1. **Split-brain**: Two replicas are fighting for the lease due to network partition or clock skew.
2. **Misconfigured lease**: `RenewDeadline` ≥ `LeaseDuration` causes the leader to lose the lease before it can renew.
3. **RBAC**: The ServiceAccount lacks `update` permission on `coordination.k8s.io/leases`.

### Fix

1. **Verify RBAC**:

```bash
kubectl get clusterrole annotation-ctrl -o yaml | grep -A 5 leases
```

Expected:

```yaml
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "create", "update"]
```

2. **Check lease status**:

```bash
kubectl get lease annotation-ctrl -n certchain -o yaml
```

Look for `holderIdentity` (should be one of the annotation-ctrl Pod names).

3. **Restart annotation-ctrl**:

```bash
kubectl rollout restart deployment annotation-ctrl -n certchain
```

4. **If rapid lease churn persists**:

Increase `LeaseDuration` and `RenewDeadline` (requires code change in `internal/leader`). Default values:
- `LeaseDuration: 15s`
- `RenewDeadline: 10s`

Symptoms of clock skew: lease is acquired and lost every few seconds. Fix: enable NTP on all cluster nodes.

---

## Private Key Placeholder

### Symptom

You mount the Secret but your app logs:

```
TLS handshake failed: tls: failed to find any PEM data in key input
```

or:

```
Error reading private key: unexpected format
```

### Root Cause

`tls.key` contains a **placeholder**:

```
# certchain: private key not yet provisioned (see CM-33 / native-ann-renewal)
```

certd's query API currently returns only the public cert + chain. Production private-key delivery is tracked under [CM-35](../../spec/FAILURES.md#cm-35).

### Fix

**Option 1: Use the cert-manager issuer path**

The cert-manager external issuer (`certchain-issuer`) integrates with cert-manager's CSR flow, which includes private key generation. Switch to `Certificate` resources:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: foo
  namespace: default
spec:
  secretName: foo-tls
  issuerRef:
    name: certchain
    kind: Issuer
  dnsNames:
  - foo.example.com
```

cert-manager generates the private key, submits a CSR, and writes the full TLS Secret (including `tls.key`).

**Option 2: Provision private keys separately**

If you must use annotation-ctrl, provision private keys via a separate process (e.g., a sidecar or init container that generates the key and patches the Secret).

**Option 3: Wait for native-ann-renewal**

The `native-ann-renewal` task (tracked under [CM-35](../../spec/FAILURES.md#cm-35)) will add private-key delivery to the annotation path. Check the project roadmap for status.

---

## Summary Table

| Issue | Symptom | Fix |
|-------|---------|-----|
| **Bearer token missing** | HTTP 401, "certd query token not configured" | Create Secret, mount at `--query-token-file` |
| **RBAC denied** | HTTP 403, "User cannot create secrets" | Apply ClusterRole/ClusterRoleBinding |
| **NetworkPolicy blocks egress** | "certd unreachable", `/readyz` stale | Add NetworkPolicy egress rule for port 9879 |
| **Secret ownership conflict** | "exists but is not managed by annotation-ctrl" | Use `cert-secret-name`, delete Secret, or migrate label |
| **CN sanitization** | Leading `-` in Secret name, "secret missing CN label" | Use `cert-secret-name` to override |
| **Cert not found** | "waiting for certd to issue cert" | Verify cert in AppViewX, force certd poll |
| **Multiple Secrets for same CN** | Two Secrets with hash suffix | Use `cert-secret-name` to force shared Secret |
| **Renewal not triggering** | `cert_expiry_seconds` decreasing, no renewal | Check labels, restart annotation-ctrl, verify certd connectivity |
| **Leader election churn** | "lost lease", rapid re-election | Verify RBAC, check clock skew, restart annotation-ctrl |
| **Private key placeholder** | TLS handshake failed | Use cert-manager issuer path or wait for native-ann-renewal |

---

## Next Steps

- **[Annotations Reference](annotations.md)** — Supported annotations and semantics.
- **[Renewal Guide](renewal.md)** — How renewal works and how to monitor it.
- **[Examples](examples/)** — Sample YAML for common use cases.
