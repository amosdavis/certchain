# Certificate Renewal Guide

annotation-ctrl includes a built-in **renewal scheduler** that automatically updates TLS Secrets before their certificates expire. This guide explains how renewal works, how to configure the renewal window, and how to monitor renewal status.

---

## How Renewal Works

```
┌────────────────────────────────────────────────────────────┐
│ 1. Reconciler provisions Secret                           │
│    └─> Calls scheduler.OnNearExpiry(cn)                   │
└────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────┐
│ 2. Scheduler parses tls.crt NotAfter                      │
│    └─> renewAt = NotAfter - renewBefore (default 30d)     │
└────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────┐
│ 3. Workqueue.AddAfter(secret, delay)                      │
│    └─> Secret sits in queue until renewAt                 │
└────────────────────────────────────────────────────────────┘
                           │
                           ▼ (after delay)
┌────────────────────────────────────────────────────────────┐
│ 4. Worker fetches fresh cert from certd                   │
│    └─> Updates Secret.Data[tls.crt] and Secret.Data[ca.crt]│
└────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────┐
│ 5. Emits Event on owning Pod/Service                      │
│    └─> "renewed TLS Secret 'foo' for CN=foo.example.com"  │
└────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────┐
│ 6. Re-schedules next renewal                               │
│    └─> Parses new NotAfter, adds back to workqueue        │
└────────────────────────────────────────────────────────────┘
```

### Key Points

1. **No watch on Secrets**: The scheduler does not maintain a separate watch on Secrets. Instead, the reconciler calls `scheduler.OnNearExpiry(cn)` after every successful Secret provision. The scheduler looks up all Secrets with `certchain.io/managed-by=annotation-ctrl` and `certchain.io/cn=<sanitized-cn>` and schedules renewal for each.

2. **Workqueue-based**: Renewals are scheduled using `workqueue.AddAfter(secretKey, delay)`, where `delay = NotAfter - renewBefore - now`. The workqueue wakes up the worker at the right time.

3. **Automatic rescheduling**: After a successful renewal, the scheduler parses the new cert's NotAfter and re-schedules the next renewal. This continues indefinitely as long as the annotated Pod/Service exists.

4. **Retry on failure**: If renewal fails (certd unreachable, network error, etc.), the workqueue rate-limits the retry and re-adds the Secret. The scheduler increments `certchain_annotation_renewals_total{result="error"}`.

---

## Configuring the Renewal Window

The `--renew-before` flag controls when renewal triggers:

```
--renew-before=30d
```

**Default**: `720h` (30 days)

annotation-ctrl will attempt renewal at `NotAfter - renewBefore`. For example:
- Cert issued with NotAfter = `2026-06-01 00:00:00 UTC`
- `--renew-before=30d` (default)
- Renewal triggers at `2026-05-02 00:00:00 UTC` (30 days before expiry)

### Choosing a Value

| renewBefore | Use Case |
|-------------|----------|
| **7d** | Short-lived certs (dev/test environments) |
| **30d** (default) | Production; gives 30 days to resolve transient certd outages |
| **60d** | High-security environments with 90-day cert lifetimes |

**Recommendation**: Use at least **30 days** in production. This gives you a month to:
- Recover from certd downtime
- Fix network issues between annotation-ctrl and certd
- Address RBAC or Secret write failures

**Anti-pattern**: Setting `--renew-before` too short (e.g., 1 day) means a single day of certd unavailability can cause expired certs.

---

## Metrics

annotation-ctrl exposes renewal metrics on `--metrics-addr` (default `:9880`):

```
# Total renewal attempts (success or error)
certchain_annotation_renewals_total{result="success"} 42
certchain_annotation_renewals_total{result="error"} 3

# Seconds until expiry for each Secret (updated every reconcile)
certchain_annotation_cert_expiry_seconds{namespace="default",name="certchain-foo"} 2592000  # 30 days
certchain_annotation_cert_expiry_seconds{namespace="prod",name="certchain-bar"} 604800      # 7 days
```

### Alerting

Use `certchain_annotation_cert_expiry_seconds` to alert when a cert is close to expiry and renewal has not triggered:

**Prometheus alert rule**:

```yaml
groups:
- name: certchain_annotation
  rules:
  - alert: CertchainAnnotationCertExpiringSoon
    expr: certchain_annotation_cert_expiry_seconds < 604800  # 7 days
    for: 1h
    labels:
      severity: warning
    annotations:
      summary: "certchain annotation-ctrl managed cert expiring soon"
      description: "Secret {{ $labels.namespace }}/{{ $labels.name }} expires in {{ $value | humanizeDuration }}. Check renewal scheduler."

  - alert: CertchainAnnotationRenewalFailing
    expr: rate(certchain_annotation_renewals_total{result="error"}[5m]) > 0
    for: 15m
    labels:
      severity: critical
    annotations:
      summary: "certchain annotation-ctrl renewals failing"
      description: "Renewal attempts are failing. Check certd connectivity and logs."
```

---

## Events

annotation-ctrl emits Kubernetes Events on the **owning Pod or Service** when renewal succeeds or fails:

```yaml
Reason: CertchainSecretRenewed
Type: Normal
Message: "renewed TLS Secret 'certchain-foo' for CN=foo.example.com"
```

```yaml
Reason: CertchainSecretError
Type: Warning
Message: "fetch cert for CN 'foo.example.com': certd unreachable: dial tcp 10.0.0.1:9879: i/o timeout"
```

Check with:

```bash
kubectl describe pod <name> | grep -A 5 Events
kubectl describe service <name> | grep -A 5 Events
```

---

## Renewal Behavior on Restart

When annotation-ctrl restarts:
1. All Secrets with `certchain.io/managed-by=annotation-ctrl` are re-evaluated.
2. The scheduler re-schedules renewal for each Secret based on the current NotAfter and `--renew-before`.
3. If a cert is already past its renewal window, it is queued for immediate renewal.

**No state is persisted** — the scheduler rebuilds its queue from the Kubernetes API every time it starts. This makes the scheduler stateless and resilient to crashes.

---

## Manual Renewal

If you need to force renewal immediately (e.g., after rotating the cert in certd or AppViewX):

### Option 1: Delete the Secret

```bash
kubectl delete secret certchain-foo
```

annotation-ctrl will detect the deletion via the ownerReference and re-provision the Secret on the next reconcile (triggered by the next watch event on the annotated Pod/Service or when you update the Pod/Service).

**Caveat**: Deleting the Secret may cause a brief TLS outage if your workload does not tolerate missing Secrets. Prefer Option 2 if downtime is unacceptable.

### Option 2: Update the Annotation

Add or modify a second annotation on the Pod/Service (any key/value) to trigger a reconcile:

```bash
kubectl annotate pod web-server certchain.io/force-renew="$(date +%s)" --overwrite
```

This causes a watch event, which triggers the reconciler. The reconciler fetches the latest cert from certd and updates the Secret.

**Remove the annotation afterward** to avoid confusion:

```bash
kubectl annotate pod web-server certchain.io/force-renew-
```

### Option 3: Restart annotation-ctrl

```bash
kubectl rollout restart deployment annotation-ctrl -n certchain
```

On restart, the scheduler re-evaluates all Secrets. If a cert is past its renewal window, it is renewed immediately.

---

## Renewal and Owner Deletion

When the **owner is deleted** (e.g., `kubectl delete pod web-server`), Kubernetes' garbage collector automatically deletes the Secret (because the Secret has an ownerReference to the Pod). The scheduler's workqueue will still have a pending renewal for that Secret, but when the worker attempts to fetch the Secret, it gets a 404 NotFound and logs:

```
INFO renewal scheduler: secret no longer exists, skipping renewal key=default/certchain-foo
```

No error is emitted. The workqueue entry is silently discarded.

---

## Renewal and Annotation Removal

When the **annotation is removed** (but the Pod/Service still exists), the reconciler:
1. Sweeps: deletes any Secrets with `certchain.io/managed-by=annotation-ctrl` owned by the Pod/Service
2. Emits Event: `CertchainSecretDeleted` with message "deleted TLS Secret 'certchain-foo' (annotation removed)"

The scheduler's workqueue may still have a pending renewal for that Secret. When the worker wakes up and tries to fetch the Secret, it gets a 404 NotFound and skips renewal (same as owner deletion above).

---

## Renewal and Multiple Owners

If multiple Pods/Services reference the same Secret name (via `cert-secret-name`), the Secret will have multiple ownerReferences. The scheduler treats this as a single Secret and schedules renewal once (not per owner).

When **any** owner triggers a reconcile, the reconciler fetches the latest cert and updates the Secret. The scheduler detects the update and re-schedules renewal based on the new NotAfter.

**Caveat**: If one owner is deleted but others remain, Kubernetes does not delete the Secret (because ownerReferences are still present). The scheduler continues renewing the Secret for the remaining owners.

---

## Renewal and certd Downtime

If certd is unreachable during a renewal attempt:
1. The scheduler logs: `WARN renewal failed, will retry key=default/certchain-foo err="fetch cert for CN 'foo.example.com': certd unreachable"`
2. The workqueue rate-limits the retry (exponential backoff starting at 5 ms, doubling up to 1000 seconds)
3. `certchain_annotation_renewals_total{result="error"}` is incremented
4. The scheduler continues retrying until certd is reachable or the Secret is deleted

**No Events are emitted** during retry (to avoid event spam). An Event is emitted only if the reconciler itself fails, not the scheduler.

### Graceful Degradation

If certd is down for longer than `--renew-before`, the cert will expire before renewal succeeds. To avoid this:
- Set `--renew-before` to at least **30 days** in production
- Monitor `certchain_annotation_cert_expiry_seconds` and alert when < 7 days
- Ensure certd is deployed with HA (multiple replicas, load-balanced query API)

---

## Renewal and NotAfter Changes

If certd returns a cert with a **different NotAfter** than the previous cert (e.g., certd re-fetched from AppViewX and AVX issued a new cert with a longer validity), the scheduler:
1. Updates the Secret with the new cert
2. Re-schedules renewal based on the **new NotAfter**
3. Emits Event: `CertchainSecretRenewed`

This is normal behavior — the scheduler always uses the NotAfter from the cert currently in the Secret.

---

## Scheduler Lifecycle

The renewal scheduler runs in a **goroutine** started by `main()`:

```go
go scheduler.Run(ctx, 1)  // 1 worker
```

When `ctx` is cancelled (e.g., SIGTERM, SIGINT), the scheduler:
1. Stops the workqueue (no new items are processed)
2. Workers exit their loops
3. Any in-flight HTTP requests to certd are cancelled (context cancellation propagates)

Pending workqueue items (future renewal deadlines) are **discarded**. On restart, the scheduler rebuilds the queue by re-evaluating all Secrets.

---

## Debugging Renewal Issues

### 1. Check Metrics

```bash
curl -s http://annotation-ctrl:9880/metrics | grep certchain_annotation
```

Look for:
- `certchain_annotation_cert_expiry_seconds{namespace="...",name="..."}` — Is the TTL decreasing?
- `certchain_annotation_renewals_total{result="error"}` — Are renewals failing?

### 2. Check Events

```bash
kubectl describe pod <name> | grep -A 5 Events
kubectl describe service <name> | grep -A 5 Events
```

Look for `CertchainSecretRenewed` (success) or `CertchainSecretError` (failure).

### 3. Check Logs

```bash
kubectl logs -n certchain deployment/annotation-ctrl | grep renewal
```

Look for:
- `INFO scheduled renewal key=default/certchain-foo notAfter=2026-06-01 renewAt=2026-05-02 delay=30d`
- `WARN renewal failed, will retry key=default/certchain-foo err="..."`

### 4. Verify Secret Labels

```bash
kubectl get secret certchain-foo -o yaml | grep -A 5 labels
```

Ensure:
- `certchain.io/managed-by: annotation-ctrl`
- `certchain.io/cn: <sanitized-cn>`

If these labels are missing, the Secret was not created by annotation-ctrl and will not be renewed.

### 5. Verify certd Connectivity

```bash
# Exec into annotation-ctrl pod
kubectl exec -n certchain deployment/annotation-ctrl -it -- sh

# Test certd query API
curl -H "Authorization: Bearer $TOKEN" http://certd-url:9879/cert?cn=foo.example.com
```

If this fails, check:
- certd Service DNS: `nslookup certd-url`
- NetworkPolicy egress rules (see [Troubleshooting](troubleshooting.md#networkpolicy-egress))
- Bearer token Secret (see [Troubleshooting](troubleshooting.md#bearer-token))

---

## Summary

| Aspect | Details |
|--------|---------|
| **Trigger** | Automatic at `NotAfter - renewBefore` (default 30d) |
| **Mechanism** | Workqueue with `AddAfter` |
| **Fetches from** | certd query API (`/cert?cn=<cn>`) |
| **Updates** | Secret.Data[tls.crt], Secret.Data[ca.crt] |
| **Events** | Emitted on owner (Pod/Service) |
| **Metrics** | `certchain_annotation_renewals_total`, `certchain_annotation_cert_expiry_seconds` |
| **Retry** | Exponential backoff on failure |
| **State** | Stateless; rebuilds queue from Kubernetes API on restart |

---

## Next Steps

- **[Annotations Reference](annotations.md)** — Supported annotations and semantics.
- **[Troubleshooting](troubleshooting.md)** — Common renewal issues (certd unreachable, RBAC, NetworkPolicy).
- **[Examples](examples/)** — Sample YAML for annotated Pods and Services.
