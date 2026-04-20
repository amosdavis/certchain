# Annotations Reference

annotation-ctrl supports two annotations that control TLS Secret provisioning for Pods and Services.

---

## `certchain.io/cert-cn`

**Type**: Opt-in annotation (required)  
**Applied to**: Pod, Service  
**Value**: Fully-qualified Common Name (CN) of the certificate you want  
**Example**: `"myapp.example.com"`

### Behavior

When annotation-ctrl detects this annotation on a Pod or Service:

1. **Fetch**: Calls certd's query API: `GET /cert?cn=<value>`
2. **Create/Update Secret**: Provisions a `kubernetes.io/tls` Secret in the same namespace
3. **Ownership**: Sets an ownerReference pointing to the annotated Pod/Service
4. **Renewal**: Schedules automatic renewal at `NotAfter - renewBefore` (default 30 days)

### Removal

When you **remove** the annotation from a Pod/Service, annotation-ctrl deletes any Secrets it created for that object (scoped to `certchain.io/managed-by=annotation-ctrl` only — Secrets owned by other systems are never touched).

### Example

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web-server
  namespace: production
  annotations:
    certchain.io/cert-cn: "www.example.com"
spec:
  containers:
  - name: nginx
    image: nginx:latest
    volumeMounts:
    - name: tls
      mountPath: /etc/nginx/tls
      readOnly: true
  volumes:
  - name: tls
    secret:
      secretName: certchain-www-example-com
```

annotation-ctrl creates `production/certchain-www-example-com` with:
- `tls.crt` — PEM-encoded leaf certificate
- `ca.crt` — PEM-encoded chain (intermediate + root)
- `tls.key` — Placeholder (see [Private Key Delivery](#private-key-delivery))

---

## `certchain.io/cert-secret-name`

**Type**: Optional annotation  
**Applied to**: Pod, Service (only when `certchain.io/cert-cn` is also present)  
**Value**: Custom Secret name (DNS-1123 subdomain format)  
**Example**: `"my-custom-tls-secret"`

### Behavior

By default, annotation-ctrl generates the Secret name as `certchain-<sanitized-cn>`. Use this annotation to **override** the generated name.

### Secret Name Sanitization

When you do **not** provide `cert-secret-name`, annotation-ctrl sanitizes the CN:
1. Converts to lowercase
2. Replaces non-alphanumeric characters (except `-` and `.`) with `-`
3. Trims leading/trailing `-` and `.`
4. Truncates to 253 characters (DNS-1123 subdomain length limit)

**Examples**:
- CN `App.Example.COM` → Secret `certchain-app-example-com`
- CN `my_app-123.local` → Secret `certchain-my-app-123-local`
- CN `*.wildcard.example.com` → Secret `certchain-wildcard-example-com`

### When to Use

Use `cert-secret-name` when:
- You have existing YAML that references a specific Secret name
- You want a human-readable name instead of the sanitized CN
- You're migrating from another cert provisioning system and need to preserve Secret names

### Caveats

1. **Name collision**: If multiple Pods/Services in the same namespace specify the same `cert-secret-name`, the Secret will be updated whenever any of them reconciles. annotation-ctrl does not prevent this — it's your responsibility to ensure unique Secret names per namespace.
2. **Ownership**: annotation-ctrl will **refuse** to overwrite a Secret that exists but is not labelled `certchain.io/managed-by=annotation-ctrl`. This prevents hijacking Secrets owned by certd's legacy writer or cert-manager.

### Example

```yaml
apiVersion: v1
kind: Service
metadata:
  name: api-gateway
  namespace: default
  annotations:
    certchain.io/cert-cn: "api.internal.example.com"
    certchain.io/cert-secret-name: "api-gateway-tls"
spec:
  selector:
    app: api-gateway
  ports:
  - port: 443
    targetPort: 8443
```

annotation-ctrl creates `default/api-gateway-tls` instead of `default/certchain-api-internal-example-com`.

---

## Secret Labels

Every Secret created by annotation-ctrl carries two labels:

```yaml
metadata:
  labels:
    certchain.io/managed-by: "annotation-ctrl"
    certchain.io/cn: "<sanitized-cn>"
```

### `certchain.io/managed-by`

**Value**: `"annotation-ctrl"` (constant)

This label is the **ownership marker** that distinguishes Secrets created by annotation-ctrl from:
- Secrets created by certd's legacy writer (`managed-by=certd`)
- Secrets created by cert-manager (no `managed-by` label, or `managed-by=cert-manager`)
- Manually created Secrets (no label)

annotation-ctrl will **never** update or delete a Secret unless `managed-by=annotation-ctrl`. This prevents overlap with other systems (see [CM-30](../../spec/FAILURES.md#cm-30) and [CM-33](../../spec/FAILURES.md#cm-33)).

### `certchain.io/cn`

**Value**: Sanitized Common Name (lowercase, alphanumeric + `-` `_` `.`, max 63 chars)

This label stores the CN associated with the Secret so:
1. The renewal scheduler can find all Secrets for a given CN
2. Operators can list Secrets by CN: `kubectl get secrets -l certchain.io/cn=myapp-example-com`

**Sanitization rules**:
- Lowercase
- Strip characters not in `[A-Za-z0-9\-_.]`
- Trim leading/trailing `-`, `_`, `.`
- Truncate to 63 characters (Kubernetes label value limit)

**Examples**:
- CN `MyApp.Example.COM` → label value `myapp-example-com`
- CN `my_app-123.local` → label value `my_app-123-local`
- CN `*.wildcard.example.com` → label value `-wildcard-example-com`

---

## Owner References

Every Secret created by annotation-ctrl includes an ownerReference pointing back to the annotated Pod or Service:

```yaml
metadata:
  ownerReferences:
  - apiVersion: v1
    kind: Pod
    name: web-server
    uid: <pod-uid>
    blockOwnerDeletion: false
    controller: false
```

### Garbage Collection Behavior

When the **owner is deleted** (e.g., `kubectl delete pod web-server`), Kubernetes automatically deletes the Secret (via its garbage collector). This ensures Secrets don't accumulate for deleted workloads.

When the **annotation is removed** (but the Pod/Service still exists), annotation-ctrl explicitly deletes the Secret during the next reconcile. This is the "sweep-on-revoke" behavior scoped to Secrets with `certchain.io/managed-by=annotation-ctrl`.

### Multiple Owners

If the same Secret name is referenced by multiple Pods/Services (via `cert-secret-name`), the Secret will have multiple ownerReferences. Kubernetes will only delete the Secret when **all** owners are deleted.

---

## Private Key Delivery

**Current Status**: `tls.key` contains a placeholder:

```
# certchain: private key not yet provisioned (see CM-33 / native-ann-renewal)
```

**Why**: certd's query API currently returns only the public cert + chain. Production private-key delivery is tracked under [CM-35](../../spec/FAILURES.md#cm-35) and will be implemented via the `native-ann-renewal` task.

**Workaround**: If your workload only needs the public cert for verification (e.g., mTLS client validating server certs), the Secret is usable as-is. For server-side TLS, use the cert-manager issuer path or provision private keys separately.

---

## Supported Resources

annotation-ctrl watches:
- ✅ **Pods** (`v1/Pod`)
- ✅ **Services** (`v1/Service`)

**Not supported** (yet):
- ❌ Ingress
- ❌ Deployments / StatefulSets / DaemonSets
- ❌ Custom Resources

**Workaround**: Annotate the **Pod** directly (if using a bare Pod) or annotate the **Service** that selects the Pods. For Deployments, you can annotate the Pod template, but annotation-ctrl will reconcile for **each Pod** individually, creating separate Secrets (unless you also use `cert-secret-name` to force a shared Secret name).

---

## Namespace Isolation

annotation-ctrl provisions Secrets in the **same namespace** as the annotated Pod/Service. Cross-namespace Secret references are not supported.

If you need the same cert in multiple namespaces:
1. Annotate a Pod/Service in each namespace
2. Use `cert-secret-name` to enforce consistent Secret naming across namespaces
3. Or copy the Secret manually with `kubectl get secret -o yaml | kubectl apply -n other-namespace -f -`

---

## Annotation Syntax

Kubernetes annotation **keys** must:
- Be valid DNS subdomains (alphanumeric + `-` and `.`)
- Contain a `/` separating prefix and name
- Prefix (optional): max 253 chars
- Name: max 63 chars

Annotation **values** are opaque strings (max 256 KB). annotation-ctrl trims leading/trailing whitespace from values before processing.

**Valid**:
```yaml
certchain.io/cert-cn: "myapp.example.com"
certchain.io/cert-cn: " myapp.example.com "  # trimmed to "myapp.example.com"
```

**Invalid**:
```yaml
certchain.io/cert-cn: ""  # empty after trim → annotation absent, no-op
certchain.io/cert_cn: "myapp.example.com"  # wrong annotation key (underscore), ignored
```

---

## Summary Table

| Annotation | Required | Applied To | Value | Default Behavior |
|------------|----------|-----------|-------|-----------------|
| `certchain.io/cert-cn` | ✅ Yes | Pod, Service | Fully-qualified CN | Fetches cert, provisions Secret, schedules renewal |
| `certchain.io/cert-secret-name` | ❌ No | Pod, Service | Custom Secret name | Falls back to `certchain-<sanitized-cn>` |

| Label | Value | Purpose |
|-------|-------|---------|
| `certchain.io/managed-by` | `annotation-ctrl` | Ownership marker; prevents overlap with certd/cert-manager |
| `certchain.io/cn` | Sanitized CN (max 63 chars) | CN lookup for renewal scheduler and `kubectl` filtering |

| ownerReference | Purpose |
|----------------|---------|
| Points to annotated Pod/Service | Automatic Secret deletion when owner is deleted (Kubernetes GC) |

---

## Next Steps

- **[Renewal Guide](renewal.md)** — How automatic renewal works and how to monitor it.
- **[Troubleshooting](troubleshooting.md)** — Common issues with annotations, Secret naming, and RBAC.
- **[Examples](examples/)** — Sample YAML for annotated Pods, Services, and Ingress.
