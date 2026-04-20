# Ingress Referencing Annotated Secret Example

This example shows an Ingress controller (e.g., nginx-ingress, Traefik) referencing a TLS Secret provisioned by annotation-ctrl via a Service annotation.

```yaml
# Service with annotation-ctrl annotation
apiVersion: v1
kind: Service
metadata:
  name: web-frontend
  namespace: default
  annotations:
    # Request a TLS cert for the public hostname
    certchain.io/cert-cn: "www.example.com"
    certchain.io/cert-secret-name: "web-frontend-tls"
  labels:
    app: web
spec:
  type: ClusterIP
  selector:
    app: web
  ports:
  - name: http
    port: 80
    targetPort: 8080
---
# Deployment (Pods do NOT need the annotation; the Service owns the Secret)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-frontend
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:1.25-alpine
        ports:
        - containerPort: 8080
---
# Ingress referencing the Secret created by annotation-ctrl
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web-frontend-ingress
  namespace: default
  annotations:
    # Ingress controller annotations (example for nginx-ingress)
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  ingressClassName: nginx  # Or your Ingress controller class
  tls:
  - hosts:
    - www.example.com
    secretName: web-frontend-tls  # References the Secret created by annotation-ctrl
  rules:
  - host: www.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web-frontend
            port:
              number: 80
```

## What Happens

1. annotation-ctrl watches the Service, sees `certchain.io/cert-cn: "www.example.com"`
2. Fetches the cert from certd: `GET /cert?cn=www.example.com`
3. Creates Secret `default/web-frontend-tls` with:
   - `tls.crt` — PEM cert
   - `ca.crt` — PEM chain
   - `tls.key` — Placeholder
4. Sets ownerReference: the Secret is owned by the Service
5. The Ingress controller (e.g., nginx-ingress) watches Ingress resources, sees `spec.tls[].secretName: web-frontend-tls`
6. The Ingress controller mounts the Secret and uses it for TLS termination

## Private Key Limitation

**Important**: Most Ingress controllers require a valid `tls.key` for TLS termination. Since annotation-ctrl writes a **placeholder** for `tls.key` (see [Private Key Delivery](../README.md#private-key-delivery)), this setup will **not work** with standard Ingress controllers.

**Workarounds**:

1. **Use the cert-manager issuer path** (recommended):

```yaml
# Certificate resource (cert-manager generates private key)
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: web-frontend
  namespace: default
spec:
  secretName: web-frontend-tls
  issuerRef:
    name: certchain
    kind: Issuer
  dnsNames:
  - www.example.com
---
# Ingress references the same Secret (now with a real tls.key)
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web-frontend-ingress
  namespace: default
spec:
  tls:
  - hosts:
    - www.example.com
    secretName: web-frontend-tls  # cert-manager writes full TLS Secret
  rules:
  - host: www.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web-frontend
            port:
              number: 80
```

2. **Provision private keys separately**:

Use a sidecar or init container to generate the private key and patch the Secret:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secret-patcher
  namespace: default
spec:
  serviceAccountName: secret-patcher  # Needs RBAC to patch Secrets
  containers:
  - name: patcher
    image: bitnami/kubectl:latest
    command: ["/bin/sh"]
    args:
    - -c
    - |
      openssl genrsa -out /tmp/tls.key 2048
      kubectl patch secret web-frontend-tls -p "{\"data\":{\"tls.key\":\"$(base64 -w0 /tmp/tls.key)\"}}"
```

**Note**: This is a workaround until [native-ann-renewal](../../spec/FAILURES.md#cm-35) implements private-key delivery.

3. **Use annotation-ctrl for cert-only Ingress**:

If your Ingress controller supports mTLS or certificate validation (not TLS termination), you can use annotation-ctrl to provide the public cert:

```yaml
# Example: Ingress with certificate validation (not termination)
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/auth-tls-verify-client: "on"
    nginx.ingress.kubernetes.io/auth-tls-secret: "default/web-frontend-tls"  # Only ca.crt is used
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 80
```

This uses only `ca.crt` from the Secret (which annotation-ctrl does provide).

## Verify

```bash
# Check that the Secret was created
kubectl get secret web-frontend-tls -o yaml

# Check Events on the Service
kubectl describe service web-frontend | grep -A 5 Events

# Check Ingress status
kubectl get ingress web-frontend-ingress -o wide

# Test TLS (will fail if tls.key is a placeholder)
curl -v https://www.example.com
```

## Cleanup

Deleting the **Service** automatically deletes the Secret (via ownerReference):

```bash
kubectl delete service web-frontend
```

The Ingress will remain, but it will fail to load the Secret (because the Secret no longer exists).

## Multi-Host Ingress

If your Ingress serves multiple hostnames with different certs:

```yaml
# Service A
apiVersion: v1
kind: Service
metadata:
  name: web-a
  namespace: default
  annotations:
    certchain.io/cert-cn: "a.example.com"
    certchain.io/cert-secret-name: "web-a-tls"
spec:
  selector:
    app: web-a
  ports:
  - port: 80
---
# Service B
apiVersion: v1
kind: Service
metadata:
  name: web-b
  namespace: default
  annotations:
    certchain.io/cert-cn: "b.example.com"
    certchain.io/cert-secret-name: "web-b-tls"
spec:
  selector:
    app: web-b
  ports:
  - port: 80
---
# Ingress with multiple TLS entries
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: multi-host-ingress
  namespace: default
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - a.example.com
    secretName: web-a-tls
  - hosts:
    - b.example.com
    secretName: web-b-tls
  rules:
  - host: a.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web-a
            port:
              number: 80
  - host: b.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web-b
            port:
              number: 80
```

annotation-ctrl creates two Secrets (`web-a-tls`, `web-b-tls`), and the Ingress controller uses the appropriate Secret for each hostname.

## Summary

| Component | Role |
|-----------|------|
| **Service annotation** | Triggers annotation-ctrl to provision the Secret |
| **Ingress spec.tls** | Tells the Ingress controller which Secret to mount |
| **Ingress controller** | Performs TLS termination using the Secret |

**Current Limitation**: annotation-ctrl writes a placeholder for `tls.key`, so most Ingress controllers cannot use the Secret for TLS termination. Use the cert-manager issuer path for production Ingress TLS.
