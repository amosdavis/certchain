# Service with Annotation Example

This example shows a Service annotated with `certchain.io/cert-cn`. annotation-ctrl provisions a TLS Secret owned by the Service, which all Pods selected by the Service can mount.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: api-service
  namespace: production
  annotations:
    # Request a TLS cert for the Service's external hostname
    certchain.io/cert-cn: "api.production.example.com"
    certchain.io/cert-secret-name: "api-service-tls"
  labels:
    app: api
spec:
  type: ClusterIP
  selector:
    app: api
  ports:
  - name: https
    port: 443
    targetPort: 8443
    protocol: TCP
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-deployment
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: api
        image: myorg/api-server:v1.2.3
        ports:
        - containerPort: 8443
          name: https
        env:
        - name: TLS_CERT_FILE
          value: /etc/tls/tls.crt
        - name: TLS_KEY_FILE
          value: /etc/tls/tls.key
        - name: TLS_CA_FILE
          value: /etc/tls/ca.crt
        volumeMounts:
        - name: tls
          mountPath: /etc/tls
          readOnly: true
      volumes:
      # Mount the TLS Secret created by annotation-ctrl (owned by the Service)
      - name: tls
        secret:
          secretName: api-service-tls  # Matches cert-secret-name annotation
```

## What Happens

1. annotation-ctrl watches the Service, sees `certchain.io/cert-cn: "api.production.example.com"`
2. Fetches the cert from certd: `GET /cert?cn=api.production.example.com`
3. Creates Secret `production/api-service-tls` (custom name via `cert-secret-name`) with:
   - `tls.crt` — PEM cert
   - `ca.crt` — PEM chain
   - `tls.key` — Placeholder
4. Sets ownerReference: the Secret is owned by the Service (not by individual Pods)
5. Emits Event on Service: `CertchainSecretIssued`
6. Schedules renewal at `NotAfter - 30d`

## Why Annotate the Service Instead of Pods?

| Annotate Service | Annotate Pods |
|------------------|---------------|
| ✅ One Secret for all replicas | ❌ One Secret per Pod (N Secrets for N replicas) |
| ✅ Secret survives Pod restarts | ⚠️ Secret deleted when Pod is deleted |
| ✅ Easier to manage (single annotation) | ❌ Must annotate Pod template in Deployment |
| ✅ Secret deleted only when Service is deleted | ❌ Pod churn causes Secret churn |

**Recommendation**: Annotate the **Service** when multiple Pods share the same cert. Annotate the **Pod** only when the Pod is standalone or needs a unique cert.

## Verify

```bash
# Check that the Secret was created
kubectl get secret api-service-tls -n production -o yaml

# Check Events on the Service
kubectl describe service api-service -n production | grep -A 5 Events

# Check that the Secret is owned by the Service
kubectl get secret api-service-tls -n production -o jsonpath='{.metadata.ownerReferences}' | jq
```

Expected output:

```json
[
  {
    "apiVersion": "v1",
    "kind": "Service",
    "name": "api-service",
    "uid": "...",
    "blockOwnerDeletion": false,
    "controller": false
  }
]
```

## Cleanup

Deleting the **Service** automatically deletes the Secret (via ownerReference):

```bash
kubectl delete service api-service -n production
```

Deleting the **Deployment** (or individual Pods) does **not** delete the Secret, because the Secret is owned by the Service, not the Pods.

## LoadBalancer / Ingress Integration

If your Service is exposed via LoadBalancer or Ingress:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: public-api
  namespace: production
  annotations:
    certchain.io/cert-cn: "api.example.com"
    certchain.io/cert-secret-name: "public-api-tls"
spec:
  type: LoadBalancer  # Or NodePort
  selector:
    app: api
  ports:
  - name: https
    port: 443
    targetPort: 8443
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-api-ingress
  namespace: production
spec:
  tls:
  - hosts:
    - api.example.com
    secretName: public-api-tls  # References the Secret created by annotation-ctrl
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: public-api
            port:
              number: 443
```

The Ingress controller (e.g., nginx-ingress, Traefik) will mount `public-api-tls` and use it for TLS termination.

**Note**: Some Ingress controllers require a valid `tls.key`. Since annotation-ctrl writes a placeholder, you may need to use the cert-manager issuer path instead, or provision private keys separately.

## Multiple Services, Same CN

If two Services need the same CN (e.g., blue/green deployment):

```yaml
# Blue Service
apiVersion: v1
kind: Service
metadata:
  name: api-blue
  namespace: production
  annotations:
    certchain.io/cert-cn: "api.example.com"
    certchain.io/cert-secret-name: "api-tls"  # Shared Secret name
spec:
  selector:
    app: api
    color: blue
---
# Green Service
apiVersion: v1
kind: Service
metadata:
  name: api-green
  namespace: production
  annotations:
    certchain.io/cert-cn: "api.example.com"
    certchain.io/cert-secret-name: "api-tls"  # Same Secret name
spec:
  selector:
    app: api
    color: green
```

annotation-ctrl will reconcile the **same Secret** (`production/api-tls`) for both Services. The Secret will have two ownerReferences (one for `api-blue`, one for `api-green`). Deleting either Service does not delete the Secret (because the other owner still exists).
