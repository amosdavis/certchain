# Pod with Annotation Example

This example shows a standalone Pod annotated with `certchain.io/cert-cn`. annotation-ctrl provisions a TLS Secret and the Pod mounts it.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-with-tls
  namespace: default
  annotations:
    # Request a TLS cert for this CN from certd
    certchain.io/cert-cn: "nginx.example.com"
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx:1.25-alpine
    ports:
    - containerPort: 443
      name: https
    volumeMounts:
    - name: tls
      mountPath: /etc/nginx/tls
      readOnly: true
    - name: nginx-config
      mountPath: /etc/nginx/conf.d
      readOnly: true
  volumes:
  # Mount the TLS Secret created by annotation-ctrl
  - name: tls
    secret:
      secretName: certchain-nginx-example-com  # Auto-generated name
  # nginx config that uses the TLS cert
  - name: nginx-config
    configMap:
      name: nginx-tls-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-tls-config
  namespace: default
data:
  default.conf: |
    server {
      listen 443 ssl;
      server_name nginx.example.com;

      ssl_certificate     /etc/nginx/tls/tls.crt;
      ssl_certificate_key /etc/nginx/tls/tls.key;  # Note: currently a placeholder (see docs)
      ssl_protocols       TLSv1.2 TLSv1.3;

      location / {
        root /usr/share/nginx/html;
        index index.html;
      }
    }
```

## What Happens

1. annotation-ctrl watches the Pod, sees `certchain.io/cert-cn: "nginx.example.com"`
2. Fetches the cert from certd: `GET /cert?cn=nginx.example.com`
3. Creates Secret `default/certchain-nginx-example-com` with:
   - `tls.crt` — PEM cert
   - `ca.crt` — PEM chain
   - `tls.key` — Placeholder
4. Sets ownerReference: the Secret is owned by the Pod
5. Emits Event on Pod: `CertchainSecretIssued`
6. Schedules renewal at `NotAfter - 30d`

## Verify

```bash
# Check that the Secret was created
kubectl get secret certchain-nginx-example-com -o yaml

# Check Events on the Pod
kubectl describe pod nginx-with-tls | grep -A 5 Events

# Check metrics
curl -s http://annotation-ctrl:9880/metrics | grep certchain_annotation
```

## Cleanup

Deleting the Pod automatically deletes the Secret (via ownerReference):

```bash
kubectl delete pod nginx-with-tls
```

## Custom Secret Name

To override the auto-generated name:

```yaml
metadata:
  annotations:
    certchain.io/cert-cn: "nginx.example.com"
    certchain.io/cert-secret-name: "nginx-tls"  # Custom name
spec:
  volumes:
  - name: tls
    secret:
      secretName: nginx-tls  # Must match cert-secret-name
```

## Multi-Container Pod

If your Pod has multiple containers that need the same cert:

```yaml
spec:
  containers:
  - name: app
    image: myapp:latest
    volumeMounts:
    - name: tls
      mountPath: /app/tls
      readOnly: true
  - name: sidecar
    image: envoy:latest
    volumeMounts:
    - name: tls
      mountPath: /etc/envoy/tls
      readOnly: true
  volumes:
  - name: tls
    secret:
      secretName: certchain-myapp-example-com
```

Both containers mount the same Secret.
