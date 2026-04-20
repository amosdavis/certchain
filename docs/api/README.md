# certchain certd Query API

HTTP API for querying certificate metadata, chain status, and retrieving DER/key material from the certchain certd daemon.

## Specification

Full OpenAPI 3.0 spec: [certd-query.openapi.yaml](./certd-query.openapi.yaml)

- Swagger UI compatible
- Validatable with `openapi-generator`
- Supports Bearer token authentication (configurable via `--query-token-file` or `CERTD_QUERY_TOKEN`)

## Authentication

Protected endpoints require a Bearer token configured at startup:

```bash
certd --query-token-file /etc/certd/query-token.secret
```

Health, readiness, and metrics endpoints are always unauthenticated for Kubernetes probes and Prometheus scrapes.

## Endpoints

### Health & Metrics (unauthenticated)

#### `GET /healthz`
Liveness probe. Returns `200 OK` when the process is alive.

```bash
curl http://localhost:9879/healthz
```

#### `GET /readyz`
Readiness probe. Returns `200 OK` when ready to serve traffic, `503` when not ready.

```bash
curl http://localhost:9879/readyz
```

Response:
```json
{
  "leader": "disabled",
  "chain": "loaded"
}
```

#### `GET /metrics`
Prometheus-format metrics (chain height, peer count, AVX counters).

```bash
curl http://localhost:9879/metrics
```

### Query API (authenticated)

All endpoints below require `Authorization: Bearer <token>`.

#### `GET /status`
Chain status: height, peer count, cert count.

```bash
curl -H "Authorization: Bearer your-token-here" \
  http://localhost:9879/status
```

Response:
```json
{
  "chain_height": 42,
  "peer_count": 3,
  "cert_count": 17
}
```

#### `GET /cert?cn=<hostname>`
Get certificate metadata by Common Name.

```bash
curl -H "Authorization: Bearer your-token-here" \
  "http://localhost:9879/cert?cn=api.example.com"
```

Response:
```json
{
  "cert_id": "a1b2c3d4e5f6...",
  "cn": "api.example.com",
  "avx_cert_id": "12345",
  "not_before": 1704067200,
  "not_after": 1735689600,
  "sans": ["api.example.com", "www.example.com"],
  "serial": "01:23:45:67:89:AB:CD:EF",
  "status": "active",
  "block_height": 15
}
```

#### `GET /cert?id=<hex>`
Get certificate metadata by cert ID (64-character hex).

```bash
curl -H "Authorization: Bearer your-token-here" \
  "http://localhost:9879/cert?id=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
```

#### `GET /cert/list?page=1&limit=50`
List active certificates with pagination.

```bash
curl -H "Authorization: Bearer your-token-here" \
  "http://localhost:9879/cert/list?page=1&limit=50"
```

Response:
```json
{
  "total": 123,
  "page": 1,
  "limit": 50,
  "certs": [
    {
      "cert_id": "a1b2c3d4e5f6...",
      "cn": "api.example.com",
      ...
    }
  ]
}
```

#### `GET /cert/<hex>/der`
Get raw DER-encoded certificate. If not cached locally, certd attempts peer fetch.

```bash
curl -H "Authorization: Bearer your-token-here" \
  http://localhost:9879/cert/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2/der \
  -o cert.der
```

Content-Type: `application/pkix-cert`

#### `GET /cert/<hex>/key`
Get PEM-encoded private key.

⚠️ **WARNING:** This endpoint serves private key material. Restrict access via NetworkPolicy in production.

```bash
curl -H "Authorization: Bearer your-token-here" \
  http://localhost:9879/cert/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2/key \
  -o cert.key
```

Content-Type: `application/x-pem-file`

## Error Responses

| Code | Meaning |
|------|---------|
| `400` | Bad request (invalid query parameter, malformed hex) |
| `401` | Missing or invalid Bearer token |
| `404` | Certificate, DER, or key not found |
| `503` | Node not ready (only `/readyz`) |

## Usage with Swagger UI

Serve the spec with Swagger UI:

```bash
docker run -p 8080:8080 \
  -e SWAGGER_JSON=/spec/certd-query.openapi.yaml \
  -v $(pwd)/docs/api:/spec \
  swaggerapi/swagger-ui
```

Open http://localhost:8080 in your browser.

## Usage with openapi-generator

Validate the spec:

```bash
openapi-generator-cli validate -i docs/api/certd-query.openapi.yaml
```

Generate a client (example: Go):

```bash
openapi-generator-cli generate \
  -i docs/api/certd-query.openapi.yaml \
  -g go \
  -o ./client
```

## Integration Examples

### cert-manager External Issuer

The [certchain-issuer](../../cmd/certchain-issuer) consumes this API to:

1. Query cert readiness: `GET /cert?cn=<hostname>`
2. Retrieve DER: `GET /cert/<id>/der`
3. Retrieve key: `GET /cert/<id>/key`

### annotation-ctrl

The annotation controller monitors certs and updates Kubernetes annotations:

1. Poll: `GET /cert/list`
2. Check expiry from `not_after` field
3. Update Pod/Ingress annotations with expiry info

## References

- Implementation: [internal/query/server.go](../../internal/query/server.go)
- Auth middleware: [internal/certd/http.go](../../internal/certd/http.go)
- Readiness probe: [internal/certd/readiness.go](../../internal/certd/readiness.go)
