# certchain

A standalone Go blockchain application that manages TLS/SSL X.509 certificates
issued by AppViewX and makes them available to any node on the network.
Workloads on Kubernetes consume certs through a cert-manager external issuer
(`certchain-issuer`), which turns `Certificate` resources into on-chain CSRs
and writes the signed material back into Kubernetes Secrets — private keys
never leave the cluster.

certchain is independent of addrchain but shares the peer-discovery UDP port
(9876) so addrchain nodes can perform optional soft-lookup queries.

---

## Quick Start (GKE)

Get from an empty GKE cluster to a Pod mounting a certchain-issued TLS cert
in ~10 minutes: **[docs/GKE-QUICKSTART.md](docs/GKE-QUICKSTART.md)**.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the component diagram
(AVX → certd chain → certchain-issuer → cert-manager → Secret → Pod) and
trust boundaries. Sample manifests live in
[`deploy/k8s/examples/`](deploy/k8s/examples).

> **Deprecated:** certd's direct-write Secret path
> (`internal/k8s/secret_writer.go`) is superseded by the cert-manager
> external issuer above and is gated behind `--enable-legacy-secret-writer`
> (default `false`).  Running both paths concurrently risks split-brain
> Secret ownership (CM-30).  The legacy path will be removed in certchain
> v2 — see **[docs/MIGRATION-LEGACY-SECRETS.md](docs/MIGRATION-LEGACY-SECRETS.md)**
> for the migration runbook.

---

## Why a Separate Blockchain?

| Concern | Reason |
|---------|--------|
| Transaction volume | Cert renewals every 90 days generate far more transactions than address claims |
| Retention policy | Cert audit history must be kept long-term for compliance |
| Different participation | An AppViewX gateway may not be an addrchain node |
| Security isolation | A certchain key compromise does not affect address ownership |
| Independent deployment | certchain works without addrchain |

---

## Architecture

```
AppViewX REST API
        │  poll every 60 s (±10% jitter)
        ▼
┌───────────────────────────────────────────────────────┐
│  certd  (certchain daemon)                            │
│  ├─ internal/avx     AVX REST client                  │
│  ├─ internal/chain   blockchain engine                │
│  ├─ internal/cert    certificate store                │
│  ├─ internal/peer    discovery (UDP :9876 shared)     │
│  │                   sync      (TCP :9878 certchain)  │
│  └─ internal/query   HTTP query API  (:9879)          │
└───────────────────────────────────────────────────────┘
```

---

## Ports

| Port | Transport | Purpose |
|------|-----------|---------|
| 9876 | UDP | Peer discovery (shared with addrchain) |
| 9878 | TCP | certchain block sync |
| 9879 | HTTP | Query API for soft-lookup |

---

## Installation

```bash
git clone https://github.com/amosdavis/certchain
cd certchain
make build
```

Binaries are written to `bin/certd` and `bin/certctl`.

---

## Running the Daemon

```bash
certd \
  --avx-url   https://avx.example.com \
  --avx-key   <api-key> \
  --config    ~/.certchain \
  --poll      60s
```

| Flag | Default | Description |
|------|---------|-------------|
| `--avx-url` | — | AppViewX REST base URL (required) |
| `--avx-key` | — | AppViewX API key (required) |
| `--config` | `~/.certchain` | Config/data directory |
| `--poll` | `60s` | AVX poll interval (±10% jitter applied) |
| `--max-certs` | `100000` | Maximum certs in store before LRU eviction |
| `--query-addr` | `:9879` | HTTP query API listen address |
| `--sync-addr` | `:9878` | TCP sync listen address |
| `--discover-addr` | `:9876` | UDP discovery listen address |

The daemon persists the full chain to `<config>/chain.json` and DER files to
`<config>/certs/<cert_id_hex>.der`.

---

## certctl CLI

```bash
# Chain and peer status
certctl status

# List all active certificates
certctl cert list

# Get cert metadata by Common Name
certctl cert get <cn>

# Get cert metadata by cert_id (hex SHA-256 of DER)
certctl cert get-id <hex>

# Download raw DER bytes
certctl cert der <hex>

# Show on-chain status (active / revoked / replaced / not_yet_valid)
certctl cert status <cn>
```

---

## Query API

All endpoints are read-only and require no authentication.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status` | Chain height, peer count, cert count |
| GET | `/cert?cn=<hostname>` | Cert metadata JSON by Common Name |
| GET | `/cert?id=<hex>` | Cert metadata JSON by cert_id |
| GET | `/cert/<hex>/der` | Raw DER bytes (if cached locally) |
| GET | `/cert/list` | All active certs (paginated with `?offset=&limit=`) |

### Example response — `/cert?cn=example.com`

```json
{
  "cert_id": "a3b4c5...",
  "cn": "example.com",
  "sans": ["example.com", "www.example.com"],
  "not_before": 1700000000,
  "not_after": 1707776000,
  "status": "active",
  "avx_cert_id": "avx-12345",
  "serial": "0a1b2c"
}
```

---

## Transaction Types

| Type | Value | Purpose |
|------|-------|---------|
| `TxCertPublish` | 0x01 | Publish cert hash + metadata |
| `TxCertRevoke` | 0x02 | Revoke cert (RFC 5280 reason code) |
| `TxCertRenew` | 0x03 | Replace old cert_id with new cert_id |

**Lifecycle rules:**

1. A `TxCertPublish` with a `not_before` in the future is accepted and stored
   with status `not_yet_valid` until the block timestamp crosses `not_before`.
2. A `TxCertRevoke` always wins over a conflicting `TxCertPublish` in the same
   block (CM-06, safety-first).
3. A `TxCertRenew` requires the new cert to be published (via `TxCertPublish`)
   before the renew transaction; the old cert's status becomes `replaced`.

---

## Failure Modes (Tenets)

See [spec/FAILURES.md](spec/FAILURES.md) for the full table (CM-01 to CM-15).

Key guarantees:

- **CM-01**: AVX unreachable → exponential backoff with jitter; cached state used
- **CM-03**: Duplicate publish rejected; cert_id must be unique per active cert
- **CM-04**: Revoke of unknown cert_id rejected at validation
- **CM-06**: REVOKE beats PUBLISH on same-block conflict
- **CM-08**: Validity checked against block timestamp, not local clock
- **CM-09**: Daemon tracks published cert_ids; no re-publish across restarts
- **CM-15**: Deterministic genesis — all nodes start from the same block

---

## Development

```bash
# Run all tests (unit + BDD)
go test ./...

# Run only BDD scenarios
go test ./features/ -v

# Build all binaries
go build ./cmd/...
```

BDD tests use [godog](https://github.com/cucumber/godog) with Gherkin feature
files in `features/`.

---

## Repository Structure

```
certchain/
├── cmd/
│   ├── certd/main.go       daemon entry point
│   └── certctl/main.go     CLI entry point
├── internal/
│   ├── avx/                AppViewX REST client + types
│   ├── cert/               certificate store (publish/revoke/renew)
│   ├── chain/              blockchain engine (blocks, consensus, signing)
│   ├── crypto/             Ed25519 identity management
│   ├── peer/               UDP discovery + TCP block sync
│   └── query/              HTTP query API server
├── features/               Gherkin BDD scenarios + godog step definitions
├── spec/                   Protocol, certificate lifecycle, failure mode docs
├── go.mod
├── Makefile
└── README.md
```

---

## License

See repository root.
