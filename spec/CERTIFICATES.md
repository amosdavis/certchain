# certchain Certificate Lifecycle Specification

## Certificate Identity

Each certificate on certchain is identified by its **cert_id**: the SHA-256
digest of the certificate's DER-encoded bytes. This is stable across chain
nodes as long as the DER is identical (no re-encoding).

```
cert_id = SHA-256(DER bytes)
```

## On-Chain vs Off-Chain Storage

| Data                         | Location           | Reason                          |
|------------------------------|--------------------|---------------------------------|
| cert_id (SHA-256)            | On-chain           | Tamper-evident identity         |
| Common Name, SANs, validity  | On-chain           | Enables lookup without DER      |
| AppViewX cert ID             | On-chain           | Audit trail to issuing system   |
| Full DER certificate         | Off-chain (disk)   | Size: up to 4 KB per cert       |

The DER is stored at `<config-dir>/certs/<cert_id_hex>.der`. When a node
publishes a cert it saves the DER locally and pushes it to peers on request
via the `CERT_REQ` / `CERT_RESP` sync protocol message.

## TxCertPublish Payload

```json
{
  "cert_id":    "<64-char hex of SHA-256>",
  "cn":         "example.com",
  "avx_cert_id":"AVX-12345",
  "not_before": 1700000000,
  "not_after":  1731536000,
  "sans":       ["example.com", "www.example.com", "192.168.1.1"],
  "serial":     "0a1b2c3d"
}
```

### Validation Rules

- `cert_id` must be 32 non-zero bytes.
- `cn` must be non-empty.
- `not_before` must be ≤ `not_after`.
- `not_before` and `not_after` must be > 0.
- No active cert with the same `cert_id` may already exist on chain.
- `avx_cert_id` must be non-empty.
- `sans` may be empty but must not exceed 16 entries.

### Cert Status After Publish

- `not_before > block.Timestamp` → `not_yet_valid` (accepted but not usable)
- `not_after  < block.Timestamp` → `expired` (auto-revoked by daemon, see CM-02)
- Otherwise → `active`

## TxCertRevoke Payload

```json
{
  "cert_id":    "<64-char hex>",
  "reason":     1,
  "revoked_at": 1700001000
}
```

RFC 5280 reason codes:

| Code | Name                    |
|------|-------------------------|
| 0    | unspecified             |
| 1    | keyCompromise           |
| 2    | cACompromise            |
| 3    | affiliationChanged      |
| 4    | superseded              |
| 5    | cessationOfOperation    |
| 6    | certificateHold         |
| 8    | removeFromCRL           |
| 9    | privilegeWithdrawn      |
| 10   | aACompromise            |

### Validation Rules

- `cert_id` must refer to a cert that is in the `active` or `not_yet_valid`
  state. Revoking an already-revoked cert is idempotent (accepted, no-op).
- `reason` must be 0–10 (code 7 is not used per RFC 5280).
- `revoked_at` must be > 0.

### REVOKE Wins Rule

On a chain fork where both a `TxCertPublish` and a `TxCertRevoke` exist for
the same `cert_id`, the certificate is always treated as revoked after merge,
regardless of which transaction appeared first. Safety is preferred over
availability.

## TxCertRenew Payload

```json
{
  "old_cert_id": "<64-char hex>",
  "new_cert_id": "<64-char hex>"
}
```

### Validation Rules

- `old_cert_id` must refer to an active cert.
- `new_cert_id` must not be equal to `old_cert_id`.
- `new_cert_id` must not already exist on chain.
- The signing node must be the same node that originally published `old_cert_id`.

After a RENEW, the old cert moves to status `replaced` and the new cert becomes
`active`. A separate `TxCertPublish` for `new_cert_id` must appear in the same
or a prior block (the renew references an already-published new cert).

## Certificate States

```
                 TxCertPublish
                      │
             not_before check
            ┌──────────┴──────────┐
     not_yet_valid           active / expired
            │                    │
     (time passes)        TxCertRevoke or
            │              TxCertRenew
            ▼                    │
          active          revoked / replaced
```

| State          | Description                                             |
|----------------|---------------------------------------------------------|
| `not_yet_valid`| Published but `not_before > block.Timestamp`            |
| `active`       | Valid and usable                                        |
| `expired`      | `not_after < block.Timestamp`; daemon posts TxCertRevoke|
| `revoked`      | Explicitly revoked via TxCertRevoke                     |
| `replaced`     | Superseded by TxCertRenew                               |

## AppViewX REST API Integration

certd polls the AppViewX REST API at a configurable interval (default 60 s,
±10% random jitter to avoid thundering-herd).

### Endpoints Used

| Method | Path                             | Purpose               |
|--------|----------------------------------|-----------------------|
| GET    | `/avxapi/certificate`            | List active certs     |
| GET    | `/avxapi/certificate/{id}`       | Get cert metadata     |
| GET    | `/avxapi/certificate/{id}/download` | Download DER       |

Authentication: `Authorization: Bearer <api_key>` header on all requests.

### Poll Behaviour

1. Call `GET /avxapi/certificate?status=ACTIVE&type=SSL`.
2. For each returned cert whose `avx_cert_id` is not in the local published set:
   a. Download DER via `/avxapi/certificate/{id}/download`.
   b. Compute `cert_id = SHA-256(DER)`.
   c. Save DER to `<config-dir>/certs/<cert_id_hex>.der`.
   d. Build and sign a `TxCertPublish` transaction.
   e. Create a new block containing the transaction and broadcast to peers.
   f. Add `avx_cert_id` to the published set.
3. For each cert whose `avx_cert_id` is in the published set but AVX now reports
   as `REVOKED` or `EXPIRED`:
   a. Build and sign a `TxCertRevoke` transaction.
   b. Create and broadcast the block.
   c. Remove from the published set.

### Error Handling

| Error                | Action                                          |
|----------------------|-------------------------------------------------|
| HTTP 401/403         | Log error; stop polling; alert operator         |
| HTTP 429             | Respect `Retry-After` header; use jitter        |
| HTTP 5xx / timeout   | Exponential backoff starting at 5 s, cap 10 min |
| JSON parse error     | Log and skip that cert; continue                |
| DER download failure | Retry once; skip cert; try again next poll      |

## Query API Response Format

Cert metadata JSON returned by the HTTP query API:

```json
{
  "cert_id":    "a1b2c3...",
  "cn":         "example.com",
  "avx_cert_id":"AVX-12345",
  "not_before": 1700000000,
  "not_after":  1731536000,
  "sans":       ["example.com", "www.example.com"],
  "serial":     "0a1b2c3d",
  "status":     "active",
  "block_height": 42,
  "revoke_reason": null,
  "der":        "/cert/a1b2c3.../der"
}
```

The `der` field is a URL path to download the DER. If the DER is not available
locally or from any peer, `der` is `null`.
