# certchain Failure Mode Tenets (CM-01 to CM-15)

This document lists every identified failure mode for certchain. It is a
**governing design document**: no code change, configuration choice, or
architectural decision may cause any of these failures to occur. All
implementations must be reviewed against this list before merging.

---

## Category: AppViewX API Connectivity

### CM-01 — AVX API Unreachable

**Risk:** certd cannot reach the AppViewX REST API (network failure, firewall,
AVX maintenance). Certificates on chain become stale; new certs are not
published.

**Mitigation:**
- Exponential backoff starting at 5 s, doubling on each failure, capped at 10 min.
- ±10% random jitter applied to each retry interval.
- On reconnect, immediately poll for the full cert list and reconcile.
- The cert store retains the last known state; existing certs remain valid.
- Log every consecutive failure at WARN level; alert after 5 consecutive failures.

**Test:** `TestAVXUnreachableRetriesWithBackoff` in `avx/client_test.go`.

---

### CM-11 — AppViewX REST Rate Limiting

**Risk:** AVX responds with HTTP 429, blocking cert discovery for extended
periods if certd polls too aggressively.

**Mitigation:**
- Default poll interval is 60 s with ±10% jitter.
- On HTTP 429: honour `Retry-After` header if present; otherwise use current
  backoff interval.
- Poll interval is configurable via `--poll-interval` flag.

**Test:** `TestAVXRateLimit429` in `avx/client_test.go`.

---

## Category: Chain Validation

### CM-03 — Duplicate TxCertPublish for Same cert_id

**Risk:** The same cert is published twice (e.g., two certd nodes both poll AVX
and publish the same cert before syncing). Chain grows unnecessarily; lookup
ambiguity.

**Mitigation:**
- `cert-store` validation rejects any `TxCertPublish` whose `cert_id` already
  exists as an `active` or `not_yet_valid` entry.
- certd maintains an in-memory set of published `avx_cert_id`s; skips
  already-published certs on every poll.

**Test:** `TestPublishDuplicate` in `cert/store_test.go`.

---

### CM-04 — TxCertRevoke for Unknown cert_id

**Risk:** A REVOKE transaction references a cert_id that was never published.
This could cause panics or corrupt cert store state.

**Mitigation:**
- `cert-store` validation rejects `TxCertRevoke` for any cert_id not present
  in the store.
- Revoking an already-revoked cert is accepted as a no-op (idempotent).

**Test:** `TestRevokeUnknown` in `cert/store_test.go`.

---

### CM-15 — Genesis Block Mismatch Between Nodes

**Risk:** Two certchain nodes start with different genesis blocks and can never
sync (incompatible chains).

**Mitigation:**
- Genesis block is fully deterministic: fixed Index=0, Timestamp=0,
  PrevHash=0x00*32, payload="certchain-v1-genesis".
- On sync handshake, if peer genesis hash differs from local, connection is
  refused and an error is logged.
- Genesis hash is printed in `certctl status` for operator verification.

**Test:** `TestGenesisBlockDeterministic` in `chain/chain_test.go`.

---

## Category: Cert Expiry and Revocation

### CM-02 — Cert Expires Before On-Chain Renewal

**Risk:** A cert's `not_after` timestamp passes without a corresponding
`TxCertRevoke` or `TxCertRenew` on chain. Consumers receive `active` status
for an expired cert.

**Mitigation:**
- certd runs an expiry-checker goroutine every 60 s. For each cert where
  `not_after < now`, a `TxCertRevoke` (reason=cessationOfOperation) is posted.
- Cert store sets status `expired` during `ApplyBlock` when
  `not_after < block.Timestamp`, regardless of whether a REVOKE tx is present.

**Test:** `TestExpiredCertFlagged` in `cert/store_test.go`.

---

### CM-05 — TxCertPublish with Future not_before

**Risk:** A cert published before its validity window is treated as `active` and
served to consumers, causing TLS handshake failures.

**Mitigation:**
- Cert store sets status `not_yet_valid` when `not_before > block.Timestamp`.
- Query API returns `"status": "not_yet_valid"` for such certs.
- certd does not serve DER for `not_yet_valid` certs via CERT_RESP.

**Test:** `TestNotYetValid` in `cert/store_test.go`.

---

### CM-06 — Chain Fork: Conflicting PUBLISH vs REVOKE

**Risk:** A chain fork results in one branch having `TxCertPublish` and another
having `TxCertRevoke` for the same cert_id. After merge, the cert appears
`active` when it should be `revoked`.

**Mitigation:**
- `ApplyBlock` and `chain.Replace` enforce the **REVOKE-wins rule**: if a
  cert_id has any `TxCertRevoke` in the final chain (at any block height), its
  status is always `revoked`, overriding any `TxCertPublish`.
- This is re-evaluated after every `chain.Replace`.

**Test:** `TestRevokeWinsOnFork` in `cert/store_test.go`.

---

### CM-07 — AVX API Key Leaked

**Risk:** The AppViewX API key is compromised, allowing an attacker to inject
malicious revocations or publish fake certs.

**Mitigation:**
- Rotate the AVX API key immediately; update `--avx-key` on all certd nodes.
- Post `TxCertRevoke` for all certs published using the compromised key.
- API key is stored in config file with `0600` permissions; never logged.
- Use `--avx-key` flag or `CERTCHAIN_AVX_KEY` env var; never commit to source.

**Procedure:** `certctl cert revoke --all --avx-key <new_key>`

---

## Category: Cert Distribution

### CM-09 — AVX Polling Re-Publishes Already-Known Certs

**Risk:** certd polls AVX, finds certs already on chain, and posts duplicate
`TxCertPublish` transactions, bloating the chain.

**Mitigation:**
- certd maintains `publishedIDs map[string]struct{}` (keyed by `avx_cert_id`).
- On startup, rebuilds this set by replaying the cert store.
- On each poll, skips any cert whose `avx_cert_id` is in the set.

**Test:** `TestDuplicateSkipped` in `avx/client_test.go`.

---

### CM-10 — TxCertRevoke Not Propagated During Partition

**Risk:** A network partition prevents a REVOKE transaction from reaching all
peers. Partitioned nodes continue to serve a revoked cert as `active`.

**Mitigation:**
- `TxCertRevoke` takes effect locally the moment the block is applied.
- On partition reconnect, `chain.Replace` applies the longer chain, which
  includes the REVOKE. The REVOKE-wins rule ensures the cert is revoked even
  if the local chain had a conflicting state.
- Query API always reflects the current chain state.

**Test:** `TestRevokeNotPropagatedDuringPartition` in `peer/sync_test.go`.

---

### CM-12 — DER Not Available From Any Peer

**Risk:** A consumer requests a cert's DER bytes but neither the local node nor
any reachable peer has the file cached.

**Mitigation:**
- Query API returns `"der": null` and `"status": "active"` — metadata is still
  available.
- certd attempts `CERT_REQ` to all known peers before returning null.
- `certctl cert get` prints a warning: "DER not available; cert metadata only."
- The cert remains valid on-chain; only DER serving is degraded.

**Test:** `TestDERUnavailableReturnsNull` in `query/server_test.go`.

---

## Category: Storage

### CM-08 — Clock Skew: Validity Differs Across Nodes

**Risk:** `not_before`/`not_after` validation produces different results on
different nodes because each uses its local clock, causing split-brain cert
status.

**Mitigation:**
- Cert status is always evaluated against the **block's `Timestamp`**, not the
  local wall clock.
- Local clock is used only for deciding when to poll AVX and when to post expiry
  revocations (CM-02), which is safe: worst case is a delayed revocation post.

**Test:** `TestClockSkewUsesBlockTimestamp` in `cert/store_test.go`.

---

### CM-13 — Cert Store Grows Unbounded

**Risk:** Over time, revoked and replaced certs accumulate in the store. Memory
and disk usage grow without bound.

**Mitigation:**
- `max_certs` configuration (default 10,000). When exceeded, LRU eviction
  removes the oldest `revoked` or `replaced` records first. Active certs are
  never evicted.
- DER files for revoked/replaced certs are deleted from disk after 90 days.
- `certctl status` shows current cert count and max.

**Test:** `TestMaxCertsEviction` in `cert/store_test.go`.

---

### CM-14 — addrchain Soft-Lookup Times Out

**Risk:** An addrchain node queries certchain's HTTP query API but certchain is
slow or unreachable, hanging the addrchain operation.

**Mitigation:**
- HTTP query API enforces a 10 s request timeout; requests exceeding this are
  cancelled with 503.
- addrchain consumers must set their own HTTP client timeout (recommended: 5 s).
- certchain is purely optional for addrchain; a timeout must not block address
  management operations.

**Test:** `TestQueryAPITimeout` in `query/server_test.go`.
