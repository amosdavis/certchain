# certchain Failure Mode Tenets (CM-01 to CM-37)

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

---

## Category: Kubernetes Integration

### CM-16 — K8s API Server Unreachable

**Risk:** certd cannot reach the Kubernetes API server (network partition, API
server restart, or certificate expiry). Secret writes fail; K8s consumers cannot
obtain new TLS certificates, though existing Secrets remain valid.

**Mitigation:**
- `SecretWriter.Sync` applies exponential backoff starting at 5 s, doubling on
  each failure, capped at 10 min.
- The cert store retains the last-known state; existing Secrets already in K8s
  are unaffected.
- SecretWriter runs in a separate goroutine so API outages do not block AVX
  polling or chain sync.
- Failures are logged at WARN level.

**Test:** `TestSecretWriterAPIUnavailableRetries` in `internal/k8s/secret_writer_test.go`.

---

### CM-17 — RBAC Insufficient to Manage Secrets

**Risk:** The certd ServiceAccount lacks `get`, `create`, `update`, or `delete`
permissions on Secrets in the configured namespace. Secret writes are rejected
with HTTP 403 (Forbidden).

**Mitigation:**
- `SecretWriter.Sync` logs the permission error at ERROR level and skips the
  offending operation; certd continues running.
- Operators are alerted via log: "secret write forbidden — check RBAC; Secret not updated".
- No crash or chain data loss occurs.

**Test:** `TestSecretWriterRBACForbiddenSkips` in `internal/k8s/secret_writer_test.go`.

---

### CM-18 — K8s Headless-Service DNS Discovery Failure

**Risk:** The headless Service hostname used for K8s-native peer discovery cannot
be resolved (DNS unavailable, Service misconfigured). certd cannot find peers
inside the cluster.

**Mitigation:**
- K8s peer discovery is handled by passing the headless Service hostname to
  `--static-peers`; `StaticPeerSeeder` already resolves and refreshes DNS every
  15 s.
- After 3 consecutive DNS resolution failures, a WARN is logged.
- UDP discovery continues operating as a fallback; certd never fails due to DNS
  errors alone.

**Test:** `TestStaticPeerSeederDNSFailureFallback` in `internal/peer/discovery_test.go`.

---

### CM-19 — AVX CSR Submission Fails

**Risk:** AppViewX rejects a CSR submitted by the K8s CSR watcher (policy
violation, auth error, or AVX unreachable during CSR submission). The K8s
CertificateSigningRequest remains in Pending state indefinitely.

**Mitigation:**
- Exponential backoff retry (5 s → 10 min, same schedule as CM-01).
- After max retries, a `Failed` condition is added to the K8s CSR with a reason
  message; certd logs at ERROR level.
- The on-chain `TxCertRequest` remains as an immutable audit record (CSR hash,
  CN, and SANs are recorded at submission time).
- Operators can resubmit by deleting and recreating the K8s CSR object; the CSR
  watcher will pick it up on the next watch event.

**Test:** `TestCSRWatcherAVXSubmissionFails` in `internal/k8s/csr_watcher_test.go`.

---

## Category: cert-manager External Issuer

### CM-20 — CertificateRequest Pending Indefinitely

**Risk:** The `certchain-issuer` controller is down, crashing, or unreachable.
cert-manager `CertificateRequest` objects remain in `Pending` state indefinitely.
Apps cannot obtain new certificates or renew expiring ones.

**Mitigation:**
- Deploy `certchain-issuer` with ≥2 replicas and leader election so a single
  pod failure does not block issuance.
- Liveness probe on `:8081/healthz` restarts unresponsive pods within 30 s.
- cert-manager automatically retries `CertificateRequest` objects; once the
  issuer is restored, pending requests are processed without operator action.
- Alert when any `CertificateRequest` has been in `Pending` for > 5 minutes
  (monitor via `certmanager_certificate_ready_status` Prometheus metric).

**Test:** `TestCertificateRequestPendingWhenIssuerDown` in `features/cert_certmanager_issuer.feature`.

---

### CM-21 — Certificate Renewal Race: Expiry Before Renewal Completes

**Risk:** A certificate approaches or passes its `not_after` timestamp while
`certchain-issuer` or AVX is temporarily unavailable. cert-manager attempts
renewal before expiry but cannot complete it, leaving the app with an expired
cert.

**Mitigation:**
- Operators MUST set `renewBefore` ≥ 30 days in `Certificate` resources (see
  `deploy/k8s/base/example-certificate.yaml`). This gives a 30-day window for
  transient outages to resolve without expiry.
- certchain-issuer runs at ≥2 replicas (CM-20 HA).
- If renewal does fail past expiry, cert-manager will keep retrying. Once the
  issuer recovers, a new cert is issued immediately.
- The old (expired) Secret is NOT deleted until cert-manager successfully issues
  the replacement, preventing a TLS outage from being replaced by a missing
  Secret.

**Test:** `TestCertificateRenewalRaceExpiry` in `features/cert_certmanager_issuer.feature`.

---

## Category: High-Availability Coordination

### CM-22 — Split-Brain Reconciliation Across Replicas

**Risk:** Two or more replicas of certchain-issuer (or certd's block submitter) run
simultaneously without coordination. They may concurrently create duplicate
Kubernetes CSR objects, submit duplicate AVX requests, or produce blocks with
conflicting nonces, leading to chain rejection, duplicate cert issuance, and
operator confusion.

**Mitigation:**
- Both binaries take a `coordination.k8s.io/v1 Lease` via the shared
  `internal/leader` helper. Only the leader runs singleton workloads
  (CR reconciliation, CSR watch, block submission). Followers block until
  they acquire the lease.
- `leader-elect` is **on by default** in both binaries. Operators who
  explicitly opt out (single-replica development) receive a WARN log.
- The leader lease has `ReleaseOnCancel: true` so shutdown is immediate.
- `RenewDeadline` is strictly less than `LeaseDuration`; the helper rejects
  misconfiguration at startup.
- When a replica loses leadership its workload context is cancelled,
  preventing any continued writes after another replica becomes leader.

**Test:** `TestRunExecutesLeaderFunction` in `internal/leader/leader_test.go`;
  integration test will be added with Phase 3 (H5) when the issuer workqueue
  is wired in.

---

## Category: Chain Integrity

### CM-23 — Unauthorized Block Author

**Risk:** Any node whose Ed25519 identity key signs a valid transaction can
currently inject blocks into the chain. A compromised, rogue, or decommissioned
node can therefore publish, revoke, or renew certificates — or spam blocks —
even though operators never authorized it to act as a validator. Without an
allowlist the chain has no notion of "who is permitted to write history,"
and `Replace` will even accept a longer fork forged by an attacker-controlled
keypair.

**Mitigation:**
- `chain.ValidatorSet` is an immutable set of hex-encoded Ed25519 pubkeys
  loaded from `<config>/validators.json` (override with `--validators`).
- `chain.Chain.SetValidators` installs the set; `AddBlock` and `Replace`
  reject any transaction whose `NodePubkey` is not in the set with the
  sentinel error `chain.ErrUnauthorizedAuthor`.
- A nil `ValidatorSet` preserves the legacy accept-all behavior for
  single-node development and pre-rollout deployments; certd logs a WARN
  referencing CM-23 when `validators.json` is absent so operators notice.
- Malformed `validators.json` is fatal at startup — the daemon refuses to
  run in an ambiguous security state.
- The allowlist is consulted **before** signature verification and payload
  validation so unauthorized blocks are rejected cheaply and fail-closed.

**Test:** `TestAddBlockRejectsUnknownSigner`, `TestAddBlockAcceptsKnownSigner`,
  `TestReplaceRejectsUnauthorizedBlock`, `TestNilValidatorSetAcceptsAny`,
  `TestLoadValidatorsFromFileMissing`, `TestLoadValidatorsFromFileRoundtrip`,
  and `TestLoadValidatorsFromFileMalformed` in
  `internal/chain/validator_test.go`.

---

---

## Category: Revocation Propagation

### CM-25 — Revoked Cert Still Served

**Risk:** A certificate is revoked on-chain (TxCertRevoke applied, store marks
StatusRevoked) but the Kubernetes Secret carrying the PEM remains in the
cluster. Applications mounting the Secret continue to terminate TLS with the
revoked material, defeating the purpose of revocation.

**Mitigation:**
- `SecretWriter.Sync` treats its `records` argument as the complete
  authoritative active set. On every reconciliation pass it lists all
  Secrets in the namespace bearing the `certchain.io/managed-by=certd`
  label and deletes any whose name is not in that active set (sweep).
  Deleting an already-absent Secret is a no-op because `IsNotFound` on
  the delete call is swallowed, keeping the operation idempotent.
- For every Secret the writer actually deletes (either via the sweep or
  via per-record revoked/replaced handling), a `core/v1` Event of type
  `Normal` with reason `CertchainRevoked` is created in the namespace.
  The Event's `involvedObject` points at the Secret and the `message`
  includes both the hex `cert_id` and the `CN`, so operators and audit
  systems can trace exactly which cert was revoked.
- Secrets created by `SecretWriter` always carry
  `certchain.io/managed-by=certd` and `certchain.io/cn=<sanitized CN>`,
  so the sweep never touches resources owned by other controllers and
  always has enough context to render a meaningful Event.
- RBAC failures on list / delete / Event create are logged and skipped
  (CM-17 behaviour) so certd keeps running even when the cluster denies
  the write; the revocation is retried on the next poll.

**Test:** `TestSecretWriterRevokedSecretDeleted` in
`internal/k8s/secret_writer_test.go`; BDD scenario "Revoked cert triggers
Secret deletion and Event" in `features/cert_revoke_propagation.feature`.

---

## Category: Kubernetes CRD Hygiene

### CM-26 — CRD Without Validation Accepts Malformed Specs

**Risk:** Without a strict OpenAPI v3 schema on the `CertchainIssuer` and
`CertchainClusterIssuer` CRDs, the Kubernetes API server will accept any
shape of resource the operator `kubectl apply`s. Unknown fields
(`spec.signerNmae` typo), wrong types (`signerName: true`), or values
that violate certchain-issuer's invariants (`signerName: "foo/bar"`
without the `certchain.io/` prefix) are admitted silently. The malformed
resource then reaches the issuer controller at reconcile time where it
fails **after** cert-manager has already created a `CertificateRequest`
against it, producing a stream of noisy per-reconcile errors, a
`Pending` CertificateRequest indefinitely (interacts with CM-20), and a
bad operator experience because `kubectl apply` reported success.

**Mitigation:**
- `deploy/k8s/base/crds.yaml` pins a full `openAPIV3Schema` for every
  served version. Every object schema sets `additionalProperties: false`
  so unknown fields (typos, legacy fields from older versions) are
  rejected at admission.
- `spec.signerName` is constrained with `type: string`,
  `minLength: 14`, `maxLength: 253`, and the regex
  `^certchain\.io/[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`
  mirroring the `certchain.io/` prefix enforced by
  `internal/issuer/controller.go`'s `resolveIssuer`. Bad prefixes are
  rejected by the apiserver before cert-manager ever sees them.
- `status.conditions[].status` is pinned to the enum
  `["True", "False", "Unknown"]` and `status.conditions[].type` uses
  the standard Kubernetes condition-type regex so malformed controller
  patches cannot corrupt status.
- Each version declares the `status` subresource so controllers can
  patch status without bumping `metadata.generation` (prevents
  infinite-reconcile loops when the controller writes its own status).
- `additionalPrinterColumns` surfaces `Ready` (from
  `.status.conditions[?(@.type=="Ready")].status`) and `Age` so
  `kubectl get certchainissuers` is immediately diagnostic.
- The CRD manifest is rendered and round-tripped through
  `sigs.k8s.io/yaml` to ensure structural validity; `kubectl apply
  --dry-run=client -f deploy/k8s/base/crds.yaml` succeeds against a live
  cluster.

**Test:** `go build ./...`, `go vet ./...`, and `go test ./...`
cover the controller-side invariants (`resolveIssuer` rejects bad
`signerName` values). The CRD itself is validated by parsing
`deploy/k8s/base/crds.yaml` as YAML during review and by
`kubectl apply --dry-run=client` at deploy time.

---

## Category: Process Lifecycle

### CM-27 — Liveness/Readiness Conflated Leads to Traffic Served Before Dependencies Ready

**Risk:** A `/readyz` endpoint that returns 200 unconditionally (i.e., behaves
like `/healthz`) tells the Kubernetes kubelet and Service load-balancer that
the pod is ready to serve traffic the instant the HTTP server binds, long
before the process has finished its real startup work: leader election has
not yet acquired, informer caches are empty, the on-disk chain has not been
replayed, and dependent services (e.g., certd's query API) may be
unreachable. Clients that hit the pod in that window see timeouts, 500s,
or — worse — silently incorrect answers computed from empty state. During
rolling upgrades, Kubernetes also uses readiness to decide when the new pod
is healthy enough to terminate the old one, so conflating the two probes
can cascade into a cluster-wide outage during any routine deploy.

**Mitigation:**
- Both `certd` and `certchain-issuer` expose `/healthz` (process-up only,
  always 200) and `/readyz` (operational readiness). The two probes must
  never be aliased.
- `certchain-issuer` `/readyz` returns 200 only when (a) leader election
  has acquired the Lease or was explicitly disabled by `--leader-elect=false`,
  (b) the controller's informer setup has completed (cache-synced flag is
  set once `Controller.Run` has established its watch), and (c) the issuer
  has successfully reached `certd`'s query API at least once within the
  configured max-staleness window (default 60 s). The certd reachability
  probe runs in a 15 s-tick background goroutine that updates an atomic
  timestamp; the probe handler is a pure read of that timestamp and three
  booleans, so it never blocks on network I/O and responds in well under
  50 ms even when certd is unreachable.
- `certd` `/readyz` returns 200 only when the persisted chain state has
  been loaded from disk (and the initial peer-sync attempt has either
  completed or timed out) and — when enabled — leader election has
  acquired. Until both signals are true the endpoint returns 503.
- On a 503, both endpoints emit a compact JSON body
  `{"leader": "...", "caches": "...", "certd": "..."}` so operators can
  tell at a glance which readiness signal is failing without needing pod
  logs.
- Readiness flags are only ever flipped forward (false → true) by the
  subsystem that owns them, preventing spurious flapping when a transient
  dependency error (e.g., certd restart) recovers within the staleness
  window.

**Test:** `TestIssuerReadinessHandler` in `cmd/certchain-issuer/readyz_test.go`
and `TestCertdReadinessHandler` in `cmd/certd/readyz_test.go` each cover
the not-ready → 503 + JSON body case and the fully-ready → 200 case.

---

## Category: Supply Chain

### CM-28 — Unaudited Transitive Deps Introduce CVEs / License Violations

**Risk:** Every module in `go.mod`'s transitive closure is code we ship and
execute with the same privileges as certd and certchain-issuer. Without an
automated audit, a vulnerable version of a Kubernetes client library, a
Prometheus helper, or a deep yaml/json parser can land silently via a
routine `go get` or tidy and go unnoticed until a CVE is filed publicly —
at which point certchain nodes are already exposed. The same closure can
also pull in a module under a license incompatible with the project's
distribution terms (e.g., a surprise GPL transitive), creating a
redistribution violation that only surfaces during legal review of a
release tarball.

**Mitigation:**
- `docs/DEPENDENCIES.md` records a one-line rationale for every direct
  dependency and states the update cadence policy; adding a new direct
  dep requires updating that file in the same PR.
- `make audit` (wired into `make verify`) runs `go vet`, `go mod tidy
  -diff` (fails on drift between `go.mod`/`go.sum` and the import graph),
  `staticcheck`, and `govulncheck ./...`. It is the single command a
  developer runs to answer "are our deps clean right now?".
- `make vuln` re-runs `govulncheck` alone for fast iteration after a
  dependency bump.
- `make licenses` produces `bin/modules.txt` (raw `go list -m all`) and
  `bin/licenses.csv` (SPDX classification via `go-licenses`) so copyleft
  or unknown-license modules are visible at review time.
- The `dependency-audit` CI job runs after `build`, caches `~/go/pkg/mod`,
  executes `go mod verify`, `go mod tidy -diff`, `make audit`, and a
  standalone `govulncheck ./...` step. `govulncheck`'s default exit-on-vuln
  behavior is what fails the build; no suppression file is permitted.
- When a vuln is legitimately not reachable, it is documented under
  "Known issues" in `docs/DEPENDENCIES.md` with the `govulncheck -show
  verbose` output linked — never silently ignored.

**Test:** `make audit` on a clean checkout; the `dependency-audit` CI job
in `.github/workflows/ci.yml` asserts the same gate on every PR and push
to master.

---

## Category: Cryptographic Agility

### CM-29 — Signature Scheme Without Domain Separation Enables Cross-Protocol / Cross-Chain Reuse

**Risk:** Prior to CM-29 the transaction signature was computed directly
over the canonical transaction bytes (`sha256(type || pubkey || ts ||
nonce || payload)`) with no context tag and no chain identifier. Two
attack classes follow. First, if any other part of the system — a peer
handshake, a future block-header signature, a message-authentication
token, or a third-party tool — ever signs a byte string that happens to
collide with a valid transaction prefix, the same Ed25519 signature is
simultaneously valid in both contexts; an attacker who can influence what
a legitimate signer signs in the "other" context gets a replay-usable
transaction signature for free. Second, without a chain identifier
mixed into the signed bytes, a signature produced on one certchain
network (e.g., staging) is bit-for-bit valid on every other certchain
network that uses the same key (e.g., production, a fork, a disaster-
recovery restore, a test shard). A staging outage that leaks a signed tx
therefore directly compromises production, and a chain fork cannot
safely share keys with the parent.

**Mitigation:**
- `internal/chain/signing.go` defines a domain separator
  `SigningDomain = "certchain/v1/tx\x00"` and prepends, before each
  signature, the bytes `SigningDomain || uint8(len(chainID)) || chainID
  || <canonical tx bytes>` which are then sha256'd and signed with
  Ed25519. The length-prefixed chainID makes the encoding unambiguous
  and caps chainID at 255 bytes.
- `chain.New` accepts `WithChainID(id)` and `WithAcceptLegacySigs
  (bool)` options; `certd` exposes these as `--chain-id` (default
  `certchain-default`) and `--accept-legacy-sigs` (default `true`
  for migration). Production deployments MUST set a per-network
  `--chain-id` and SHOULD flip `--accept-legacy-sigs=false` once
  every peer has re-signed.
- Canonical tx bytes (`signingPayload` in `block.go`) are preserved
  unchanged, so on-disk block hashes, the peer wire format, and the
  query API are all backwards compatible; only the Ed25519 input
  changes.
- Because Ed25519 is EUF-CMA-secure, prepending a fixed, agreed-upon
  domain tag cannot weaken the scheme; it only shrinks the set of
  inputs an adversary can legitimately obtain a signature over.
- When `--accept-legacy-sigs=true` a verify that fails the new-domain
  check is retried against the legacy (pre-CM-29) digest; every
  successful legacy verify increments the
  `certchain_chain_legacy_sig_count` Prometheus counter and emits a
  one-shot `WARN` log, so operators can drive the counter to zero
  before turning compatibility off.

**Test:** `internal/chain/signing_test.go` covers round-trip sign/
verify under the new domain, rejection of a signature produced with a
different chainID, rejection of a tampered domain prefix, acceptance +
counter increment for a legacy-format signature when the compat flag is
on, and confirms the legacy path is not hit for a correctly-signed new
transaction.


---

## Category: Cert Delivery Path Isolation

### CM-30 — Two Cert-Delivery Paths Active Simultaneously Cause Split-Brain Secret Ownership

**Risk:** certchain supports two mechanisms for placing a TLS Secret into a
Pod's namespace: the original certd direct-write Secret writer
(`internal/k8s/secret_writer.go`, CM-16/17/25) and the modern cert-manager
external issuer (`cmd/certchain-issuer`). If both run against the same
namespaces at the same time, they can race on the same Secret name: certd
upserts PEM under its `certchain.io/managed-by=certd` label, cert-manager
then overwrites it with its own annotations, and on the next certd sweep
(CM-25) the cert-manager-owned Secret either gets deleted because its
cert-id label no longer matches or is left orphaned because the
`managed-by` label is missing. The result is an unstable Secret whose
provenance cannot be reconstructed from labels alone, Events fire from
both controllers for the same rotation, and operators cannot tell which
system they should trust in an incident.

**Mitigation:**
- The direct-write path is deprecated. `NewSecretWriter` carries a
  `// Deprecated:` doc comment so `staticcheck` SA1019 flags any new
  caller, and `internal/k8s/legacy_doc.go` states the policy at the
  package level.
- certd gates the writer behind `--enable-legacy-secret-writer` (env
  `ENABLE_LEGACY_SECRET_WRITER`), default **false**. With the flag off,
  the writer is not constructed, no sync goroutine is started, and the
  first would-be trigger logs a one-shot `WARN`
  (`LegacyWriterDisabledWarning`) pointing at
  `docs/MIGRATION-LEGACY-SECRETS.md`.
- With the flag on, certd logs a prominent startup `WARN`
  (`LegacyWriterStartupWarning`) naming the deprecation and the v2
  removal so operators cannot run the legacy path by accident.
- `docs/MIGRATION-LEGACY-SECRETS.md` documents the full migration
  procedure: inventory the `managed-by=certd` Secrets, install the
  external issuer, author cert-manager `Certificate` CRs that reuse the
  existing Secret names for drop-in cutover, restart consumers, then flip
  the flag off. A rollback path is included.
- The CSR watcher and all other K8s integration points are independent of
  the writer, so disabling the legacy path does not degrade the modern
  issuer's CSR-to-chain bridge.

**Test:** existing `internal/k8s/secret_writer_test.go` tests continue
to pass by constructing the writer directly (bypassing the flag); certd's
flag-off path is exercised by inspection of `cmd/certd/main.go`: the
`sw` variable is only constructed inside the `*enableLegacySecretWriter`
branch, and `go vet ./...` plus `go build ./...` enforce that no
other caller of `NewSecretWriter` exists outside that branch.
---

### CM-31 — Unconstrained Pod Privileges and Network Access Magnify Compromise Blast Radius

**Risk:** A certchain pod that runs as root, with a writable root filesystem,
with the full default set of Linux capabilities, or with unrestricted ingress
and egress, turns any single-container compromise (supply-chain, RCE via a
parsed PEM, a hostile CRD, a dependency CVE — CM-28) into cluster-wide
lateral movement. Specifically: a root process can mutate `/etc/ssl`,
write a backdoor into `/usr/local/bin`, call `mount`/`ptrace`/
`net_admin` via retained capabilities, reach arbitrary peer pods in the
cluster, scrape the kube-apiserver, or exfiltrate the AVX API key to any
public IP. None of these motions are required for certd, certchain-issuer,
or certchain-sync to do their jobs, so the default-permissive Kubernetes
admission posture is strictly a liability.

**Mitigation:**
- The `certchain` namespace is labeled
  `pod-security.kubernetes.io/enforce=restricted` (plus `audit` and
  `warn`) so PodSecurity admission rejects any manifest that does not
  satisfy the restricted profile.
- Every Deployment and StatefulSet in `deploy/k8s/base` sets both a
  pod-level and container-level `securityContext` with
  `runAsNonRoot: true`, `runAsUser: 10001`, `runAsGroup: 10001`,
  `fsGroup: 10001`, `allowPrivilegeEscalation: false`,
  `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`, and
  `seccompProfile.type: RuntimeDefault`. Writable paths the binaries
  still need (`/tmp`, and `/data/certchain` for certd) are backed by
  explicit `emptyDir: {medium: Memory}` tmpfs volumes or the certd PVC
  — no other path on the container image is writable at runtime.
- `deploy/k8s/base/networkpolicy.yaml` installs a namespace-wide
  `default-deny-all` policy and then layers narrow allow-lists:
    - certd ingress: 9879 (query) from certchain-issuer + same-namespace +
      kube-system; 9880 (metrics) only from namespaces labeled
      `prometheus: enabled`; 9878 (peer) from same-app peers only.
    - certchain-issuer ingress: 9443 (webhook) from kube-system;
      9880 (metrics) from Prometheus only.
    - Namespace-wide egress: DNS to kube-dns, 443/6443 to kube-apiserver
      (via kube-system selector), intra-namespace peer/query/discovery
      ports, and a single documented `ipBlock` for the AppViewX REST
      endpoint. The AVX CIDR is shipped as the unroutable RFC 5737
      `192.0.2.0/24` placeholder so the manifest fails closed until an
      operator substitutes the real range.
- `deploy/k8s/base/pdb.yaml` caps voluntary disruptions
  (`maxUnavailable: 1` for certd, `minAvailable: 1` for the issuer) so
  a hardened pod set cannot be evicted all at once during a node drain —
  the runtime invariant behind CM-20.

**Test:** `go build ./...`, `go vet ./...`, and
`go test -count=1 ./...` continue to pass because the change is
deployment-surface-only. `kubectl apply --dry-run=client -k
deploy/k8s/base/` structurally validates the full manifest set against the
in-cluster schema when kubectl is available; otherwise YAML parse
correctness is verified via `kustomize build deploy/k8s/base`.

---

## Category: Chain Throughput

### CM-32 — One Tx Per Block Inflates Chain to O(N) Blocks per Burst

**Risk:** The pre-CM-32 submit path built one block per transaction. A
proactive-renewal sweep, a large CSR burst, or any operator action that
fans out many cert mutations in a short window therefore produced N
blocks for N txs. Three concrete failures follow:
- Persisted `chain.json` grows linearly with the submission rate rather
  than with the cert population, pushing PVC usage past its reservation
  and starving other writers.
- Peer block-push fan-out multiplies by N: every peer receives N HTTP
  pushes (each with its own HMAC, TLS handshake budget, and certd query
  side-effects) for what is logically one batch of work.
- Block-index pressure: index is a uint32, so a node that sustains
  1 tx/s hits the 2^32 ceiling in ~136 years. That is nominally safe
  today, but it is trivially halved by anyone who can drive the submit
  path (CSR watcher, AVX poll sweep) at peak rate, and once indices
  wrap, validation (`b.Index != prev.Index+1`) rejects every subsequent
  block network-wide.

**Mitigation:**
- `chain.BatchSubmit(ctx, []Transaction)` atomically commits a single
  multi-tx block. Canonical block bytes (and therefore the CM-29 block
  hash) fold every tx's signing payload in, so block-level integrity
  still covers the full batch; per-tx signatures continue to verify
  individually under the domain-separated context.
- `chain.Batcher` sits in front of `BatchSubmit`. Producers call
  `Submit(tx)` and block on a per-tx promise; the Batcher's single
  drain goroutine collects pending txs until `--batch-max-txs`
  transactions are queued or `--batch-max-wait` elapses (defaults 64
  and 250 ms), then commits them as one block. Because the drain loop
  is single-threaded, the `Signer` hook assigns monotonic per-node
  nonces lock-free and in commit order.
- certd's `blockSubmitter` implements `chain.Signer`: it advances the
  node nonce inside `SignTx` and rolls it back via `OnBatchRollback`
  when a batch is rejected, preserving the replay-prevention invariant
  from CM-03 without the pre-CM-32 per-tx mutex.
- On shutdown, the Batcher drains any queued txs and either commits or
  errors every promise so no caller is left blocked on an unresolved
  reply — the shutdown-flush guarantee tested by
  `TestBatcherShutdownFlushesPending`.

**Test:** `internal/chain/batcher_test.go` covers
`TestBatcherDrainsOnFull` (64-tx full-buffer drain producing one block),
`TestBatcherDrainsOnDeadline` (3-tx partial batch committed once
`MaxWait` expires), `TestBatcherPreservesOrder` (tx order in the
committed block matches submit order and nonce sequence),
`TestBatcherErrorPropagation` (a single invalid tx makes the whole
batch fail with one shared error delivered to every promise and leaves
the chain untouched), and `TestBatcherShutdownFlushesPending` (ctx
cancel resolves every in-flight promise). `go build ./...`,
`go vet ./...`, and `go test -count=1 ./...` continue to pass.


---

## Category: Annotation-Driven Delivery Path

### CM-33 — Annotation Path Without Explicit Opt-In Causes Secret Ownership Ambiguity

**Risk:** annotation-ctrl (cmd/annotation-ctrl) watches Pods and Services
for the `certchain.io/cert-cn` annotation and provisions a
`kubernetes.io/tls` Secret in the same namespace. If it silently
competes with certd's legacy writer (CM-30) or cert-manager's external
issuer (cmd/certchain-issuer) on the same Secret name, operators cannot
tell which controller owns the material, renewals race, and a single
revocation can trigger conflicting Events from two sources. CM-30
covered the legacy writer's deprecation; CM-33 is the forward-looking
contract for the annotation path itself: it must claim a distinct,
explicit label/annotation namespace and must refuse to hijack Secrets
it does not already own.

**Mitigation:**
- Opt-in is per-object: the controller acts only when the
  `certchain.io/cert-cn` annotation is present. Absence of the
  annotation is a no-op plus a scoped sweep (deletes only Secrets
  labelled `certchain.io/managed-by=annotation-ctrl` and owned by the
  object via `ownerReferences`).
- All managed Secrets carry
  `certchain.io/managed-by=annotation-ctrl` and
  `certchain.io/cn=<sanitized-cn>`. The `managed-by` value is
  deliberately distinct from certd's `certd` value so the two control
  loops cannot target the same Secret.
- If a Secret with the target name exists but does not carry the
  annotation-ctrl `managed-by` label, the reconciler refuses to write
  and surfaces an Event of reason `CertchainSecretError`. This is the
  explicit-opt-in contract: the controller will not hijack a Secret it
  did not create.
- Secrets are emitted as `kubernetes.io/tls` with `tls.crt` +
  `ca.crt` populated from certd's Bearer-authenticated query API
  (CM-28). Private-key delivery is not yet implemented by this
  controller; `tls.key` contains a well-known placeholder until the
  separate `native-ann-renewal` task wires a private-key source. The
  placeholder is documented in code (`annotation.KeyPlaceholder`) so
  consumers cannot mistake the Secret for a fully-provisioned TLS
  Secret.
- A `RenewalNotifier` interface is exposed by the reconciler so the
  renewal scheduler (`native-ann-renewal`) can hook in without this
  controller having to watch the apiserver a second time. The default
  `NopRenewalNotifier` keeps the reconcile path self-contained.

**Test:** `internal/annotation/reconciler_test.go` covers (a)
annotation-add creates a TLS Secret with the expected labels/owner
references, (b) annotation-remove deletes only Secrets this controller
owns (the scoped analogue of certd's CM-25 sweep), (c) CN-mismatch on
a pinned Secret name updates material and the CN label without
hijacking a foreign Secret, (d) certd unreachable returns an error and
increments `certchain_annotation_errors_total` plus emits a
`CertchainSecretError` Event, and (e) `NotFound` from certd is
not counted as an error because it's the expected state during
initial issuance.

---

### CM-34 — Coarse-Grained Submit Mutex Serializes Unrelated Chain Operations and Collapses Under Batch Load

**Risk:** The pre-CM-34 `BatchSubmit` implementation held a single
write-lock across the entire operation (tx copy → build block → hash →
validate → apply seq/rate → append). When the C5 Batcher feeds Submit
under sustained load (proactive renewal sweeps, CSR bursts), all
concurrent submit calls serialize even when they could safely run
validation and block construction in parallel. This degrades throughput
in proportion to validation cost (signature checks, payload parsing),
creates unnecessary head-of-line blocking in peer submission paths, and
wastes CPU idle time that could be doing useful work. Additionally, if
future work (H7 WAL persistence, peer broadcast) performs I/O inside the
critical section, the lock hold time grows linearly with disk latency
and network RTT, magnifying the serialization penalty.

**Mitigation:**
- The chain struct already uses `sync.RWMutex`. All read paths (`Len`,
  `Tip`, `GetBlock`, `GetBlocks`, `GenesisHash`, `Validators`,
  `ChainID`, `AcceptsLegacySigs`) acquire `RLock` and can proceed
  concurrently with each other.
- `BatchSubmit` acquires the write-lock ONLY for the
  append-and-advance-head linearization point (the critical section that
  actually mutates `c.blocks`, `c.seqMap`, `c.rateMap`). Block
  construction, hashing, and validation now happen outside the lock:
    1. Snapshot the current tip under `RLock`.
    2. Build the candidate block in local memory (copy txs, compute hash).
    3. Call `validateBlockUnlocked`, which snapshots validators and
       chain state (`seqMap`, `rateMap`) under `RLock` and validates the
       candidate without holding any lock during signature verification,
       payload parse, or rate-limit checks.
    4. Acquire `Lock`, re-check the tip hasn't advanced (retry if stale),
       apply seq/rate updates, append, release lock.
- Multiple concurrent `BatchSubmit` calls can construct and validate
  blocks in parallel. Only the final append is serialized, so lock hold
  time is constant (map writes + slice append) and independent of I/O.
- When H7 wires WAL persistence and peer broadcast, those operations
  run outside the lock: persistence happens before the lock is acquired
  (with a rollback path if the tip-check fails), and broadcast happens
  after the lock is released. This keeps the critical section bounded.

**Test:** Existing `internal/chain/chain_test.go`,
`internal/chain/batcher_test.go`, and `internal/chain/submit.go` tests
continue to pass with `go test -race -count=1 ./internal/chain/...` to
verify race-freedom. A future benchmark `BenchmarkSubmitParallel` may
be added to quantify the throughput improvement, but is not required for
correctness.

---

### CM-35 — Missing Renewal Scheduler Leaves Annotated Certs to Silently Expire

**Risk:** annotation-ctrl (CM-33) provisions TLS Secrets on-demand when
certchain.io/cert-cn annotation is present, but without an automatic
renewal scheduler those Secrets remain at the NotAfter returned by certd
at initial issuance. When the underlying cert expires on-chain and certd
re-fetches fresh material from AVX, the annotation controller does not
re-reconcile the Secret, leaving Pods and Services with expired TLS
material. Apps fail TLS handshakes; operators get no Event warning that
renewal is required.

**Mitigation:**
- RenewalScheduler watches Secrets carrying
  certchain.io/managed-by=annotation-ctrl, parses the leaf cert's
  NotAfter, and schedules a workqueue requeue at NotAfter - renewBefore
  (default 30 days, configurable via --renew-before).
- On requeue, the scheduler calls the same CertFetcher used by the
  reconciler to fetch the latest cert from certd and updates the Secret
  in-place (preserving metadata and ownerReferences).
- Emits an Event of reason CertchainSecretRenewed on the owning
  Pod/Service so kubectl describe shows the renewal timestamp.
- If a cert has already expired at schedule time (delay <= 0), the
  Secret is requeued immediately with exponential backoff so the
  scheduler does not tight-loop on a permanently failed fetch.
- Uses workqueue.AddAfter so each Secret has at most one pending
  deadline; no unbounded goroutine-per-secret.
- Metrics: certchain_annotation_renewals_total{result=success|error}
  counter, certchain_annotation_cert_expiry_seconds gauge per
  namespace/name to surface approaching expirations in dashboards.
- The reconciler calls scheduler.OnNearExpiry(cn) after every
  successful Secret upsert so schedule times stay synchronized with
  on-chain material without polling.

**Test:** TestScheduleRenewalTime table-driven unit tests verify delay
computation; integration test with fake clock not provided but manual
testing confirmed the full flow works in-cluster.

---

### CM-36 — Whole-File chain.json Rewrite Without WAL Loses Blocks on Crash Mid-Write

**Risk:** The persisted chain snapshot is written by SaveChain as a complete
replace of chain.json. If certd crashes during os.WriteFile or the OS/disk
fails mid-write, chain.json can be truncated or torn, resulting in loss of
all blocks committed since the previous snapshot. On restart, the chain
reverts to the last consistent state, dropping transactions that clients
already observed as confirmed (violates durability).

**Mitigation:**
- Write-ahead log (WAL) at <config-dir>/chain.wal (configurable via
  --chain-wal-path) using length-prefixed CRC32-protected JSON records.
- Every BatchSubmit/Submit appends the candidate block to the WAL with
  fsync (configurable; default on) BEFORE appending to the in-memory
  chain.blocks slice. If the WAL write fails, the block commit is aborted
  and the caller receives an error.
- On startup, LoadChain replays the WAL on top of the last chain.json
  snapshot. Truncated tail records (short read when reading the length
  prefix) are logged and skipped. CRC mismatches are logged and skipped
  so partial writes do not crash the process.
- After a successful SaveChain snapshot completes, the WAL is rotated
  (truncated to zero length) so it doesn't grow unbounded.
- The WAL format is: | len(4 LE) | crc32(4) | JSON payload |

**Test:** TestWAL_AppendReplay, TestWAL_TruncatedTail, TestWAL_CRCMismatch,
TestWAL_Rotate in internal/chain/wal_test.go verify record framing, replay
correctness, and tail-truncation handling.

---

### CM-37 — Silently Swallowed Snapshot Errors Cause Stale Persisted Chain and Data Loss on Crash

**Risk:** SaveChain persists the in-memory chain to disk (chain.json snapshot +
WAL rotation). If the write fails due to transient I/O errors (disk full, NFS
timeout, read-only filesystem) and the error is silently swallowed, the
persisted chain diverges from the in-memory state. On crash or restart, the
process reverts to the last successful snapshot, losing all blocks committed
since then. Clients see confirmed transactions disappear (durability violation).
Combined with CM-36, the WAL protects against mid-write corruption but only if
SaveChain successfully completes; dropped errors mean the WAL never rotates and
the snapshot remains stale.

**Mitigation:**
- SaveChain logs every failure with slog.Error at ERROR level, including full
  context (file path, operation, underlying error).
- A Prometheus counter certchain_chain_save_errors_total{op="snapshot"} is
  incremented on every save failure (snapshot write or WAL rotate).
- Errors are NOT treated as fatal; certd continues running because the WAL
  still provides crash safety for the current session. However, operators must
  monitor the metric and investigate repeated failures before disk fills or the
  process restarts.
- WAL append failures (during Submit/BatchSubmit) remain fatal to the commit
  operation and are NOT counted by this metric; the caller receives the error
  and the transaction is not applied.

**Test:** TestSaveChainErrorMetric and TestSaveChainWALRotateError in
internal/certd/chain_test.go verify that the metric is incremented when writes
fail (non-existent directory, read-only file, missing WAL path) and NOT
incremented on successful writes.

