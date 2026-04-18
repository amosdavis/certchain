# certchain Protocol Specification

## Overview

certchain is a standalone blockchain that manages TLS/SSL X.509 certificates
issued by AppViewX. It uses the same FCFS + longest-chain-wins consensus model
as addrchain and shares the peer-discovery UDP port so addrchain peers can
discover certchain nodes without additional configuration.

## Ports

| Port  | Transport | Purpose                                                  |
|-------|-----------|----------------------------------------------------------|
| 9876  | UDP       | Peer discovery (shared with addrchain, distinguished by  |
|       |           | `CAP_CERTCHAIN = 0x04` capability flag in announce)      |
| 9878  | TCP       | certchain block synchronization                          |
| 9879  | HTTP      | Soft-lookup query API (for addrchain and other consumers)|

## Peer Discovery (UDP :9876)

certchain announces on the same UDP port as addrchain using a compatible
announce payload. The `capabilities` field includes `CAP_CERTCHAIN = 0x04`
to distinguish certchain-capable peers from address-only peers.

### Announce Payload (binary, little-endian)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            magic (4 bytes: "CERT")                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           version (2 bytes LE)                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           node_pubkey (32 bytes, Ed25519)                      |
|                ...                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           chain_height (4 bytes LE)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           tip_hash (32 bytes, SHA-256)                         |
|                ...                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           sync_port (2 bytes LE, default 9878)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           capabilities (1 byte, must include 0x04)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Capability flags:
- `0x01` — POOL transport (addrchain)
- `0x02` — VPN tunneling (addrchain)
- `0x04` — certchain (`CAP_CERTCHAIN`)

Nodes without `CAP_CERTCHAIN` are ignored by certchain peers.

## Block Sync Protocol (TCP :9878)

All messages use 4-byte little-endian length prefix framing.

### Handshake

```
Client → Server: HELLO { version uint16, chain_height uint32, tip_hash [32]byte }
Server → Client: HELLO { version uint16, chain_height uint32, tip_hash [32]byte }
```

If version major differs, connection is closed.

### Sync Request

```
Client → Server: SYNC_REQ { from_index uint32, to_index uint32 }
Server → Client: SYNC_RESP { block_count uint32, blocks []Block }
```

### New Block Broadcast

```
Sender → All peers: BLOCK_PUSH { block Block }
```

Receivers validate before applying. Invalid blocks are discarded (peer failure
count incremented after 3 consecutive invalid pushes).

### DER Request

```
Client → Server: CERT_REQ { cert_id [32]byte }
Server → Client: CERT_RESP { found bool, der_len uint32, der []byte }
```

If `found` is false, `der_len` is 0. The client should try other peers.

## Block Format

```go
type Block struct {
    Index     uint32
    Timestamp int64      // unix seconds (UTC)
    PrevHash  [32]byte   // SHA-256 of previous block
    Hash      [32]byte   // SHA-256 of this block (see below)
    Txs       []Transaction
}
```

Block hash input (in order, little-endian for integers):
1. Index (4 bytes LE)
2. Timestamp (8 bytes LE)
3. PrevHash (32 bytes)
4. For each transaction: serialized signing payload (see Transaction)

## Transaction Format

```go
type Transaction struct {
    Type      TxType        // 1 byte
    NodePubkey [32]byte     // Ed25519 public key of signer
    Timestamp  int64        // unix seconds
    Nonce      uint32       // monotonically increasing per node
    Payload    []byte       // JSON-encoded payload (type-specific)
    Signature  [64]byte     // Ed25519 signature of signing payload
}
```

Transaction signing payload (hashed then signed):
1. Type (1 byte)
2. NodePubkey (32 bytes)
3. Timestamp (8 bytes LE)
4. Nonce (4 bytes LE)
5. Payload (variable, JSON)

## Transaction Types

| Value | Name            | Purpose                                  |
|-------|-----------------|------------------------------------------|
| 0x01  | TxCertPublish   | Publish cert hash + metadata on chain    |
| 0x02  | TxCertRevoke    | Revoke certificate (AppViewX-driven)     |
| 0x03  | TxCertRenew     | Replace old cert_id with new cert_id     |

## Consensus Rules

1. **FCFS** — First valid CLAIM for a cert_id wins; duplicates are rejected.
2. **Longest chain wins** — On fork, the chain with higher `tip.Index` replaces
   the local chain after full validation.
3. **Tiebreaker** — Equal-length forks resolved by lowest `tip.Hash`
   (lexicographic byte comparison).
4. **REVOKE wins** — If a fork results in both PUBLISH and REVOKE for the same
   cert_id, the REVOKE takes precedence regardless of ordering.
5. **Block timestamp** — Cert validity (`not_before`/`not_after`) is evaluated
   against the block's `Timestamp`, not the local clock.

## Genesis Block

The genesis block is deterministic across all certchain nodes:

```
Index:     0
Timestamp: 0
PrevHash:  0x00...00 (32 zero bytes)
Payload:   "certchain-v1-genesis"
Hash:      SHA-256(above fields)
```

Any node with a different genesis block is incompatible and will not sync.

## Rate Limiting

Maximum 20 certificate transactions per node pubkey per 10 blocks. Nodes that
exceed this limit have their excess transactions rejected for that window.
