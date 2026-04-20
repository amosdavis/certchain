# certchain architecture

certchain is a standalone Go blockchain that records AppViewX-issued X.509
certificates and exposes them to any cluster member. Kubernetes workloads
get certs via a cert-manager external issuer (`certchain-issuer`) that
translates `CertificateRequest` objects into on-chain CSRs.

## Data flow

```mermaid
flowchart TD
    AVX[AppViewX REST API]
    subgraph Cluster[certd StatefulSet — chain quorum]
        D1[certd replica 1]
        D2[certd replica 2]
        D3[certd replica N]
    end
    ISS[certchain-issuer Deployment<br/>leader-elected, HA]
    CM[cert-manager]
    SEC[(Secret tls.crt / tls.key)]
    POD[Application Pod]

    AVX -- poll 60s ±10% --> D1
    D1 <-- P2P block sync :9878 --> D2
    D2 <-- P2P block sync :9878 --> D3

    CM -- CertificateRequest --> ISS
    ISS -- creates CSR<br/>signerName=certchain.io/* --> D1
    D1 -- submit CSR --> AVX
    AVX -- signed cert --> D1
    D1 -- writes cert to CSR status --> ISS
    ISS -- updates CertificateRequest --> CM
    CM -- stores chain+key --> SEC
    SEC -- mounted read-only --> POD
```

## Components

| Component | Kind | Notes |
|-----------|------|-------|
| `certd` | StatefulSet | Blockchain node. Polls AVX, validates blocks against the `validators.json` allowlist (CM-23), serves query API on `:9879`, exposes `/readyz` and `/metrics` on `:9880` (CM-27). |
| `certchain-issuer` | Deployment (replicas ≥ 2) | cert-manager external issuer. Leader-elected via a Lease (CM-22); only the leader processes `CertificateRequest`s. |
| `CertchainClusterIssuer` / `CertchainIssuer` | CRDs (`certchain.io/v1alpha1`) | Bind a `signerName` to an issuer reference. Cluster-scoped and namespace-scoped variants. Status subresource with `Ready` + `Age` printer columns (CM-26). |
| `cert-manager` | Third-party | v1.13+. Generates private keys, creates `CertificateRequest`s, stores Secrets, auto-renews. |

## Trust boundaries

- Private keys are generated inside the cluster by cert-manager and never
  leave; only the CSR is submitted to AVX.
- certd validates that the CSR signer is on the `validators.json`
  allowlist before admitting the block (CM-23).
- Secrets are deleted when the corresponding cert is revoked on chain
  (CM-25); the `certchain-issuer` emits a Kubernetes Event and drops the
  `tls.crt` so workloads fail closed.

See `spec/FAILURES.md` for the full tenet list.
