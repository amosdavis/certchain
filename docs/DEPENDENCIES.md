# Dependency Baseline (CM-28)

This document is the human-readable counterpart to `go.mod`. Every direct
dependency listed here must have a one-line rationale so that future
maintainers (and reviewers of `go.mod` bumps) can tell at a glance whether
a module belongs in the build graph at all.

The automated side of CM-28 is the `make audit` target and the
`dependency-audit` CI job; those guard against CVEs, tidy drift, and
`go.sum` corruption. This file guards against *rationale drift* — a
dependency silently sticking around after the code that justified it has
been deleted.

## Direct dependencies

Exactly the `require` block (non-indirect) of `go.mod`, in the same order.

| Module | Why it is a direct dependency |
| --- | --- |
| `github.com/cucumber/godog` | BDD runner for `features/`; executes Gherkin scenarios as Go tests. Required by `make bdd`. |
| `github.com/prometheus/client_golang` | `/metrics` endpoint and counters/histograms in `internal/metrics`; the operational observability contract (H3, CM-24 adjacent). |
| `k8s.io/api` | Typed Kubernetes API objects (`CertificateSigningRequest`, `Secret`, `Lease`, our CRD types) used by `certchain-issuer` and the K8s wiring in `certd`. |
| `k8s.io/apimachinery` | Runtime scheme, meta types, and label selectors that every `k8s.io/api` user needs; splitting it out is Kubernetes convention, not ours. |
| `k8s.io/client-go` | Informers, workqueue, leader election (`H2`), and REST client used by `certchain-issuer`'s controller loop. |

If a future PR adds a new entry to the `require` block, that PR **must**
also add a row here. The CI `dependency-audit` job does not enforce this
(there is no machine-readable rationale), so it is a review-time rule.

## Indirect dependencies

Indirect dependencies are whatever the direct set transitively pulls in and
are not enumerated here by name — `go list -m all` and `bin/licenses.csv`
(produced by `make licenses`) are the source of truth. They are covered by
CM-28 via `govulncheck` (CVE scan) and `go-licenses` (license
classification), not by per-module prose rationale.

## Replace directives

None. `go.mod` contains no `replace` stanzas. Introducing one requires an
explicit row here explaining *why* the upstream module is being shadowed
and when the replace is expected to be removed.

## Update cadence policy

- **Security patches (CVE in a module we actually import):** bump within
  one business day of the advisory, on a dedicated PR whose title starts
  with `sec:` and whose body links the advisory. `govulncheck` in CI is
  the tripwire.
- **Kubernetes client (`k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go`):**
  these must move as a triple — never bump one without the other two to
  the same minor version. Target one bump per Kubernetes minor release
  after it has had at least one patch release (e.g., bump to `v0.30.x`
  after `v0.30.1` ships).
- **Everything else:** opportunistic — bumped when a developer is already
  touching adjacent code, or quarterly (whichever comes first). Each bump
  PR must be audit-clean (`make audit` green) before merge.
- **`go` directive:** stay on the oldest Go toolchain that the CI matrix
  uses (currently `1.21`) unless a language/stdlib feature is required.
  Bumping the `go` line forces every consumer of the module onto the new
  toolchain and is therefore a breaking change for downstream forks.

## Known issues

None at the time of writing. If `govulncheck` begins reporting a vuln:

1. Record the GHSA/CVE ID, affected module, affected symbol, and first
   fixed version in this section.
2. State the mitigation (bump, suppression, or "not reachable — see
   govulncheck `-show verbose` output") with a link to the audit run.
3. Open a tracking issue if the fix is more than a trivial dependency
   bump.

Silent suppression via `govulncheck` exclusion files is not permitted —
every finding must be visible here.

## Running the audit locally

```
make audit       # vet + tidy-diff + staticcheck + govulncheck
make vuln        # govulncheck only (fast rerun after a bump)
make licenses    # bin/modules.txt + bin/licenses.csv
```

`make audit` is also wired into `make verify`, so the pre-push gate
implicitly enforces CM-28.
