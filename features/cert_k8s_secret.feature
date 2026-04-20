Feature: Kubernetes TLS Secret Management
  As a certchain node with K8s integration enabled
  I want active certificates written as K8s Secrets
  So that workloads can consume TLS certs natively from the cluster

  Background:
    Given a fresh certchain with a node identity
    And a K8s secret writer with namespace "certchain" and prefix "cc"

  Scenario: Active certificate creates a K8s Secret
    Given a certificate with CN "api.example.com" valid from 1000 to 9000
    When I publish the certificate at block time 5000
    And the secret writer syncs against the cert store
    Then a K8s Secret named "cc-api.example.com" exists in namespace "certchain"
    And the Secret type is Opaque
    And the Secret contains a "tls.crt" entry
    And the Secret label "certchain.io/avx-cert-id" equals "AVX-api.example.com"

  Scenario: Revoked certificate Secret is deleted
    Given a certificate with CN "revoked.example.com" valid from 1000 to 9000
    When I publish the certificate at block time 5000
    And the secret writer syncs against the cert store
    And I revoke the certificate at block time 6000
    And the secret writer syncs against the cert store
    Then no K8s Secret named "cc-revoked.example.com" exists in namespace "certchain"

  Scenario: Renewal does not delete the Secret for the new certificate
    Given a certificate with CN "renew.example.com" valid from 1000 to 9000
    When I publish the certificate at block time 5000
    And the secret writer syncs against the cert store
    And I publish a renewed certificate with CN "renew.example.com" valid from 6000 to 18000 at block time 6500
    And the old certificate is replaced
    And the secret writer syncs against the cert store
    Then a K8s Secret named "cc-renew.example.com" exists in namespace "certchain"
    And the Secret label "certchain.io/cert-id" matches the new certificate

  Scenario: Missing DER file skips Secret creation gracefully
    Given a certificate record for "nodercache.example.com" with status "active" but no DER on disk
    When the secret writer syncs against the cert store
    Then no K8s Secret named "cc-nodercache.example.com" exists in namespace "certchain"
    And no error is returned

  Scenario: RBAC forbidden response is logged and skipped (CM-17)
    Given K8s Secret writes are forbidden by RBAC
    And a certificate with CN "rbac.example.com" valid from 1000 to 9000
    When I publish the certificate at block time 5000
    And the secret writer syncs against the cert store
    Then no error is returned
    And no K8s Secret named "cc-rbac.example.com" exists in namespace "certchain"
