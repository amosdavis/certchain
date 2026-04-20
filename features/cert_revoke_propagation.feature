Feature: Revocation Propagates to Kubernetes Secrets
  As a certchain operator running certd with K8s integration
  I want a revoked certificate's Secret to be deleted promptly
  So that applications stop serving revoked certificates (CM-25)

  Background:
    Given a fresh certchain with a node identity
    And a K8s secret writer with namespace "certchain" and prefix "cc"

  Scenario: Revoked cert triggers Secret deletion and Event
    Given a certificate with CN "propagate.example.com" valid from 1000 to 9000
    When I publish the certificate at block time 5000
    And the secret writer syncs against the cert store
    Then a K8s Secret named "cc-propagate.example.com" exists in namespace "certchain"
    When I revoke the certificate at block time 6000
    And the secret writer syncs against the cert store
    Then no K8s Secret named "cc-propagate.example.com" exists in namespace "certchain"
    And a "CertchainRevoked" Event exists for Secret "cc-propagate.example.com" in namespace "certchain"
