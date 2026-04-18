Feature: Certificate Revoke
  As a certchain node
  I want to revoke certificates on the blockchain
  So that nodes stop trusting expired or compromised certs

  Background:
    Given a fresh certchain with a node identity

  Scenario: Revoke an active certificate
    Given a certificate with CN "revoke.example.com" valid from 1000 to 2000
    And the certificate is published at block time 1500
    When I revoke the certificate at block time 1600
    Then the chain height is 3
    And the cert store contains "revoke.example.com" with status "revoked"

  Scenario: Revoke wins over publish in the same block
    Given a certificate with CN "conflict.example.com" valid from 1000 to 2000
    When I publish and revoke the certificate in the same block at time 1500
    Then the cert store contains "conflict.example.com" with status "revoked"

  Scenario: Revoking an unknown cert_id is rejected by the store
    Given a cert_id that is not on the chain
    When I attempt to apply a revoke block for the unknown cert
    Then the store apply returns an error
