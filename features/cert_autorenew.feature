Feature: Certificate Auto-Renewal
  As a certchain node
  I want expired certificates to be automatically revoked
  And AVX-driven renewals to be linked on-chain via TxCertRenew
  And certs approaching expiry to trigger a proactive AVX renewal request
  So that the blockchain accurately reflects the current certificate lifecycle

  Background:
    Given a fresh certchain with a node identity

  Scenario: Cert past not_after is auto-revoked by the expiry monitor
    Given a certificate with CN "old.example.com" valid from 1000 to 2000
    And the certificate is published at block time 1500
    When the expiry monitor runs at wall time 3000
    Then the cert store contains "old.example.com" with status "revoked"
    And the chain height is 3

  Scenario: AVX renewal emits TxCertPublish then TxCertRenew
    Given a certificate with CN "linked.example.com" valid from 1000 to 2000
    And the certificate is published at block time 1500
    When AVX reports a renewal for CN "linked.example.com" valid from 1800 to 4000 at block time 1800
    Then the chain height is 4
    And the old cert has status "replaced"
    And the new cert for "linked.example.com" has status "active"

  Scenario: Expiry monitor does not re-revoke an already-revoked cert
    Given a certificate with CN "done.example.com" valid from 1000 to 2000
    And the certificate is published at block time 1500
    And I revoke the certificate at block time 1600
    When the expiry monitor runs at wall time 3000
    Then the cert store contains "done.example.com" with status "revoked"
    And the chain height is 3

  Scenario: Cert within renewal window triggers AVX renewal API call
    Given a mock AVX renewal server is configured
    And a certificate with CN "soon.example.com" valid from 1000 to 2000
    And the certificate is published at block time 1500
    When the proactive renewal check runs with window 1500 seconds at wall time 600
    Then the AVX renewal API was called for "soon.example.com"

  Scenario: Cert outside renewal window does not trigger AVX renewal
    Given a mock AVX renewal server is configured
    And a certificate with CN "distant.example.com" valid from 1000 to 9999
    And the certificate is published at block time 1500
    When the proactive renewal check runs with window 1500 seconds at wall time 600
    Then the AVX renewal API was not called
