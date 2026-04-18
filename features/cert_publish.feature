Feature: Certificate Publish
  As a certchain node
  I want to publish TLS certificates to the blockchain
  So that network nodes can verify certificate authenticity

  Background:
    Given a fresh certchain with a node identity

  Scenario: Successfully publish an active certificate
    Given a certificate with CN "valid.example.com" valid from 1000 to 2000
    When I publish the certificate at block time 1500
    Then the chain height is 2
    And the cert store contains "valid.example.com" with status "active"

  Scenario: Certificate with future not_before is not_yet_valid
    Given a certificate with CN "future.example.com" valid from 5000 to 9000
    When I publish the certificate at block time 1000
    Then the cert store contains "future.example.com" with status "not_yet_valid"

  Scenario: Duplicate publish of the same cert_id is rejected
    Given a certificate with CN "dup.example.com" valid from 1000 to 2000
    When I publish the certificate at block time 1500
    And I publish the same certificate again at block time 1600
    Then the second publish fails with "cert already active on chain"

  Scenario: Listing shows published certs
    Given a certificate with CN "list.example.com" valid from 1000 to 2000
    When I publish the certificate at block time 1500
    Then the active cert list contains "list.example.com"
