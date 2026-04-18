Feature: Certificate Renew
  As a certchain node
  I want to replace an expiring certificate with a new one
  So that services maintain continuous valid certificate coverage

  Background:
    Given a fresh certchain with a node identity

  Scenario: Renew replaces the old cert with a new cert
    Given a certificate with CN "renew.example.com" valid from 1000 to 2000
    And the certificate is published at block time 1500
    And a replacement certificate with CN "renew.example.com" valid from 1800 to 4000
    When the replacement certificate is published at block time 1800
    And I renew the old cert with the new cert at block time 1800
    Then the old cert has status "replaced"
    And the new cert has status "active"
    And the chain height is 4

  Scenario: Renew with same old and new cert_id is rejected
    Given a certificate with CN "same.example.com" valid from 1000 to 2000
    When I attempt to renew a cert with its own cert_id
    Then the renew transaction payload is invalid
