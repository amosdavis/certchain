Feature: Certificate Query
  As a client system
  I want to query the certchain for certificate metadata
  So that I can verify and use certificates issued by AppViewX

  Background:
    Given a fresh certchain with a node identity
    And a certificate with CN "query.example.com" valid from 1000 to 2000
    And the certificate is published at block time 1500

  Scenario: Query active cert by Common Name
    When I query the cert store by CN "query.example.com"
    Then the result has status "active"
    And the result CN is "query.example.com"

  Scenario: Query cert by cert_id hex
    When I query the cert store by cert_id of "query.example.com"
    Then the result has status "active"

  Scenario: Query not_yet_valid cert
    Given a certificate with CN "soon.example.com" valid from 9999 to 19999
    And the certificate is published at block time 1500
    When I query the cert store by CN "soon.example.com"
    Then the result has status "not_yet_valid"

  Scenario: Query unknown CN returns not found
    When I query the cert store by CN "unknown.example.com"
    Then the cert is not found
