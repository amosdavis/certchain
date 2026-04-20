Feature: Kubernetes CSR-Driven Certificate Issuance
  As a certchain node acting as a K8s signer
  I want to fulfil CertificateSigningRequest objects via AppViewX
  So that K8s workloads can obtain certificates through native K8s APIs

  Background:
    Given a fresh certchain with a node identity
    And AppViewX accepts CSR submissions
    And a K8s CSR watcher with signer name "certchain.io/appviewx"

  Scenario: Approved CSR triggers AVX submission and on-chain audit record
    Given a CertificateSigningRequest "web.example.com" with signer "certchain.io/appviewx" is approved
    When the CSR watcher processes the event
    Then a TxCertRequest is submitted to the chain with CN "web.example.com"
    And the CSR annotation "certchain.io/avx-request-id" is set

  Scenario: CSR with non-matching signer name is ignored
    Given a CertificateSigningRequest "other.example.com" with signer "other.io/issuer" is approved
    When the CSR watcher processes the event
    Then no TxCertRequest is submitted to the chain

  Scenario: CSR already claimed by another replica is skipped
    Given a CertificateSigningRequest "shared.example.com" with signer "certchain.io/appviewx" is approved
    And the annotation "certchain.io/avx-request-id" is already set on the CSR
    When the CSR watcher processes the event
    Then no TxCertRequest is submitted to the chain

  Scenario: Issued certificate is written back to K8s CSR status (CM-19 happy path)
    Given a CertificateSigningRequest "issued.example.com" with signer "certchain.io/appviewx" is approved
    And AppViewX eventually issues the certificate
    When the CSR watcher processes the event
    Then the CSR status.certificate field is set

  Scenario: AVX submission failure marks CSR as Failed (CM-19)
    Given a CertificateSigningRequest "fail.example.com" with signer "certchain.io/appviewx" is approved
    And AppViewX rejects all CSR submissions
    When the CSR watcher processes the event
    Then the CSR has a "Failed" condition
    And no TxCertRequest is submitted to the chain
