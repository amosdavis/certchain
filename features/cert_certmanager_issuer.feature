Feature: cert-manager External Issuer
  As a certchain node acting as a cert-manager external issuer
  I want to process CertificateRequest objects created by cert-manager
  So that GKE applications in any namespace can obtain TLS certificates
  with private keys managed by cert-manager

  Background:
    Given a fresh certchain with a node identity
    And AppViewX accepts CSR submissions
    And a K8s CSR watcher with signer name "certchain.io/appviewx"
    And a CertchainClusterIssuer named "appviewx" with signerName "certchain.io/appviewx"
    And a certchain-issuer controller watching CertificateRequests

  Scenario: CertificateRequest triggers K8s CSR creation and cert issuance
    Given a cert-manager CertificateRequest "my-app-tls" in namespace "my-app" with issuerRef group "certchain.io" kind "CertchainClusterIssuer" name "appviewx" and CN "my-app.example.com"
    And AppViewX eventually issues the certificate
    When the certchain-issuer processes the CertificateRequest
    Then a K8s CertificateSigningRequest named with prefix "certchain-" is created
    And the K8s CSR has signerName "certchain.io/appviewx"
    And the K8s CSR is approved
    And the CertificateRequest status.certificate is set
    And the CertificateRequest has condition "Ready" with status "True"

  Scenario: CertificateRequest with non-matching issuerRef group is ignored
    Given a cert-manager CertificateRequest "other-tls" in namespace "my-app" with issuerRef group "other.io" kind "ClusterIssuer" name "letsencrypt" and CN "other.example.com"
    When the certchain-issuer processes the CertificateRequest
    Then no K8s CertificateSigningRequest is created
    And the CertificateRequest status.certificate is not set

  Scenario: CertificateRequest already approved is not reprocessed
    Given a cert-manager CertificateRequest "done-tls" in namespace "my-app" with issuerRef group "certchain.io" kind "CertchainClusterIssuer" name "appviewx" and CN "done.example.com"
    And the CertificateRequest already has status.certificate set
    When the certchain-issuer processes the CertificateRequest
    Then no K8s CertificateSigningRequest is created

  Scenario: K8s CSR status.certificate written by certd watcher updates CertificateRequest
    Given a cert-manager CertificateRequest "issued-tls" in namespace "prod" with issuerRef group "certchain.io" kind "CertchainClusterIssuer" name "appviewx" and CN "issued.example.com"
    And the K8s CertificateSigningRequest status.certificate is pre-populated
    When the certchain-issuer processes the CertificateRequest
    Then the CertificateRequest status.certificate is set
    And the CertificateRequest has condition "Ready" with status "True"

  Scenario: AVX submission failure marks CertificateRequest as Failed (CM-20)
    Given a cert-manager CertificateRequest "fail-tls" in namespace "my-app" with issuerRef group "certchain.io" kind "CertchainClusterIssuer" name "appviewx" and CN "fail.example.com"
    And AppViewX rejects all CSR submissions
    And the certchain-issuer cert wait timeout is 100 milliseconds
    When the certchain-issuer processes the CertificateRequest
    Then the CertificateRequest has condition "Failed" with status "True"
    And the CertificateRequest status.certificate is not set

