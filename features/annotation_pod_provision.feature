Feature: Pod annotation yields a TLS Secret
  As an annotation-ctrl operator
  I want Pods with certchain.io/cert-cn to get TLS Secrets
  So that workloads can consume certificates automatically

  Background:
    Given annotation-ctrl is running with fake K8s and stub CertFetcher

  Scenario: Pod with cert-cn annotation gets a TLS Secret
    Given a Pod "test-pod" in namespace "default" with annotation "certchain.io/cert-cn" set to "example.com"
    When annotation-ctrl reconciles the Pod
    Then a TLS Secret "certchain-example.com" is created in namespace "default"
    And the Secret has label "certchain.io/managed-by" set to "annotation-ctrl"
    And the Secret has label "certchain.io/cn" set to "example.com"
    And the Secret has ownerReference to the Pod
    And the Secret data contains "tls.crt" and "ca.crt"

  Scenario: Custom secret name via annotation
    Given a Pod "custom-pod" in namespace "default" with annotations:
      | certchain.io/cert-cn          | custom.example.com |
      | certchain.io/cert-secret-name | my-custom-secret   |
    When annotation-ctrl reconciles the Pod
    Then a TLS Secret "my-custom-secret" is created in namespace "default"
    And the Secret has ownerReference to the Pod

  Scenario: Pod without annotation is ignored
    Given a Pod "plain-pod" in namespace "default" without cert-cn annotation
    When annotation-ctrl reconciles the Pod
    Then no TLS Secret is created

  Scenario: Cert not yet issued waits silently
    Given a Pod "waiting-pod" in namespace "default" with annotation "certchain.io/cert-cn" set to "pending.com"
    And CertFetcher will return "not found" for CN "pending.com"
    When annotation-ctrl reconciles the Pod
    Then no TLS Secret is created
    And no error is recorded
    And an Event "CertchainSecretIssued" is emitted on the Pod
