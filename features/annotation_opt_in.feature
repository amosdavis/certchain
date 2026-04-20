Feature: Opt-in via annotation only
  As an annotation-ctrl operator
  I want Secrets created only when explicitly requested
  So that no implicit ownership conflicts occur (CM-33)

  Background:
    Given annotation-ctrl is running with fake K8s and stub CertFetcher

  Scenario: Pod without annotation has no Secret created
    Given a Pod "no-annotation-pod" in namespace "default" without cert-cn annotation
    When annotation-ctrl reconciles the Pod
    Then no Secret with label "certchain.io/managed-by=annotation-ctrl" is created

  Scenario: Refusing to hijack existing Secret not managed by annotation-ctrl
    Given a Secret "existing-secret" in namespace "default" with label "certchain.io/managed-by" set to "certd"
    And a Pod "hijack-pod" in namespace "default" with annotations:
      | certchain.io/cert-cn          | hijack.com       |
      | certchain.io/cert-secret-name | existing-secret  |
    When annotation-ctrl reconciles the Pod
    Then the reconcile returns an error containing "not managed by annotation-ctrl"
    And the Secret "existing-secret" label remains "certd"

  Scenario: Service annotation also provisions Secrets
    Given a Service "test-service" in namespace "default" with annotation "certchain.io/cert-cn" set to "service.example.com"
    When annotation-ctrl reconciles the Service
    Then a TLS Secret "certchain-service.example.com" is created in namespace "default"
    And the Secret has ownerReference to the Service
