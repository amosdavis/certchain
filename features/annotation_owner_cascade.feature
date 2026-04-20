Feature: Owner deletion cascades to Secret
  As an annotation-ctrl operator
  I want Secrets to be garbage collected when their owner is deleted
  So that orphaned credentials are cleaned up automatically

  Background:
    Given annotation-ctrl is running with fake K8s and stub CertFetcher

  Scenario: Pod deletion with ownerRef triggers Secret GC
    Given a Pod "owned-pod" in namespace "default" with annotation "certchain.io/cert-cn" set to "owned.com"
    And annotation-ctrl has created Secret "certchain-owned.com" with ownerRef to the Pod
    When the Pod "owned-pod" is deleted
    Then the fake K8s client GC behavior removes Secret "certchain-owned.com"

  Scenario: Annotation removal triggers explicit sweep
    Given a Pod "annotated-pod" in namespace "default" with annotation "certchain.io/cert-cn" set to "sweep.com"
    And annotation-ctrl has created Secret "certchain-sweep.com" with ownerRef to the Pod
    When the Pod annotation "certchain.io/cert-cn" is removed
    And annotation-ctrl reconciles the Pod
    Then the Secret "certchain-sweep.com" is deleted
    And an Event "CertchainSecretDeleted" is emitted on the Pod
