Feature: Secret renewal before NotAfter
  As an annotation-ctrl operator
  I want managed Secrets to renew automatically
  So that certificates don't expire unexpectedly

  Background:
    Given annotation-ctrl is running with fake K8s and stub CertFetcher
    And the renewal scheduler is configured with renewBefore "24h"

  Scenario: Secret with cert near expiry triggers renewal
    Given a managed Secret "certchain-renew.com" in namespace "default"
    And the Secret cert has NotAfter within renewBefore
    When the renewal scheduler processes the Secret
    Then CertFetcher is called for a fresh cert
    And the Secret data is updated with the new cert
    And an Event "CertchainSecretRenewed" is emitted

  Scenario: Secret with fresh cert is not renewed
    Given a managed Secret "certchain-fresh.com" in namespace "default"
    And the Secret cert has NotAfter far in the future
    When the renewal scheduler processes the Secret
    Then CertFetcher is not called

  Scenario: Renewal updates in-place without changing Secret name
    Given a managed Secret "certchain-stable.com" in namespace "default" with ownerRef
    And the Secret cert has NotAfter within renewBefore
    When the renewal scheduler processes the Secret
    Then the Secret "certchain-stable.com" still exists
    And the Secret ownerReferences are preserved
    And the Secret has updated cert data
