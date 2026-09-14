Feature: Fraud Revocation
  Scenario: User can simulate fraud revocation
    Given I visit the demo client homepage
    When I click "🚀 Start Secure Login (PAR + DPoP + PKCE)"
    When I fill in "username" with "alice_smith"
    And I fill in "password" with "secret123"
    And I click "Authorize & Return to OAuth Server"
    Then I should see "Successfully authenticated via OAuth 2.1"
    When I click "⚠️ Simulate Fraud Revocation on Auth Server"
    Then I should see "Simulated Fraud Alert"
