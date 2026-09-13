Feature: OAuth 2.1 Authorization Flow

  Scenario: User successfully logs in via the Rails IdP and completes the PAR/DPoP flow
    Given I visit the demo client homepage
    When I click "🚀 Start Secure Login (PAR + DPoP + PKCE)"
    Then I should be redirected to the Rails login page
    When I fill in "username" with "alice_smith"
    And I fill in "password" with "secret123"
    And I click "Authorize & Return to OAuth Server"
    Then I should be redirected to the user profile page
    And I should see "Successfully authenticated via OAuth 2.1"
