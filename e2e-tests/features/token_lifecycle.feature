Feature: Token Lifecycle Management
  Background:
    Given I visit the demo client homepage
    When I click "🚀 Start Secure Login (PAR + DPoP + PKCE)"
    When I fill in the test user credentials
    And I click "Authorize & Return to OAuth Server"
    Then I should see "Successfully authenticated via OAuth 2.1"

  Scenario: Refresh Access Token
    When I click "🔄 Refresh Access Token (Rotation)"
    Then I should see "Access Token successfully refreshed"

  Scenario: Perform Sensitive Action (Introspection)
    When I click "🛡️ Perform Sensitive Action (Introspection Guard)"
    Then I should see "Sensitive Action Approved! Token Introspection verified active=true"

  Scenario: Revoke Tokens
    When I click "🛑 Revoke Tokens (RFC 7009)"
    Then I should see "Tokens successfully revoked at Authorization Server via RFC 7009!"
