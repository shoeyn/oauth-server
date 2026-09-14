Feature: Fraud flag terminates the flagged user's active session
  # Regression guard: flagging a user as fraud MUST revoke that user's active sessions and
  # authorizations. This broke previously because revocation was performed by email while
  # sessions/authorizations are keyed by the user's id. This end-to-end scenario exercises the
  # real controller -> UserSessionRevocationService -> Redis chain that a unit test cannot.

  Background:
    Given I visit the demo client homepage
    When I click "🚀 Start Secure Login (PAR + DPoP + PKCE)"
    When I fill in the test user credentials
    And I click "Authorize & Return to OAuth Server"
    Then I should see "Successfully authenticated via OAuth 2.1"

  Scenario: Flagging the logged-in user as fraud revokes their session
    # Sanity: the freshly authenticated user can perform an introspection-guarded action.
    When I click "🛡️ Perform Sensitive Action (Introspection Guard)"
    Then I should see "Sensitive Action Approved! Token Introspection verified active=true"

    # Flag the user as fraud via the admin API (terminates sessions + purges authorizations).
    When I flag the test user as fraud

    # The previously-valid session must now be dead: the introspection guard should report the
    # token is no longer active, proving the fraud flag actually revoked THIS user's session.
    When I click "🛡️ Perform Sensitive Action (Introspection Guard)"
    Then I should not see "Token Introspection verified active=true"
