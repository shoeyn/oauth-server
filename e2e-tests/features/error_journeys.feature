Feature: Error Journeys
  Scenario: Simulate Account Locked
    Given I visit the demo client homepage
    When I click "🚀 Start Secure Login (PAR + DPoP + PKCE)"
    Then I should be redirected to the Rails login page
    When I click "🔒 Simulate Account Locked (Client View Override)"
    Then I should see "Access Denied"
    And I should see "access_denied"

  Scenario: Simulate Account Suspended
    Given I visit the demo client homepage
    When I click "🚀 Start Secure Login (PAR + DPoP + PKCE)"
    Then I should be redirected to the Rails login page
    When I click "⛔ Simulate Account Suspended (Library Default View)"
    Then I should see "account_suspended"
