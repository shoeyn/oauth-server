Feature: Invalid Login
  Scenario: User enters incorrect credentials
    Given I visit the demo client homepage
    When I click "🚀 Start Secure Login (PAR + DPoP + PKCE)"
    Then I should be redirected to the Rails login page
    When I fill in the test user credentials
    And I fill in "Password" with "wrongpassword"
    And I click "Authorize & Return to OAuth Server"
    Then I should see "incorrect username or password"
