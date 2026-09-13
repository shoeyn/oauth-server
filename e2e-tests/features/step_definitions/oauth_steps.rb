Given("I visit the demo client homepage") do
  visit '/'
end

When("I click {string}") do |button_text|
  click_on button_text
end

Then("I should be redirected to the Rails login page") do
  expect(page).to have_current_path(/http:\/\/localhost:3000\/login/, url: true)
end

When("I fill in {string} with {string}") do |field, value|
  fill_in field, with: value
end

Then("I should be redirected to the user profile page") do
  expect(page).to have_current_path('/profile')
end

Then("I should see {string}") do |content|
  expect(page).to have_content(content)
end
