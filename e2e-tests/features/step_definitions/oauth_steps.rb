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

Then("I should not see {string}") do |content|
  expect(page).not_to have_content(content)
end

When("I fill in the test user credentials") do
  fill_in "Email Address", with: @test_email
  fill_in "Password", with: @test_password
end

When("I flag the test user as fraud") do
  uri = URI("http://localhost:9001/api/admin/users/#{@test_email}/fraud")
  req = Net::HTTP::Post.new(uri)
  req['X-Admin-Api-Key'] = 'secret-admin-key'
  res = Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
  expect(res).to be_a(Net::HTTPSuccess)
end
