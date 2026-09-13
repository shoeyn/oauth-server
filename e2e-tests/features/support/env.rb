require 'capybara/cucumber'
require 'capybara/cuprite'
require 'rspec/expectations'

Capybara.register_driver :cuprite do |app|
  Capybara::Cuprite::Driver.new(app, window_size: [1200, 800], headless: true)
end

Capybara.default_driver = :cuprite
Capybara.javascript_driver = :cuprite

# We are testing external running services (Demo Client is on 8080)
Capybara.app_host = 'http://localhost:8080'
Capybara.run_server = false
