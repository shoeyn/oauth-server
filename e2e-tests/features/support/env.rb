# frozen_string_literal: true

require 'capybara/cucumber'
require 'capybara/cuprite'
require 'rspec/expectations'

Capybara.register_driver :cuprite do |app|
  options = {
    window_size: [1200, 800],
    headless: true
  }

  if ENV['ZAP_PROXY'] == 'true'
    zap_host = ENV.fetch('ZAP_HOST', '127.0.0.1')
    zap_port = ENV.fetch('ZAP_PORT', '8090')
    options[:browser_options] = {
      'proxy-server' => "http://#{zap_host}:#{zap_port}",
      'proxy-bypass-list' => '<-loopback>',
      'ignore-certificate-errors' => nil,
      'disable-background-networking' => nil,
      'disable-component-update' => nil,
      'disable-sync' => nil,
      'disable-default-apps' => nil
    }
  end

  Capybara::Cuprite::Driver.new(app, **options)
end

Capybara.default_driver = :cuprite
Capybara.javascript_driver = :cuprite
Capybara.default_max_wait_time = 6

# We are testing external running services (Demo Client is on 8080)
Capybara.app_host = ENV.fetch('APP_HOST', 'http://localhost:8080')
Capybara.run_server = false
