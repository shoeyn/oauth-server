require_relative "boot"

require "rails"
require "action_controller/railtie"
require "action_view/railtie"

Bundler.require(*Rails.groups)

module RailsLoginApp
  class Application < Rails::Application
    config.load_defaults 8.0
    config.api_only = false
    config.secret_key_base = ENV.fetch("SECRET_KEY_BASE", "a" * 64)
  end
end
