require_relative "boot"

require "rails"
require "action_controller/railtie"
require "action_view/railtie"
require "uri"
require "set"

Bundler.require(*Rails.groups)

module RailsLoginApp
  class Application < Rails::Application
    config.load_defaults 8.0
    config.api_only = false
    config.secret_key_base = ENV.fetch("SECRET_KEY_BASE", "a" * 64)

    config.x.auth_server.allowed_return_hosts = -> {
      hosts = Set.new
      [ENV["AUTH_SERVER_URL"], ENV["SPRING_AUTH_SERVER_URL"]].compact.each do |url|
        uri = URI.parse(url) rescue nil
        next unless uri
        hosts << "#{uri.host}:#{uri.port}" if uri.host && uri.port
        hosts << uri.host if uri.host
      end
      if ENV["ALLOWED_RETURN_HOSTS"].present?
        ENV["ALLOWED_RETURN_HOSTS"].split(",").map(&:strip).each { |h| hosts << h }
      end
      hosts.freeze
    }.call
  end
end
