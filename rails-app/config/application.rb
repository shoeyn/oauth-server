# frozen_string_literal: true

require_relative 'boot'

require 'rails'
require 'action_controller/railtie'
require 'action_view/railtie'
require 'uri'

Bundler.require(*Rails.groups)

module RailsLoginApp
  # Rails application configuration for the external authentication IdP.
  class Application < Rails::Application
    config.load_defaults 8.0
    config.api_only = false
    config.secret_key_base = ENV.fetch('SECRET_KEY_BASE', 'a' * 64)

    config.x.auth_server.allowed_return_hosts = lambda {
      hosts = Set.new
      [ENV.fetch('AUTH_SERVER_URL', nil), ENV.fetch('SPRING_AUTH_SERVER_URL', nil)].compact.each do |url|
        uri = begin
          URI.parse(url)
        rescue StandardError
          nil
        end
        next unless uri

        hosts << "#{uri.host}:#{uri.port}" if uri.host && uri.port
        hosts << uri.host if uri.host
      end
      if ENV['ALLOWED_RETURN_HOSTS'].present?
        ENV['ALLOWED_RETURN_HOSTS'].split(',').map(&:strip).each { |h| hosts << h }
      end
      hosts.freeze
    }.call
  end
end
