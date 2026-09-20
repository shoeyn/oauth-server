# frozen_string_literal: true

require 'logger'
require_relative 'oauth2_client_kit/version'
require_relative 'oauth2_client_kit/configuration'
require_relative 'oauth2_client_kit/client'
require_relative 'oauth2_client_kit/token_store'

# Main entrypoint and configuration provider for the OAuth2ClientKit gem.
module OAuth2ClientKit
  class << self
    attr_writer :config, :logger

    def config
      @config ||= Configuration.new
    end

    def configure
      yield(config)
    end

    def client
      validate_client_config!

      @client ||= Client.new(
        config.client_id,
        config.resolved_private_key_pem,
        public_issuer_url: config.issuer_url,
        internal_issuer_url: config.internal_issuer_url
      )
    end

    def reset_client!
      @client = nil
    end

    def token_store
      @token_store ||= TokenStore.new(config.redis_url)
    end

    def logger
      @logger ||= if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
                    Rails.logger
                  else
                    Logger.new($stdout, level: Logger::INFO)
                  end
    end

    private

    def validate_client_config!
      validate_client_id!
      validate_private_key!
    end

    def validate_client_id!
      return if config.client_id.to_s.strip.length.positive?

      raise ArgumentError,
            'OAuth2ClientKit client_id is not configured. Please configure config.client_id in your initializer.'
    end

    def validate_private_key!
      return if config.resolved_private_key_pem.to_s.strip.length.positive?

      raise ArgumentError,
            'OAuth2ClientKit private_key is not configured. ' \
            'Please configure config.private_key or config.private_key_path in your initializer.'
    end
  end
end

if defined?(Rails)
  if defined?(ActiveSupport::Inflector)
    ActiveSupport::Inflector.inflections(:en) do |inflect|
      inflect.acronym 'OAuth2'
    end
  end
  require_relative 'oauth2_client_kit/rails/path_helpers'
  require_relative 'oauth2_client_kit/rails/session_readers'
  require_relative 'oauth2_client_kit/rails/session_lifecycle'
  require_relative 'oauth2_client_kit/rails/auth_flow_helper'
  require_relative 'oauth2_client_kit/rails/auth_error_renderer'
  require_relative 'oauth2_client_kit/rails/controller_methods'
  require_relative 'oauth2_client_kit/rails/routes'
  require_relative 'oauth2_client_kit/rails/engine'
  require_relative 'oauth2_client_kit/rails/railtie'
end
