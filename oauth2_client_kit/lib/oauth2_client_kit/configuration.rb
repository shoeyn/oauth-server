# frozen_string_literal: true

require 'openssl'

module OAuth2ClientKit
  # Configuration settings for OAuth2ClientKit including client credentials and endpoints.
  class Configuration
    attr_accessor :client_id,
                  :private_key,
                  :private_key_path,
                  :issuer_url,
                  :internal_issuer_url,
                  :redis_url,
                  :token_cache_ttl,
                  :admin_api_key,
                  :after_login_path,
                  :after_logout_path

    def initialize
      @client_id = ENV['CLIENT_ID'] || ENV.fetch('OAUTH2_CLIENT_ID', nil)
      @issuer_url = ENV.fetch('AUTH_SERVER_URL', 'http://localhost:9000')
      internal_env = ENV.fetch('AUTH_SERVER_URL_INTERNAL', nil)
      @internal_issuer_url = internal_env && !internal_env.empty? ? internal_env : @issuer_url
      @redis_url = ENV.fetch('REDIS_URL', 'redis://localhost:6379/1')
      @token_cache_ttl = 30 * 24 * 60 * 60 # 30 days
      @admin_api_key = ENV.fetch('ADMIN_API_KEY', nil)
      @after_login_path = '/profile'
      @after_logout_path = '/'
    end

    def resolved_private_key_pem
      if private_key.present?
        private_key.is_a?(OpenSSL::PKey::RSA) ? private_key.to_pem : private_key.to_s
      elsif private_key_path.present? && File.exist?(private_key_path)
        File.read(private_key_path)
      end
    end
  end
end
