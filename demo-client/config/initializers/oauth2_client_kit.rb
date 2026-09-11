# frozen_string_literal: true

require "oauth2_client_kit"

OAuth2ClientKit.configure do |config|
  config.client_id = "demo-client"
  config.private_key_path = ENV.fetch("CLIENT_PRIVATE_KEY_PATH", Rails.root.join("keys/client_private_key.pem").to_s)
  config.issuer_url = ENV.fetch("AUTH_SERVER_URL", "http://localhost:9000")
  config.internal_issuer_url = ENV.fetch("AUTH_SERVER_URL_INTERNAL", config.issuer_url)
  config.redis_url = ENV.fetch("REDIS_URL", "redis://localhost:6379/1")
  config.admin_api_key = ENV.fetch("ADMIN_API_KEY", "secret-admin-key")
  config.after_login_path = "/profile"
  config.after_logout_path = "/"
end
