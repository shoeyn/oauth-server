require_relative "boot"

require "rails"
require "action_controller/railtie"
require "action_view/railtie"

Bundler.require(*Rails.groups)

module DemoClientApp
  class Application < Rails::Application
    config.load_defaults 7.1
    config.api_only = false
    config.secret_key_base = ENV.fetch("SECRET_KEY_BASE", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    config.autoload_paths += %W(#{config.root}/app/services)
    # Persistence Improvement: Store all cache entries (tokens, OAuth flow states) in Redis
    config.cache_store = :redis_cache_store, {
      url: ENV.fetch("REDIS_URL", "redis://localhost:6379/1"),
      namespace: "demo_client",
      connect_timeout: 3,
      read_timeout: 3,
      write_timeout: 3
    }

    # Security & Persistence Improvement: Store client sessions in Redis (via CacheStore)
    # 1. httponly: true -> Stop malicious scripts from accessing session cookies via XSS
    # 2. same_site: :lax -> Prevent CSRF attacks on cross-site requests
    # 3. secure: false (for HTTP localhost PoC) or enabled via SECURE_COOKIES env var
    config.session_store :cache_store,
      key: "_demo_client_session",
      httponly: true,
      same_site: :lax,
      secure: ENV["SECURE_COOKIES"] == "true"
  end
end
