# frozen_string_literal: true

module OAuth2ClientKit
  module Routing
    module RouteSetExtension
      def mount_oauth2_client_kit(at: "")
        post "#{at}/auth/start", to: "oauth2_client_kit/auth#start", as: :auth_start
        get "#{at}/callback", to: "oauth2_client_kit/auth#callback", as: :auth_callback
        post "#{at}/auth/refresh", to: "oauth2_client_kit/auth#refresh", as: :auth_refresh
        post "#{at}/auth/revoke", to: "oauth2_client_kit/auth#revoke", as: :auth_revoke
        post "#{at}/oidc/backchannel_logout", to: "oauth2_client_kit/auth#backchannel_logout", as: :oidc_backchannel_logout
        post "#{at}/auth/simulate_fraud_revocation", to: "oauth2_client_kit/auth#simulate_fraud_revocation", as: :auth_simulate_fraud_revocation
        post "#{at}/logout", to: "oauth2_client_kit/auth#logout", as: :logout
      end
    end
  end
end

if defined?(ActionDispatch::Routing::Mapper)
  ActionDispatch::Routing::Mapper.include(OAuth2ClientKit::Routing::RouteSetExtension)
end
