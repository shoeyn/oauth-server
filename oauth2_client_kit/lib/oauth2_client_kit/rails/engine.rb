# frozen_string_literal: true

module OAuth2ClientKit
  class Engine < ::Rails::Engine
    isolate_namespace OAuth2ClientKit

    routes.draw do
      post "/auth/start", to: "auth#start"
      get "/callback", to: "auth#callback"
      post "/auth/refresh", to: "auth#refresh"
      post "/auth/revoke", to: "auth#revoke"
      post "/oidc/backchannel_logout", to: "auth#backchannel_logout"
      post "/auth/simulate_fraud_revocation", to: "auth#simulate_fraud_revocation"
      post "/logout", to: "auth#logout"
    end
  end
end
