# frozen_string_literal: true

module OAuth2ClientKit
  class Engine < ::Rails::Engine
    isolate_namespace OAuth2ClientKit

    # Ensure engine views are included in the host application's lookup paths
    initializer "oauth2_client_kit.view_paths" do |app|
      views_path = File.expand_path("../../../app/views", __dir__)
      ActionController::Base.prepend_view_path(views_path) if defined?(ActionController::Base)
    end

    config.to_prepare do
      require_relative "auth_controller"
    end

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
