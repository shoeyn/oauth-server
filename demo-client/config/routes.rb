Rails.application.routes.draw do
  root to: "pages#index"
  get "/profile", to: "pages#profile"
  post "/auth/sensitive_action", to: "pages#sensitive_action"
  get "/health", to: proc { [200, { "Content-Type" => "application/json" }, ['{"status":"UP","service":"demo-client"}']] }

  # Mount all standard OAuth 2.1 & OIDC endpoints from the oauth2_client_kit library
  mount_oauth2_client_kit
end
