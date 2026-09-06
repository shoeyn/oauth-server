Rails.application.routes.draw do
  root to: "auth#index"
  post "/auth/start", to: "auth#start"
  get "/callback", to: "auth#callback"
  get "/profile", to: "auth#profile"
  post "/auth/refresh", to: "auth#refresh"
  post "/auth/sensitive_action", to: "auth#sensitive_action"
  post "/auth/simulate_fraud_revocation", to: "auth#simulate_fraud_revocation"
  post "/auth/revoke", to: "auth#revoke"
  post "/oidc/backchannel_logout", to: "auth#backchannel_logout"
  post "/logout", to: "auth#logout"
  get "/health", to: proc { [200, { "Content-Type" => "application/json" }, ['{"status":"UP","service":"demo-client"}']] }
end
