Rails.application.routes.draw do
  get "/login", to: "sessions#new"
  post "/login", to: "sessions#create"
  get "/health", to: "sessions#health"
  get "/logout", to: "sessions#destroy"
  root to: "sessions#new"
end
