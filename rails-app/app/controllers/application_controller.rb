class ApplicationController < ActionController::Base
  # Protect state-changing requests against Cross-Site Request Forgery (CSRF)
  protect_from_forgery with: :exception
end
