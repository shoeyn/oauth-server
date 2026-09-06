class ApplicationController < ActionController::Base
  # Security Improvement: Enforce CSRF protection to stop unauthorized third-party sites from forging requests on behalf of users
  protect_from_forgery with: :exception
end
