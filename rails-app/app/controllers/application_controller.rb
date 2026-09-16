# frozen_string_literal: true

# Base controller for Rails Identity Provider application.
class ApplicationController < ActionController::Base
  # Protect state-changing requests against Cross-Site Request Forgery (CSRF)
  protect_from_forgery with: :exception
end
