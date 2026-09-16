# frozen_string_literal: true

# Base controller for Demo Client application.
class ApplicationController < ActionController::Base
  # Security Improvement: Enforce CSRF protection on state-changing requests
  protect_from_forgery with: :exception
end
