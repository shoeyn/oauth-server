# frozen_string_literal: true

module OAuth2ClientKit
  # Renders OAuth error responses with appropriate HTTP status codes and templates.
  module AuthErrorRenderer
    def handle_auth_error(error_code, error_description = nil, error_uri = nil)
      @error = error_code.to_s.strip
      @error_description = error_description.to_s.strip if error_description.present?
      @error_uri = error_uri.to_s.strip if error_uri.present?
      OAuth2ClientKit.logger.warn("OAuth Callback Error: error=#{@error}, description=#{@error_description}")

      status = resolve_error_status(@error)
      render resolve_error_template(@error), status: status
    end

    private

    def resolve_error_status(error)
      case error
      when 'access_denied', 'unauthorized_client'
        :forbidden
      when 'login_required', 'interaction_required', 'account_selection_required'
        :unauthorized
      else
        :bad_request
      end
    end

    def resolve_error_template(error)
      specific = "oauth2_client_kit/auth/#{error.gsub(/[^a-zA-Z0-9_-]/, '')}"
      lookup_context.exists?(specific) ? specific : 'oauth2_client_kit/auth/error'
    end
  end
end
