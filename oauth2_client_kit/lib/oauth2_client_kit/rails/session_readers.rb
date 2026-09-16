# frozen_string_literal: true

module OAuth2ClientKit
  # Helper methods for accessing token claims and session data.
  module SessionReaders
    def current_user
      session[:user]
    end

    def authenticated?
      session[:user].present? && session[:token_key].present?
    end

    def current_token_data
      return {} unless session[:token_key].present?

      OAuth2ClientKit.token_store.read(session[:token_key]) || {}
    end

    def current_access_token
      current_token_data[:raw_access_token]
    end

    def current_raw_id_token
      session[:raw_id_token] || current_token_data[:raw_id_token]
    end

    def current_raw_refresh_token
      current_token_data[:raw_refresh_token]
    end

    def current_token_scopes
      session[:token_scopes]
    end

    def current_auth_flow
      session[:auth_flow_used] || 'PAR'
    end

    def current_token_expires_at
      current_token_data[:expires_at]
    end

    def current_token_type
      current_token_data[:token_type] || 'Bearer'
    end

    def current_id_token_claims
      session[:id_token_claims] || {}
    end

    def current_userinfo_claims
      current_token_data[:userinfo_claims] || {}
    end

    def current_access_token_claims
      current_token_data[:access_token_claims] || {}
    end

    def oauth_redirect_uri
      "#{request.protocol}#{request.host_with_port}/callback"
    end
  end
end
