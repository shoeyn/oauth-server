# frozen_string_literal: true

module OAuth2ClientKit
  module ControllerMethods
    extend ActiveSupport::Concern if defined?(ActiveSupport::Concern)

    included do
      if respond_to?(:helper_method)
        helper_method :current_user,
                      :authenticated?,
                      :current_access_token,
                      :current_raw_id_token,
                      :current_raw_refresh_token,
                      :current_token_data,
                      :current_token_scopes,
                      :current_auth_flow,
                      :current_token_expires_at,
                      :current_token_type,
                      :current_id_token_claims,
                      :current_userinfo_claims,
                      :current_access_token_claims,
                      :oauth_redirect_uri,
                      :auth_start_path,
                      :auth_refresh_path,
                      :auth_revoke_path,
                      :auth_simulate_fraud_revocation_path,
                      :logout_path,
                      :callback_path
      end
    end

    def auth_start_path(params = {})
      "/auth/start" + (params.any? ? "?#{URI.encode_www_form(params)}" : "")
    end

    def auth_refresh_path
      "/auth/refresh"
    end

    def auth_revoke_path
      "/auth/revoke"
    end

    def auth_simulate_fraud_revocation_path
      "/auth/simulate_fraud_revocation"
    end

    def logout_path
      "/logout"
    end

    def callback_path
      "/callback"
    end

    def current_user
      session[:user]
    end

    def authenticated?
      session[:user].present? && session[:token_key].present?
    end

    def require_authentication!
      unless authenticated?
        flash[:error] = "Please log in first."
        redirect_to "/" and return false
      end
      true
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
      session[:auth_flow_used] || "PAR"
    end

    def current_token_expires_at
      current_token_data[:expires_at]
    end

    def current_token_type
      current_token_data[:token_type] || "Bearer"
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

    # Auto-renews access token using Refresh Token if expiring within 60 seconds
    def ensure_fresh_access_token!
      token_data = current_token_data
      expires_at = token_data[:expires_at].to_i

      if expires_at > 0 && (expires_at - Time.now.to_i) <= 60
        refresh_token_session!
      end
    end

    def refresh_token_session!
      token_key = session[:token_key]
      token_data = OAuth2ClientKit.token_store.read(token_key) || {}
      refresh_token = token_data[:raw_refresh_token]
      dpop_key = token_data[:dpop_key]
      return false if refresh_token.blank?

      begin
        new_token = OAuth2ClientKit.client.refresh_access_token(refresh_token, dpop_key)
        new_access_token = new_token.token
        new_refresh_token = new_token.refresh_token || refresh_token
        new_token_type = new_token.params["token_type"] || token_data[:token_type] || "Bearer"

        new_access_claims = begin
          JWT.decode(new_access_token, nil, false)[0]
        rescue
          {}
        end

        updated = token_data.merge(
          raw_access_token: new_access_token,
          raw_refresh_token: new_refresh_token,
          token_type: new_token_type,
          access_token_claims: new_access_claims,
          expires_at: new_access_claims["exp"].to_i
        )

        OAuth2ClientKit.token_store.write(token_key, updated)
        true
      rescue => e
        OAuth2ClientKit.logger.warn("Automatic token refresh failed: #{e.message}")
        false
      end
    end

    # ==============================================================================
    # Identity Checkpoint (Pre-flight Introspection)
    # ==============================================================================
    # Executes RFC 7662 Token Introspection before sensitive business actions
    # (e.g. payments, transfers, privileged operations) to verify if the session
    # is still valid at the Authorization Server or has been terminated early.
    # If the token was revoked, evicts the local session immediately.
    #
    # @return [Hash] { active: Boolean, sub: String, reason: String, claims: Hash }
    def identity_checkpoint!
      unless authenticated?
        return { active: false, reason: "unauthenticated" }
      end

      token_data = current_token_data
      raw_token = token_data[:raw_access_token]

      if raw_token.blank?
        reset_session
        return { active: false, reason: "missing_access_token" }
      end

      result = OAuth2ClientKit.client.verify_active!(raw_token)

      if result[:active]
        result
      else
        # Token is revoked or invalid: evict local session immediately to protect user
        OAuth2ClientKit.token_store.delete(session[:token_key]) if session[:token_key].present?
        reset_session
        result
      end
    end

    # Expressive aliases for developers
    alias_method :validate_user!, :identity_checkpoint!
    alias_method :verify_active_token_for_sensitive_action!, :identity_checkpoint!
  end
end
