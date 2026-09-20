# frozen_string_literal: true

require_relative 'path_helpers'
require_relative 'session_readers'
require_relative 'session_lifecycle'

module OAuth2ClientKit
  # Controller methods mixed into Rails controllers for accessing authenticated session
  # state, token inspection, and pre-flight identity checkpoints.
  module ControllerMethods
    extend ActiveSupport::Concern if defined?(ActiveSupport::Concern)
    include PathHelpers
    include SessionReaders
    include SessionLifecycle

    included do
      before_action :validate_session_and_refresh_tokens! if respond_to?(:before_action)

      if respond_to?(:helper_method)
        helper_method :current_user, :authenticated?, :current_access_token,
                      :current_raw_id_token, :current_raw_refresh_token, :current_token_data,
                      :current_token_scopes, :current_auth_flow, :current_token_expires_at,
                      :current_token_type, :current_id_token_claims, :current_userinfo_claims,
                      :current_access_token_claims, :oauth_redirect_uri, :auth_start_path,
                      :auth_refresh_path, :auth_revoke_path, :logout_path, :callback_path
      end
    end

    def require_authentication?
      unless authenticated?
        flash[:error] = 'Please log in first.'
        redirect_to '/' and return false
      end
      true
    end
    alias require_authentication! require_authentication?

    # Auto-renews access token using Refresh Token if expiring within 60 seconds
    def ensure_fresh_access_token!
      token_data = current_token_data
      expires_at = token_data[:expires_at].to_i

      return true unless expires_at.positive? && (expires_at - Time.now.to_i) <= 60

      refresh_token_session!
    end

    def refresh_token_session!
      token_key = session[:token_key]
      token_data = OAuth2ClientKit.token_store.read(token_key) || {}
      if token_data[:raw_refresh_token].blank?
        force_sign_out_session!(reason: 'No refresh token available for session refresh')
        return false
      end

      refreshed = execute_token_refresh(token_key, token_data)
      force_sign_out_session!(reason: 'Token refresh execution failed') unless refreshed
      refreshed
    end

    def identity_checkpoint!
      return { active: false, reason: 'unauthenticated' } unless session_has_auth_markers?

      raw_token = current_token_data[:raw_access_token]
      if raw_token.blank?
        force_sign_out_session!(reason: 'Missing access token during identity checkpoint')
        return { active: false, reason: 'missing_access_token' }
      end

      return { active: false, reason: 'unauthenticated' } unless authenticated?

      evaluate_identity_checkpoint(raw_token)
    end

    alias validate_user! identity_checkpoint!
    alias verify_active_token_for_sensitive_action! identity_checkpoint!

    private

    def execute_token_refresh(token_key, token_data)
      new_token = OAuth2ClientKit.client.refresh_access_token(
        token_data[:raw_refresh_token], token_data[:dpop_key]
      )
      updated = build_refreshed_token_data(token_data, new_token)
      OAuth2ClientKit.token_store.write(token_key, updated)
      true
    rescue StandardError => e
      OAuth2ClientKit.logger.warn("Automatic token refresh failed: #{e.message}")
      false
    end

    def build_refreshed_token_data(token_data, new_token)
      access_token = new_token.token
      claims = decode_token_payload(access_token)
      token_data.merge(
        raw_access_token: access_token,
        raw_refresh_token: new_token.refresh_token || token_data[:raw_refresh_token],
        token_type: new_token.params['token_type'] || token_data[:token_type] || 'Bearer',
        access_token_claims: claims, expires_at: claims['exp'].to_i
      )
    end

    def decode_token_payload(token)
      JWT.decode(token, nil, false)[0]
    rescue StandardError
      {}
    end

    def evaluate_identity_checkpoint(raw_token)
      result = OAuth2ClientKit.client.verify_active!(raw_token)
      return result if result[:active]

      force_sign_out_session!(reason: 'Token revoked or inactive during identity checkpoint')
      result
    end
  end
end
