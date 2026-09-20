# frozen_string_literal: true

module OAuth2ClientKit
  # Manages automated session validation, token freshness checks, and forced sign-out on expiry.
  module SessionLifecycle
    # Automatic page-load filter: verifies session tokens, auto-refreshes expiring tokens,
    # and forces sign-out if tokens are missing, expired without refresh token, or refresh fails.
    def validate_session_and_refresh_tokens!
      return unless session_has_auth_markers?

      token_key = session[:token_key]
      token_data = token_key.present? ? OAuth2ClientKit.token_store.read(token_key) : nil

      if token_data.blank? || token_data[:raw_access_token].blank?
        force_sign_out_session!(reason: 'Session token data missing or evicted')
        return
      end

      check_and_refresh_expiring_token(token_key, token_data)
    end

    def force_sign_out_session!(reason: nil)
      OAuth2ClientKit.logger.warn("[OAuth2ClientKit] Forcing session sign-out: #{reason}") if reason

      token_key = session[:token_key]
      delete_token_store_entry(token_key) if token_key.present?
      clear_application_session
    end

    private

    def session_has_auth_markers?
      session[:user].present? || session[:token_key].present?
    end

    def check_and_refresh_expiring_token(token_key, token_data)
      expires_at = token_data[:expires_at].to_i
      return unless expires_at.positive? && (expires_at - Time.now.to_i) <= 60

      if token_data[:raw_refresh_token].blank?
        force_sign_out_session!(reason: 'Access token expired with no refresh token')
        return
      end

      refreshed = execute_token_refresh(token_key, token_data)
      force_sign_out_session!(reason: 'Automatic token refresh failed') unless refreshed
    end

    def delete_token_store_entry(token_key)
      OAuth2ClientKit.token_store.delete(token_key)
    rescue StandardError => e
      OAuth2ClientKit.logger.warn("[OAuth2ClientKit] Failed to delete token store entry: #{e.message}")
    end

    def clear_application_session
      reset_session if respond_to?(:reset_session)
      %i[user token_key raw_id_token id_token_claims token_scopes auth_flow_used].each do |k|
        session.delete(k)
      end
    end
  end
end
