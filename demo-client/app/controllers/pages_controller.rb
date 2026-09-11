# frozen_string_literal: true

class PagesController < ApplicationController
  include OAuth2ClientKit::ControllerMethods

  # GET /
  def index
    session[:initialized] ||= true

    @auth_server_url = OAuth2ClientKit.config.issuer_url
    @client_id = OAuth2ClientKit.config.client_id
    @redirect_uri = oauth_redirect_uri
    @authenticated = authenticated?
  end

  # GET /profile
  def profile
    require_authentication! or return

    token_data = current_token_data
    if token_data.blank? || token_data[:raw_access_token].blank?
      reset_session
      flash[:error] = "Session tokens have expired or are unavailable. Please log in again."
      return redirect_to "/"
    end

    ensure_fresh_access_token!
    token_data = current_token_data

    @user = current_user
    @id_token_claims = current_id_token_claims
    @token_scopes = current_token_scopes
    @userinfo_claims = current_userinfo_claims
    @access_token_claims = current_access_token_claims
    @raw_id_token = current_raw_id_token
    @raw_access_token = current_access_token
    @raw_refresh_token = current_raw_refresh_token
    @auth_flow = current_auth_flow
    @expires_at = current_token_expires_at
    @token_type = current_token_type
    @dpop_jkt = @access_token_claims.dig("cnf", "jkt")
  end

  # POST /auth/sensitive_action
  # Demonstrates pre-flight Identity Checkpoint (introspection) before sensitive business actions (e.g. payments)
  def sensitive_action
    require_authentication! or return

    # Pre-flight Identity Checkpoint:
    # Verifies with the Authorization Server via RFC 7662 Introspection that the token is still active and valid.
    # If the session was revoked early at the AS, identity_checkpoint! clears local state immediately.
    checkpoint = identity_checkpoint!
    @introspection_result = checkpoint[:claims]

    if checkpoint[:active]
      flash[:notice] = "🛡️ Sensitive Action Approved! Token Introspection verified active=true (Subject: #{checkpoint[:sub]})."
    else
      flash[:error] = "🚨 SECURITY ALERT: Token Introspection check returned active=false. Authorization Server terminated the session early. Local session cleared."
      return redirect_to "/"
    end

    redirect_to "/profile"
  end
end
