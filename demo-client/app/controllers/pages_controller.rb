# frozen_string_literal: true

# Controller providing landing, user profile, and sensitive action demo endpoints
# leveraging OAuth2ClientKit session and token methods.
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

    assign_profile_variables
  end

  # POST /auth/sensitive_action
  # Demonstrates pre-flight Identity Checkpoint (introspection) before sensitive business actions
  def sensitive_action
    require_authentication! or return

    checkpoint = identity_checkpoint!
    @introspection_result = checkpoint[:claims]

    handle_checkpoint_result(checkpoint)
  end

  private

  def assign_profile_variables
    @user = current_user
    @id_token_claims = current_id_token_claims
    @token_scopes = current_token_scopes
    @userinfo_claims = current_userinfo_claims
    @access_token_claims = current_access_token_claims
    assign_token_metadata
  end

  def assign_token_metadata
    @raw_id_token = current_raw_id_token
    @raw_access_token = current_access_token
    @raw_refresh_token = current_raw_refresh_token
    @auth_flow = current_auth_flow
    @expires_at = current_token_expires_at
    @token_type = current_token_type
    @dpop_jkt = @access_token_claims.dig('cnf', 'jkt')
  end

  def handle_checkpoint_result(checkpoint)
    if checkpoint[:active]
      flash[:notice] =
        "🛡️ Sensitive Action Approved! Token Introspection verified active=true (Subject: #{checkpoint[:sub]})."
      redirect_to '/profile'
    else
      flash[:error] = I18n.t('pages.sensitive_action.alert_revoked')
      redirect_to '/'
    end
  end
end
