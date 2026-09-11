# frozen_string_literal: true

require "securerandom"
require "base64"
require "digest"

module OAuth2ClientKit
  class AuthController < ::ApplicationController
    include OAuth2ClientKit::ControllerMethods

    skip_before_action :verify_authenticity_token, only: [:backchannel_logout], raise: false

    # POST /auth/start
    def start
      flow = params[:flow] == "direct" ? :direct : :par

      pkce = OAuth2ClientKit::Client.generate_pkce_codes
      code_verifier = pkce[:code_verifier]
      code_challenge = pkce[:code_challenge]

      state = SecureRandom.hex(24)
      nonce = SecureRandom.hex(24)
      redirect_uri = oauth_redirect_uri

      dpop_key = OAuth2ClientKit::Client.generate_dpop_key
      dpop_key_pem = dpop_key.to_pem

      session[:oauth_code_verifier] = code_verifier
      session[:oauth_state] = state
      session[:oauth_nonce] = nonce
      session[:oauth_flow] = flow.to_s
      session[:oauth_redirect_uri] = redirect_uri
      session[:oauth_dpop_key] = dpop_key_pem

      # Server-side cache backup for cross-origin cookie edge cases
      if defined?(Rails) && Rails.respond_to?(:cache) && Rails.cache
        Rails.cache.write("oauth_flow:#{state}", {
          code_verifier: code_verifier,
          nonce: nonce,
          flow: flow.to_s,
          redirect_uri: redirect_uri,
          dpop_key: dpop_key_pem
        }, expires_in: 10.minutes)
      end

      client = OAuth2ClientKit.client
      auth_params = {
        response_type: "code",
        client_id: client.id,
        redirect_uri: redirect_uri,
        state: state,
        nonce: nonce,
        code_challenge: code_challenge,
        code_challenge_method: "S256"
      }

      if flow == :par
        begin
          request_uri = client.push_authorization_request(auth_params)
          session[:request_uri] = request_uri
          authorize_url = "#{client.public_issuer_url}/oauth2/authorize?client_id=#{client.id}&request_uri=#{ERB::Util.url_encode(request_uri)}"
          redirect_to authorize_url, allow_other_host: true, status: :see_other
        rescue => e
          flash[:error] = "PAR Initialization Error: #{e.message}"
          redirect_to "/"
        end
      else
        authorize_url = "#{client.public_issuer_url}/oauth2/authorize?#{URI.encode_www_form(auth_params)}"
        redirect_to authorize_url, allow_other_host: true, status: :see_other
      end
    end

    # GET /callback
    def callback
      if params[:error].present?
        return handle_auth_error(params[:error], params[:error_description], params[:error_uri])
      end

      state_param = params[:state]
      cached_flow = Rails.cache.read("oauth_flow:#{state_param}") if defined?(Rails) && Rails.respond_to?(:cache) && Rails.cache && state_param.present?
      Rails.cache.delete("oauth_flow:#{state_param}") if defined?(Rails) && Rails.respond_to?(:cache) && Rails.cache && state_param.present?

      expected_state = session.delete(:oauth_state)
      valid_state = (expected_state.present? && state_param == expected_state) || cached_flow.present?

      unless valid_state
        flash[:error] = "Security Error: State parameter mismatch or expired. Possible CSRF attack."
        return redirect_to "/"
      end

      code = params[:code]
      if code.blank?
        flash[:error] = "OAuth Error: No authorization code received."
        return redirect_to "/"
      end

      client = OAuth2ClientKit.client

      # RFC 9207 Issuer Identification validation
      if params[:iss].present? && params[:iss] != client.public_issuer_url
        flash[:error] = "Security Error: Authorization Server Issuer Identification mismatch (RFC 9207). Expected #{client.public_issuer_url}, got #{params[:iss]}."
        return redirect_to "/"
      end

      code_verifier = session.delete(:oauth_code_verifier) || cached_flow&.dig(:code_verifier)
      expected_nonce = session.delete(:oauth_nonce) || cached_flow&.dig(:nonce)
      flow = session.delete(:oauth_flow) || cached_flow&.dig(:flow) || "par"
      redirect_uri = session.delete(:oauth_redirect_uri) || cached_flow&.dig(:redirect_uri) || oauth_redirect_uri
      dpop_key_pem = session.delete(:oauth_dpop_key) || cached_flow&.dig(:dpop_key)

      begin
        token = client.exchange_code(code, code_verifier, redirect_uri, dpop_key_pem)

        raw_id_token = token.params["id_token"]
        raw_access_token = token.token
        raw_refresh_token = token.refresh_token
        token_type = token.params["token_type"] || "Bearer"

        id_token_claims = client.decode_and_verify_id_token(raw_id_token, expected_nonce, raw_access_token, code)

        access_token_claims = begin
          JWT.decode(raw_access_token, nil, false)[0]
        rescue
          {}
        end

        userinfo_claims = client.fetch_userinfo(raw_access_token, dpop_key_pem)
        returned_scopes = token.params["scope"] || access_token_claims["scope"]

        token_key = SecureRandom.uuid
        OAuth2ClientKit.token_store.write(token_key, {
          access_token_claims: access_token_claims,
          userinfo_claims: userinfo_claims,
          raw_id_token: raw_id_token,
          raw_access_token: raw_access_token,
          raw_refresh_token: raw_refresh_token,
          token_type: token_type,
          dpop_key: dpop_key_pem,
          sub: id_token_claims["sub"],
          sid: id_token_claims["sid"],
          expires_at: access_token_claims["exp"].to_i
        })

        session[:user] = id_token_claims.merge(userinfo_claims)
        session[:id_token_claims] = id_token_claims
        session[:token_key] = token_key
        session[:token_scopes] = returned_scopes
        session[:auth_flow_used] = flow
        session[:raw_id_token] = raw_id_token

        flash[:notice] = "Successfully authenticated via OAuth 2.1 (#{flow.upcase})!"
        redirect_to OAuth2ClientKit.config.after_login_path
      rescue => e
        OAuth2ClientKit.logger.error("Token Exchange Exception: #{e.class}: #{e.message}\n#{e.backtrace&.first(10)&.join("\n")}")
        flash[:error] = "Token Exchange Error: #{e.message}"
        redirect_to "/"
      end
    end

    # POST /auth/refresh
    def refresh
      unless authenticated?
        flash[:error] = "No active session to refresh."
        return redirect_to "/"
      end

      if refresh_token_session!
        flash[:notice] = "Access Token successfully refreshed using Refresh Token (Rotation verified)!"
      else
        flash[:error] = "Token refresh failed. Refresh token may be expired or revoked."
      end
      redirect_to OAuth2ClientKit.config.after_login_path
    end

    # POST /auth/revoke
    def revoke
      token_data = current_token_data
      raw_access_token = token_data[:raw_access_token]
      raw_refresh_token = token_data[:raw_refresh_token]
      client = OAuth2ClientKit.client

      if raw_access_token.present?
        client.revoke_token(raw_access_token, "access_token")
        client.revoke_token(raw_refresh_token, "refresh_token") if raw_refresh_token.present?

        OAuth2ClientKit.token_store.delete(session[:token_key]) if session[:token_key].present?
        reset_session
        flash[:notice] = "Tokens successfully revoked at Authorization Server via RFC 7009! Local session cleared."
      else
        flash[:error] = "No active tokens to revoke."
      end
      redirect_to "/"
    end

    # POST /oidc/backchannel_logout
    def backchannel_logout
      logout_token = params[:logout_token]
      if logout_token.blank?
        render plain: "Missing logout_token", status: :bad_request
        return
      end

      begin
        claims = OAuth2ClientKit.client.verify_logout_token(logout_token)
        sub = claims["sub"]
        sid = claims["sid"]

        OAuth2ClientKit.logger.info("Processing OIDC Back-Channel Logout for sub=#{sub}, sid=#{sid}")
        OAuth2ClientKit.token_store.evict_sessions_for!(sub: sub, sid: sid)

        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        head :ok
      rescue => e
        OAuth2ClientKit.logger.warn("OIDC Back-Channel Logout failed: #{e.message}")
        render plain: "Invalid logout_token: #{e.message}", status: :bad_request
      end
    end

    # POST /auth/simulate_fraud_revocation
    def simulate_fraud_revocation
      token_data = current_token_data
      access_token = token_data[:raw_access_token]
      client = OAuth2ClientKit.client

      if access_token.present?
        begin
          response = client.connection.post("#{client.public_issuer_url}/api/admin/revoke-session") do |req|
            req.headers["Content-Type"] = "application/x-www-form-urlencoded"
            req.headers["X-Admin-Api-Key"] = OAuth2ClientKit.config.admin_api_key
            req.body = URI.encode_www_form({ token: access_token })
          end

          if response.status == 403
            flash[:notice] = "🛡️ Perimeter Isolation Verified: The edge reverse proxy (Nginx) correctly rejected public access to /api/admin/revoke-session with HTTP 403 Forbidden. Administrative operations are isolated from external clients."
          elsif response.status == 200
            flash[:notice] = "⚠️ Simulated Fraud Alert: Authorization Server has revoked your authorization session! Test Introspection or Refresh now to observe immediate rejection."
          else
            flash[:error] = "Administrative revocation returned HTTP #{response.status}: #{response.body}"
          end
        rescue => e
          flash[:error] = "Failed to simulate revocation: #{e.message}"
        end
      end

      redirect_to OAuth2ClientKit.config.after_login_path
    end

    # POST /logout
    def logout
      token_key = session[:token_key]
      token_data = current_token_data
      raw_access_token = token_data[:raw_access_token]
      raw_refresh_token = token_data[:raw_refresh_token]
      id_token_hint = session[:raw_id_token] || token_data[:raw_id_token]
      client = OAuth2ClientKit.client

      client.revoke_token(raw_access_token, "access_token") if raw_access_token.present?
      client.revoke_token(raw_refresh_token, "refresh_token") if raw_refresh_token.present?

      OAuth2ClientKit.token_store.delete(token_key) if token_key.present?
      reset_session

      if id_token_hint.present?
        post_logout_redirect = "#{request.protocol}#{request.host_with_port}#{OAuth2ClientKit.config.after_logout_path}"
        oidc_logout_url = client.end_session_url(id_token_hint, post_logout_redirect)
        redirect_to oidc_logout_url, allow_other_host: true, status: :see_other
      else
        flash[:notice] = "You have been logged out."
        redirect_to "/"
      end
    end

    private

    # Handles OAuth 2.1 authentication errors:
    # 1. Specific error template (e.g. app/views/oauth2_client_kit/auth/access_denied.html.erb)
    # 2. General error fallback template (app/views/oauth2_client_kit/auth/error.html.erb)
    def handle_auth_error(error_code, error_description = nil, error_uri = nil)
      @error = error_code.to_s.strip
      @error_description = error_description.to_s.strip if error_description.present?
      @error_uri = error_uri.to_s.strip if error_uri.present?

      OAuth2ClientKit.logger.warn("OAuth Callback Error encountered: error=#{@error}, description=#{@error_description}")

      status = case @error
               when "access_denied", "unauthorized_client"
                 :forbidden # 403
               when "login_required", "interaction_required", "account_selection_required"
                 :unauthorized # 401
               else
                 :bad_request # 400
               end

      sanitized_error = @error.gsub(/[^a-zA-Z0-9_\-]/, "")
      specific_template = "oauth2_client_kit/auth/#{sanitized_error}"

      template_to_render = lookup_context.exists?(specific_template) ? specific_template : "oauth2_client_kit/auth/error"
      render template_to_render, status: status
    end
  end
end
