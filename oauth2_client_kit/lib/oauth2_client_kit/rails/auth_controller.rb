# frozen_string_literal: true

require 'securerandom'
require 'base64'
require 'digest'
require_relative 'auth_flow_helper'
require_relative 'auth_error_renderer'

module OAuth2ClientKit
  # Mountable controller providing standard OAuth 2.1 routes: start, callback, refresh, revoke, and logout.
  class AuthController < ::ApplicationController
    include OAuth2ClientKit::ControllerMethods
    include OAuth2ClientKit::AuthFlowHelper
    include OAuth2ClientKit::AuthErrorRenderer

    skip_before_action :verify_authenticity_token, only: [:backchannel_logout], raise: false
    skip_before_action :validate_session_and_refresh_tokens!,
                       only: %i[start callback backchannel_logout], raise: false

    rescue_from ActionController::InvalidAuthenticityToken do |exception|
      raise exception unless action_name == 'start'

      logger.info('[OAuth2ClientKit] Stale CSRF token on auth start. Resetting session and initiating fresh login.')
      reset_session
      start
    end

    def start
      flow = params[:flow] == 'direct' ? :direct : :par
      state_data = initialize_auth_state(flow)
      persist_auth_session(state_data)
      dispatch_auth_redirect(OAuth2ClientKit.client, flow, state_data)
    end

    def callback
      client = OAuth2ClientKit.client
      jarm = validate_jarm_response(client)
      return if performed?
      return redirect_to '/' unless jarm
      return redirect_to '/' unless valid_callback_context?(client, jarm)

      cached = pop_cached_flow(jarm['state'])
      complete_code_exchange(client, jarm, cached)
    end

    def refresh
      return redirect_unauthenticated unless authenticated?

      if refresh_token_session!
        handle_successful_refresh
      else
        handle_failed_refresh
      end
    end

    def redirect_unauthenticated
      redirect_with_error('No active session to refresh.')
    end

    def handle_successful_refresh
      flash[:notice] = 'Access Token successfully refreshed using Refresh Token (Rotation verified)!'
      redirect_to OAuth2ClientKit.config.after_login_path
    end

    def handle_failed_refresh
      force_sign_out_session!(reason: 'Manual token refresh failed')
      redirect_with_error('Token refresh failed. Your session has expired, please log in again.')
    end

    def revoke
      token_data = current_token_data
      if token_data[:raw_access_token].present?
        execute_token_revocation(token_data)
        flash[:notice] = 'Tokens successfully revoked at Authorization Server via RFC 7009! Local session cleared.'
      else
        flash[:error] = 'No active tokens to revoke.'
      end
      redirect_to '/'
    end

    def backchannel_logout
      logout_token = params[:logout_token]
      return render plain: 'Missing logout_token', status: :bad_request if logout_token.blank?

      claims = OAuth2ClientKit.client.verify_logout_token(logout_token)
      process_backchannel_eviction(claims['sub'], claims['sid'])
    rescue StandardError => e
      OAuth2ClientKit.logger.warn("OIDC Back-Channel Logout failed: #{e.message}")
      render plain: "Invalid logout_token: #{e.message}", status: :bad_request
    end

    def logout
      token_data = current_token_data
      revoke_active_tokens_on_logout(token_data)
      clear_local_session
      dispatch_post_logout_redirect(token_data[:raw_id_token] || session[:raw_id_token])
    end

    private

    def validate_jarm_response(client)
      return nil unless valid_jarm_param_present?

      jarm = verify_jarm_payload(client)
      return nil unless jarm

      if jarm['error'].present?
        handle_auth_error(jarm['error'], jarm['error_description'], jarm['error_uri'])
        return nil
      end

      jarm
    end

    def valid_jarm_param_present?
      return true if params[:response].present?

      OAuth2ClientKit.logger.warn(
        "Rejected authorization callback: Missing signed JARM 'response' parameter. " \
        'Insecure plaintext responses are prohibited.'
      )
      flash[:error] = 'Security Error: RFC 9221 JARM is strictly enforced. ' \
                      'Unsigned plain authorization response rejected.'
      false
    end

    def verify_jarm_payload(client)
      client.decode_and_verify_jarm_response(params[:response])
    rescue StandardError => e
      OAuth2ClientKit.logger.error("JARM Verification Failed: #{e.message}")
      flash[:error] = "Security Error: Cryptographic JARM verification failed (#{e.message})"
      nil
    end

    def valid_callback_context?(client, jarm)
      valid_callback_state?(jarm['state']) && valid_callback_issuer?(jarm['iss'], client)
    end

    def valid_callback_state?(state_param)
      expected_state = session.delete(:oauth_state)
      return true if expected_state.present? && state_param == expected_state

      flash[:error] = 'Security Error: State parameter mismatch or expired. Possible CSRF attack.'
      false
    end

    def valid_callback_issuer?(iss, client)
      return true if iss.blank? || iss == client.public_issuer_url

      flash[:error] = 'Security Error: Authorization Server Issuer Identification mismatch (RFC 9207). ' \
                      "Expected #{client.public_issuer_url}, got #{iss}."
      false
    end

    def complete_code_exchange(client, jarm_claims, cached_flow)
      code = jarm_claims['code']
      return redirect_with_error('OAuth Error: No authorization code received in JARM response.') if code.blank?

      process_flow_exchange(client, code, extract_flow_credentials(cached_flow))
    rescue StandardError => e
      log_and_redirect_exchange_error(e)
    end

    def process_flow_exchange(client, code, flow)
      token = client.exchange_code(code, flow[:code_verifier], flow[:redirect_uri], flow[:dpop_key])
      persist_authenticated_tokens(client, token, flow, code)
      flash[:notice] = "Successfully authenticated via OAuth 2.1 (#{flow[:flow].upcase})!"
      redirect_to OAuth2ClientKit.config.after_login_path
    end

    def redirect_with_error(msg)
      flash[:error] = msg
      redirect_to '/'
    end

    def persist_authenticated_tokens(client, token, flow, code)
      claims = collect_token_claims(client, token, flow, code)
      token_key = store_token_payload(token, claims, flow[:dpop_key])
      session_ids = {
        token_key: token_key,
        scopes: token.params['scope'] || claims[:access_claims]['scope'],
        id_token: token.params['id_token']
      }
      reset_session if respond_to?(:reset_session)
      assign_auth_session(claims, session_ids, flow[:flow])
    end

    def collect_token_claims(client, token, flow, code)
      access_token = token.token
      {
        id_claims: client.decode_and_verify_id_token(token.params['id_token'], flow[:expected_nonce], access_token,
                                                     code),
        access_claims: decode_raw_access_claims(access_token),
        userinfo: client.fetch_userinfo(access_token, flow[:dpop_key])
      }
    end

    def store_token_payload(token, claims, dpop_key)
      token_key = SecureRandom.uuid
      payload = build_stored_token_payload(token, claims[:id_claims], claims[:access_claims], claims[:userinfo],
                                           dpop_key)
      OAuth2ClientKit.token_store.write(token_key, payload)
      token_key
    end

    def log_and_redirect_exchange_error(err)
      first_lines = err.backtrace&.first(10)&.join("\n")
      OAuth2ClientKit.logger.error("Token Exchange Exception: #{err.class}: #{err.message}\n#{first_lines}")
      flash[:error] = "Token Exchange Error: #{err.message}"
      redirect_to '/'
    end

    def execute_token_revocation(data)
      OAuth2ClientKit.client.revoke_token(data[:raw_access_token], 'access_token')
      safely_revoke_refresh_token(OAuth2ClientKit.client, data[:raw_refresh_token])
      clear_local_session
    end

    def process_backchannel_eviction(sub, sid)
      OAuth2ClientKit.logger.info("Processing OIDC Back-Channel Logout for sub=#{sub}, sid=#{sid}")
      OAuth2ClientKit.token_store.evict_sessions_for!(sub: sub, sid: sid)
      response.headers['Cache-Control'] = 'no-store'
      response.headers['Pragma'] = 'no-cache'
      head :ok
    end

    def revoke_active_tokens_on_logout(data)
      safely_revoke_access_token(data[:raw_access_token])
      safely_revoke_refresh_token(OAuth2ClientKit.client, data[:raw_refresh_token])
    end

    def safely_revoke_access_token(access_token)
      OAuth2ClientKit.client.revoke_token(access_token, 'access_token') if access_token.present?
    rescue StandardError => e
      OAuth2ClientKit.logger.warn("Access token revocation ignored during logout: #{e.message}")
    end

    def safely_revoke_refresh_token(client, refresh_token)
      client.revoke_token(refresh_token, 'refresh_token') if refresh_token.present?
    rescue StandardError => e
      OAuth2ClientKit.logger.warn("Refresh token revocation ignored during logout: #{e.message}")
    end

    def dispatch_post_logout_redirect(id_token_hint)
      if id_token_hint.present?
        post_logout = "#{request.protocol}#{request.host_with_port}#{OAuth2ClientKit.config.after_logout_path}"
        url = OAuth2ClientKit.client.end_session_url(id_token_hint, post_logout)
        redirect_to url, allow_other_host: true, status: :see_other
      else
        flash[:notice] = 'You have been logged out.'
        redirect_to '/'
      end
    end
  end
end
