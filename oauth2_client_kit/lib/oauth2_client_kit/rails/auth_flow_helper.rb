# frozen_string_literal: true

require 'jwt'
require 'securerandom'

module OAuth2ClientKit
  # Helper module for managing OAuth 2.1 state and session transitions during authentication.
  module AuthFlowHelper
    def initialize_auth_state(flow)
      pkce = OAuth2ClientKit::Client.generate_pkce_codes
      {
        flow: flow.to_s, code_verifier: pkce[:code_verifier], code_challenge: pkce[:code_challenge],
        state: SecureRandom.hex(24), nonce: SecureRandom.hex(24),
        redirect_uri: oauth_redirect_uri, dpop_key: OAuth2ClientKit::Client.generate_dpop_key.to_pem
      }
    end

    def persist_auth_session(data)
      map = {
        oauth_code_verifier: data[:code_verifier], oauth_state: data[:state], oauth_nonce: data[:nonce],
        oauth_flow: data[:flow], oauth_redirect_uri: data[:redirect_uri], oauth_dpop_key: data[:dpop_key]
      }
      map.each { |key, val| session[key] = val }
      cache_flow_state(data)
    end

    def cache_flow_state(data)
      return unless defined?(Rails) && Rails.respond_to?(:cache) && Rails.cache

      Rails.cache.write("oauth_flow:#{data[:state]}", data, expires_in: 10.minutes)
    end

    def pop_cached_flow(state_param)
      return nil unless defined?(Rails) && Rails.respond_to?(:cache) && Rails.cache && state_param.present?

      cached = Rails.cache.read("oauth_flow:#{state_param}")
      Rails.cache.delete("oauth_flow:#{state_param}")
      cached
    end

    def clear_local_session
      OAuth2ClientKit.token_store.delete(session[:token_key]) if session[:token_key].present?
      reset_session
    end

    def dispatch_auth_redirect(client, flow, data)
      auth_params = {
        response_type: 'code', response_mode: 'jwt', client_id: client.id,
        redirect_uri: data[:redirect_uri], state: data[:state], nonce: data[:nonce],
        code_challenge: data[:code_challenge], code_challenge_method: 'S256'
      }
      flow == :par ? dispatch_par_redirect(client, auth_params) : dispatch_direct_redirect(client, auth_params)
    end

    def dispatch_par_redirect(client, auth_params)
      req_uri = client.push_authorization_request(auth_params)
      session[:request_uri] = req_uri
      target = "#{client.public_issuer_url}/oauth2/authorize?client_id=#{client.id}&request_uri=#{ERB::Util.url_encode(req_uri)}"
      redirect_to target, allow_other_host: true, status: :see_other
    rescue StandardError => e
      flash[:error] = "PAR Initialization Error: #{e.message}"
      redirect_to '/'
    end

    def dispatch_direct_redirect(client, auth_params)
      target = "#{client.public_issuer_url}/oauth2/authorize?#{URI.encode_www_form(auth_params)}"
      redirect_to target, allow_other_host: true, status: :see_other
    end

    def extract_flow_credentials(cached_flow)
      {
        code_verifier: fetch_session_or_cache(:oauth_code_verifier, :code_verifier, cached_flow),
        expected_nonce: fetch_session_or_cache(:oauth_nonce, :nonce, cached_flow),
        flow: fetch_session_or_cache(:oauth_flow, :flow, cached_flow) || 'par',
        redirect_uri: fetch_session_or_cache(:oauth_redirect_uri, :redirect_uri, cached_flow) || oauth_redirect_uri,
        dpop_key: fetch_session_or_cache(:oauth_dpop_key, :dpop_key, cached_flow)
      }
    end

    def fetch_session_or_cache(session_key, cache_key, cached_flow)
      session.delete(session_key) || cached_flow&.dig(cache_key)
    end

    def build_stored_token_payload(token, id_claims, access_claims, userinfo, dpop_key = nil)
      {
        access_token_claims: access_claims, userinfo_claims: userinfo,
        raw_id_token: token.params['id_token'], raw_access_token: token.token,
        raw_refresh_token: token.refresh_token, token_type: token.params['token_type'] || 'Bearer',
        dpop_key: dpop_key || session[:oauth_dpop_key], sub: id_claims['sub'], sid: id_claims['sid'],
        expires_at: access_claims['exp'].to_i
      }
    end

    def assign_auth_session(claims_data, session_ids, flow)
      session[:user] = claims_data[:id_claims].merge(claims_data[:userinfo])
      session[:id_token_claims] = claims_data[:id_claims]
      assign_session_metadata(session_ids, flow)
    end

    def assign_session_metadata(session_ids, flow)
      session[:token_key] = session_ids[:token_key]
      session[:token_scopes] = session_ids[:scopes]
      session[:auth_flow_used] = flow
      session[:raw_id_token] = session_ids[:id_token]
    end

    def decode_raw_access_claims(token)
      JWT.decode(token, nil, false)[0]
    rescue StandardError
      {}
    end
  end
end
