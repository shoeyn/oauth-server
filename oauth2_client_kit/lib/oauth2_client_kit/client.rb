# frozen_string_literal: true

require 'oauth2'
require 'jwt'
require 'securerandom'
require 'openssl'
require 'uri'
require 'base64'
require_relative 'jwks_cache'
require_relative 'dpop_handler'
require_relative 'token_validator'
require_relative 'http_retries'
require_relative 'token_exchange'
require_relative 'token_inspection'

module OAuth2ClientKit
  # High-assurance OAuth 2.1 & OpenID Connect client extending OAuth2::Client.
  class Client < OAuth2::Client
    include HttpRetries
    include TokenExchange
    include TokenInspection

    attr_reader :private_key, :issuer_url, :public_issuer_url, :internal_issuer_url, :par_url

    def initialize(client_id, private_key_pem, options = {})
      resolve_urls(options)
      @private_key = parse_rsa_key(private_key_pem)
      @par_url = options.delete(:par_url) || "#{@internal_issuer_url}/oauth2/par"
      @token_validator = TokenValidator.new(client_id, @public_issuer_url, @internal_issuer_url) do |kid|
        fetch_jwks(kid)
      end

      super(client_id, nil, build_client_options(options))
    end

    def build_client_assertion(audience = nil)
      aud = audience || token_url
      now = Time.now.to_i
      payload = {
        iss: id, sub: id, aud: aud, jti: SecureRandom.uuid, iat: now, exp: now + 60
      }
      headers = { kid: "#{id}-key-1", alg: 'RS256', typ: 'JWT' }
      JWT.encode(payload, @private_key, 'RS256', headers)
    end

    def self.generate_pkce_codes
      code_verifier = SecureRandom.urlsafe_base64(64).tr('=', '')
      code_challenge = Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(code_verifier), padding: false)
      { code_verifier: code_verifier, code_challenge: code_challenge, code_challenge_method: 'S256' }
    end

    def self.generate_dpop_key(type = :ec)
      DpopHandler.generate_key(type)
    end

    def build_dpop_proof(http_method, http_url, access_token = nil, dpop_key = nil, nonce = nil)
      DpopHandler.build_proof(http_method, http_url, access_token, dpop_key, nonce)
    end

    def parse_dpop_key(dpop_key)
      DpopHandler.parse_key(dpop_key)
    end

    def decode_and_verify_id_token(id_token_jwt, expected_nonce, raw_access_token = nil, code = nil)
      @token_validator.decode_and_verify_id_token(id_token_jwt, expected_nonce, raw_access_token, code)
    end

    def decode_and_verify_jarm_response(jarm_jwt, expected_state = nil)
      @token_validator.decode_and_verify_jarm_response(jarm_jwt, expected_state)
    end

    def verify_signed_jwt(jwt_string, token_type: 'JWT')
      @token_validator.verify_signed_jwt(jwt_string, token_type: token_type)
    end

    def fetch_jwks(kid = nil)
      JwksCache.resolve_jwks(@issuer_url, kid) { request_remote_jwks }
    rescue StandardError => e
      OAuth2ClientKit.logger.warn("Failed to fetch JWKS from #{@internal_issuer_url}/oauth2/jwks: #{e.message}")
      nil
    end

    def jwk_set_contains_kid?(jwk_set, kid)
      JwksCache.contains_kid?(jwk_set, kid)
    end

    def end_session_url(id_token_hint, post_logout_redirect_uri)
      params = {
        id_token_hint: id_token_hint,
        post_logout_redirect_uri: post_logout_redirect_uri,
        client_id: id
      }.compact
      "#{@public_issuer_url}/connect/logout?#{URI.encode_www_form(params)}"
    end

    def verify_logout_token(logout_token_jwt)
      return nil if logout_token_jwt.blank?

      payload = verify_signed_jwt(logout_token_jwt, token_type: 'logout token')
      validate_logout_events(payload)
      raise 'Security Error: logout_token MUST NOT contain a nonce claim' if payload.key?('nonce')
      if payload['sub'].blank? && payload['sid'].blank?
        raise "Security Error: logout_token MUST contain a 'sub' and/or 'sid' claim."
      end

      payload
    end

    def client_assertion_payload(endpoint_url = token_url)
      {
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => build_client_assertion(endpoint_url)
      }
    end

    def client_assertion_params(endpoint_url)
      {
        client_id: id,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: build_client_assertion(endpoint_url)
      }
    end

    private

    def resolve_urls(options)
      @public_issuer_url = options.delete(:public_issuer_url) || options.delete(:issuer_url) ||
                           options.delete(:site) || ENV.fetch('AUTH_SERVER_URL', 'http://localhost:9000')
      internal_env = ENV.fetch('AUTH_SERVER_URL_INTERNAL', nil)
      @internal_issuer_url = options.delete(:internal_issuer_url) ||
                             (internal_env.to_s.strip.length.positive? ? internal_env : @public_issuer_url)
      @issuer_url = @public_issuer_url
    end

    def parse_rsa_key(key)
      key.is_a?(OpenSSL::PKey::RSA) ? key : OpenSSL::PKey::RSA.new(key)
    end

    def build_client_options(options)
      conn_opts = { request: { timeout: 5, open_timeout: 2 } }.merge(options[:connection_opts] || {})
      conn_opts[:headers] = {
        'Connection' => 'keep-alive', 'Keep-Alive' => 'timeout=30, max=1000'
      }.merge(conn_opts[:headers] || {})

      { site: @internal_issuer_url, authorize_url: "#{@public_issuer_url}/oauth2/authorize",
        token_url: "#{@internal_issuer_url}/oauth2/token", auth_scheme: :request_body,
        connection_opts: conn_opts }.merge(options)
    end

    def validate_logout_events(payload)
      events = payload['events'] || {}
      return if events.key?('http://schemas.openid.net/event/backchannel-logout')

      raise 'Security Error: logout_token missing required event claim ' \
            '(http://schemas.openid.net/event/backchannel-logout)'
    end

    def request_remote_jwks
      raw_json = with_retries(operation_name: 'Fetch JWKS') do
        resp = connection.get("#{@internal_issuer_url}/oauth2/jwks")
        resp.status == 200 ? resp.body : nil
      end
      return nil if raw_json.to_s.strip.empty?

      jwks_hash = parse_json_safe(raw_json, default: nil)
      jwks_hash ? JWT::JWK::Set.new(jwks_hash) : nil
    end

    def parse_json_safe(json_string, default: {})
      JSON.parse(json_string)
    rescue StandardError
      default
    end
  end
end
