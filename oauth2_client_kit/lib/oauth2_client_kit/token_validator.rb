# frozen_string_literal: true

require 'jwt'
require 'openssl'
require 'base64'

module OAuth2ClientKit
  # Cryptographic verification and claims assertion validator for OpenID Connect ID Tokens
  # and RFC 9221 JWT-Secured Authorization Responses (JARM).
  class TokenValidator
    attr_reader :client_id, :public_issuer_url, :internal_issuer_url, :jwks_fetcher

    def initialize(client_id, public_issuer_url, internal_issuer_url, &jwks_fetcher)
      @client_id = client_id
      @public_issuer_url = public_issuer_url
      @internal_issuer_url = internal_issuer_url
      @jwks_fetcher = jwks_fetcher
    end

    def decode_and_verify_id_token(id_token_jwt, expected_nonce, raw_access_token = nil, code = nil)
      return {} if id_token_jwt.blank?

      payload = verify_signed_jwt(id_token_jwt, token_type: 'ID Token')
      validate_nonce(payload, expected_nonce)
      validate_at_hash(payload, raw_access_token) if raw_access_token.present?
      validate_c_hash(payload, code) if code.present?
      payload
    end

    def decode_and_verify_jarm_response(jarm_jwt, expected_state = nil)
      raise 'Security Error: Missing JARM response parameter' if jarm_jwt.blank?

      payload = verify_signed_jwt(jarm_jwt, token_type: 'JARM response')
      if expected_state.present? && payload['state'] != expected_state
        raise 'Security Error: JARM state parameter mismatch. Possible CSRF attack.'
      end

      payload
    end

    def verify_signed_jwt(jwt_string, token_type: 'JWT')
      header = decode_header(jwt_string)
      validate_algorithm(header['alg'], token_type)
      jwk_set = resolve_jwks(header['kid'], token_type)
      payload = decode_payload(jwt_string, jwk_set)
      validate_issued_at(payload, token_type)
      payload
    end

    private

    def decode_header(jwt_string)
      JWT.decode(jwt_string, nil, false)[1] || {}
    rescue StandardError
      {}
    end

    def validate_algorithm(alg, token_type)
      return if alg.present? && alg.downcase != 'none' && alg == 'RS256'

      raise "Security Error: Strict Algorithm Pinning: #{token_type} must use 'RS256'. Rejected algorithm '#{alg}'."
    end

    def resolve_jwks(kid, token_type)
      jwk_set = @jwks_fetcher&.call(kid)
      return jwk_set if jwk_set.present?

      raise 'Security Error: Unable to fetch JWKS from Authorization Server ' \
            "(#{@internal_issuer_url}/oauth2/jwks) to verify #{token_type}."
    end

    def decode_payload(jwt_string, jwk_set)
      decoded = JWT.decode(
        jwt_string, nil, true,
        { algorithms: ['RS256'], jwks: jwk_set, iss: @public_issuer_url, verify_iss: true,
          aud: @client_id, verify_aud: true }
      )
      decoded[0]
    end

    def validate_issued_at(payload, token_type)
      now = Time.now.to_i
      leeway = 60
      return unless payload['iat'].present? && payload['iat'].to_i > (now + leeway)

      raise "Security Error: #{token_type} issued in the future at #{Time.at(payload['iat'].to_i)}."
    end

    def validate_nonce(payload, expected_nonce)
      return unless expected_nonce.present? && payload['nonce'] != expected_nonce

      raise "Security Error: ID Token nonce ('#{payload['nonce']}') does not match expected nonce ('#{expected_nonce}')"
    end

    def validate_at_hash(payload, raw_access_token)
      if payload['at_hash'].blank?
        raise 'Security Error: ID Token is missing the required at_hash claim while an access token is present.'
      end

      expected = calculate_claim_hash(raw_access_token)
      return if payload['at_hash'] == expected

      raise "Security Error: ID Token at_hash ('#{payload['at_hash']}') does not match " \
            "calculated access token hash ('#{expected}')"
    end

    def validate_c_hash(payload, code)
      if payload['c_hash'].blank?
        raise 'Security Error: ID Token is missing the required c_hash claim while an authorization code is present.'
      end

      expected = calculate_claim_hash(code)
      return if payload['c_hash'] == expected

      raise "Security Error: ID Token c_hash ('#{payload['c_hash']}') does not match " \
            "calculated code hash ('#{expected}')"
    end

    def calculate_claim_hash(value)
      digest = OpenSSL::Digest::SHA256.digest(value)
      Base64.urlsafe_encode64(digest[0...16], padding: false)
    end
  end
end
