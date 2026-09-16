# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'base64'
require 'jwt'

module OAuth2ClientKit
  # Handles generation of ephemeral DPoP keys and construction of signed DPoP proof JWTs (RFC 9449).
  class DpopHandler
    class << self
      def generate_key(type = :ec)
        if type == :rsa
          OpenSSL::PKey::RSA.generate(2048)
        else
          OpenSSL::PKey::EC.generate('prime256v1')
        end
      end

      def build_proof(http_method, http_url, access_token = nil, dpop_key = nil, nonce = nil)
        key = parse_key(dpop_key)
        raise 'Missing DPoP private key' unless key

        is_ec = key.is_a?(OpenSSL::PKey::EC)
        alg = is_ec ? 'ES256' : 'RS256'
        headers = build_headers(key, alg, is_ec)
        payload = build_payload(http_method, http_url, access_token, nonce)

        JWT.encode(payload, key, alg, headers)
      end

      def parse_key(dpop_key)
        return nil if dpop_key.nil?
        return dpop_key if dpop_key.is_a?(OpenSSL::PKey::RSA) || dpop_key.is_a?(OpenSSL::PKey::EC)
        return unless dpop_key.is_a?(String)

        parse_pem_string(dpop_key)
      end

      private

      def parse_pem_string(dpop_key)
        OpenSSL::PKey::EC.new(dpop_key)
      rescue StandardError
        OpenSSL::PKey::RSA.new(dpop_key)
      end

      def build_headers(key, alg, is_ec)
        jwk = JWT::JWK.new(key)
        public_jwk = is_ec ? jwk.export.slice(:kty, :crv, :x, :y) : jwk.export.slice(:kty, :n, :e)
        { typ: 'dpop+jwt', alg: alg, jwk: public_jwk }
      end

      def build_payload(http_method, http_url, access_token, nonce)
        payload = {
          jti: SecureRandom.uuid,
          htm: http_method.to_s.upcase,
          htu: http_url.to_s.split('?').first,
          iat: Time.now.to_i
        }
        payload[:nonce] = nonce if nonce.present?
        attach_access_token_hash(payload, access_token) if access_token.present?
        payload
      end

      def attach_access_token_hash(payload, access_token)
        digest = OpenSSL::Digest::SHA256.digest(access_token)
        payload[:ath] = Base64.urlsafe_encode64(digest, padding: false)
      end
    end
  end
end
