# frozen_string_literal: true

module OAuth2ClientKit
  # Token inspection, verification, revocation, and userinfo operations.
  module TokenInspection
    def introspect_token(token_value, token_type_hint = 'access_token')
      return { 'active' => false } if token_value.blank?

      introspect_url = "#{@internal_issuer_url}/oauth2/introspect"
      public_url = "#{@public_issuer_url}/oauth2/introspect"
      request_body = client_assertion_params(public_url).merge(
        token: token_value, token_type_hint: token_type_hint
      )
      execute_introspect_request(introspect_url, request_body)
    end

    def verify_active!(token_value)
      claims = introspect_token(token_value, 'access_token')
      return { active: false, reason: 'token_inactive_or_revoked', claims: claims } unless claims['active'] == true

      { active: true, sub: claims['sub'], client_id: claims['client_id'], exp: claims['exp'], claims: claims }
    end

    def revoke_token?(token_value, token_type_hint = 'access_token')
      return false if token_value.blank?

      params = client_assertion_params("#{@public_issuer_url}/oauth2/revoke").merge(
        token: token_value, token_type_hint: token_type_hint
      )
      send_revocation_request(params).status == 200
    end
    alias revoke_token revoke_token?

    def fetch_userinfo(access_token, dpop_key = nil)
      return {} if access_token.blank?

      userinfo_url = "#{@internal_issuer_url}/userinfo"
      response = execute_userinfo_request(userinfo_url, access_token, dpop_key)
      return {} unless response&.status == 200

      parse_json_safe(response.body)
    end

    private

    def send_revocation_request(params)
      with_retries(operation_name: 'Token Revocation') do
        connection.post("#{@internal_issuer_url}/oauth2/revoke") do |req|
          req.headers['Content-Type'] = 'application/x-www-form-urlencoded'
          req.body = URI.encode_www_form(params)
        end
      end
    end

    def execute_introspect_request(introspect_url, request_body)
      response = with_retries(operation_name: 'Token Introspection') do
        connection.post(introspect_url) do |req|
          req.headers['Content-Type'] = 'application/x-www-form-urlencoded'
          req.body = URI.encode_www_form(request_body)
        end
      end
      return parse_json_safe(response.body, default: { 'active' => false }) if response.status == 200

      OAuth2ClientKit.logger.warn("Introspection failed with HTTP #{response.status}: #{response.body}")
      { 'active' => false }
    end

    def execute_userinfo_request(url, access_token, dpop_key)
      response = with_retries(operation_name: 'Fetch UserInfo') do
        connection.get(url) { |req| configure_userinfo_request(req, url, access_token, dpop_key) }
      end
      server_nonce = response.headers['dpop-nonce'] || response.headers['DPoP-Nonce']
      if response.status == 401 && server_nonce.present? && dpop_key.present?
        response = with_retries(operation_name: 'Fetch UserInfo Nonce Retry') do
          connection.get(url) { |req| configure_userinfo_request(req, url, access_token, dpop_key, server_nonce) }
        end
      end
      response
    end

    def configure_userinfo_request(req, url, access_token, dpop_key, nonce = nil)
      if dpop_key.present?
        dpop_proof = build_dpop_proof('GET', url, access_token, dpop_key, nonce)
        req.headers['Authorization'] = "DPoP #{access_token}"
        req.headers['DPoP'] = dpop_proof
      else
        req.headers['Authorization'] = "Bearer #{access_token}"
      end
      req.headers['Accept'] = 'application/json'
    end
  end
end
