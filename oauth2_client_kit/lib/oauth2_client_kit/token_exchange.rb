# frozen_string_literal: true

module OAuth2ClientKit
  # Token grant operations including RFC 9126 PAR, authorization code exchange, and token refresh.
  module TokenExchange
    def push_authorization_request(auth_params)
      public_par_url = "#{@public_issuer_url}/oauth2/par"
      request_body = auth_params.merge(client_assertion_params(public_par_url))
      response = connection.post(@par_url) do |req|
        req.headers['Content-Type'] = 'application/x-www-form-urlencoded'
        req.body = URI.encode_www_form(request_body)
      end
      parse_par_response(response)
    end

    def exchange_code(code, code_verifier, redirect_uri, dpop_key = nil)
      public_token_url = "#{@public_issuer_url}/oauth2/token"
      params = build_code_exchange_params(code, code_verifier, redirect_uri, public_token_url)
      apply_dpop_header(params, token_url, nil, dpop_key) if dpop_key.present?

      execute_token_request(code, params, dpop_key, public_token_url)
    end

    def refresh_access_token(refresh_token_value, dpop_key = nil)
      token_obj = OAuth2::AccessToken.new(self, '', refresh_token: refresh_token_value)
      public_token_url = "#{@public_issuer_url}/oauth2/token"
      params = client_assertion_payload(public_token_url)
      apply_dpop_header(params, token_url, nil, dpop_key) if dpop_key.present?

      execute_refresh_request(token_obj, params, dpop_key, public_token_url)
    end

    private

    def parse_par_response(response)
      parsed = parse_json_safe(response.body)
      unless [201, 200].include?(response.status)
        error_msg = parsed['error_description'] || parsed['error'] || "HTTP #{response.status}"
        raise "PAR Request Failed: #{error_msg}"
      end
      parsed['request_uri'] || raise('No request_uri returned from PAR endpoint')
    end

    def build_code_exchange_params(code, verifier, redirect_uri, public_token_url)
      client_assertion_payload(public_token_url).merge(
        'grant_type' => 'authorization_code',
        'code' => code,
        'redirect_uri' => redirect_uri,
        'code_verifier' => verifier
      )
    end

    def apply_dpop_header(params, url, access_token, dpop_key, nonce = nil)
      params[:headers] ||= {}
      params[:headers]['DPoP'] = build_dpop_proof('POST', url, access_token, dpop_key, nonce)
    end

    def execute_token_request(code, params, dpop_key, public_token_url)
      auth_code.get_token(code, params)
    rescue OAuth2::Error => e
      server_nonce = extract_dpop_nonce(e)
      raise e unless server_nonce.present? && dpop_key.present?

      OAuth2ClientKit.logger.info(
        "Captured RFC 9449 DPoP-Nonce '#{server_nonce}'. Retrying code exchange with bound nonce."
      )
      params.merge!(client_assertion_payload(public_token_url))
      apply_dpop_header(params, token_url, nil, dpop_key, server_nonce)
      auth_code.get_token(code, params)
    end

    def execute_refresh_request(token_obj, params, dpop_key, public_token_url)
      token_obj.refresh!(params)
    rescue OAuth2::Error => e
      server_nonce = extract_dpop_nonce(e)
      raise e unless server_nonce.present? && dpop_key.present?

      OAuth2ClientKit.logger.info(
        "Captured RFC 9449 DPoP-Nonce '#{server_nonce}' on refresh. Retrying token refresh with bound nonce."
      )
      params.merge!(client_assertion_payload(public_token_url))
      apply_dpop_header(params, token_url, nil, dpop_key, server_nonce)
      token_obj.refresh!(params)
    end

    def extract_dpop_nonce(err)
      err.response&.headers&.[]('dpop-nonce') || err.response&.headers&.[]('DPoP-Nonce')
    end
  end
end
