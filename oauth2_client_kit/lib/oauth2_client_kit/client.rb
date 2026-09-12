# frozen_string_literal: true

require "oauth2"
require "jwt"
require "securerandom"
require "openssl"
require "uri"
require "monitor"
require "base64"

module OAuth2ClientKit
  # High-assurance OAuth 2.1 & OpenID Connect client extending OAuth2::Client.
  #
  # Standards & Specifications:
  # - RFC 9126: Pushed Authorization Requests (PAR)
  # - RFC 7523: Asymmetric Client Authentication (private_key_jwt)
  # - RFC 7636: Proof Key for Code Exchange (PKCE S256)
  # - RFC 9449: Demonstrating Proof-of-Possession (DPoP sender-constrained tokens)
  # - RFC 9207: Authorization Server Issuer Identification
  # - RFC 7662: OAuth 2.0 Token Introspection
  # - RFC 7009: OAuth 2.0 Token Revocation
  # - OpenID Connect Core 1.0 & RP-Initiated / Back-Channel Logout 1.0
  class Client < OAuth2::Client
    attr_reader :private_key, :issuer_url, :public_issuer_url, :internal_issuer_url, :par_url

    # Thread-safe in-memory cache for authorization server JWKS sets across worker threads
    @@jwks_cache = Monitor.new
    @@cached_jwks = {} # issuer_url => { jwk_set: JWT::JWK::Set, expires_at: Time, last_fetched_at: Time }

    def initialize(client_id, private_key_pem, options = {})
      @public_issuer_url = options.delete(:public_issuer_url) || options.delete(:issuer_url) || options.delete(:site) || ENV.fetch("AUTH_SERVER_URL", "http://localhost:9000")
      internal_env = ENV["AUTH_SERVER_URL_INTERNAL"]
      @internal_issuer_url = options.delete(:internal_issuer_url) || (internal_env && !internal_env.empty? ? internal_env : @public_issuer_url)
      @issuer_url = @public_issuer_url

      @private_key = private_key_pem.is_a?(OpenSSL::PKey::RSA) ? private_key_pem : OpenSSL::PKey::RSA.new(private_key_pem)
      @par_url = options.delete(:par_url) || "#{@internal_issuer_url}/oauth2/par"

      conn_opts = { request: { timeout: 5, open_timeout: 2 } }.merge(options[:connection_opts] || {})
      conn_opts[:headers] = {
        "Connection" => "keep-alive",
        "Keep-Alive" => "timeout=30, max=1000"
      }.merge(conn_opts[:headers] || {})

      super(
        client_id,
        nil, # Client secret omitted; authentication handled exclusively via private_key_jwt
        {
          site: @internal_issuer_url,
          authorize_url: "#{@public_issuer_url}/oauth2/authorize",
          token_url: "#{@internal_issuer_url}/oauth2/token",
          auth_scheme: :request_body,
          connection_opts: conn_opts
        }.merge(options)
      )
    end

    # Builds and cryptographically signs an RFC 7523 client assertion JWT using RS256.
    def build_client_assertion(audience = nil)
      aud = audience || token_url
      now = Time.now.to_i
      payload = {
        iss: id,
        sub: id,
        aud: aud,
        jti: SecureRandom.uuid,
        iat: now,
        exp: now + 60
      }
      headers = {
        kid: "#{id}-key-1",
        alg: "RS256",
        typ: "JWT"
      }
      JWT.encode(payload, @private_key, "RS256", headers)
    end

    # Generates high-entropy PKCE code_verifier and S256 code_challenge (RFC 7636)
    def self.generate_pkce_codes
      code_verifier = SecureRandom.urlsafe_base64(64).tr("=", "")
      code_challenge = Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(code_verifier), padding: false)
      { code_verifier: code_verifier, code_challenge: code_challenge, code_challenge_method: "S256" }
    end

    # Submits authorization parameters directly over the authenticated backchannel
    # using RFC 9126 Pushed Authorization Requests (PAR).
    def push_authorization_request(auth_params)
      public_par_url = "#{@public_issuer_url}/oauth2/par"
      request_body = auth_params.merge(client_assertion_params(public_par_url))

      response = connection.post(@par_url) do |req|
        req.headers["Content-Type"] = "application/x-www-form-urlencoded"
        req.body = URI.encode_www_form(request_body)
      end

      parsed = JSON.parse(response.body) rescue {}
      unless response.status == 201 || response.status == 200
        error_msg = parsed["error_description"] || parsed["error"] || "HTTP #{response.status}"
        raise "PAR Request Failed: #{error_msg}"
      end

      parsed["request_uri"] || raise("No request_uri returned from PAR endpoint")
    end

    def exchange_code(code, code_verifier, redirect_uri, dpop_key = nil)
      public_token_url = "#{@public_issuer_url}/oauth2/token"
      params = client_assertion_payload(public_token_url).merge(
        "grant_type" => "authorization_code",
        "code" => code,
        "redirect_uri" => redirect_uri,
        "code_verifier" => code_verifier
      )

      if dpop_key.present?
        dpop_proof = build_dpop_proof("POST", token_url, nil, dpop_key)
        params[:headers] = { "DPoP" => dpop_proof }
      end

      begin
        auth_code.get_token(code, params)
      rescue OAuth2::Error => e
        # RFC 9449 Section 8: Server-Provided Nonces
        server_nonce = e.response&.headers&.[]("dpop-nonce") || e.response&.headers&.[]("DPoP-Nonce")
        if server_nonce.present? && dpop_key.present?
          OAuth2ClientKit.logger.info("Captured RFC 9449 DPoP-Nonce '#{server_nonce}'. Retrying code exchange with bound nonce.")
          params.merge!(client_assertion_payload(public_token_url))
          params[:headers] = { "DPoP" => build_dpop_proof("POST", token_url, nil, dpop_key, server_nonce) }
          auth_code.get_token(code, params)
        else
          raise e
        end
      end
    end

    # Generates an ephemeral asymmetric key for DPoP proof-of-possession (RFC 9449).
    def self.generate_dpop_key(type = :ec)
      if type == :rsa
        OpenSSL::PKey::RSA.generate(2048)
      else
        OpenSSL::PKey::EC.generate("prime256v1")
      end
    end

    # Constructs a signed DPoP proof JWT (RFC 9449 Section 4.2).
    def build_dpop_proof(http_method, http_url, access_token = nil, dpop_key = nil, nonce = nil)
      key = parse_dpop_key(dpop_key)
      raise "Missing DPoP private key" unless key

      is_ec = key.is_a?(OpenSSL::PKey::EC)
      alg = is_ec ? "ES256" : "RS256"

      jwk = JWT::JWK.new(key)
      public_jwk = is_ec ? jwk.export.slice(:kty, :crv, :x, :y) : jwk.export.slice(:kty, :n, :e)

      headers = {
        typ: "dpop+jwt",
        alg: alg,
        jwk: public_jwk
      }

      uri_clean = http_url.to_s.split("?").first
      now = Time.now.to_i
      payload = {
        jti: SecureRandom.uuid,
        htm: http_method.to_s.upcase,
        htu: uri_clean,
        iat: now
      }

      payload[:nonce] = nonce if nonce.present?

      if access_token.present?
        digest = OpenSSL::Digest::SHA256.digest(access_token)
        payload[:ath] = Base64.urlsafe_encode64(digest, padding: false)
      end

      JWT.encode(payload, key, alg, headers)
    end

    def parse_dpop_key(dpop_key)
      return nil if dpop_key.nil?
      return dpop_key if dpop_key.is_a?(OpenSSL::PKey::RSA) || dpop_key.is_a?(OpenSSL::PKey::EC)

      if dpop_key.is_a?(String)
        begin
          OpenSSL::PKey::EC.new(dpop_key)
        rescue
          OpenSSL::PKey::RSA.new(dpop_key)
        end
      end
    end

    # Validates and decodes an OpenID Connect ID Token according to OIDC Core 1.0 Section 3.1.3.7.
    def decode_and_verify_id_token(id_token_jwt, expected_nonce, raw_access_token = nil, code = nil)
      return {} if id_token_jwt.blank?

      payload = verify_signed_jwt(id_token_jwt, token_type: "ID Token")

      if expected_nonce.present? && payload["nonce"] != expected_nonce
        raise "Security Error: ID Token nonce ('#{payload['nonce']}') does not match expected nonce ('#{expected_nonce}')"
      end

      if payload["at_hash"].present? && raw_access_token.present?
        digest = OpenSSL::Digest::SHA256.digest(raw_access_token)
        expected_at_hash = Base64.urlsafe_encode64(digest[0...16], padding: false)
        if payload["at_hash"] != expected_at_hash
          raise "Security Error: ID Token at_hash ('#{payload['at_hash']}') does not match calculated access token hash ('#{expected_at_hash}')"
        end
      end

      if payload["c_hash"].present? && code.present?
        code_digest = OpenSSL::Digest::SHA256.digest(code)
        expected_c_hash = Base64.urlsafe_encode64(code_digest[0...16], padding: false)
        if payload["c_hash"] != expected_c_hash
          raise "Security Error: ID Token c_hash ('#{payload['c_hash']}') does not match calculated code hash ('#{expected_c_hash}')"
        end
      end

      payload
    end

    # Validates and cryptographically verifies an RFC 9221 JWT-Secured Authorization Response (JARM).
    # Ensures non-repudiation and prevents response parameter tampering, code injection, and forged error messages.
    def decode_and_verify_jarm_response(jarm_jwt, expected_state = nil)
      if jarm_jwt.blank?
        raise "Security Error: Missing JARM response parameter"
      end

      payload = verify_signed_jwt(jarm_jwt, token_type: "JARM response")

      if expected_state.present? && payload["state"] != expected_state
        raise "Security Error: JARM state parameter mismatch. Possible CSRF attack."
      end

      payload
    end

    # Executes a block with exponential backoff and randomized jitter
    def with_retries(max_retries: 3, base_delay: 0.1, max_delay: 1.0, operation_name: "Operation")
      retries = 0
      begin
        yield
      rescue Faraday::ConnectionFailed, Faraday::TimeoutError, Errno::ECONNRESET, Errno::ETIMEDOUT,
             Net::OpenTimeout, Net::ReadTimeout, SocketError => e
        retries += 1
        if retries <= max_retries
          sleep_time = [base_delay * (2**(retries - 1)), max_delay].min + (rand * 0.05)
          OAuth2ClientKit.logger.warn("[Retry] #{operation_name} failed with #{e.class} (#{e.message}). Retrying in #{sleep_time.round(3)}s (Attempt #{retries}/#{max_retries})...")
          sleep(sleep_time)
          retry
        else
          raise
        end
      end
    end

    # Resolves the authorization server JWKS with thread-safe in-memory caching (1-hour TTL)
    def fetch_jwks(kid = nil)
      now = Time.now
      @@jwks_cache.synchronize do
        entry = @@cached_jwks[@issuer_url]

        if entry && entry[:expires_at] > now
          jwk_set = entry[:jwk_set]
          if kid.nil? || jwk_set_contains_kid?(jwk_set, kid)
            return jwk_set
          end

          if (now - entry[:last_fetched_at]) < 5
            return jwk_set
          end
        end

        raw_json = with_retries(operation_name: "Fetch JWKS") do
          resp = connection.get("#{@internal_issuer_url}/oauth2/jwks")
          resp.status == 200 ? resp.body : nil
        end

        if raw_json && !raw_json.to_s.strip.empty?
          jwks_hash = JSON.parse(raw_json) rescue nil
          if jwks_hash
            new_set = JWT::JWK::Set.new(jwks_hash)
            @@cached_jwks[@issuer_url] = {
              jwk_set: new_set,
              expires_at: now + 3600,
              last_fetched_at: now
            }
            return new_set
          end
        end

        entry ? entry[:jwk_set] : nil
      end
    rescue => e
      OAuth2ClientKit.logger.warn("Failed to fetch JWKS from #{@internal_issuer_url}/oauth2/jwks: #{e.message}")
      nil
    end

    def jwk_set_contains_kid?(jwk_set, kid)
      return false unless jwk_set && kid
      jwk_set.any? do |jwk|
        (jwk.respond_to?(:kid) && jwk.kid == kid) ||
          (jwk.respond_to?(:[]) && (jwk[:kid] == kid || jwk["kid"] == kid))
      end
    end

    # OpenID Connect RP-Initiated Logout 1.0 URL builder
    def end_session_url(id_token_hint, post_logout_redirect_uri)
      params = {
        id_token_hint: id_token_hint,
        post_logout_redirect_uri: post_logout_redirect_uri,
        client_id: id
      }.compact
      "#{@public_issuer_url}/connect/logout?#{URI.encode_www_form(params)}"
    end

    # Refresh Token Grant (RFC 6749 / OAuth 2.1)
    def refresh_access_token(refresh_token_value, dpop_key = nil)
      token_obj = OAuth2::AccessToken.new(self, "", refresh_token: refresh_token_value)
      public_token_url = "#{@public_issuer_url}/oauth2/token"
      params = client_assertion_payload(public_token_url)

      if dpop_key.present?
        dpop_proof = build_dpop_proof("POST", token_url, nil, dpop_key)
        params[:headers] = { "DPoP" => dpop_proof }
      end

      begin
        token_obj.refresh!(params)
      rescue OAuth2::Error => e
        # RFC 9449 Section 8: Server-Provided Nonces
        server_nonce = e.response&.headers&.[]("dpop-nonce") || e.response&.headers&.[]("DPoP-Nonce")
        if server_nonce.present? && dpop_key.present?
          OAuth2ClientKit.logger.info("Captured RFC 9449 DPoP-Nonce '#{server_nonce}' on refresh. Retrying token refresh with bound nonce.")
          params.merge!(client_assertion_payload(public_token_url))
          params[:headers] = { "DPoP" => build_dpop_proof("POST", token_url, nil, dpop_key, server_nonce) }
          token_obj.refresh!(params)
        else
          raise e
        end
      end
    end

    # RFC 7662 Token Introspection
    def introspect_token(token_value, token_type_hint = "access_token")
      return { "active" => false } if token_value.blank?

      introspect_url = "#{@internal_issuer_url}/oauth2/introspect"
      public_introspect_url = "#{@public_issuer_url}/oauth2/introspect"
      request_body = client_assertion_params(public_introspect_url).merge(
        token: token_value,
        token_type_hint: token_type_hint
      )

      response = with_retries(operation_name: "Token Introspection") do
        connection.post(introspect_url) do |req|
          req.headers["Content-Type"] = "application/x-www-form-urlencoded"
          req.body = URI.encode_www_form(request_body)
        end
      end

      if response.status == 200
        JSON.parse(response.body) rescue { "active" => false }
      else
        OAuth2ClientKit.logger.warn("Introspection failed with HTTP #{response.status}: #{response.body}")
        { "active" => false }
      end
    end

    # High-level Pre-flight Introspection Method ("Identity Checkpoint")
    # Designed specifically for verifying session validity before sensitive operations (e.g. payments)
    # to confirm the authorization server has not terminated or revoked the session early.
    #
    # @param token_value [String] Raw access token
    # @return [Hash] { active: Boolean, sub: String, claims: Hash, reason: String }
    def verify_active!(token_value)
      claims = introspect_token(token_value, "access_token")

      unless claims["active"] == true
        return {
          active: false,
          reason: "token_inactive_or_revoked",
          claims: claims
        }
      end

      {
        active: true,
        sub: claims["sub"],
        client_id: claims["client_id"],
        exp: claims["exp"],
        claims: claims
      }
    end

    # RFC 7009 Token Revocation
    def revoke_token(token_value, token_type_hint = "access_token")
      return false if token_value.blank?

      revoke_url = "#{@internal_issuer_url}/oauth2/revoke"
      public_revoke_url = "#{@public_issuer_url}/oauth2/revoke"
      request_body = client_assertion_params(public_revoke_url).merge(
        token: token_value,
        token_type_hint: token_type_hint
      )

      response = with_retries(operation_name: "Token Revocation") do
        connection.post(revoke_url) do |req|
          req.headers["Content-Type"] = "application/x-www-form-urlencoded"
          req.body = URI.encode_www_form(request_body)
        end
      end

      response.status == 200
    end

    # Validates and decodes a signed logout_token according to OIDC Back-Channel Logout 1.0 Section 2.4
    def verify_logout_token(logout_token_jwt)
      return nil if logout_token_jwt.blank?

      payload = verify_signed_jwt(logout_token_jwt, token_type: "logout token")

      events = payload["events"] || {}
      unless events.key?("http://schemas.openid.net/event/backchannel-logout")
        raise "Security Error: logout_token missing required event claim (http://schemas.openid.net/event/backchannel-logout)"
      end

      if payload.key?("nonce")
        raise "Security Error: logout_token MUST NOT contain a nonce claim"
      end

      payload
    end

    # Fetches UserInfo claims (OIDC Core 1.0 Section 5.3) using Bearer or DPoP authentication
    def fetch_userinfo(access_token, dpop_key = nil)
      return {} if access_token.blank?

      userinfo_url = "#{@internal_issuer_url}/userinfo"
      response = with_retries(operation_name: "Fetch UserInfo") do
        connection.get(userinfo_url) do |req|
          if dpop_key.present?
            dpop_proof = build_dpop_proof("GET", userinfo_url, access_token, dpop_key)
            req.headers["Authorization"] = "DPoP #{access_token}"
            req.headers["DPoP"] = dpop_proof
          else
            req.headers["Authorization"] = "Bearer #{access_token}"
          end
          req.headers["Accept"] = "application/json"
        end
      end

      unless response.status == 200
        OAuth2ClientKit.logger.warn("UserInfo request returned HTTP #{response.status}: #{response.body}")
        return {}
      end

      JSON.parse(response.body) rescue {}
    end

    private

    # Shared JWT signature verification pipeline used by all signed-token validators
    # (ID Token, JARM response, logout token). Handles:
    # - RS256 algorithm pinning (rejects alg=none and non-RS256)
    # - JWKS resolution with kid-based cache invalidation
    # - Full signature verification via JWT.decode
    # - Standard claims validation: iss, aud, exp, iat
    #
    # @param jwt_string [String] Raw JWT to verify
    # @param token_type [String] Human-readable label for error messages (e.g. "ID Token", "JARM response")
    # @return [Hash] Decoded JWT payload
    def verify_signed_jwt(jwt_string, token_type: "JWT")
      header = (JWT.decode(jwt_string, nil, false)[1] rescue {}) || {}
      alg = header["alg"]
      if alg.blank? || alg.downcase == "none" || alg != "RS256"
        raise "Security Error: Strict Algorithm Pinning: #{token_type} must use 'RS256'. Rejected algorithm '#{alg}'."
      end

      kid = header["kid"]
      jwk_set = fetch_jwks(kid)

      unless jwk_set.present?
        raise "Security Error: Unable to fetch JWKS from Authorization Server (#{@internal_issuer_url}/oauth2/jwks) to verify #{token_type}."
      end

      decoded = JWT.decode(jwt_string, nil, true, {
        algorithms: ["RS256"],
        jwks: jwk_set,
        iss: @public_issuer_url,
        verify_iss: true,
        aud: id,
        verify_aud: true
      })

      payload = decoded[0]
      now = Time.now.to_i
      leeway = 60

      if payload["iss"] != @public_issuer_url
        raise "Security Error: #{token_type} issuer ('#{payload['iss']}') mismatch. Expected '#{@public_issuer_url}'."
      end

      aud = payload["aud"]
      valid_aud = aud == id || (aud.is_a?(Array) && aud.include?(id))
      unless valid_aud
        raise "Security Error: #{token_type} audience ('#{aud}') does not match client_id ('#{id}')."
      end

      if payload["exp"].to_i < (now - leeway)
        raise "Security Error: #{token_type} has expired at #{Time.at(payload['exp'].to_i)}."
      end

      if payload["iat"].present? && payload["iat"].to_i > (now + leeway)
        raise "Security Error: #{token_type} issued in the future at #{Time.at(payload['iat'].to_i)}."
      end

      payload
    end

    # Builds authenticated request body params with string keys for oauth2 gem token operations
    # (code exchange, refresh token) where client_id is injected by the authenticator strategy.
    #
    # @param endpoint_url [String] The audience URL for the client assertion
    # @return [Hash] Params with client_assertion_type and client_assertion
    def client_assertion_payload(endpoint_url = token_url)
      {
        "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion" => build_client_assertion(endpoint_url)
      }
    end

    # Builds the common authenticated request body params for token endpoint operations
    # (introspection, revocation) that use direct Faraday calls with private_key_jwt.
    #
    # @param endpoint_url [String] The audience URL for the client assertion
    # @return [Hash] Base params with client_id, client_assertion_type, and client_assertion
    def client_assertion_params(endpoint_url)
      {
        client_id: id,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: build_client_assertion(endpoint_url)
      }
    end
  end
end
