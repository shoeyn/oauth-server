require "oauth2"
require "jwt"
require "securerandom"
require "openssl"
require "uri"
require "monitor"

# High-assurance OAuth 2.1 & OpenID Connect client extending OAuth2::Client.
#
# Standards & Specifications:
# - RFC 9126: Pushed Authorization Requests (PAR)
# - RFC 7523: Asymmetric Client Authentication (private_key_jwt)
# - RFC 7636: Proof Key for Code Exchange (PKCE S256)
# - RFC 9449: Demonstrating Proof-of-Possession (DPoP sender-constrained tokens)
# - RFC 9207: Authorization Server Issuer Identification
# - OpenID Connect Core 1.0 & RP-Initiated / Back-Channel Logout 1.0
class ParOAuth2Client < OAuth2::Client
  attr_reader :private_key, :issuer_url, :public_issuer_url, :internal_issuer_url, :par_url

  # Thread-safe in-memory cache for authorization server JWKS sets across worker threads
  @@jwks_cache = Monitor.new
  @@cached_jwks = {} # issuer_url => { jwk_set: JWT::JWK::Set, expires_at: Time, last_fetched_at: Time }

  def initialize(client_id, private_key_pem, options = {})
    # Public URL is the canonical issuer exposed to browsers and encoded in JWT claims
    @public_issuer_url = options.delete(:public_issuer_url) || options.delete(:issuer_url) || ENV.fetch("AUTH_SERVER_URL", "http://localhost:9000")
    # Internal URL is used for direct backchannel HTTP calls (e.g. within container networks)
    internal_env = ENV["AUTH_SERVER_URL_INTERNAL"]
    @internal_issuer_url = options.delete(:internal_issuer_url) || (internal_env && !internal_env.empty? ? internal_env : @public_issuer_url)
    @issuer_url = @public_issuer_url # Backward compatibility alias

    @private_key = OpenSSL::PKey::RSA.new(private_key_pem)
    @par_url = options.delete(:par_url) || "#{@internal_issuer_url}/oauth2/par"

    # Configure persistent HTTP keep-alive connection pooling
    conn_opts = (options[:connection_opts] || {}).dup
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
  #
  # @param audience [String, nil] Target endpoint URI (defaults to token_url)
  # @return [String] Compact serialized signed client assertion JWT
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
      kid: "demo-client-key-1",
      alg: "RS256",
      typ: "JWT"
    }
    JWT.encode(payload, @private_key, "RS256", headers)
  end

  # Submits authorization parameters directly over the authenticated backchannel
  # using RFC 9126 Pushed Authorization Requests (PAR).
  #
  # @param auth_params [Hash] Authorization parameters (state, nonce, code_challenge, etc.)
  # @return [String] Opaque request_uri returned by the authorization server
  def push_authorization_request(auth_params)
    assertion = build_client_assertion(@par_url)

    request_body = auth_params.merge(
      client_id: id,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion
    )

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

  # Exchanges an authorization code for tokens with PKCE code_verifier,
  # private_key_jwt client assertion, and optional RFC 9449 DPoP proof header.
  #
  # @param code [String] Authorization code
  # @param code_verifier [String] PKCE code verifier
  # @param redirect_uri [String] Client redirect URI matching the authorization request
  # @param dpop_key [OpenSSL::PKey::EC, OpenSSL::PKey::RSA, nil] Ephemeral key for DPoP proof
  # @return [OAuth2::AccessToken]
  def exchange_code(code, code_verifier, redirect_uri, dpop_key = nil)
    assertion = build_client_assertion(token_url)

    params = {
      grant_type: "authorization_code",
      code: code,
      redirect_uri: redirect_uri,
      code_verifier: code_verifier,
      client_id: id,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion
    }

    opts = {}
    if dpop_key.present?
      dpop_proof = build_dpop_proof("POST", token_url, nil, dpop_key)
      params[:headers] = { "DPoP" => dpop_proof }
      opts[:headers] = { "DPoP" => dpop_proof }
    end

    begin
      auth_code.get_token(code, params, opts)
    rescue OAuth2::Error => e
      # RFC 9449 Section 8: Server-Provided Nonces
      # If the server challenges with use_dpop_nonce and provides DPoP-Nonce header, retry once
      server_nonce = e.response&.headers&.[]("dpop-nonce") || e.response&.headers&.[]("DPoP-Nonce")
      if server_nonce.present? && dpop_key.present?
        Rails.logger.info("Captured RFC 9449 DPoP-Nonce '#{server_nonce}'. Retrying code exchange with bound nonce.") if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
        new_assertion = build_client_assertion(token_url)
        params[:client_assertion] = new_assertion
        retried_dpop_proof = build_dpop_proof("POST", token_url, nil, dpop_key, server_nonce)
        params[:headers] = { "DPoP" => retried_dpop_proof }
        opts[:headers] = { "DPoP" => retried_dpop_proof }
        auth_code.get_token(code, params, opts)
      else
        raise e
      end
    end
  end

  # Generates an ephemeral asymmetric key for DPoP proof-of-possession (RFC 9449).
  # Defaults to EC P-256 (ES256) for sub-millisecond generation time.
  #
  # @param type [Symbol] :ec for P-256 (default) or :rsa for RSA-2048
  # @return [OpenSSL::PKey::EC, OpenSSL::PKey::RSA]
  def self.generate_dpop_key(type = :ec)
    if type == :rsa
      OpenSSL::PKey::RSA.generate(2048)
    else
      OpenSSL::PKey::EC.generate("prime256v1")
    end
  end

  # Constructs a signed DPoP proof JWT (RFC 9449 Section 4.2).
  # Binds the request method and URI to the client's public key (jwk header claim).
  #
  # @param http_method [String] HTTP request method (e.g. "POST", "GET")
  # @param http_url [String] Target request URI
  # @param access_token [String, nil] Raw access token for 'ath' claim binding
  # @param dpop_key [OpenSSL::PKey::EC, OpenSSL::PKey::RSA, String]
  # @param nonce [String, nil] Server-provided nonce for RFC 9449 replay protection
  # @return [String] Compact serialized DPoP proof JWT
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
  #
  # Cryptographic & Semantic Checks:
  # 1. Strict Algorithm Pinning: Enforces RS256 algorithm.
  # 2. Cryptographic Signature: Verified against the authorization server's JWKS (/oauth2/jwks).
  # 3. Fail-Closed Architecture: Rejects token if JWKS cannot be resolved.
  # 4. Nonce Matching: Prevents token injection and replay attacks.
  # 5. Issuer & Audience Verification: Matches configured issuer URL and client ID.
  # 6. Temporal Validity: Validates exp and iat with 60-second clock skew tolerance.
  # 7. Access Token Hash (at_hash): Validates cryptographic binding between access token and ID token.
  #
  # @param id_token_jwt [String] Raw JWS ID token string
  # @param expected_nonce [String, nil] Expected nonce value from authorization request
  # @param raw_access_token [String, nil] Raw access token for at_hash verification
  # @param code [String, nil] Authorization code for c_hash verification
  # @return [Hash] Decoded JWT payload claims
  def decode_and_verify_id_token(id_token_jwt, expected_nonce, raw_access_token = nil, code = nil)
    return {} if id_token_jwt.blank?

    # Inspect unverified header to extract key ID for JWKS resolution and enforce algorithm pinning
    header = (JWT.decode(id_token_jwt, nil, false)[1] rescue {}) || {}
    alg = header["alg"]
    if alg.blank? || alg.downcase == "none" || alg != "RS256"
      raise "Security Error: Strict Algorithm Pinning: Only 'RS256' algorithm is permitted. Rejected algorithm '#{alg}'."
    end

    kid = header["kid"]
    jwk_set = fetch_jwks(kid)

    # Fail closed if JWKS cannot be loaded or returns empty set
    unless jwk_set.present?
      raise "Security Error: Cryptographic failure. Unable to fetch valid JWKS from Authorization Server (#{@internal_issuer_url}/oauth2/jwks). Refusing to process unverified ID Token."
    end

    # Cryptographic RS256 signature verification against published JWKS
    decoded = JWT.decode(id_token_jwt, nil, true, {
      algorithms: ["RS256"],
      jwks: jwk_set,
      iss: @public_issuer_url,
      verify_iss: true,
      aud: id,
      verify_aud: true
    })

    payload = decoded[0]
    now = Time.now.to_i
    leeway = 60 # 60 seconds clock skew tolerance

    # Validate nonce matches authorization session
    if expected_nonce.present? && payload["nonce"] != expected_nonce
      raise "Security Error: ID Token nonce ('#{payload['nonce']}') does not match expected nonce ('#{expected_nonce}')"
    end

    # Validate issuer matches authorization server URL
    if payload["iss"] != @public_issuer_url
      raise "Security Error: ID Token issuer ('#{payload['iss']}') does not match expected issuer ('#{@public_issuer_url}')"
    end

    # Validate audience contains client ID
    aud = payload["aud"]
    valid_aud = aud == id || (aud.is_a?(Array) && aud.include?(id))
    unless valid_aud
      raise "Security Error: ID Token audience ('#{aud}') does not include client_id ('#{id}')"
    end

    # Validate expiration timestamp
    if payload["exp"].to_i < (now - leeway)
      raise "Security Error: ID Token has expired at #{Time.at(payload['exp'].to_i)}"
    end

    # Validate issuance time is not future-dated
    if payload["iat"].present? && payload["iat"].to_i > (now + leeway)
      raise "Security Error: ID Token issued in the future at #{Time.at(payload['iat'].to_i)}"
    end

    # Validate access token hash (at_hash) binding
    if payload["at_hash"].present? && raw_access_token.present?
      digest = OpenSSL::Digest::SHA256.digest(raw_access_token)
      expected_at_hash = Base64.urlsafe_encode64(digest[0...16], padding: false)
      if payload["at_hash"] != expected_at_hash
        raise "Security Error: ID Token at_hash ('#{payload['at_hash']}') does not match calculated access token hash ('#{expected_at_hash}')"
      end
    end

    # Validate authorization code hash (c_hash) binding (OIDC Core 1.0 Section 3.3.2.11)
    if payload["c_hash"].present? && code.present?
      code_digest = OpenSSL::Digest::SHA256.digest(code)
      expected_c_hash = Base64.urlsafe_encode64(code_digest[0...16], padding: false)
      if payload["c_hash"] != expected_c_hash
        raise "Security Error: ID Token c_hash ('#{payload['c_hash']}') does not match calculated code hash ('#{expected_c_hash}')"
      end
    end

    payload
  end

  # Executes a block with exponential backoff and randomized jitter
  # for idempotent HTTP network operations.
  #
  # @param max_retries [Integer] Maximum retry attempts (default 3)
  # @param base_delay [Float] Base backoff delay in seconds
  # @param max_delay [Float] Ceiling for backoff delay
  # @param operation_name [String] Descriptive name for logging
  def with_retries(max_retries: 3, base_delay: 0.1, max_delay: 1.0, operation_name: "Operation")
    retries = 0
    begin
      yield
    rescue Faraday::ConnectionFailed, Faraday::TimeoutError, Errno::ECONNRESET, Errno::ETIMEDOUT,
           Net::OpenTimeout, Net::ReadTimeout, SocketError => e
      retries += 1
      if retries <= max_retries
        sleep_time = [base_delay * (2**(retries - 1)), max_delay].min + (rand * 0.05)
        Rails.logger.warn("[Retry] #{operation_name} failed with #{e.class} (#{e.message}). Retrying in #{sleep_time.round(3)}s (Attempt #{retries}/#{max_retries})...") if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
        sleep(sleep_time)
        retry
      else
        raise
      end
    end
  end

  # Resolves the authorization server JWKS with thread-safe in-memory caching (1-hour TTL).
  # If a token presents an unknown kid, triggers a single rate-limited network refresh
  # to seamlessly accommodate zero-downtime key rotations.
  #
  # @param kid [String, nil] Target key ID
  # @return [JWT::JWK::Set, nil]
  def fetch_jwks(kid = nil)
    now = Time.now
    @@jwks_cache.synchronize do
      entry = @@cached_jwks[@issuer_url]

      # Check if cached set is valid and contains kid (if kid specified)
      if entry && entry[:expires_at] > now
        jwk_set = entry[:jwk_set]
        if kid.nil? || jwk_set_contains_kid?(jwk_set, kid)
          return jwk_set
        end

        # kid is unknown! Possible key rotation by Authorization Server.
        # Only re-fetch if at least 5s has elapsed since last fetch to prevent cache-busting DDoS.
        if (now - entry[:last_fetched_at]) < 5
          return jwk_set
        end
      end

      # Fetch from network with automated retries
      raw_json = with_retries(operation_name: "Fetch JWKS") do
        resp = connection.get("#{@internal_issuer_url}/oauth2/jwks")
        resp.status == 200 ? resp.body : nil
      end

      if raw_json.present?
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

      # Return previous cached set if fetch failed
      entry ? entry[:jwk_set] : nil
    end
  rescue => e
    Rails.logger.warn("Failed to fetch JWKS from #{@internal_issuer_url}/oauth2/jwks: #{e.message}") if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
    nil
  end

  def jwk_set_contains_kid?(jwk_set, kid)
    return false unless jwk_set && kid
    jwk_set.any? do |jwk|
      (jwk.respond_to?(:kid) && jwk.kid == kid) ||
        (jwk.respond_to?(:[]) && (jwk[:kid] == kid || jwk["kid"] == kid))
    end
  end

  # OpenID Connect RP-Initiated Logout 1.0: Construct standard end_session_endpoint URL
  def end_session_url(id_token_hint, post_logout_redirect_uri)
    params = {
      id_token_hint: id_token_hint,
      post_logout_redirect_uri: post_logout_redirect_uri,
      client_id: id
    }.compact
    "#{@public_issuer_url}/connect/logout?#{URI.encode_www_form(params)}"
  end

  # RFC 6749 Section 6 / OAuth 2.1: Refresh Token Grant using private_key_jwt client assertion and optional DPoP proof
  def refresh_access_token(refresh_token_value, dpop_key = nil)
    assertion = build_client_assertion(token_url)
    token_obj = OAuth2::AccessToken.new(self, "", refresh_token: refresh_token_value)

    params = {
      client_id: id,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion
    }

    opts = {}
    if dpop_key.present?
      dpop_proof = build_dpop_proof("POST", token_url, nil, dpop_key)
      # OAuth2::Client#params_to_req_opts extracts :headers from params
      params[:headers] = { "DPoP" => dpop_proof }
      opts[:headers] = { "DPoP" => dpop_proof }
    end

    # Uses oauth2 gem's built-in refresh! method with client assertion parameters
    token_obj.refresh!(params, opts)
  end

  # RFC 7662: OAuth 2.0 Token Introspection
  # Allows clients to query the active state and metadata of an access or refresh token
  # Authenticates using private_key_jwt client assertion
  def introspect_token(token_value, token_type_hint = "access_token")
    return { "active" => false } if token_value.blank?

    introspect_url = "#{@internal_issuer_url}/oauth2/introspect"
    assertion = build_client_assertion(introspect_url)

    request_body = {
      token: token_value,
      token_type_hint: token_type_hint,
      client_id: id,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion
    }

    response = with_retries(operation_name: "Token Introspection") do
      connection.post(introspect_url) do |req|
        req.headers["Content-Type"] = "application/x-www-form-urlencoded"
        req.body = URI.encode_www_form(request_body)
      end
    end

    if response.status == 200
      JSON.parse(response.body) rescue { "active" => false }
    else
      Rails.logger.warn("Introspection failed with HTTP #{response.status}: #{response.body}")
      { "active" => false }
    end
  end

  # Revokes an access token or refresh token via RFC 7009 Token Revocation,
  # authenticating via RFC 7523 private_key_jwt client assertion.
  #
  # @param token_value [String] Token string to revoke
  # @param token_type_hint [String] "access_token" or "refresh_token"
  # @return [Boolean] True if revocation was successful
  def revoke_token(token_value, token_type_hint = "access_token")
    return false if token_value.blank?

    revoke_url = "#{@internal_issuer_url}/oauth2/revoke"
    assertion = build_client_assertion(revoke_url)

    request_body = {
      token: token_value,
      token_type_hint: token_type_hint,
      client_id: id,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion
    }

    response = with_retries(operation_name: "Token Revocation") do
      connection.post(revoke_url) do |req|
        req.headers["Content-Type"] = "application/x-www-form-urlencoded"
        req.body = URI.encode_www_form(request_body)
      end
    end

    response.status == 200
  end

  # Validates and decodes a signed logout_token according to OIDC Back-Channel Logout 1.0 Section 2.4.
  #
  # Cryptographic & Semantic Checks:
  # 1. Strict Algorithm Pinning: Enforces RS256 algorithm.
  # 2. Cryptographic Signature: Verified against AS JWKS.
  # 3. Events Claim: Must contain 'http://schemas.openid.net/event/backchannel-logout'.
  # 4. Nonce Prohibition: Rejects tokens containing a nonce to avoid token confusion attacks.
  # 5. Audience & Issuer: Validates client ID and issuer URL.
  #
  # @param logout_token_jwt [String] Compact serialized JWT
  # @return [Hash, nil] Validated payload claims or nil
  def verify_logout_token(logout_token_jwt)
    return nil if logout_token_jwt.blank?

    kid = nil
    begin
      headers = JWT.decode(logout_token_jwt, nil, false)[1]
      kid = headers["kid"]
      alg = headers["alg"]
      if alg.blank? || alg.downcase == "none" || alg != "RS256"
        raise "Security Error: Strict Algorithm Pinning: Only 'RS256' algorithm is permitted for logout tokens. Rejected algorithm '#{alg}'."
      end
    rescue => e
      raise e if e.message.include?("Strict Algorithm Pinning")
      # If other header decode fails, let standard decode handle it
    end

    jwk_set = fetch_jwks(kid)
    unless jwk_set.present?
      raise "Security Error: Unable to fetch AS JWKS to verify logout_token signature"
    end

    decoded = JWT.decode(logout_token_jwt, nil, true, {
      algorithms: ["RS256"],
      jwks: jwk_set,
      iss: @public_issuer_url,
      verify_iss: true,
      aud: id,
      verify_aud: true
    })

    payload = decoded[0]

    # Section 2.4: events claim MUST contain the backchannel-logout event
    events = payload["events"] || {}
    unless events.key?("http://schemas.openid.net/event/backchannel-logout")
      raise "Security Error: logout_token missing required event claim (http://schemas.openid.net/event/backchannel-logout)"
    end

    # Section 2.4: MUST NOT contain nonce
    if payload.key?("nonce")
      raise "Security Error: logout_token MUST NOT contain a nonce claim"
    end

    payload
  end

  # Fetches UserInfo claims (OIDC Core 1.0 Section 5.3) using Bearer or DPoP authentication.
  #
  # @param access_token [String] Active access token
  # @param dpop_key [OpenSSL::PKey::EC, OpenSSL::PKey::RSA, String, nil] Ephemeral DPoP key
  # @return [Hash] User profile claims
  def fetch_userinfo(access_token, dpop_key = nil)
    return {} if access_token.blank?

    userinfo_url = "#{@internal_issuer_url}/userinfo"
    response = with_retries(operation_name: "Fetch UserInfo") do
      connection.get(userinfo_url) do |req|
        if dpop_key.present?
          # RFC 9449 Section 7: Accessing Protected Resources with DPoP
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
      Rails.logger.warn("UserInfo request returned HTTP #{response.status}: #{response.body}")
      return {}
    end

    JSON.parse(response.body) rescue {}
  end
end

# Zeitwerk autoloading compatibility alias
ParOauth2Client = ParOAuth2Client
