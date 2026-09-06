require "oauth2"
require "jwt"
require "securerandom"
require "openssl"
require "uri"

# Security Improvement: ParOAuth2Client extends the official, maintained OAuth2::Client library
# adding first-class support for:
# 1. RFC 9126: Pushed Authorization Requests (PAR)
# 2. RFC 7523: Private Key JWT Client Authentication (private_key_jwt)
# 3. RFC 7636: Proof Key for Code Exchange (PKCE)
# 4. OpenID Connect ID Token validation (State & Nonce matching)
class ParOAuth2Client < OAuth2::Client
  attr_reader :private_key, :issuer_url, :par_url

  def initialize(client_id, private_key_pem, options = {})
    @issuer_url = options.delete(:issuer_url) || ENV.fetch("AUTH_SERVER_URL", "http://localhost:9000")
    @private_key = OpenSSL::PKey::RSA.new(private_key_pem)
    @par_url = options.delete(:par_url) || "#{@issuer_url}/oauth2/par"

    super(
      client_id,
      nil, # Security: No client secret; client authenticates exclusively via private_key_jwt
      {
        site: @issuer_url,
        authorize_url: "#{@issuer_url}/oauth2/authorize",
        token_url: "#{@issuer_url}/oauth2/token",
        auth_scheme: :request_body
      }.merge(options)
    )
  end

  # Security Improvement (RFC 7523 Section 3): Build and sign an authentication assertion JWT
  # - iss & sub: Must match client_id to prevent client impersonation
  # - aud: Strictly targeted to the authorization server endpoint to prevent cross-server replay
  # - jti: Cryptographically random UUID to prevent assertion replay within validity window
  # - exp: Short-lived expiration (60 seconds)
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

  # Security Improvement (RFC 9126): Push Authorization Request (PAR)
  # Pushes all authorization parameters over direct authenticated TLS backchannel,
  # preventing sensitive parameters (scopes, state, PKCE challenge) from leaking into browser URL or access logs.
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

  # Security Improvement: Exchange authorization code with PKCE verification, private_key_jwt client assertion,
  # and optional RFC 9449 DPoP proof header
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
      # OAuth2::Client#params_to_req_opts extracts :headers from params
      params[:headers] = { "DPoP" => dpop_proof }
      opts[:headers] = { "DPoP" => dpop_proof }
    end

    # Calls OAuth2::Client's built-in token endpoint request mechanism
    auth_code.get_token(code, params, opts)
  end

  # Security Improvement (RFC 9449): Generate ephemeral asymmetric RSA key for DPoP proof-of-possession
  def self.generate_dpop_key
    OpenSSL::PKey::RSA.generate(2048)
  end

  # Security Improvement (RFC 9449 Section 4.2): Construct signed DPoP proof JWT
  # Binds the request to the client's private key via thumbprint (jkt)
  def build_dpop_proof(http_method, http_url, access_token = nil, dpop_key = nil)
    key = dpop_key.is_a?(String) ? OpenSSL::PKey::RSA.new(dpop_key) : dpop_key
    raise "Missing DPoP private key" unless key

    jwk = JWT::JWK.new(key.public_key)
    public_jwk = jwk.export.slice(:kty, :n, :e)

    headers = {
      typ: "dpop+jwt",
      alg: "RS256",
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

    if access_token.present?
      digest = OpenSSL::Digest::SHA256.digest(access_token)
      payload[:ath] = Base64.urlsafe_encode64(digest, padding: false)
    end

    JWT.encode(payload, key, "RS256", headers)
  end

  # Security Improvement (OIDC Core 1.0 Section 3.1.3.7): Cryptographically verify ID Token signature and claims
  # 1. Signature Verification: Validates JWS signature against the Authorization Server's published JWKS (/oauth2/jwks)
  #    to ensure the ID token was authentically minted by the AS and has not been tampered with or forged.
  # 2. Issuer Validation: Ensures 'iss' matches the configured issuer URL, preventing token substitution attacks.
  # 3. Audience Validation: Ensures 'aud' contains client_id, preventing token confusion attacks across clients.
  # 4. Nonce Validation: Validates 'nonce' matches the value sent during authorization, stopping replay and token injection.
  # 5. Access Token Hash (at_hash) Validation: Cryptographically binds access token to ID token (OIDC Core Section 3.1.3.7).
  # 6. Expiration & Future-Dating Check: Validates exp and iat timestamps with clock skew tolerance.
  def decode_and_verify_id_token(id_token_jwt, expected_nonce, raw_access_token = nil)
    return {} if id_token_jwt.blank?

    jwk_set = fetch_jwks
    # Security Improvement: Fail-Secure Architecture (RFC 7519 & OIDC Core 1.0)
    # Fail-closed: Never accept unverified tokens if the AS JWKS cannot be loaded or returns invalid keys
    unless jwk_set.present?
      raise "Security Error: Cryptographic failure. Unable to fetch valid JWKS from Authorization Server (#{@issuer_url}/oauth2/jwks). Refusing to process unverified ID Token."
    end

    # Security Improvement: Cryptographic RS256 signature verification against AS published JWKS
    decoded = JWT.decode(id_token_jwt, nil, true, {
      algorithms: ["RS256"],
      jwks: jwk_set,
      iss: @issuer_url,
      verify_iss: true,
      aud: id,
      verify_aud: true
    })

    payload = decoded[0]
    now = Time.now.to_i
    leeway = 60 # 60 seconds clock skew tolerance (standard RFC 7519 recommendation)

    # Security Improvement: Nonce validation prevents token injection and replay attacks (OIDC Core Section 3.1.3.7)
    if expected_nonce.present? && payload["nonce"] != expected_nonce
      raise "Security Error: ID Token nonce ('#{payload['nonce']}') does not match expected nonce ('#{expected_nonce}')"
    end

    # Security Improvement: Issuer validation ensures token was minted by trusted auth server
    if payload["iss"] != @issuer_url
      raise "Security Error: ID Token issuer ('#{payload['iss']}') does not match expected issuer ('#{@issuer_url}')"
    end

    # Security Improvement: Audience validation ensures token was intended for this client
    aud = payload["aud"]
    valid_aud = aud == id || (aud.is_a?(Array) && aud.include?(id))
    unless valid_aud
      raise "Security Error: ID Token audience ('#{aud}') does not include client_id ('#{id}')"
    end

    # Security Improvement: Expiration check with clock skew tolerance
    if payload["exp"].to_i < (now - leeway)
      raise "Security Error: ID Token has expired at #{Time.at(payload['exp'].to_i)}"
    end

    # Security Improvement: Future-dating check on Issued-At (iat)
    # Rejects tokens fabricated with future issuance times
    if payload["iat"].present? && payload["iat"].to_i > (now + leeway)
      raise "Security Error: ID Token issued in the future at #{Time.at(payload['iat'].to_i)}"
    end

    # Security Improvement (OIDC Core 1.0 Section 3.1.3.7): at_hash (Access Token Hash) Validation
    # Mitigates access token substitution and injection attacks by verifying the SHA-256 hash
    if payload["at_hash"].present? && raw_access_token.present?
      digest = OpenSSL::Digest::SHA256.digest(raw_access_token)
      expected_at_hash = Base64.urlsafe_encode64(digest[0...16], padding: false)
      if payload["at_hash"] != expected_at_hash
        raise "Security Error: ID Token at_hash ('#{payload['at_hash']}') does not match calculated access token hash ('#{expected_at_hash}')"
      end
    end

    payload
  end

  # Security Improvement: Fetch and cache Authorization Server's JWKS in Redis with a 1-hour TTL
  # Ensures key rotation by AS is honored while mitigating network latency and DDoS against JWKS endpoint
  def fetch_jwks
    jwks_json = Rails.cache.fetch("oauth2:jwks:#{@issuer_url}", expires_in: 1.hour) do
      response = connection.get("#{@issuer_url}/oauth2/jwks")
      if response.status == 200
        response.body
      else
        nil
      end
    end

    if jwks_json.present?
      jwks_hash = JSON.parse(jwks_json) rescue nil
      JWT::JWK::Set.new(jwks_hash) if jwks_hash
    end
  rescue => e
    Rails.logger.warn("Failed to fetch JWKS from #{@issuer_url}/oauth2/jwks: #{e.message}")
    nil
  end

  # OpenID Connect RP-Initiated Logout 1.0: Construct standard end_session_endpoint URL
  def end_session_url(id_token_hint, post_logout_redirect_uri)
    params = {
      id_token_hint: id_token_hint,
      post_logout_redirect_uri: post_logout_redirect_uri,
      client_id: id
    }.compact
    "#{@issuer_url}/connect/logout?#{URI.encode_www_form(params)}"
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

    introspect_url = "#{@issuer_url}/oauth2/introspect"
    assertion = build_client_assertion(introspect_url)

    request_body = {
      token: token_value,
      token_type_hint: token_type_hint,
      client_id: id,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion
    }

    response = connection.post(introspect_url) do |req|
      req.headers["Content-Type"] = "application/x-www-form-urlencoded"
      req.body = URI.encode_www_form(request_body)
    end

    if response.status == 200
      JSON.parse(response.body) rescue { "active" => false }
    else
      Rails.logger.warn("Introspection failed with HTTP #{response.status}: #{response.body}")
      { "active" => false }
    end
  end

  # Security Improvement (RFC 7009): Client-Authenticated Token Revocation
  # Allows clients to explicitly revoke access tokens or refresh tokens via /oauth2/revoke
  def revoke_token(token_value, token_type_hint = "access_token")
    return false if token_value.blank?

    revoke_url = "#{@issuer_url}/oauth2/revoke"
    assertion = build_client_assertion(revoke_url)

    request_body = {
      token: token_value,
      token_type_hint: token_type_hint,
      client_id: id,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion
    }

    response = connection.post(revoke_url) do |req|
      req.headers["Content-Type"] = "application/x-www-form-urlencoded"
      req.body = URI.encode_www_form(request_body)
    end

    response.status == 200
  end

  # Security Improvement (OIDC Back-Channel Logout 1.0 Section 2.4): Verify logout_token
  # - Cryptographically validates JWS signature against AS published JWKS
  # - events claim MUST contain "http://schemas.openid.net/event/backchannel-logout"
  # - MUST NOT contain nonce claim (prevents ID token substitution)
  # - aud MUST match client_id
  # - iss MUST match issuer_url
  def verify_logout_token(logout_token_jwt)
    return nil if logout_token_jwt.blank?

    jwk_set = fetch_jwks
    unless jwk_set.present?
      raise "Security Error: Unable to fetch AS JWKS to verify logout_token signature"
    end

    decoded = JWT.decode(logout_token_jwt, nil, true, {
      algorithms: ["RS256"],
      jwks: jwk_set,
      iss: @issuer_url,
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

  # OpenID Connect Core 1.0 Section 5.3: UserInfo Request
  # Uses Bearer or DPoP access token to request protected user claims authorized by requested scopes
  def fetch_userinfo(access_token, dpop_key = nil)
    return {} if access_token.blank?

    response = connection.get("#{@issuer_url}/userinfo") do |req|
      if dpop_key.present?
        # RFC 9449 Section 7: Accessing Protected Resources with DPoP
        dpop_proof = build_dpop_proof("GET", "#{@issuer_url}/userinfo", access_token, dpop_key)
        req.headers["Authorization"] = "DPoP #{access_token}"
        req.headers["DPoP"] = dpop_proof
      else
        req.headers["Authorization"] = "Bearer #{access_token}"
      end
      req.headers["Accept"] = "application/json"
    end

    # Security Improvement: Check HTTP status code and log or raise if token is unauthorized/expired
    unless response.status == 200
      Rails.logger.warn("UserInfo request returned HTTP #{response.status}: #{response.body}")
      return {}
    end

    JSON.parse(response.body) rescue {}
  end
end

# Zeitwerk autoloading compatibility alias
ParOauth2Client = ParOAuth2Client
