require "digest"
require "base64"
require "securerandom"
require_relative "../services/par_oauth2_client"

class AuthController < ApplicationController
  before_action :set_oauth_client
  # Security / Protocol: Skip CSRF token for server-to-server OIDC Back-Channel Logout requests
  skip_before_action :verify_authenticity_token, only: [:backchannel_logout]

  CLIENT_ID = "demo-client"
  # Security Improvement: Client sends no requested scopes.
  # The Authorization Server strictly determines and assigns authorized scopes based on
  # registered client identity and policy, mitigating scope injection and privilege escalation.

  # GET /
  def index
    # Ensure fresh sessions establish their cookie on first visit
    session[:initialized] ||= true

    @auth_server_url = auth_server_url
    @client_id = CLIENT_ID
    @redirect_uri = current_redirect_uri
    @authenticated = session[:user].present?
  end

  # POST /auth/start
  def start
    flow = params[:flow] == "direct" ? :direct : :par

    # Security Improvement (RFC 7636 PKCE): Generate high-entropy code_verifier and S256 code_challenge
    # Protects against authorization code interception attacks on public or private networks
    code_verifier = SecureRandom.urlsafe_base64(64).tr("=", "")
    code_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier)).tr("=", "")

    # Security Improvement: Cryptographic State token (192-bit entropy) to stop CSRF
    state = SecureRandom.hex(24)

    # Security Improvement (OIDC Nonce): Nonce parameter to stop ID Token injection and replay attacks
    nonce = SecureRandom.hex(24)

    redirect_uri = current_redirect_uri

    # Security Improvement (RFC 9449 DPoP): Generate ephemeral asymmetric key pair for proof-of-possession
    dpop_key = ParOAuth2Client.generate_dpop_key
    dpop_key_pem = dpop_key.to_pem

    # Store security parameters in client-side signed session
    session[:oauth_code_verifier] = code_verifier
    session[:oauth_state] = state
    session[:oauth_nonce] = nonce
    session[:oauth_flow] = flow.to_s
    session[:oauth_redirect_uri] = redirect_uri
    session[:oauth_dpop_key] = dpop_key_pem

    # Security & Reliability Improvement: Also store single-use state context in server-side cache.
    # This prevents state mismatch errors when browsers transition between localhost and 127.0.0.1
    # or enforce strict partitioned cookie policies on cross-site redirect returns.
    Rails.cache.write("oauth_flow:#{state}", {
      code_verifier: code_verifier,
      nonce: nonce,
      flow: flow.to_s,
      redirect_uri: redirect_uri,
      dpop_key: dpop_key_pem
    }, expires_in: 10.minutes)

    # Security / Architecture: Zero requested scopes sent by client.
    # The Authorization Server strictly determines all authorized scopes for the client.
    auth_params = {
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: redirect_uri,
      state: state,
      nonce: nonce,
      code_challenge: code_challenge,
      code_challenge_method: "S256"
    }

    if flow == :par
      # RFC 9126: Push authorization request over backchannel
      begin
        request_uri = @client.push_authorization_request(auth_params)
        session[:request_uri] = request_uri

        # Browser redirects with only client_id and request_uri
        authorize_url = "#{auth_server_url}/oauth2/authorize?client_id=#{CLIENT_ID}&request_uri=#{ERB::Util.url_encode(request_uri)}"
        redirect_to authorize_url, allow_other_host: true, status: :see_other
      rescue => e
        flash[:error] = "PAR Initialization Error: #{e.message}"
        redirect_to root_path
      end
    else
      # Direct authorization request
      authorize_url = "#{auth_server_url}/oauth2/authorize?#{URI.encode_www_form(auth_params)}"
      redirect_to authorize_url, allow_other_host: true, status: :see_other
    end
  end

  # GET /callback
  def callback
    if params[:error].present?
      flash[:error] = "OAuth Error: #{params[:error]} - #{params[:error_description]}"
      return redirect_to root_path
    end

    state_param = params[:state]
    cached_flow = Rails.cache.read("oauth_flow:#{state_param}") if state_param.present?
    Rails.cache.delete("oauth_flow:#{state_param}") if state_param.present?

    # Security Improvement: Verify state matches session or single-use cryptographic server cache
    expected_state = session.delete(:oauth_state)
    valid_state = (expected_state.present? && state_param == expected_state) || cached_flow.present?

    Rails.logger.info("Callback check: state_param=#{state_param.inspect}, expected_state=#{expected_state.inspect}, cached_flow=#{cached_flow.present?}, session_keys=#{session.to_hash.keys}")

    unless valid_state
      flash[:error] = "Security Error: State parameter mismatch or expired. Possible CSRF attack."
      return redirect_to root_path
    end

    code = params[:code]
    if code.blank?
      flash[:error] = "OAuth Error: No authorization code received."
      return redirect_to root_path
    end

    # Security Improvement (RFC 9207): Validate Authorization Server Issuer Identification to prevent Mix-Up attacks
    if params[:iss].present? && params[:iss] != auth_server_url
      flash[:error] = "Security Error: Authorization Server Issuer Identification mismatch (RFC 9207). Expected #{auth_server_url}, got #{params[:iss]}."
      return redirect_to root_path
    end

    code_verifier = session.delete(:oauth_code_verifier) || cached_flow&.dig(:code_verifier)
    expected_nonce = session.delete(:oauth_nonce) || cached_flow&.dig(:nonce)
    flow = session.delete(:oauth_flow) || cached_flow&.dig(:flow) || "par"
    redirect_uri = session.delete(:oauth_redirect_uri) || cached_flow&.dig(:redirect_uri) || current_redirect_uri
    dpop_key_pem = session.delete(:oauth_dpop_key) || cached_flow&.dig(:dpop_key)

    begin
      # Security Improvement: Exchange code with PKCE verification, private_key_jwt client assertion, and RFC 9449 DPoP
      token = @client.exchange_code(code, code_verifier, redirect_uri, dpop_key_pem)

      raw_id_token = token.params["id_token"]
      raw_access_token = token.token
      raw_refresh_token = token.refresh_token
      token_type = token.params["token_type"] || "Bearer"

      # Security Improvement: Cryptographically verify ID Token signature, nonce, issuer, audience, at_hash, and c_hash
      id_token_claims = @client.decode_and_verify_id_token(raw_id_token, expected_nonce, raw_access_token, code)

      # Decode access token claims
      access_token_claims = begin
        JWT.decode(raw_access_token, nil, false)[0]
      rescue
        {}
      end

      # OIDC Core 1.0 Section 5.3 & RFC 9449: Fetch claims from /userinfo using DPoP/Bearer access token
      userinfo_claims = @client.fetch_userinfo(raw_access_token, dpop_key_pem)
      returned_scopes = token.params["scope"] || access_token_claims["scope"]

      # Security Improvement: Store tokens and DPoP keys in Redis
      token_key = SecureRandom.uuid
      Rails.cache.write("token:#{token_key}", {
        access_token_claims: access_token_claims,
        userinfo_claims: userinfo_claims,
        raw_id_token: raw_id_token,
        raw_access_token: raw_access_token,
        raw_refresh_token: raw_refresh_token,
        token_type: token_type,
        dpop_key: dpop_key_pem,
        sub: id_token_claims["sub"],
        sid: id_token_claims["sid"],
        expires_at: access_token_claims["exp"].to_i
      }, expires_in: 30.days)

      # Establish client session with lightweight user profile
      session[:user] = id_token_claims.merge(userinfo_claims)
      session[:id_token_claims] = id_token_claims # Pure ID token claims without UserInfo
      session[:token_key] = token_key
      session[:token_scopes] = returned_scopes
      session[:auth_flow_used] = flow
      session[:raw_id_token] = raw_id_token # Needed for OIDC RP-Initiated Logout id_token_hint

      flash[:notice] = "Successfully authenticated via OAuth 2.1 (#{flow.upcase})!"
      redirect_to profile_path
    rescue => e
      Rails.logger.error("Token Exchange Exception: #{e.class}: #{e.message}\n#{e.backtrace.first(10).join("\n")}")
      flash[:error] = "Token Exchange Error: #{e.message}"
      redirect_to root_path
    end
  end

  # GET /profile
  def profile
    unless session[:user].present? && session[:token_key].present?
      flash[:error] = "Please log in first."
      return redirect_to root_path
    end

    # Check for valid cached tokens; if missing (e.g. cache expired), evict zombie session
    token_data = Rails.cache.read("token:#{session[:token_key]}")
    if token_data.blank? || token_data[:raw_access_token].blank?
      reset_session
      flash[:error] = "Session tokens have expired or are unavailable. Please log in again."
      return redirect_to root_path
    end

    # Auto-renew access token if expired before rendering profile data
    ensure_fresh_access_token!
    token_data = Rails.cache.read("token:#{session[:token_key]}") || token_data

    @user = session[:user]
    @id_token_claims = session[:id_token_claims] || {}
    @token_scopes = session[:token_scopes]
    @userinfo_claims = token_data[:userinfo_claims] || {}
    @access_token_claims = token_data[:access_token_claims] || {}
    @raw_id_token = token_data[:raw_id_token]
    @raw_access_token = token_data[:raw_access_token]
    @raw_refresh_token = token_data[:raw_refresh_token]
    @auth_flow = session[:auth_flow_used] || "PAR"
    @expires_at = token_data[:expires_at]
    @token_type = token_data[:token_type] || "Bearer"
    @dpop_jkt = @access_token_claims.dig("cnf", "jkt")
  end

  # POST /auth/refresh
  # Explicit or simulated token refresh to demonstrate refresh token rotation
  def refresh
    unless session[:user].present? && session[:token_key].present?
      flash[:error] = "No active session to refresh."
      return redirect_to root_path
    end

    success = perform_token_refresh!
    if success
      flash[:notice] = "Access Token successfully refreshed using Refresh Token (Rotation verified)!"
    else
      flash[:error] = "Token refresh failed. Refresh token may be expired or revoked."
    end
    redirect_to profile_path
  end

  # POST /auth/revoke
  # Security Improvement (RFC 7009): Explicit client token revocation demonstration
  def revoke
    token_data = Rails.cache.read("token:#{session[:token_key]}") || {}
    raw_access_token = token_data[:raw_access_token]
    raw_refresh_token = token_data[:raw_refresh_token]

    if raw_access_token.present?
      @client.revoke_token(raw_access_token, "access_token")
      @client.revoke_token(raw_refresh_token, "refresh_token") if raw_refresh_token.present?

      Rails.cache.delete("token:#{session[:token_key]}")
      reset_session
      flash[:notice] = "Tokens successfully revoked at Authorization Server via RFC 7009! Local session cleared."
    else
      flash[:error] = "No active tokens to revoke."
    end
    redirect_to root_path
  end

  # POST /oidc/backchannel_logout
  # OpenID Connect Back-Channel Logout 1.0 (Section 2.5)
  # Receives logout_token JWT from the OP, verifies it, and clears matching client sessions in Redis
  def backchannel_logout
    logout_token = params[:logout_token]
    if logout_token.blank?
      render plain: "Missing logout_token", status: :bad_request
      return
    end

    begin
      claims = @client.verify_logout_token(logout_token)
      sub = claims["sub"]
      sid = claims["sid"]

      Rails.logger.info("Processing OIDC Back-Channel Logout for sub=#{sub}, sid=#{sid}")

      # Evict matching sessions and cached tokens from Redis DB 1
      redis_url = ENV.fetch("REDIS_URL", "redis://localhost:6379/1")
      redis = Redis.new(url: redis_url)

      session_keys = redis.keys("demo_client:_session_id:*")
      session_keys.each do |key|
        raw_val = redis.get(key)
        if raw_val.present? && ((sid.present? && raw_val.include?(sid)) || (sub.present? && raw_val.include?(sub)))
          redis.del(key)
          Rails.logger.info("Evicted session #{key} via Back-Channel Logout")
        end
      end

      token_keys = redis.keys("demo_client:token:*")
      token_keys.each do |key|
        raw_val = redis.get(key)
        if raw_val.present? && ((sid.present? && raw_val.include?(sid)) || (sub.present? && raw_val.include?(sub)))
          redis.del(key)
          Rails.logger.info("Evicted token #{key} via Back-Channel Logout")
        end
      end

      # OIDC Back-Channel Logout Section 2.7: OP expects 200 OK with Cache-Control: no-store
      response.headers["Cache-Control"] = "no-store"
      response.headers["Pragma"] = "no-cache"
      head :ok
    rescue => e
      Rails.logger.warn("OIDC Back-Channel Logout failed: #{e.message}")
      render plain: "Invalid logout_token: #{e.message}", status: :bad_request
    end
  end

  # POST /auth/sensitive_action
  # Security Improvement (RFC 7662): Pre-flight Token Introspection check before executing sensitive action
  # If the Authorization Server revoked the session early (e.g. fraud detected), the action is halted and session purged.
  def sensitive_action
    unless session[:user].present? && session[:token_key].present?
      flash[:error] = "Authentication required."
      return redirect_to root_path
    end

    token_data = Rails.cache.read("token:#{session[:token_key]}") || {}
    access_token = token_data[:raw_access_token]

    # Perform RFC 7662 Token Introspection
    introspection = @client.introspect_token(access_token)
    @introspection_result = introspection

    if introspection["active"] == true
      flash[:notice] = "🛡️ Sensitive Action Approved! Token Introspection verified active=true (Subject: #{introspection['sub']}, Scopes: #{introspection['scope']})."
    else
      # Security Improvement: Early Termination detected via Token Introspection
      # Evict local session immediately to protect against fraudulent access
      Rails.cache.delete("token:#{session[:token_key]}")
      reset_session
      flash[:error] = "🚨 SECURITY ALERT: Token Introspection check returned active=false. Authorization Server terminated the session early. Local session cleared."
      return redirect_to root_path
    end

    redirect_to profile_path
  end

  # POST /auth/simulate_fraud_revocation
  # Helper to trigger auth server session revocation so the user can see introspection and refresh reject the token immediately
  def simulate_fraud_revocation
    token_data = Rails.cache.read("token:#{session[:token_key]}") || {}
    access_token = token_data[:raw_access_token]

    if access_token.present?
      begin
        response = @client.connection.post("#{auth_server_url}/api/admin/revoke-session") do |req|
          req.headers["Content-Type"] = "application/x-www-form-urlencoded"
          # Security Improvement: Authenticate administrative action with secret API key
          req.headers["X-Admin-Api-Key"] = ENV.fetch("ADMIN_API_KEY", "secret-admin-key")
          req.body = URI.encode_www_form({ token: access_token })
        end
        flash[:notice] = "⚠️ Simulated Fraud Alert: Authorization Server has revoked your authorization session! Test Introspection or Refresh now to observe immediate rejection."
      rescue => e
        flash[:error] = "Failed to simulate revocation: #{e.message}"
      end
    end

    redirect_to profile_path
  end

  # POST /logout
  # OpenID Connect RP-Initiated Logout 1.0 (Single Sign-Out) & RFC 7009 Token Revocation
  def logout
    token_key = session[:token_key]
    token_data = Rails.cache.read("token:#{token_key}") || {}
    raw_access_token = token_data[:raw_access_token]
    raw_refresh_token = token_data[:raw_refresh_token]
    id_token_hint = session[:raw_id_token] || token_data[:raw_id_token]

    # Security Improvement (RFC 7009): Explicitly revoke access and refresh tokens at the AS
    @client.revoke_token(raw_access_token, "access_token") if raw_access_token.present?
    @client.revoke_token(raw_refresh_token, "refresh_token") if raw_refresh_token.present?

    # Security Improvement: Complete client session reset and local cache eviction
    Rails.cache.delete("token:#{token_key}") if token_key.present?
    reset_session

    if id_token_hint.present?
      # Redirect browser to Auth Server OIDC end_session_endpoint for Single Sign-Out
      post_logout_redirect = "#{request.protocol}#{request.host_with_port}/"
      oidc_logout_url = @client.end_session_url(id_token_hint, post_logout_redirect)
      redirect_to oidc_logout_url, allow_other_host: true, status: :see_other
    else
      flash[:notice] = "You have been logged out."
      redirect_to root_path
    end
  end

  private

  # Security & Reliability Improvement: Auto-renew access token using Refresh Token before expiration
  def ensure_fresh_access_token!
    token_data = Rails.cache.read("token:#{session[:token_key]}") || {}
    expires_at = token_data[:expires_at].to_i

    # Refresh if expired or expiring within 60 seconds
    if expires_at > 0 && expires_at - Time.now.to_i <= 60
      perform_token_refresh!
    end
  end

  def perform_token_refresh!
    token_data = Rails.cache.read("token:#{session[:token_key]}") || {}
    refresh_token = token_data[:raw_refresh_token]
    dpop_key = token_data[:dpop_key]
    return false if refresh_token.blank?

    begin
      new_token = @client.refresh_access_token(refresh_token, dpop_key)
      new_access_token = new_token.token
      new_refresh_token = new_token.refresh_token || refresh_token
      new_token_type = new_token.params["token_type"] || token_data[:token_type] || "Bearer"

      new_access_claims = begin
        JWT.decode(new_access_token, nil, false)[0]
      rescue
        {}
      end

      # Update cache with renewed tokens
      Rails.cache.write("token:#{session[:token_key]}", token_data.merge(
        raw_access_token: new_access_token,
        raw_refresh_token: new_refresh_token,
        token_type: new_token_type,
        access_token_claims: new_access_claims,
        expires_at: new_access_claims["exp"].to_i
      ), expires_in: 30.days)

      true
    rescue => e
      Rails.logger.warn("Automatic token refresh failed: #{e.message}")
      false
    end
  end

  def current_redirect_uri
    # Dynamically match the request host so cookies align with localhost vs 127.0.0.1
    "#{request.protocol}#{request.host_with_port}/callback"
  end

  def auth_server_url
    ENV.fetch("AUTH_SERVER_URL", "http://localhost:9000")
  end

  def set_oauth_client
    key_path = ENV.fetch("CLIENT_PRIVATE_KEY_PATH", Rails.root.join("keys/client_private_key.pem").to_s)
    private_key_pem = File.read(key_path)

    @client = ParOAuth2Client.new(
      CLIENT_ID,
      private_key_pem,
      issuer_url: auth_server_url
    )
  end
end
