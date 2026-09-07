require "redis"
require "json"
require "securerandom"
require "uri"
require "active_support/security_utils"

class SessionsController < ApplicationController
  # Security Improvement: Allowed origins for OAuth return_to redirects to prevent Open Redirect phishing attacks
  ALLOWED_RETURN_HOSTS = [
    "localhost:9000",
    "127.0.0.1:9000",
    "spring-auth-server:9000"
  ].freeze

  def new
    @return_to = sanitize_return_to(params[:return_to])
  end

  def create
    # Security Improvement: Sanitize inputs to prevent unexpected payload injection
    username = params[:username].to_s.strip.slice(0, 100)
    username = "demo_user" if username.blank?

    password = params[:password].to_s

    # Security Improvement: Use secure_compare to prevent timing attacks through side-channel latency differences
    expected_password = "password"
    is_valid_password = ActiveSupport::SecurityUtils.secure_compare(password, expected_password)

    # In PoC mode, we accept valid credentials or valid non-empty password
    unless is_valid_password || password.present?
      flash[:error] = "Invalid credentials"
      return render :new, status: :unprocessable_entity
    end

    return_to = sanitize_return_to(params[:return_to])

    # Simulated user details collected by Rails app
    user_payload = {
      username: username,
      email: "#{username}@example.com",
      name: "#{username.capitalize} User",
      roles: ["ROLE_USER"],
      authenticated_at: Time.now.utc.iso8601
    }

    # Store user session JSON in shared Redis (using persistent connection pool/client)
    # Security Improvement: Invalidate old session in Redis to stop session fixation attacks
    old_session_id = cookies[:SHARED_SESSION_ID]
    if old_session_id.present? && valid_session_id?(old_session_id)
      redis_client.del("session:#{old_session_id}")
    end

    # Security Improvement: Generate a cryptographically strong UUIDv4 for the session identifier
    session_id = SecureRandom.uuid
    redis_client.set("session:#{session_id}", user_payload.to_json, ex: 7200)

    # Security Improvement: Hardened Cookie Settings
    # 1. httponly: true -> Stop malicious client-side JavaScript from grabbing the sensitive session cookie (mitigates XSS cookie theft)
    # 2. same_site: :lax -> Prevent Cross-Site Request Forgery (CSRF) by blocking cookie inclusion on third-party cross-site requests
    # 3. secure: request.ssl? -> Transmit cookie only over encrypted HTTPS/TLS connections to prevent man-in-the-middle network interception
    cookies[:SHARED_SESSION_ID] = {
      value: session_id,
      path: "/",
      expires: 2.hours.from_now,
      same_site: :lax,
      httponly: true,
      secure: request.ssl?
    }

    # Security Improvement: Do NOT append session_id into URL query parameters!
    # Transmitting session identifiers in query strings leaks them into browser histories, access logs,
    # and HTTP Referer headers (CWE-598: Information Exposure Through Query Strings in GET Request).
    # The session is maintained exclusively via the HttpOnly cookie above.
    redirect_to return_to, allow_other_host: true, status: :see_other
  end

  def health
    render json: { status: "UP", service: "rails-login-app" }
  end

  def destroy
    session_id = cookies[:SHARED_SESSION_ID]
    if session_id.present? && valid_session_id?(session_id)
      redis_client.del("session:#{session_id}")
      # Security Improvement: Explicitly clear the cookie with matching path to prevent orphaned session cookies
      cookies.delete(:SHARED_SESSION_ID, path: "/")
    end
    redirect_to "/login", notice: "Logged out"
  end

  private

  # Performance Improvement: Reusable thread-safe Redis client to avoid TCP connection churn under high load
  def self.redis_client
    @redis_client ||= Redis.new(
      url: ENV.fetch("REDIS_URL", "redis://localhost:6379"),
      connect_timeout: 2,
      read_timeout: 2,
      write_timeout: 2,
      reconnect_attempts: 2
    )
  end

  def redis_client
    self.class.redis_client
  end

  # Security Improvement: Validate return_to parameter against trusted OAuth host whitelist to prevent Open Redirect attacks
  def sanitize_return_to(target_url)
    return "http://localhost:9000" if target_url.blank?

    begin
      parsed = URI.parse(target_url.to_s.strip)
      # Allow relative paths or whitelisted hosts
      if parsed.host.nil?
        target_url.start_with?("/") ? target_url : "http://localhost:9000"
      elsif ALLOWED_RETURN_HOSTS.include?(parsed.host) || ALLOWED_RETURN_HOSTS.include?("#{parsed.host}:#{parsed.port}")
        target_url
      else
        # Security Improvement: Disallow redirecting to unauthorized external domains
        Rails.logger.warn("Blocked potentially malicious open redirect to: #{target_url}")
        "http://localhost:9000"
      end
    rescue URI::InvalidURIError
      "http://localhost:9000"
    end
  end

  # Security Improvement: Validate session_id format to prevent key injection attacks against Redis
  def valid_session_id?(session_id)
    session_id.is_a?(String) && session_id.match?(/\A[0-9a-fA-F\-]{36}\z/)
  end
end
