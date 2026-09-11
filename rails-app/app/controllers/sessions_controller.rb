require "redis"
require "json"
require "securerandom"
require "uri"
require "active_support/security_utils"

class SessionsController < ApplicationController
  # Whitelist of allowed redirect targets for the return_to parameter to prevent Open Redirect attacks
  # Configured dynamically via environment variables with safe defaults
  def self.allowed_return_hosts
    @allowed_return_hosts ||= begin
      hosts = Set.new(["localhost:9000", "127.0.0.1:9000", "spring-auth-server:9000"])
      if ENV["AUTH_SERVER_URL"].present?
        uri = URI.parse(ENV["AUTH_SERVER_URL"]) rescue nil
        hosts << "#{uri.host}:#{uri.port}" if uri&.host
        hosts << uri.host if uri&.host
      end
      if ENV["SPRING_AUTH_SERVER_URL"].present?
        uri = URI.parse(ENV["SPRING_AUTH_SERVER_URL"]) rescue nil
        hosts << "#{uri.host}:#{uri.port}" if uri&.host
        hosts << uri.host if uri&.host
      end
      hosts.freeze
    end
  end

  def new
    @return_to = sanitize_return_to(params[:return_to])
  end

  def create
    username = params[:username].to_s.strip.slice(0, 100)
    username = "demo_user" if username.blank?

    password = params[:password].to_s

    # Error Journey Simulation:
    # Allows testing how client applications handle auth errors returned by the IdP (RFC 6749 Section 4.1.2.1).
    if params[:simulate_error].present? || username == "locked_user" || username == "suspended_user"
      error_code = if username == "locked_user" || params[:simulate_error] == "access_denied"
                     "access_denied"
                   elsif username == "suspended_user" || params[:simulate_error] == "account_suspended"
                     "account_suspended"
                   else
                     params[:simulate_error].to_s
                   end

      error_desc = case error_code
                   when "access_denied"
                     "User account is locked or administrative access was denied."
                   when "account_suspended"
                     "Your account has been temporarily suspended. Please contact customer support."
                   else
                     "Authentication rejected: #{error_code}"
                   end

      failure_redirect_uri = resolve_client_failure_redirect(params[:return_to], error_code, error_desc)
      if failure_redirect_uri.present?
        return redirect_to failure_redirect_uri, allow_other_host: true, status: :see_other
      else
        flash[:error] = "Authentication error: #{error_desc} (No return_to destination provided)"
        return render :new, status: :unprocessable_entity
      end
    end

    # Constant-time comparison to mitigate timing attacks
    expected_password = "password"
    is_valid_password = ActiveSupport::SecurityUtils.secure_compare(password, expected_password)

    # In development/PoC mode, accept predefined credentials or non-empty password
    unless is_valid_password || password.present?
      flash[:error] = "Invalid credentials"
      return render :new, status: :unprocessable_entity
    end

    return_to = sanitize_return_to(params[:return_to])

    user_payload = {
      username: username,
      email: "#{username}@example.com",
      name: "#{username.capitalize} User",
      roles: ["ROLE_USER"],
      authenticated_at: Time.now.utc.iso8601
    }

    # Invalidate previous session in Redis to prevent session fixation attacks
    old_session_id = cookies[:SHARED_SESSION_ID]
    if old_session_id.present? && valid_session_id?(old_session_id)
      redis_client.del("session:#{old_session_id}")
    end

    # Issue cryptographically secure UUIDv4 session identifier and persist to Redis
    session_id = SecureRandom.uuid
    redis_client.set("session:#{session_id}", user_payload.to_json, ex: 7200)

    # Issue hardened session cookie:
    # - HttpOnly: Prevents client-side script access (mitigates XSS cookie theft)
    # - SameSite: Lax: Mitigates CSRF on cross-site requests
    # - Secure: Transmitted only over TLS in production
    cookies[:SHARED_SESSION_ID] = {
      value: session_id,
      path: "/",
      expires: 2.hours.from_now,
      same_site: :lax,
      httponly: true,
      secure: request.ssl?
    }

    # Session identifier is transmitted exclusively via cookie, never in URL query strings (CWE-598)
    redirect_to return_to, allow_other_host: true, status: :see_other
  end

  def health
    render json: { status: "UP", service: "rails-login-app" }
  end

  def destroy
    session_id = cookies[:SHARED_SESSION_ID]
    if session_id.present? && valid_session_id?(session_id)
      redis_client.del("session:#{session_id}")
      cookies.delete(:SHARED_SESSION_ID, path: "/")
    end
    redirect_to "/login", notice: "Logged out"
  end

  private

  # Thread-safe persistent Redis connection
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

  # Validates return_to parameter against trusted hosts to prevent open redirects
  def sanitize_return_to(target_url)
    return "http://localhost:9000" if target_url.blank?

    begin
      parsed = URI.parse(target_url.to_s.strip)
      allowed = self.class.allowed_return_hosts
      if parsed.host.nil?
        target_url.start_with?("/") ? target_url : "http://localhost:9000"
      elsif allowed.include?(parsed.host) || allowed.include?("#{parsed.host}:#{parsed.port}")
        target_url
      else
        Rails.logger.warn("Blocked untrusted return_to redirect: #{target_url}")
        "http://localhost:9000"
      end
    rescue URI::InvalidURIError
      "http://localhost:9000"
    end
  end

  # Enforces strict UUID format before querying Redis to prevent key injection
  def valid_session_id?(session_id)
    session_id.is_a?(String) && session_id.match?(/\A[0-9a-fA-F\-]{36}\z/)
  end

  # Resolves client failure redirect:
  # Redirects back to the Authorization Server (return_to) with RFC 6749 error parameters
  # so that the Authorization Server issues an RFC 9221 KMS-signed JARM error JWT to the client callback.
  def resolve_client_failure_redirect(return_to_url, error_code, error_description)
    return nil if return_to_url.blank?

    begin
      target = URI.parse(return_to_url.to_s.strip)
      separator = target.query.present? ? "&" : "?"
      "#{target}#{separator}error=#{ERB::Util.url_encode(error_code)}&error_description=#{ERB::Util.url_encode(error_description)}"
    rescue => e
      Rails.logger.warn("Failed to construct IdP failure redirect: #{e.message}")
      nil
    end
  end
end
