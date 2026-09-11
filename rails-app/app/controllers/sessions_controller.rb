require "redis"
require "json"
require "securerandom"
require "uri"
require "active_support/security_utils"

class SessionsController < ApplicationController
  # Whitelist of allowed redirect targets for the return_to parameter to prevent Open Redirect attacks
  ALLOWED_RETURN_HOSTS = [
    "localhost:9000",
    "127.0.0.1:9000",
    "spring-auth-server:9000"
  ].freeze

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
      if parsed.host.nil?
        target_url.start_with?("/") ? target_url : "http://localhost:9000"
      elsif ALLOWED_RETURN_HOSTS.include?(parsed.host) || ALLOWED_RETURN_HOSTS.include?("#{parsed.host}:#{parsed.port}")
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

  # Resolves client failure URL according to RFC 6749 Section 4.1.2.1:
  # Extracts redirect_uri and state from the return_to authorization request URI
  # (whether passed as direct query params or via PAR request_uri stored in PostgreSQL / session).
  def resolve_client_failure_redirect(return_to_url, error_code, error_description)
    return nil if return_to_url.blank?

    begin
      parsed_uri = URI.parse(return_to_url.to_s.strip)
      query_params = URI.decode_www_form(parsed_uri.query || "").to_h

      redirect_uri = query_params["redirect_uri"]
      state = query_params["state"]

      # If direct parameters missing (e.g. PAR request_uri flow), attempt to lookup authorization from Postgres DB
      if redirect_uri.blank? && query_params["request_uri"].present?
        par_uri = query_params["request_uri"]
        # In Spring Authorization Server, PAR request_uri maps to state in oauth2_authorization table
        # Format: urn:ietf:params:oauth:request_uri:<state_token>
        state_token = par_uri.sub("urn:ietf:params:oauth:request_uri:", "")
        db_record = ActiveRecord::Base.connection.select_one(
          ActiveRecord::Base.sanitize_sql_array([
            "SELECT attributes FROM oauth2_authorization WHERE state LIKE ? LIMIT 1",
            "#{state_token}%"
          ])
        )

        if db_record && db_record["attributes"].present?
          attrs_json = db_record["attributes"]
          # Extract redirectUri and state from stored OAuth2AuthorizationRequest JSON
          if attrs_json =~ /"redirectUri":"([^"]+)"/
            redirect_uri = $1
          end
          if attrs_json =~ /"state":"([^"]+)"/
            state = $1
          end
        end
      end

      # Fallback to default registered demo client callback if cannot extract dynamically
      redirect_uri ||= "http://localhost:8080/callback"

      callback_uri = URI.parse(redirect_uri)
      existing_params = URI.decode_www_form(callback_uri.query || "").to_h
      existing_params["error"] = error_code
      existing_params["error_description"] = error_description
      existing_params["state"] = state if state.present?

      callback_uri.query = URI.encode_www_form(existing_params)
      callback_uri.to_s
    rescue => e
      Rails.logger.warn("Failed to resolve client failure redirect: #{e.message}")
      "http://localhost:8080/callback?error=#{error_code}&error_description=#{ERB::Util.url_encode(error_description)}"
    end
  end
end
