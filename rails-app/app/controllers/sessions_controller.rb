require "redis"
require "json"
require "securerandom"
require "uri"
require "net/http"
require "digest"

class SessionsController < ApplicationController
  def new
    @return_to = sanitize_return_to(params[:return_to])
  end

  def create
    email = params[:email].to_s.strip.slice(0, 100)
    password = params[:password].to_s
    return_to = sanitize_return_to(params[:return_to])

    if params[:simulate_error].present?
      error_code = params[:simulate_error] == "access_denied" ? "access_denied" : "account_suspended"
      
      error_desc = case error_code
                   when "access_denied"
                     "User account is locked or administrative access was denied."
                   else
                     "Your account has been temporarily suspended. Please contact customer support."
                   end
      
      if return_to.present?
        return redirect_to resolve_client_failure_redirect(return_to, error_code, error_desc), allow_other_host: true, status: :see_other
      else
        @error_message = error_desc
        return render :new, status: :unprocessable_entity
      end
    end

    if email.blank? || password.blank?
      @error_message = "incorrect username or password"
      return render :new, status: :unprocessable_entity
    end

    begin
      uri = URI.parse("#{ENV.fetch('SPRING_AUTH_SERVER_URL', 'http://spring-auth-server:9000')}/api/admin/users/authenticate")
      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = 2
      http.read_timeout = 2
      
      http_request = Net::HTTP::Post.new(uri.path, {
        "Content-Type" => "application/json",
        "X-Admin-Api-Key" => ENV.fetch("ADMIN_API_KEY", "secret-admin-key")
      })
      # Pre-hash password with SHA-256 before sending to auth server.
      # Plaintext password never crosses a service boundary (defense-in-depth).
      password_hash = Digest::SHA256.hexdigest(password)
      http_request.body = { email: email, password: password_hash }.to_json
      
      response = http.request(http_request)
      
      if response.code == "403"
        if return_to.present?
          return redirect_to resolve_client_failure_redirect(return_to, "account_suspended", "Your account has been temporarily suspended. Please contact customer support."), allow_other_host: true, status: :see_other
        else
          @error_message = "Your account has been temporarily suspended. Please contact customer support."
          return render :new, status: :forbidden
        end
      elsif response.code == "401" || response.code == "404"
        @error_message = "incorrect username or password"
        return render :new, status: :unprocessable_entity
      elsif response.code != "200"
        Rails.logger.error("Auth Server Error: #{response.code} - #{response.body}")
        @error_message = "An internal error occurred"
        return render :new, status: :internal_server_error
      end

      # Validated
      result_body = JSON.parse(response.body)
      user_id = result_body["id"]

      user_payload = {
        username: user_id,
        email: email,
        name: "#{email.split('@').first.capitalize} User",
        roles: ["ROLE_USER"],
        authenticated_at: Time.now.utc.iso8601
      }

      # Invalidate previous session in Redis to prevent session fixation attacks
      old_session_id = cookies[:SHARED_SESSION_ID]
      if old_session_id.present? && valid_session_id?(old_session_id)
        redis_client.del(redis_session_key(old_session_id))
      end

      # Issue cryptographically secure UUIDv4 session identifier and persist to Redis
      session_id = SecureRandom.uuid
      redis_client.set(redis_session_key(session_id), user_payload.to_json, ex: 7200)

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
        secure: ENV.fetch("REQUIRE_SECURE_COOKIES", request.ssl?.to_s) == "true"
      }

      # Session identifier is transmitted exclusively via cookie, never in URL query strings (CWE-598)
      if return_to.present?
        redirect_to return_to, allow_other_host: true, status: :see_other
      else
        render :success, status: :ok
      end
    rescue => e
      Rails.logger.error("API Error: #{e.message}")
      @error_message = "An internal error occurred"
      render :new, status: :internal_server_error
    end
  end

  def health
    render json: { status: "UP", service: "rails-login-app" }
  end

  def destroy
    session_id = cookies[:SHARED_SESSION_ID]
    if session_id.present? && valid_session_id?(session_id)
      redis_client.del(redis_session_key(session_id))
      cookies.delete(:SHARED_SESSION_ID, path: "/")
    end
    redirect_to "/login", notice: "Logged out"
  end

  private

  def redis_session_key(session_id)
    "#{ENV.fetch("REDIS_PREFIX", "session:")}#{session_id}"
  end

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
    return nil if target_url.blank?

    candidate = target_url.to_s.strip

    # Reject protocol-relative ("//evil.com") and backslash-obfuscated ("/\evil.com", "\\evil.com")
    # values outright: browsers treat these as absolute cross-origin redirects even though URI
    # may parse them with a nil host.
    if candidate.start_with?("//") || candidate.include?("\\")
      Rails.logger.warn("Blocked untrusted return_to redirect (protocol-relative/backslash): #{candidate}")
      return nil
    end

    begin
      parsed = URI.parse(candidate)
      allowed = Rails.configuration.x.auth_server.allowed_return_hosts

      if parsed.host.nil?
        # Same-origin relative path only: must start with a single "/" (not "//", excluded above).
        candidate.start_with?("/") ? candidate : nil
      elsif %w[http https].include?(parsed.scheme) &&
            (allowed.include?(parsed.host) || allowed.include?("#{parsed.host}:#{parsed.port}"))
        # Absolute URL: require an http(s) scheme AND a trusted host.
        candidate
      else
        Rails.logger.warn("Blocked untrusted return_to redirect: #{candidate}")
        nil
      end
    rescue URI::InvalidURIError
      nil
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
      return_to_url
    end
  end
end
