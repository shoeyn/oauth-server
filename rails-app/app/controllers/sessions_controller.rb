# frozen_string_literal: true

require 'redis'
require 'json'
require 'securerandom'
require 'uri'
require 'net/http'
require 'digest'

# Controller handling user authentication, session creation in Redis,
# and redirect dispatching for the Rails Identity Provider.
class SessionsController < ApplicationController
  def new
    @return_to = sanitize_return_to(params[:return_to])
  end

  def create
    return_to = sanitize_return_to(params[:return_to])
    return if simulated_error_handled?(return_to)

    email = params[:email].to_s.strip.slice(0, 100)
    password = params[:password].to_s
    if email.blank? || password.blank?
      @error_message = 'incorrect username or password'
      return render :new, status: :unprocessable_content
    end

    process_authentication(email, password, return_to)
  end

  def health
    render json: { status: 'UP', service: 'rails-login-app' }
  end

  def destroy
    session_id = cookies[:SHARED_SESSION_ID]
    if session_id.present? && valid_session_id?(session_id)
      redis_client.del(redis_session_key(session_id))
      cookies.delete(:SHARED_SESSION_ID, path: '/')
    end
    redirect_to '/login', notice: I18n.t('sessions.destroy.notice')
  end

  private

  class << self
    private

    # Thread-safe persistent Redis connection
    def redis_client
      @redis_client ||= Redis.new(
        url: ENV.fetch('REDIS_URL', 'redis://localhost:6379'),
        connect_timeout: 2, read_timeout: 2, write_timeout: 2, reconnect_attempts: 2
      )
    end
  end

  def redis_client
    self.class.send(:redis_client)
  end

  def redis_session_key(session_id)
    "#{ENV.fetch('REDIS_PREFIX', 'session:')}#{session_id}"
  end

  def simulated_error_handled?(return_to)
    return false if params[:simulate_error].blank?

    error_code = params[:simulate_error] == 'access_denied' ? 'access_denied' : 'account_suspended'
    render_simulated_error(return_to, error_code, simulated_error_description(error_code))
    true
  end

  def render_simulated_error(return_to, code, desc)
    if return_to.present?
      target = resolve_client_failure_redirect(return_to, code, desc)
      redirect_to target, allow_other_host: true, status: :see_other
    else
      @error_message = desc
      render :new, status: :unprocessable_content
    end
  end

  def simulated_error_description(error_code)
    case error_code
    when 'access_denied'
      'User account is locked or administrative access was denied.'
    else
      'Your account has been temporarily suspended. Please contact customer support.'
    end
  end

  def process_authentication(email, password, return_to)
    response = request_auth_server_authentication(email, password)
    return if auth_response_handled?(response, return_to)

    result_body = JSON.parse(response.body)
    establish_user_session(result_body['id'], email)
    dispatch_successful_login(return_to)
  rescue StandardError => e
    Rails.logger.error("API Error: #{e.message}")
    @error_message = 'An internal error occurred'
    render :new, status: :internal_server_error
  end

  def dispatch_successful_login(return_to)
    if return_to.present?
      redirect_to return_to, allow_other_host: true, status: :see_other
    else
      render :success, status: :ok
    end
  end

  def request_auth_server_authentication(email, password)
    uri = URI.parse("#{ENV.fetch('SPRING_AUTH_SERVER_URL', 'http://spring-auth-server:9000')}/api/admin/users/authenticate")
    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = 2
    http.read_timeout = 2
    http.request(build_auth_request(uri, email, password))
  end

  def build_auth_request(uri, email, password)
    req = Net::HTTP::Post.new(uri.path, { 'Content-Type' => 'application/json',
                                          'X-Admin-Api-Key' => ENV.fetch('ADMIN_API_KEY', 'secret-admin-key') })
    req.body = { email: email, password: Digest::SHA256.hexdigest(password) }.to_json
    req
  end

  def auth_response_handled?(response, return_to)
    return account_suspended_handled?(return_to) if response.code == '403'

    if %w[401 404].include?(response.code)
      @error_message = 'incorrect username or password'
      render :new, status: :unprocessable_content
      return true
    end

    unexpected_response_handled?(response)
  end

  def unexpected_response_handled?(response)
    return false if response.code == '200'

    Rails.logger.error("Auth Server Error: #{response.code} - #{response.body}")
    @error_message = 'An internal error occurred'
    render :new, status: :internal_server_error
    true
  end

  def account_suspended_handled?(return_to)
    desc = 'Your account has been temporarily suspended. Please contact customer support.'
    if return_to.present?
      target = resolve_client_failure_redirect(return_to, 'account_suspended', desc)
      redirect_to target, allow_other_host: true, status: :see_other
    else
      @error_message = desc
      render :new, status: :forbidden
    end
    true
  end

  def establish_user_session(user_id, email)
    invalidate_previous_session
    session_id = SecureRandom.uuid
    payload = build_user_payload(user_id, email)
    redis_client.set(redis_session_key(session_id), payload.to_json, ex: 7200)
    apply_session_cookie(session_id)
  end

  def invalidate_previous_session
    old_id = cookies[:SHARED_SESSION_ID]
    redis_client.del(redis_session_key(old_id)) if old_id.present? && valid_session_id?(old_id)
  end

  def build_user_payload(user_id, email)
    {
      username: user_id, email: email, name: "#{email.split('@').first.capitalize} User",
      roles: ['ROLE_USER'], authenticated_at: Time.now.utc.iso8601
    }
  end

  def apply_session_cookie(session_id)
    cookies[:SHARED_SESSION_ID] = {
      value: session_id, path: '/', expires: 2.hours.from_now, same_site: :lax, httponly: true,
      secure: ENV.fetch('REQUIRE_SECURE_COOKIES', request.ssl?.to_s) == 'true'
    }
  end

  def sanitize_return_to(target_url)
    return nil if target_url.blank?

    candidate = target_url.to_s.strip
    return nil if invalid_redirect_prefix?(candidate)

    validate_return_to_url(candidate)
  rescue URI::InvalidURIError
    nil
  end

  def invalid_redirect_prefix?(candidate)
    if candidate.start_with?('//') || candidate.include?('\\')
      Rails.logger.warn("Blocked untrusted return_to redirect (protocol-relative/backslash): #{candidate}")
      return true
    end
    false
  end

  def validate_return_to_url(candidate)
    parsed = URI.parse(candidate)
    allowed = Rails.configuration.x.auth_server.allowed_return_hosts

    if parsed.host.nil?
      candidate.start_with?('/') ? candidate : nil
    elsif trusted_host?(parsed, allowed)
      candidate
    else
      Rails.logger.warn("Blocked untrusted return_to redirect: #{candidate}")
      nil
    end
  end

  def trusted_host?(parsed, allowed)
    %w[http https].include?(parsed.scheme) &&
      (allowed.include?(parsed.host) || allowed.include?("#{parsed.host}:#{parsed.port}"))
  end

  def valid_session_id?(session_id)
    session_id.is_a?(String) && session_id.match?(/\A[0-9a-fA-F-]{36}\z/)
  end

  def resolve_client_failure_redirect(return_to_url, error_code, error_description)
    return nil if return_to_url.blank?

    target = URI.parse(return_to_url.to_s.strip)
    separator = target.query.present? ? '&' : '?'
    encoded_code = ERB::Util.url_encode(error_code)
    encoded_desc = ERB::Util.url_encode(error_description)
    "#{target}#{separator}error=#{encoded_code}&error_description=#{encoded_desc}"
  rescue StandardError => e
    Rails.logger.warn("Failed to construct IdP failure redirect: #{e.message}")
    return_to_url
  end
end
