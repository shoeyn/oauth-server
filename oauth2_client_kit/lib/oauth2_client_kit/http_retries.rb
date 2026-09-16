# frozen_string_literal: true

require 'faraday'

module OAuth2ClientKit
  # Exponential backoff and retry helper for transient network and timeout errors.
  module HttpRetries
    RETRY_ERRORS = [
      Faraday::ConnectionFailed, Faraday::TimeoutError, Errno::ECONNRESET,
      Errno::ETIMEDOUT, Net::OpenTimeout, Net::ReadTimeout, SocketError
    ].freeze

    def with_retries(max_retries: 3, base_delay: 0.1, max_delay: 1.0, operation_name: 'Operation')
      retries = 0
      begin
        yield
      rescue *RETRY_ERRORS => e
        retries += 1
        raise if retries > max_retries

        sleep(perform_retry_delay(operation_name, e, retries, base_delay, max_delay))
        retry
      end
    end

    private

    def perform_retry_delay(name, err, retries, base, max)
      delay = [base * (2**(retries - 1)), max].min + (rand * 0.05)
      OAuth2ClientKit.logger.warn(
        "[Retry] #{name} failed with #{err.class} (#{err.message}). " \
        "Retrying in #{delay.round(3)}s (Attempt #{retries})..."
      )
      delay
    end
  end
end
