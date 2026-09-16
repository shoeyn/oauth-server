# frozen_string_literal: true

require 'monitor'
require 'json'
require 'jwt'

module OAuth2ClientKit
  # Thread-safe in-memory cache for authorization server JWKS sets across worker threads.
  class JwksCache
    @monitor = Monitor.new
    @cache = {}

    class << self
      def resolve_jwks(issuer_url, kid = nil, &)
        now = Time.now
        @monitor.synchronize do
          entry = @cache[issuer_url]
          return entry[:jwk_set] if valid_cache_entry?(entry, kid, now)

          fetch_and_store(issuer_url, entry, now, &)
        end
      end

      def contains_kid?(jwk_set, kid)
        return false unless jwk_set && kid

        jwk_set.any? { |jwk| match_kid?(jwk, kid) }
      end

      def reset!
        @monitor.synchronize { @cache.clear }
      end

      def cached_jwks
        @cache
      end

      private

      def fetch_and_store(issuer_url, entry, now)
        new_set = yield
        if new_set
          store_cache_entry(issuer_url, new_set, now)
          return new_set
        end

        entry ? entry[:jwk_set] : nil
      end

      def match_kid?(jwk, kid)
        (jwk.respond_to?(:kid) && jwk.kid == kid) ||
          (jwk.respond_to?(:[]) && (jwk[:kid] == kid || jwk['kid'] == kid))
      end

      def valid_cache_entry?(entry, kid, now)
        return false unless entry && entry[:expires_at] > now
        return true if kid.nil? || contains_kid?(entry[:jwk_set], kid)

        (now - entry[:last_fetched_at]) < 5
      end

      def store_cache_entry(issuer_url, jwk_set, now)
        @cache[issuer_url] = {
          jwk_set: jwk_set,
          expires_at: now + 3600,
          last_fetched_at: now
        }
      end
    end
  end
end
