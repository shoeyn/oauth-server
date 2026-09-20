# frozen_string_literal: true

require 'redis'
require 'json'

module OAuth2ClientKit
  # Redis and Rails cache token and session store with backchannel logout eviction.
  class TokenStore
    attr_reader :redis

    def initialize(redis_url = nil)
      url = redis_url || OAuth2ClientKit.config.redis_url
      @redis = Redis.new(url: url)
    end

    def write(token_key, data, expires_in: nil)
      ttl = expires_in || OAuth2ClientKit.config.token_cache_ttl
      @redis.set("token:#{token_key}", data.to_json, ex: ttl)
      Rails.cache.write("token:#{token_key}", data, expires_in: ttl) if rails_cache_available?
    end

    def read(token_key)
      raw = @redis.get("token:#{token_key}")
      if raw.nil?
        Rails.cache.delete("token:#{token_key}") if rails_cache_available?
        return nil
      end

      JSON.parse(raw, symbolize_names: true)
    rescue JSON::ParserError
      nil
    end

    def delete(token_key)
      Rails.cache.delete("token:#{token_key}") if rails_cache_available?
      @redis.del("token:#{token_key}")
    end

    # Evicts all tokens and sessions matching sub or sid across Redis (for Back-Channel Logout)
    # Uses non-blocking SCAN cursor (scan_each) to avoid blocking the Redis server in shared environments.
    #
    # Matching is performed on EXACT parsed fields (sub / sid) rather than a naive substring search
    # over the serialized blob, so a sub/sid that merely appears as a substring of unrelated data
    # cannot cause cross-user eviction.
    def evict_sessions_for!(sub: nil, sid: nil)
      %w[*_session_id:* *token:*].sum do |pattern|
        evict_pattern_keys(pattern, sub: sub, sid: sid)
      end
    end

    private

    def evict_pattern_keys(pattern, sub:, sid:)
      count = 0
      @redis.scan_each(match: pattern) do |key|
        count += 1 if evict_key_if_matched?(key, sub: sub, sid: sid)
      end
      count
    end

    def evict_key_if_matched?(key, sub:, sid:)
      raw_val = @redis.get(key)
      return false if raw_val.nil? || raw_val.empty?
      return false unless record_matches?(raw_val, sub: sub, sid: sid)

      @redis.del(key)
      OAuth2ClientKit.logger.info("Evicted #{key} via Back-Channel Logout")
      true
    end

    # Returns true only when the stored record's parsed sub/sid field exactly equals the
    # requested sub/sid. Non-JSON or unparseable values never match (fail-safe: no eviction).
    def record_matches?(raw_val, sub:, sid:)
      data = JSON.parse(raw_val)
      return false unless data.is_a?(Hash)

      matches_identifier?(data['sid'] || data[:sid], sid) ||
        matches_identifier?(data['sub'] || data[:sub], sub)
    rescue JSON::ParserError
      false
    end

    def matches_identifier?(actual, expected)
      return false if expected.to_s.empty?

      actual.to_s == expected.to_s
    end

    def rails_cache_available?
      defined?(Rails) && Rails.respond_to?(:cache) && Rails.cache.present?
    end
  end
end
