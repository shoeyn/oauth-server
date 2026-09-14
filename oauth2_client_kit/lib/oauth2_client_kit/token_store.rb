# frozen_string_literal: true

require "redis"
require "json"

module OAuth2ClientKit
  class TokenStore
    attr_reader :redis

    def initialize(redis_url = nil)
      url = redis_url || OAuth2ClientKit.config.redis_url
      @redis = Redis.new(url: url)
    end

    def write(token_key, data, expires_in: nil)
      ttl = expires_in || OAuth2ClientKit.config.token_cache_ttl
      # If Rails cache is available, also write there
      if defined?(Rails) && Rails.respond_to?(:cache) && Rails.cache
        Rails.cache.write("token:#{token_key}", data, expires_in: ttl)
      else
        @redis.set("token:#{token_key}", data.to_json, ex: ttl)
      end
    end

    def read(token_key)
      if defined?(Rails) && Rails.respond_to?(:cache) && Rails.cache
        Rails.cache.read("token:#{token_key}")
      else
        raw = @redis.get("token:#{token_key}")
        raw ? JSON.parse(raw, symbolize_names: true) : nil
      end
    end

    def delete(token_key)
      if defined?(Rails) && Rails.respond_to?(:cache) && Rails.cache
        Rails.cache.delete("token:#{token_key}")
      end
      @redis.del("token:#{token_key}")
    end

    # Evicts all tokens and sessions matching sub or sid across Redis (for Back-Channel Logout)
    # Uses non-blocking SCAN cursor (scan_each) to avoid blocking the Redis server in shared environments.
    #
    # Matching is performed on EXACT parsed fields (sub / sid) rather than a naive substring search
    # over the serialized blob, so a sub/sid that merely appears as a substring of unrelated data
    # cannot cause cross-user eviction.
    def evict_sessions_for!(sub: nil, sid: nil)
      evicted_count = 0

      %w[*_session_id:* *token:*].each do |pattern|
        @redis.scan_each(match: pattern) do |key|
          raw_val = @redis.get(key)
          next if raw_val.nil? || raw_val.empty?

          if record_matches?(raw_val, sub: sub, sid: sid)
            @redis.del(key)
            evicted_count += 1
            OAuth2ClientKit.logger.info("Evicted #{key} via Back-Channel Logout")
          end
        end
      end

      evicted_count
    end

    private

    # Returns true only when the stored record's parsed sub/sid field exactly equals the
    # requested sub/sid. Non-JSON or unparseable values never match (fail-safe: no eviction).
    def record_matches?(raw_val, sub:, sid:)
      data = JSON.parse(raw_val)
      return false unless data.is_a?(Hash)

      record_sub = data["sub"] || data["sub".to_sym]
      record_sid = data["sid"] || data["sid".to_sym]

      (sid && !sid.to_s.empty? && record_sid.to_s == sid.to_s) ||
        (sub && !sub.to_s.empty? && record_sub.to_s == sub.to_s)
    rescue JSON::ParserError
      false
    end
  end
end
