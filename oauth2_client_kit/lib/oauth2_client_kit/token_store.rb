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
    def evict_sessions_for!(sub: nil, sid: nil)
      evicted_count = 0

      # Match Rails session keys (e.g. demo_client:_session_id:* or _session_id:*)
      @redis.scan_each(match: "*_session_id:*") do |key|
        raw_val = @redis.get(key)
        if raw_val.present? && ((sid.present? && raw_val.include?(sid)) || (sub.present? && raw_val.include?(sub)))
          @redis.del(key)
          evicted_count += 1
          OAuth2ClientKit.logger.info("Evicted session #{key} via Back-Channel Logout")
        end
      end

      # Match token keys (e.g. demo_client:token:* or token:*)
      @redis.scan_each(match: "*token:*") do |key|
        raw_val = @redis.get(key)
        if raw_val.present? && ((sid.present? && raw_val.include?(sid)) || (sub.present? && raw_val.include?(sub)))
          @redis.del(key)
          evicted_count += 1
          OAuth2ClientKit.logger.info("Evicted token #{key} via Back-Channel Logout")
        end
      end

      evicted_count
    end
  end
end
