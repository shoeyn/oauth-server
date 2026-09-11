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
    def evict_sessions_for!(sub: nil, sid: nil)
      evicted_count = 0

      # Match Rails session keys in DB 1 (e.g. demo_client:_session_id:*)
      session_keys = @redis.keys("*_session_id:*")
      session_keys.each do |key|
        raw_val = @redis.get(key)
        if raw_val.present? && ((sid.present? && raw_val.include?(sid)) || (sub.present? && raw_val.include?(sub)))
          @redis.del(key)
          evicted_count += 1
          OAuth2ClientKit.logger.info("Evicted session #{key} via Back-Channel Logout")
        end
      end

      # Match token keys in DB 1 (e.g. demo_client:token:* or token:*)
      token_keys = @redis.keys("*token:*")
      token_keys.each do |key|
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
