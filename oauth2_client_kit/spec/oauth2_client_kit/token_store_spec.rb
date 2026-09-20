# frozen_string_literal: true

require 'spec_helper'
require 'json'
require_relative '../../lib/oauth2_client_kit'
require_relative '../../lib/oauth2_client_kit/token_store'

RSpec.describe OAuth2ClientKit::TokenStore do
  subject(:token_store) { described_class.new('redis://localhost:6379/1') }

  let(:redis) { instance_double(Redis) }

  before do
    allow(Redis).to receive(:new).and_return(redis)
    OAuth2ClientKit.class_eval do
      def self.logger
        @logger ||= Logger.new(nil)
      end
    end
  end

  describe '#initialize' do
    it 'builds a Redis client from the passed url' do
      allow(Redis).to receive(:new).with(url: 'redis://custom:6379/2').and_return(redis)
      store = described_class.new('redis://custom:6379/2')
      expect(store.redis).to eq(redis)
      expect(Redis).to have_received(:new).with(url: 'redis://custom:6379/2')
    end

    it 'falls back to the configured redis_url when none is passed' do
      allow(OAuth2ClientKit.config).to receive(:redis_url).and_return('redis://config:6379/3')
      allow(Redis).to receive(:new).with(url: 'redis://config:6379/3').and_return(redis)
      described_class.new
      expect(Redis).to have_received(:new).with(url: 'redis://config:6379/3')
    end
  end

  describe '#write' do
    before { allow(redis).to receive(:set) }

    it 'stores JSON in Redis with the configured ttl by default' do
      allow(OAuth2ClientKit.config).to receive(:token_cache_ttl).and_return(1234)
      token_store.write('abc', { a: 1 })
      expect(redis).to have_received(:set).with('token:abc', { a: 1 }.to_json, ex: 1234)
    end

    it 'honours an explicit expires_in' do
      token_store.write('abc', { a: 1 }, expires_in: 99)
      expect(redis).to have_received(:set).with('token:abc', { a: 1 }.to_json, ex: 99)
    end
  end

  describe '#read' do
    it 'parses stored JSON with symbolized names' do
      allow(redis).to receive(:get).with('token:abc').and_return({ 'a' => 1 }.to_json)
      expect(token_store.read('abc')).to eq({ a: 1 })
    end

    it 'returns nil when the key is absent' do
      allow(redis).to receive(:get).with('token:missing').and_return(nil)
      expect(token_store.read('missing')).to be_nil
    end

    it 'returns nil when the key contains unparseable JSON' do
      allow(redis).to receive(:get).with('token:corrupt').and_return('not-json')
      expect(token_store.read('corrupt')).to be_nil
    end
  end

  describe '#delete' do
    it 'deletes the token key from Redis' do
      allow(redis).to receive(:del)
      token_store.delete('abc')
      expect(redis).to have_received(:del).with('token:abc')
    end
  end

  context 'when a Rails cache is available' do
    let(:rails_cache) { instance_double(ActiveSupport::Cache::Store) }

    before do
      cache = rails_cache
      rails_klass = Class.new do
        define_singleton_method(:cache) { cache }
      end
      stub_const('Rails', rails_klass)
      allow(redis).to receive_messages(set: nil, get: nil, del: nil)
      allow(rails_cache).to receive_messages(write: nil, read: nil, delete: nil)
    end

    it 'writes to both Redis and Rails cache' do
      allow(OAuth2ClientKit.config).to receive(:token_cache_ttl).and_return(60)
      token_store.write('abc', { a: 1 })
      expect(redis).to have_received(:set).with('token:abc', { a: 1 }.to_json, ex: 60)
      expect(rails_cache).to have_received(:write).with('token:abc', { a: 1 }, expires_in: 60)
    end

    it 'reads from Redis and returns parsed data' do
      allow(redis).to receive(:get).with('token:abc').and_return({ 'a' => 1 }.to_json)
      expect(token_store.read('abc')).to eq({ a: 1 })
    end

    it 'deletes from Rails cache and returns nil when Redis key is missing' do
      allow(redis).to receive(:get).with('token:abc').and_return(nil)
      expect(token_store.read('abc')).to be_nil
      expect(rails_cache).to have_received(:delete).with('token:abc')
    end

    it 'deletes from both the Rails cache and Redis' do
      token_store.delete('abc')
      expect(rails_cache).to have_received(:delete).with('token:abc')
      expect(redis).to have_received(:del).with('token:abc')
    end
  end

  describe '#evict_sessions_for!' do
    before { allow(redis).to receive(:del) }

    it 'evicts session keys whose value contains the sid and returns the count' do
      allow(redis).to receive(:scan_each).with(match: '*_session_id:*')
                                         .and_yield('app:_session_id:1').and_yield('app:_session_id:2')
      allow(redis).to receive(:scan_each).with(match: '*token:*')

      allow(redis).to receive(:get).with('app:_session_id:1').and_return('{"sid":"SID-123"}')
      allow(redis).to receive(:get).with('app:_session_id:2').and_return('{"sid":"OTHER"}')

      expect(token_store.evict_sessions_for!(sid: 'SID-123')).to eq(1)
      expect(redis).to have_received(:del).with('app:_session_id:1')
      expect(redis).not_to have_received(:del).with('app:_session_id:2')
    end

    it 'evicts token keys whose value contains the sub' do
      allow(redis).to receive(:scan_each).with(match: '*_session_id:*')
      allow(redis).to receive(:scan_each).with(match: '*token:*')
                                         .and_yield('app:token:1').and_yield('app:token:2')

      allow(redis).to receive(:get).with('app:token:1').and_return('{"sub":"user-42"}')
      allow(redis).to receive(:get).with('app:token:2').and_return('{"sub":"user-99"}')

      expect(token_store.evict_sessions_for!(sub: 'user-42')).to eq(1)
      expect(redis).to have_received(:del).with('app:token:1')
      expect(redis).not_to have_received(:del).with('app:token:2')
    end

    it 'evicts across both session and token keyspaces and sums the count' do
      allow(redis).to receive(:scan_each).with(match: '*_session_id:*')
                                         .and_yield('app:_session_id:1')
      allow(redis).to receive(:scan_each).with(match: '*token:*')
                                         .and_yield('app:token:1')

      allow(redis).to receive(:get).with('app:_session_id:1').and_return('{"sid":"S"}')
      allow(redis).to receive(:get).with('app:token:1').and_return('{"sid":"S"}')

      expect(token_store.evict_sessions_for!(sid: 'S')).to eq(2)
      expect(redis).to have_received(:del).with('app:_session_id:1')
      expect(redis).to have_received(:del).with('app:token:1')
    end

    it 'skips keys whose value is nil or blank' do
      allow(redis).to receive(:scan_each).with(match: '*_session_id:*')
                                         .and_yield('app:_session_id:1').and_yield('app:_session_id:2')
      allow(redis).to receive(:scan_each).with(match: '*token:*')

      allow(redis).to receive(:get).with('app:_session_id:1').and_return(nil)
      allow(redis).to receive(:get).with('app:_session_id:2').and_return('')

      expect(token_store.evict_sessions_for!(sid: 'anything')).to eq(0)
      expect(redis).not_to have_received(:del)
    end

    it 'evicts nothing when neither sub nor sid match any value' do
      allow(redis).to receive(:scan_each).with(match: '*_session_id:*')
                                         .and_yield('app:_session_id:1')
      allow(redis).to receive(:scan_each).with(match: '*token:*')

      allow(redis).to receive(:get).with('app:_session_id:1').and_return('{"sid":"REAL"}')

      expect(token_store.evict_sessions_for!(sid: 'NOPE')).to eq(0)
      expect(redis).not_to have_received(:del)
    end

    # Verifies the H4 fix: eviction now matches EXACT parsed sub/sid fields, so a value
    # that merely contains the sid as a substring (e.g. inside a timestamp) is NOT evicted.
    it 'does not over-match: a substring occurrence in an unrelated field is ignored' do
      allow(redis).to receive(:scan_each).with(match: '*_session_id:*')
                                         .and_yield('app:_session_id:unrelated')
      allow(redis).to receive(:scan_each).with(match: '*token:*')

      # "42" appears inside issued_at but the sid field is "REAL-SID", so no eviction.
      allow(redis).to receive(:get).with('app:_session_id:unrelated')
                                   .and_return('{"sub":"someone","sid":"REAL-SID","issued_at":"1642000000"}')

      expect(token_store.evict_sessions_for!(sid: '42')).to eq(0)
      expect(redis).not_to have_received(:del)
    end

    it 'ignores values that are not valid JSON (fail-safe: no eviction)' do
      allow(redis).to receive(:scan_each).with(match: '*_session_id:*')
                                         .and_yield('app:_session_id:garbage')
      allow(redis).to receive(:scan_each).with(match: '*token:*')

      allow(redis).to receive(:get).with('app:_session_id:garbage').and_return('not json SID-123')

      expect(token_store.evict_sessions_for!(sid: 'SID-123')).to eq(0)
      expect(redis).not_to have_received(:del)
    end
  end
end
