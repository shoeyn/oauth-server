# frozen_string_literal: true

require 'spec_helper'
require 'tempfile'
require_relative '../../lib/oauth2_client_kit/configuration'

RSpec.describe OAuth2ClientKit::Configuration do
  subject(:config) { described_class.new }

  describe '#initialize' do
    it 'reads client_id from CLIENT_ID' do
      allow(ENV).to receive(:[]).and_call_original
      allow(ENV).to receive(:[]).with('CLIENT_ID').and_return('primary_client')
      expect(described_class.new.client_id).to eq('primary_client')
    end

    it 'falls back to OAUTH2_CLIENT_ID when CLIENT_ID is unset' do
      allow(ENV).to receive(:[]).and_call_original
      allow(ENV).to receive(:fetch).and_call_original
      allow(ENV).to receive(:[]).with('CLIENT_ID').and_return(nil)
      allow(ENV).to receive(:fetch).with('OAUTH2_CLIENT_ID', nil).and_return('fallback_client')
      expect(described_class.new.client_id).to eq('fallback_client')
    end

    it 'defaults the issuer_url when AUTH_SERVER_URL is unset' do
      allow(ENV).to receive(:fetch).and_call_original
      allow(ENV).to receive(:fetch).with('AUTH_SERVER_URL', 'http://localhost:9000').and_return('http://localhost:9000')
      expect(described_class.new.issuer_url).to eq('http://localhost:9000')
    end

    it 'uses AUTH_SERVER_URL_INTERNAL for the internal issuer when present' do
      allow(ENV).to receive(:fetch).and_call_original
      allow(ENV).to receive(:fetch).with('AUTH_SERVER_URL_INTERNAL', nil).and_return('http://internal:9000')
      expect(described_class.new.internal_issuer_url).to eq('http://internal:9000')
    end

    it 'falls back the internal issuer to the public issuer when the internal env is blank' do
      allow(ENV).to receive(:fetch).and_call_original
      allow(ENV).to receive(:fetch).with('AUTH_SERVER_URL_INTERNAL', nil).and_return('')
      allow(ENV).to receive(:fetch).with('AUTH_SERVER_URL', 'http://localhost:9000').and_return('http://public:9000')
      config = described_class.new
      expect(config.internal_issuer_url).to eq('http://public:9000')
    end

    it 'defaults the redis_url' do
      allow(ENV).to receive(:fetch).and_call_original
      allow(ENV).to receive(:fetch).with('REDIS_URL', 'redis://localhost:6379/1').and_return('redis://localhost:6379/1')
      expect(described_class.new.redis_url).to eq('redis://localhost:6379/1')
    end

    it 'sets a 30 day token cache ttl' do
      expect(config.token_cache_ttl).to eq(30 * 24 * 60 * 60)
    end

    it 'sets default post-login and post-logout paths' do
      expect(config.after_login_path).to eq('/profile')
      expect(config.after_logout_path).to eq('/')
    end
  end

  describe '#resolved_private_key_pem' do
    it 'returns the PEM of an OpenSSL::PKey::RSA object' do
      key = OpenSSL::PKey::RSA.generate(2048)
      config.private_key = key
      expect(config.resolved_private_key_pem).to eq(key.to_pem)
    end

    it 'returns a string private_key unchanged (via to_s)' do
      config.private_key = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
      expect(config.resolved_private_key_pem).to eq("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")
    end

    it 'reads the key from private_key_path when the file exists' do
      file = Tempfile.new(['key', '.pem'])
      file.write('PEM-FROM-FILE')
      file.flush
      config.private_key = nil
      config.private_key_path = file.path
      expect(config.resolved_private_key_pem).to eq('PEM-FROM-FILE')
    ensure
      file.close!
    end

    it 'returns nil when the private_key_path does not exist' do
      config.private_key = nil
      config.private_key_path = '/nonexistent/path/key.pem'
      expect(config.resolved_private_key_pem).to be_nil
    end

    it 'returns nil when neither private_key nor private_key_path are set' do
      config.private_key = nil
      config.private_key_path = nil
      expect(config.resolved_private_key_pem).to be_nil
    end
  end
end
