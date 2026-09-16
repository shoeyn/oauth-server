# frozen_string_literal: true

require 'spec_helper'
require 'webmock/rspec'
require_relative '../../lib/oauth2_client_kit/client'

RSpec.describe OAuth2ClientKit::Client do
  subject(:client) do
    described_class.new(
      client_id,
      private_key,
      public_issuer_url: public_issuer_url,
      internal_issuer_url: internal_issuer_url
    )
  end

  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:client_id) { 'test_client' }
  let(:public_issuer_url) { 'http://public.example.com' }
  let(:internal_issuer_url) { 'http://internal.example.com' }

  before do
    OAuth2ClientKit.class_eval do
      def self.logger
        @logger ||= Logger.new(nil)
      end
    end
    OAuth2ClientKit::JwksCache.reset!
  end

  describe '#initialize' do
    it 'sets URLs correctly' do
      expect(client.public_issuer_url).to eq(public_issuer_url)
      expect(client.internal_issuer_url).to eq(internal_issuer_url)
      expect(client.par_url).to eq("#{internal_issuer_url}/oauth2/par")
    end

    it 'accepts ENV["AUTH_SERVER_URL_INTERNAL"] for internal issuer' do
      allow(ENV).to receive(:fetch).and_call_original
      allow(ENV).to receive(:fetch).with('AUTH_SERVER_URL_INTERNAL', nil).and_return('http://env.example.com')
      allow(ENV).to receive(:fetch).with('AUTH_SERVER_URL', 'http://localhost:9000').and_return(public_issuer_url)

      client = described_class.new(client_id, private_key)
      expect(client.internal_issuer_url).to eq('http://env.example.com')
    end
  end

  describe '#build_client_assertion' do
    it 'creates a valid signed JWT' do
      jwt = client.build_client_assertion
      decoded = JWT.decode(jwt, private_key.public_key, true, { algorithm: 'RS256' })
      expect(decoded[0]['iss']).to eq(client_id)
      expect(decoded[0]['sub']).to eq(client_id)
      expect(decoded[1]['kid']).to eq("#{client_id}-key-1")
    end
  end

  describe '.generate_pkce_codes' do
    it 'returns verifier and challenge' do
      codes = described_class.generate_pkce_codes
      expect(codes[:code_verifier]).to be_a(String)
      expect(codes[:code_challenge]).to be_a(String)
      expect(codes[:code_challenge_method]).to eq('S256')
    end
  end

  describe '#push_authorization_request' do
    it 'posts to par_url and returns request_uri' do
      stub_request(:post, client.par_url).to_return(
        status: 201,
        body: { 'request_uri' => 'urn:foo' }.to_json
      )

      uri = client.push_authorization_request({ scope: 'openid' })
      expect(uri).to eq('urn:foo')
    end

    it 'raises error on failure' do
      stub_request(:post, client.par_url).to_return(
        status: 400,
        body: { 'error' => 'invalid_request' }.to_json
      )

      expect do
        client.push_authorization_request({})
      end.to raise_error(/PAR Request Failed: invalid_request/)
    end

    it 'raises error if no request_uri in response' do
      stub_request(:post, client.par_url).to_return(
        status: 201,
        body: {}.to_json
      )

      expect do
        client.push_authorization_request({})
      end.to raise_error(/No request_uri returned/)
    end

    it 'handles non-JSON error response from PAR endpoint' do
      stub_request(:post, client.par_url).to_return(
        status: 502,
        body: 'Bad Gateway'
      )
      expect do
        client.push_authorization_request({})
      end.to raise_error(/PAR Request Failed: HTTP 502/)
    end
  end

  describe '.generate_dpop_key' do
    it 'generates EC and RSA keys' do
      expect(described_class.generate_dpop_key(:ec)).to be_a(OpenSSL::PKey::EC)
      expect(described_class.generate_dpop_key(:rsa)).to be_a(OpenSSL::PKey::RSA)
    end
  end

  describe '#build_dpop_proof' do
    let(:dpop_key) { described_class.generate_dpop_key(:ec) }

    it 'builds a valid DPoP proof' do
      proof = client.build_dpop_proof('POST', 'http://example.com/token', nil, dpop_key)
      expect(proof).to be_a(String)
      decoded = JWT.decode(proof, dpop_key, true, { algorithm: 'ES256' })
      expect(decoded[0]['htm']).to eq('POST')
      expect(decoded[0]['htu']).to eq('http://example.com/token')
    end

    it 'includes ath claim if access_token provided' do
      proof = client.build_dpop_proof('POST', 'http://example.com/token', 'token123', dpop_key)
      decoded = JWT.decode(proof, dpop_key, true, { algorithm: 'ES256' })
      expect(decoded[0]['ath']).to be_present
    end

    it 'raises error if no key' do
      expect do
        client.build_dpop_proof('POST', 'url')
      end.to raise_error(/Missing DPoP private key/)
    end

    it 'supports RSA key' do
      rsa_key = described_class.generate_dpop_key(:rsa)
      proof = client.build_dpop_proof('POST', 'http://example.com/token', nil, rsa_key)
      decoded = JWT.decode(proof, rsa_key, true, { algorithm: 'RS256' })
      expect(decoded[1]['alg']).to eq('RS256')
    end
  end

  describe '#parse_dpop_key' do
    it 'parses string keys' do
      ec_key = described_class.generate_dpop_key(:ec)
      parsed = client.parse_dpop_key(ec_key.to_pem)
      expect(parsed).to be_a(OpenSSL::PKey::EC)

      rsa_key = described_class.generate_dpop_key(:rsa)
      parsed2 = client.parse_dpop_key(rsa_key.to_pem)
      expect(parsed2).to be_a(OpenSSL::PKey::RSA)
    end
  end

  describe '#exchange_code' do
    let(:token_url) { "#{internal_issuer_url}/oauth2/token" }

    before do
      stub_request(:post, token_url).to_return(
        status: 200,
        headers: { 'Content-Type' => 'application/json' },
        body: { access_token: 'acc_token' }.to_json
      )
    end

    it 'exchanges code successfully' do
      token = client.exchange_code('code123', 'verifier123', 'http://cb')
      expect(token.token).to eq('acc_token')
    end

    it 'adds DPoP header if dpop_key provided' do
      dpop_key = described_class.generate_dpop_key(:ec)
      client.exchange_code('code123', 'verifier123', 'http://cb', dpop_key)

      expect(WebMock).to(have_requested(:post, token_url).with do |req|
        req.headers.key?('Dpop')
      end)
    end

    it 'handles DPoP nonce retry' do
      dpop_key = described_class.generate_dpop_key(:ec)

      stub_request(:post, token_url).to_return(
        { status: 400, headers: { 'DPoP-Nonce' => 'nonce123' } },
        { status: 200, headers: { 'Content-Type' => 'application/json' }, body: { access_token: 'acc_token2' }.to_json }
      )

      token = client.exchange_code('code123', 'verifier123', 'http://cb', dpop_key)
      expect(token.token).to eq('acc_token2')
    end

    it 'raises error if nonce retry fails without dpop_key' do
      stub_request(:post, token_url).to_return(status: 400)
      expect { client.exchange_code('code123', 'verifier', 'http') }.to raise_error(OAuth2::Error)
    end
  end

  describe '#refresh_access_token' do
    let(:token_url) { "#{internal_issuer_url}/oauth2/token" }

    it 'refreshes token successfully' do
      stub_request(:post, token_url).to_return(
        status: 200,
        headers: { 'Content-Type' => 'application/json' },
        body: { access_token: 'new_token' }.to_json
      )

      token = client.refresh_access_token('refresh_token')
      expect(token.token).to eq('new_token')
    end

    it 'handles DPoP nonce retry' do
      dpop_key = described_class.generate_dpop_key(:ec)

      stub_request(:post, token_url).to_return(
        { status: 400, headers: { 'DPoP-Nonce' => 'nonce123' } },
        { status: 200, headers: { 'Content-Type' => 'application/json' }, body: { access_token: 'acc_token2' }.to_json }
      )

      token = client.refresh_access_token('code123', dpop_key)
      expect(token.token).to eq('acc_token2')
    end

    it 'raises error if refresh fails without nonce' do
      stub_request(:post, token_url).to_return(status: 400)
      expect { client.refresh_access_token('code123') }.to raise_error(OAuth2::Error)
    end
  end

  describe '#introspect_token' do
    let(:introspect_url) { "#{internal_issuer_url}/oauth2/introspect" }

    it 'returns false for blank token' do
      expect(client.introspect_token('')).to eq({ 'active' => false })
    end

    it 'returns active status' do
      stub_request(:post, introspect_url).to_return(
        status: 200,
        body: { active: true }.to_json
      )

      expect(client.introspect_token('token123')['active']).to be true
    end

    it 'returns inactive on 400' do
      stub_request(:post, introspect_url).to_return(status: 400)
      expect(client.introspect_token('token123')['active']).to be false
    end

    it 'returns inactive on 200 with invalid JSON' do
      stub_request(:post, introspect_url).to_return(status: 200, body: 'not json')
      expect(client.introspect_token('token123')['active']).to be false
    end
  end

  describe '#verify_active!' do
    let(:introspect_url) { "#{internal_issuer_url}/oauth2/introspect" }

    it 'returns claims if active' do
      stub_request(:post, introspect_url).to_return(
        status: 200,
        headers: { 'Content-Type' => 'application/json' },
        body: { active: true, sub: 'user1' }.to_json
      )
      res = client.verify_active!('token123')
      expect(res[:active]).to be true
      expect(res[:sub]).to eq('user1')
    end

    it 'returns inactive reason if not active' do
      stub_request(:post, introspect_url).to_return(
        status: 200,
        headers: { 'Content-Type' => 'application/json' },
        body: { active: false }.to_json
      )
      res = client.verify_active!('token123')
      expect(res[:active]).to be false
      expect(res[:reason]).to eq('token_inactive_or_revoked')
    end
  end

  describe '#revoke_token' do
    let(:revoke_url) { "#{internal_issuer_url}/oauth2/revoke" }

    it 'returns false for blank token' do
      expect(client.revoke_token('')).to be false
    end

    it 'returns true on success' do
      stub_request(:post, revoke_url).to_return(status: 200)
      expect(client.revoke_token('token123')).to be true
    end

    it 'returns false on failure' do
      stub_request(:post, revoke_url).to_return(status: 500)
      expect(client.revoke_token('token123')).to be false
    end
  end

  describe '#end_session_url' do
    it 'constructs url' do
      url = client.end_session_url('hint', 'http://cb')
      expect(url).to include('id_token_hint=hint')
      expect(url).to include('post_logout_redirect_uri')
    end
  end

  describe '#fetch_userinfo' do
    let(:userinfo_url) { "#{internal_issuer_url}/userinfo" }

    it 'returns empty hash for blank token' do
      expect(client.fetch_userinfo('')).to eq({})
    end

    it 'fetches userinfo successfully' do
      stub_request(:get, userinfo_url).to_return(
        status: 200,
        body: { sub: 'user1' }.to_json
      )

      expect(client.fetch_userinfo('token123')).to eq({ 'sub' => 'user1' })
    end

    it 'uses DPoP if key provided' do
      dpop_key = described_class.generate_dpop_key(:ec)
      stub_request(:get, userinfo_url).to_return(
        status: 200,
        body: { sub: 'user2' }.to_json
      )

      client.fetch_userinfo('token123', dpop_key)
      expect(WebMock).to(have_requested(:get, userinfo_url).with do |req|
        req.headers.key?('Dpop') && req.headers['Authorization'].start_with?('DPoP')
      end)
    end

    it 'returns empty on failure' do
      stub_request(:get, userinfo_url).to_return(status: 401)
      expect(client.fetch_userinfo('token123')).to eq({})
    end

    it 'returns empty hash on 200 with invalid JSON' do
      stub_request(:get, userinfo_url).to_return(status: 200, body: 'not json')
      expect(client.fetch_userinfo('token123')).to eq({})
    end
  end

  describe 'JWT verifications' do
    let(:auth_priv_key) { OpenSSL::PKey::RSA.generate(2048) }
    let(:jwks) do
      { keys: [JWT::JWK.new(auth_priv_key).export.merge(kid: 'auth-key-1')] }
    end

    before do
      stub_request(:get, "#{internal_issuer_url}/oauth2/jwks").to_return(
        status: 200,
        body: jwks.to_json
      )
    end

    def sign_jwt(payload, headers = {})
      JWT.encode(payload, auth_priv_key, 'RS256', { kid: 'auth-key-1' }.merge(headers))
    end

    describe '#fetch_jwks' do
      it 'exposes cached_jwks' do
        expect(OAuth2ClientKit::JwksCache.cached_jwks).to be_a(Hash)
      end

      it 'caches and returns JWK set' do
        set1 = client.fetch_jwks('auth-key-1')
        expect(set1).to be_a(JWT::JWK::Set)

        # Test caching
        expect(client.fetch_jwks).to be_a(JWT::JWK::Set)
      end

      it 'returns from cache if fetched within 5 seconds even if kid not found' do
        client.fetch_jwks('auth-key-1')
        # This will hit the < 5 seconds check
        expect(client.fetch_jwks('missing-key')).to be_a(JWT::JWK::Set)
      end

      it 'handles fetch errors' do
        stub_request(:get, "#{internal_issuer_url}/oauth2/jwks").to_raise(StandardError.new('Network down'))

        # Clear cache hack for test
        OAuth2ClientKit::JwksCache.reset!

        expect(client.fetch_jwks).to be_nil
      end

      it 'handles invalid JSON in JWKS response' do
        stub_request(:get, "#{internal_issuer_url}/oauth2/jwks").to_return(
          status: 200,
          body: 'invalid-json'
        )
        OAuth2ClientKit::JwksCache.reset!
        expect(client.fetch_jwks).to be_nil
      end

      it 'returns nil if jwk_set_contains_kid? matches but fetch fails' do
        # Test jwk_set_contains_kid? logic via jwk string key
        jwk = JWT::JWK.new(auth_priv_key)
        expect(client.jwk_set_contains_kid?([jwk.export.merge('kid' => '123')], '123')).to be true
      end
    end

    describe '#decode_and_verify_id_token' do
      it 'verifies valid token' do
        payload = { iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600 }
        token = sign_jwt(payload)
        expect(client.decode_and_verify_id_token(token, nil)).to eq(payload.transform_keys(&:to_s))
      end

      it 'returns empty hash if blank token' do
        expect(client.decode_and_verify_id_token(nil, nil)).to eq({})
      end

      it 'raises error when JWT string is completely unparseable' do
        expect do
          client.decode_and_verify_id_token('totally-invalid-jwt', nil)
        end.to raise_error(/Strict Algorithm Pinning/)
      end

      it 'validates nonce' do
        payload = { iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600, nonce: 'n123' }
        token = sign_jwt(payload)
        expect do
          client.decode_and_verify_id_token(token, 'wrong')
        end.to raise_error(/nonce.*does not match/)
      end

      it 'validates at_hash' do
        at = 'access_token'
        digest = OpenSSL::Digest::SHA256.digest(at)
        at_hash = Base64.urlsafe_encode64(digest[0...16], padding: false)

        payload = { iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600, at_hash: at_hash }
        token = sign_jwt(payload)
        expect(client.decode_and_verify_id_token(token, nil, at)).to be_present

        expect do
          client.decode_and_verify_id_token(token, nil, 'wrong')
        end.to raise_error(/at_hash.*does not match/)
      end

      it 'requires at_hash to be present when an access token is supplied' do
        payload = { iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600 }
        token = sign_jwt(payload)
        expect do
          client.decode_and_verify_id_token(token, nil, 'access_token')
        end.to raise_error(/missing the required at_hash/)
      end

      it 'validates c_hash' do
        code = 'code'
        digest = OpenSSL::Digest::SHA256.digest(code)
        c_hash = Base64.urlsafe_encode64(digest[0...16], padding: false)

        payload = { iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600, c_hash: c_hash }
        token = sign_jwt(payload)
        expect(client.decode_and_verify_id_token(token, nil, nil, code)).to be_present

        expect do
          client.decode_and_verify_id_token(token, nil, nil, 'wrong')
        end.to raise_error(/c_hash.*does not match/)
      end

      it 'requires c_hash to be present when an authorization code is supplied' do
        payload = { iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600 }
        token = sign_jwt(payload)
        expect do
          client.decode_and_verify_id_token(token, nil, nil, 'code')
        end.to raise_error(/missing the required c_hash/)
      end

      it 'does not require at_hash/c_hash when neither token nor code is supplied' do
        payload = { iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600 }
        token = sign_jwt(payload)
        expect(client.decode_and_verify_id_token(token, nil)).to be_present
      end
    end

    describe '#decode_and_verify_jarm_response' do
      it 'verifies valid jarm' do
        payload = { iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600, state: 's123' }
        token = sign_jwt(payload)
        expect(client.decode_and_verify_jarm_response(token, 's123')).to be_present
      end

      it 'raises on missing token' do
        expect { client.decode_and_verify_jarm_response(nil) }.to raise_error(/Missing JARM/)
      end

      it 'raises on state mismatch' do
        payload = { iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600, state: 's123' }
        token = sign_jwt(payload)
        expect { client.decode_and_verify_jarm_response(token, 'wrong') }.to raise_error(/state parameter mismatch/)
      end
    end

    describe '#verify_logout_token' do
      it 'verifies valid logout token' do
        payload = {
          iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600,
          sub: 'alice', sid: 'sess-1',
          events: { 'http://schemas.openid.net/event/backchannel-logout' => {} }
        }
        token = sign_jwt(payload)
        expect(client.verify_logout_token(token)).to be_present
      end

      it 'accepts a logout token with only sub (no sid)' do
        payload = {
          iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600,
          sub: 'alice',
          events: { 'http://schemas.openid.net/event/backchannel-logout' => {} }
        }
        token = sign_jwt(payload)
        expect(client.verify_logout_token(token)['sub']).to eq('alice')
      end

      it 'raises when neither sub nor sid is present' do
        payload = {
          iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600,
          events: { 'http://schemas.openid.net/event/backchannel-logout' => {} }
        }
        token = sign_jwt(payload)
        expect { client.verify_logout_token(token) }.to raise_error(%r{MUST contain a 'sub' and/or 'sid'})
      end

      it 'returns nil for blank token' do
        expect(client.verify_logout_token('')).to be_nil
      end

      it 'raises if missing event' do
        payload = { iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600, sub: 'alice', events: {} }
        token = sign_jwt(payload)
        expect { client.verify_logout_token(token) }.to raise_error(/missing required event claim/)
      end

      it 'raises if nonce is present' do
        payload = {
          iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600,
          sub: 'alice',
          events: { 'http://schemas.openid.net/event/backchannel-logout' => {} },
          nonce: 'n1'
        }
        token = sign_jwt(payload)
        expect { client.verify_logout_token(token) }.to raise_error(/MUST NOT contain a nonce/)
      end
    end

    describe 'JWT signature verification details' do
      it 'rejects invalid algorithm' do
        token = JWT.encode({ iss: public_issuer_url }, 'secret', 'HS256')
        expect { client.decode_and_verify_id_token(token, nil) }.to raise_error(/must use 'RS256'/)
      end

      it 'rejects invalid issuer' do
        token = sign_jwt({ iss: 'wrong', aud: client_id, exp: Time.now.to_i + 3600 })
        expect { client.decode_and_verify_id_token(token, nil) }.to raise_error(JWT::InvalidIssuerError)
      end

      it 'rejects invalid audience' do
        token = sign_jwt({ iss: public_issuer_url, aud: 'wrong', exp: Time.now.to_i + 3600 })
        expect { client.decode_and_verify_id_token(token, nil) }.to raise_error(JWT::InvalidAudError)
      end

      it 'rejects expired token' do
        token = sign_jwt({ iss: public_issuer_url, aud: client_id, exp: Time.now.to_i - 3600 })
        expect { client.decode_and_verify_id_token(token, nil) }.to raise_error(JWT::ExpiredSignature)
      end

      it 'rejects future issued token' do
        token = sign_jwt({ iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600,
                           iat: Time.now.to_i + 3600 })
        expect { client.decode_and_verify_id_token(token, nil) }.to raise_error(/issued in the future/)
      end

      it 'raises on missing JWKS' do
        # Clear cache hack for test
        OAuth2ClientKit::JwksCache.reset!
        stub_request(:get, "#{internal_issuer_url}/oauth2/jwks").to_return(status: 404)
        token = sign_jwt({ iss: public_issuer_url, aud: client_id, exp: Time.now.to_i + 3600 })
        expect { client.decode_and_verify_id_token(token, nil) }.to raise_error(/Unable to fetch JWKS/)
      end
    end
  end

  describe '#with_retries' do
    it 'retries and then raises' do
      count = 0
      expect do
        client.with_retries(max_retries: 2, base_delay: 0.01) do
          count += 1
          raise Faraday::TimeoutError
        end
      end.to raise_error(Faraday::TimeoutError)
      expect(count).to eq(3)
    end
  end
end
