# frozen_string_literal: true

require 'rails_helper'

RSpec.describe OAuth2ClientKit::AuthController, type: :controller do
  routes { OAuth2ClientKit::Engine.routes }

  let(:token_store) { instance_double(OAuth2ClientKit::TokenStore) }
  let(:client) { instance_double(OAuth2ClientKit::Client) }

  before do
    allow(OAuth2ClientKit).to receive_messages(token_store: token_store, client: client)
  end

  describe 'POST #refresh' do
    context 'when refresh token fails' do
      before do
        session[:user] = { 'sub' => 'alice' }
        session[:token_key] = 'tk_fail'
        token_data = {
          raw_access_token: 'acc',
          raw_refresh_token: 'dead_ref',
          expires_at: Time.now.to_i + 3600
        }
        allow(token_store).to receive(:read).with('tk_fail').and_return(token_data)
        allow(token_store).to receive(:delete).with('tk_fail')
        allow(client).to receive(:refresh_access_token).and_raise(StandardError, 'invalid_grant')
      end

      it 'forces sign out and redirects to root' do
        post :refresh
        expect(response).to redirect_to('/')
        expect(session[:user]).to be_nil
        expect(session[:token_key]).to be_nil
        expect(flash[:error]).to include('Token refresh failed')
      end
    end
  end

  describe 'GET #callback' do
    let(:jarm_payload) { { 'state' => 'state123', 'code' => 'code123' } }
    let(:token_double_class) { Struct.new(:token, :refresh_token, :params) }

    before do
      allow(client).to receive(:public_issuer_url).and_return('http://auth')
      allow(client).to receive(:decode_and_verify_jarm_response).with('signed_jarm_jwt').and_return(jarm_payload)
    end

    it 'rejects Login CSRF attack when state is present in cache but missing from session' do
      Rails.cache.write('oauth_flow:state123', { code_verifier: 'v123', nonce: 'n123' })
      session[:oauth_state] = 'attacker_or_other_state'

      get :callback, params: { response: 'signed_jarm_jwt' }

      expect(response).to redirect_to('/')
      expect(flash[:error]).to include('State parameter mismatch or expired')
      expect(session[:user]).to be_nil
      expect(session[:token_key]).to be_nil
    end

    it 'resets session (preventing session fixation) and establishes authenticated state on success' do
      session[:oauth_state] = 'state123'
      session[:oauth_code_verifier] = 'v123'
      session[:oauth_nonce] = 'n123'
      session[:pre_auth_attacker_data] = 'injected_session_value'

      token_double = token_double_class.new('acc_token', 'ref_token', { 'id_token' => 'id_jwt' })
      allow(client).to receive_messages(
        exchange_code: token_double,
        decode_and_verify_id_token: { 'sub' => 'alice' },
        fetch_userinfo: { 'name' => 'Alice' }
      )
      token_claims = [{ 'sub' => 'alice', 'exp' => Time.now.to_i + 3600 }]
      allow(JWT).to receive(:decode).with('acc_token', nil, false).and_return(token_claims)
      allow(token_store).to receive(:write)

      get :callback, params: { response: 'signed_jarm_jwt' }

      expect(response).to redirect_to('/profile')
      expect(flash[:notice]).to include('Successfully authenticated')
      expect(session[:user]).to eq({ 'sub' => 'alice', 'name' => 'Alice' })
      expect(session[:token_key]).to be_present
      expect(session[:pre_auth_attacker_data]).to be_nil
    end
  end
end
