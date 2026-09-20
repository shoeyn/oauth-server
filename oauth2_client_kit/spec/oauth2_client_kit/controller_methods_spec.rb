# frozen_string_literal: true

require 'spec_helper'
require 'active_support/concern'
require 'oauth2_client_kit'
require 'oauth2_client_kit/rails/controller_methods'
require 'oauth2_client_kit/token_store'

class DummyController
  attr_accessor :session, :flash, :request

  def self.helper_method(*args); end
  def self.before_action(*args); end

  include OAuth2ClientKit::ControllerMethods

  def initialize
    @session = {}
    @flash = {}
    @request = Struct.new(:protocol, :host_with_port).new('http://', 'test.host')
  end

  def redirect_to(url)
    @redirected_to = url
  end

  attr_reader :redirected_to

  def reset_session
    @session = {}
  end
end

RSpec.describe OAuth2ClientKit::ControllerMethods do
  let(:controller) { DummyController.new }
  let(:token_store) { instance_double(OAuth2ClientKit::TokenStore) }
  let(:client) { instance_double(OAuth2ClientKit::Client) }
  let(:logger) { Logger.new(nil) }

  before do
    allow(OAuth2ClientKit).to receive_messages(token_store: token_store, client: client, logger: logger)
    allow(token_store).to receive(:read).with(nil).and_return(nil)
    allow(token_store).to receive(:delete)
    allow(token_store).to receive(:read).with('tk123').and_return({
                                                                    raw_access_token: 'acc1',
                                                                    raw_refresh_token: 'ref1',
                                                                    raw_id_token: 'id1',
                                                                    expires_at: Time.now.to_i + 3600,
                                                                    token_type: 'DPoP',
                                                                    access_token_claims: { 'sub' => 'user1' },
                                                                    userinfo_claims: { 'name' => 'Alice' },
                                                                    dpop_key: 'dpop123'
                                                                  })
  end

  describe 'paths' do
    it 'returns correct paths' do
      expect(controller.auth_start_path).to eq('/auth/start')
      expect(controller.auth_start_path(prompt: 'login')).to eq('/auth/start?prompt=login')
      expect(controller.auth_refresh_path).to eq('/auth/refresh')
      expect(controller.auth_revoke_path).to eq('/auth/revoke')
      expect(controller.logout_path).to eq('/logout')
      expect(controller.callback_path).to eq('/callback')
      expect(controller.oauth_redirect_uri).to eq('http://test.host/callback')
    end
  end

  describe 'authentication helpers' do
    it 'returns current_user' do
      controller.session[:user] = 'u1'
      expect(controller.current_user).to eq('u1')
    end

    it 'checks authenticated?' do
      expect(controller).not_to be_authenticated
      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk123'
      expect(controller).to be_authenticated
    end

    it 'enforces require_authentication!' do
      expect(controller.require_authentication!).to be false
      expect(controller.flash[:error]).to eq('Please log in first.')
      expect(controller.redirected_to).to eq('/')

      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk123'
      expect(controller.require_authentication!).to be true
    end
  end

  describe 'token data helpers' do
    before do
      controller.session[:token_key] = 'tk123'
      controller.session[:token_scopes] = 'openid profile'
      controller.session[:auth_flow_used] = 'DPoP'
      controller.session[:id_token_claims] = { 'iss' => 'foo' }
    end

    it 'returns current token data' do
      expect(controller.current_token_data[:raw_access_token]).to eq('acc1')
      expect(controller.current_access_token).to eq('acc1')
      expect(controller.current_raw_refresh_token).to eq('ref1')
      expect(controller.current_raw_id_token).to eq('id1')
      expect(controller.current_token_scopes).to eq('openid profile')
      expect(controller.current_auth_flow).to eq('DPoP')
      expect(controller.current_token_type).to eq('DPoP')
      expect(controller.current_access_token_claims).to eq({ 'sub' => 'user1' })
      expect(controller.current_userinfo_claims).to eq({ 'name' => 'Alice' })
      expect(controller.current_id_token_claims).to eq({ 'iss' => 'foo' })
      expect(controller.current_token_expires_at).to be > Time.now.to_i
    end

    it 'handles missing token data gracefully' do
      controller.session[:token_key] = 'invalid'
      allow(token_store).to receive(:read).with('invalid').and_return(nil)

      expect(controller.current_token_data).to eq({})
      expect(controller.current_access_token).to be_nil
      expect(controller.current_token_type).to eq('Bearer')
      expect(controller.current_auth_flow).to eq('DPoP')
    end

    it 'falls back to PAR for current_auth_flow' do
      controller.session[:auth_flow_used] = nil
      expect(controller.current_auth_flow).to eq('PAR')
    end
  end

  describe '#ensure_fresh_access_token!' do
    it 'does not refresh if token is fresh' do
      controller.session[:token_key] = 'tk123'
      allow(controller).to receive(:refresh_token_session!)
      controller.ensure_fresh_access_token!
      expect(controller).not_to have_received(:refresh_token_session!)
    end

    it 'refreshes if token is expiring' do
      controller.session[:token_key] = 'tk123'
      allow(token_store).to receive(:read).with('tk123').and_return({
                                                                      raw_refresh_token: 'ref1',
                                                                      expires_at: Time.now.to_i + 30
                                                                    })

      allow(controller).to receive(:refresh_token_session!)
      controller.ensure_fresh_access_token!
      expect(controller).to have_received(:refresh_token_session!)
    end
  end

  describe '#refresh_token_session!' do
    let(:token_double_class) { Struct.new(:token, :refresh_token, :params) }

    it 'returns false if no refresh token' do
      controller.session[:token_key] = 'tk123'
      allow(token_store).to receive(:read).with('tk123').and_return({})
      expect(controller.refresh_token_session!).to be false
    end

    it 'refreshes token successfully' do
      controller.session[:token_key] = 'tk123'

      token_obj = token_double_class.new('new_acc', 'new_ref', { 'token_type' => 'DPoP' })
      allow(client).to receive(:refresh_access_token).with('ref1', 'dpop123').and_return(token_obj)
      allow(token_store).to receive(:write)

      # Mock JWT decode logic in refresh_token_session!
      allow(JWT).to receive(:decode).with('new_acc', nil, false).and_return([{ 'exp' => Time.now.to_i + 3600 }])

      expect(controller.refresh_token_session!).to be true
      expect(client).to have_received(:refresh_access_token).with('ref1', 'dpop123')
      expect(token_store).to have_received(:write).with('tk123', hash_including(
                                                                   raw_access_token: 'new_acc',
                                                                   raw_refresh_token: 'new_ref',
                                                                   token_type: 'DPoP'
                                                                 ))
    end

    it 'catches errors' do
      controller.session[:token_key] = 'tk123'
      allow(client).to receive(:refresh_access_token).and_raise(StandardError, 'foo')
      expect(controller.refresh_token_session!).to be false
    end

    it 'handles JWT decode errors gracefully on refresh' do
      controller.session[:token_key] = 'tk123'
      token_obj = token_double_class.new('new_acc', 'new_ref', { 'token_type' => 'DPoP' })
      allow(client).to receive(:refresh_access_token).and_return(token_obj)
      allow(JWT).to receive(:decode).and_raise(StandardError)
      allow(token_store).to receive(:write)

      expect(controller.refresh_token_session!).to be true
    end
  end

  describe '#identity_checkpoint!' do
    it 'returns unauthenticated if not authenticated' do
      expect(controller.identity_checkpoint!).to eq({ active: false, reason: 'unauthenticated' })
    end

    it 'resets session if missing access token' do
      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk_no_token'
      allow(token_store).to receive(:read).with('tk_no_token').and_return({})

      expect(controller.identity_checkpoint!).to eq({ active: false, reason: 'missing_access_token' })
      expect(controller.session).to be_empty
    end

    it 'returns result if active' do
      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk123'

      allow(client).to receive(:verify_active!).with('acc1').and_return({ active: true, sub: 'user1' })
      expect(controller.identity_checkpoint!).to eq({ active: true, sub: 'user1' })
    end

    it 'evicts session if inactive' do
      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk123'

      allow(client).to receive(:verify_active!).with('acc1').and_return({ active: false, reason: 'revoked' })
      allow(token_store).to receive(:delete)

      expect(controller.identity_checkpoint!).to eq({ active: false, reason: 'revoked' })
      expect(token_store).to have_received(:delete).with('tk123')
      expect(controller.session).to be_empty
    end

    it 'has aliases' do
      checkpoint_method = controller.method(:identity_checkpoint!)
      expect(controller.method(:validate_user!)).to eq(checkpoint_method)
      expect(controller.method(:verify_active_token_for_sensitive_action!)).to eq(checkpoint_method)
    end
  end

  describe '#validate_session_and_refresh_tokens!' do
    it 'does nothing when unauthenticated' do
      allow(controller).to receive(:force_sign_out_session!)
      controller.validate_session_and_refresh_tokens!
      expect(controller).not_to have_received(:force_sign_out_session!)
    end

    it 'forces sign out when token data is missing' do
      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk_missing'
      allow(token_store).to receive(:read).with('tk_missing').and_return(nil)
      allow(controller).to receive(:force_sign_out_session!)

      controller.validate_session_and_refresh_tokens!
      expect(controller).to have_received(:force_sign_out_session!)
        .with(reason: 'Session token data missing or evicted')
    end

    it 'forces sign out when raw access token is blank' do
      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk_blank'
      allow(token_store).to receive(:read).with('tk_blank').and_return({ raw_access_token: '' })
      allow(controller).to receive(:force_sign_out_session!)

      controller.validate_session_and_refresh_tokens!
      expect(controller).to have_received(:force_sign_out_session!)
        .with(reason: 'Session token data missing or evicted')
    end

    it 'does nothing when access token is fresh' do
      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk123'
      allow(controller).to receive(:execute_token_refresh)

      controller.validate_session_and_refresh_tokens!
      expect(controller).not_to have_received(:execute_token_refresh)
    end

    it 'forces sign out when expiring and no refresh token is present' do
      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk_no_ref'
      allow(token_store).to receive(:read).with('tk_no_ref').and_return({
                                                                          raw_access_token: 'acc1',
                                                                          raw_refresh_token: nil,
                                                                          expires_at: Time.now.to_i + 30
                                                                        })
      allow(controller).to receive(:force_sign_out_session!)

      controller.validate_session_and_refresh_tokens!
      expect(controller).to have_received(:force_sign_out_session!)
        .with(reason: 'Access token expired with no refresh token')
    end

    it 'refreshes token successfully when expiring' do
      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk_expiring'
      token_data = {
        raw_access_token: 'acc1',
        raw_refresh_token: 'ref1',
        expires_at: Time.now.to_i + 30
      }
      allow(token_store).to receive(:read).with('tk_expiring').and_return(token_data)
      allow(controller).to receive(:execute_token_refresh).and_return(true)

      controller.validate_session_and_refresh_tokens!
      expect(controller).to have_received(:execute_token_refresh).with('tk_expiring', token_data)
    end

    it 'forces sign out when refresh execution fails' do
      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk_fail'
      token_data = {
        raw_access_token: 'acc1',
        raw_refresh_token: 'ref1',
        expires_at: Time.now.to_i + 30
      }
      allow(token_store).to receive(:read).with('tk_fail').and_return(token_data)
      allow(controller).to receive(:execute_token_refresh).and_return(false)
      allow(controller).to receive(:force_sign_out_session!)

      controller.validate_session_and_refresh_tokens!
      expect(controller).to have_received(:force_sign_out_session!).with(reason: 'Automatic token refresh failed')
    end
  end

  describe '#force_sign_out_session!' do
    it 'deletes token store entry and clears session' do
      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk123'
      controller.session[:raw_id_token] = 'id1'

      controller.force_sign_out_session!(reason: 'test sign out')

      expect(token_store).to have_received(:delete).with('tk123')
      expect(controller.session).to be_empty
    end

    it 'rescues token store delete errors and still clears session' do
      controller.session[:user] = 'u1'
      controller.session[:token_key] = 'tk123'
      allow(token_store).to receive(:delete).with('tk123').and_raise(StandardError, 'redis down')

      controller.force_sign_out_session!(reason: 'test error')

      expect(controller.session).to be_empty
    end
  end
end
