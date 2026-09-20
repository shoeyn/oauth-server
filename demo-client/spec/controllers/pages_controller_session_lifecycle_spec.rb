# frozen_string_literal: true

require 'rails_helper'

RSpec.describe PagesController, type: :controller do
  let(:token_store) { instance_double(OAuth2ClientKit::TokenStore) }
  let(:client) { instance_double(OAuth2ClientKit::Client) }

  before do
    allow(OAuth2ClientKit).to receive_messages(token_store: token_store, client: client)
  end

  describe 'rebooted services and expired session handling' do
    context 'when services rebooted (token store data is missing)' do
      before do
        session[:user] = { 'sub' => 'alice' }
        session[:token_key] = 'evicted_token_key'
        allow(token_store).to receive(:read).with('evicted_token_key').and_return(nil)
        allow(token_store).to receive(:delete).with('evicted_token_key')
      end

      it 'forces sign out on landing page load and renders unauthenticated' do
        get :index
        expect(response).to have_http_status(:success)
        expect(session[:user]).to be_nil
        expect(session[:token_key]).to be_nil
        expect(controller.authenticated?).to be false
      end

      it 'forces sign out on profile page load and redirects to root' do
        get :profile
        expect(response).to redirect_to('/')
        expect(session[:user]).to be_nil
        expect(session[:token_key]).to be_nil
        expect(flash[:error]).to eq('Please log in first.')
      end
    end

    context 'when access token is expired and refresh fails' do
      before do
        session[:user] = { 'sub' => 'alice' }
        session[:token_key] = 'expired_token_key'
        token_data = {
          raw_access_token: 'expired_token',
          raw_refresh_token: 'dead_refresh_token',
          expires_at: Time.now.to_i - 300,
          dpop_key: 'key'
        }
        allow(token_store).to receive(:read).with('expired_token_key').and_return(token_data)
        allow(token_store).to receive(:delete).with('expired_token_key')
        allow(client).to receive(:refresh_access_token).and_raise(StandardError, 'invalid_grant')
      end

      it 'forces sign out on landing page load' do
        get :index
        expect(response).to have_http_status(:success)
        expect(session[:user]).to be_nil
        expect(session[:token_key]).to be_nil
        expect(controller.authenticated?).to be false
      end

      it 'forces sign out on profile page load and redirects to root' do
        get :profile
        expect(response).to redirect_to('/')
        expect(session[:user]).to be_nil
        expect(session[:token_key]).to be_nil
        expect(flash[:error]).to eq('Please log in first.')
      end
    end

    context 'when access token is expiring and refresh succeeds' do
      before do
        session[:user] = { 'sub' => 'alice' }
        session[:token_key] = 'expiring_token_key'
        token_data = {
          raw_access_token: 'old_access_token',
          raw_refresh_token: 'old_refresh_token',
          expires_at: Time.now.to_i + 30,
          dpop_key: 'key'
        }
        token_double = Struct.new(:token, :refresh_token, :params).new(
          'new_access_token', 'new_refresh_token', { 'token_type' => 'DPoP' }
        )
        allow(token_store).to receive(:read).with('expiring_token_key').and_return(token_data)
        allow(client).to receive(:refresh_access_token).and_return(token_double)
        allow(token_store).to receive(:write)
        allow(JWT).to receive(:decode).and_return([{ 'exp' => Time.now.to_i + 3600, 'sub' => 'alice' }])
      end

      it 'refreshes token seamlessly on profile page load and renders profile' do
        get :profile
        expect(response).to have_http_status(:success)
        expect(session[:user]).to eq({ 'sub' => 'alice' })
        expect(client).to have_received(:refresh_access_token)
      end
    end
  end
end
