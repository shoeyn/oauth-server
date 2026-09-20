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
end
