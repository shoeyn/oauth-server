# frozen_string_literal: true

require 'rails_helper'

RSpec.describe PagesController, type: :controller do
  before do
    # Mocking OAuth2ClientKit methods
    allow(controller).to receive_messages(
      authenticated?: true, current_user: 'user123', current_id_token_claims: {},
      current_token_scopes: [], current_userinfo_claims: {}, current_access_token_claims: {},
      current_raw_id_token: 'token', current_access_token: 'token', current_raw_refresh_token: 'token',
      current_auth_flow: 'auth_code', current_token_expires_at: Time.zone.now + 3600,
      current_token_type: 'Bearer', oauth_redirect_uri: 'http://localhost'
    )

    # Mock OAuth2ClientKit config
    config_mock = Struct.new(:issuer_url, :client_id).new('http://auth', 'client')
    stub_const('OAuth2ClientKit', Class.new do
      def self.config; end
    end)
    allow(OAuth2ClientKit).to receive(:config).and_return(config_mock)
  end

  describe 'GET #index' do
    it 'renders the index successfully' do
      get :index
      expect(response).to have_http_status(:success)
    end
  end

  describe 'GET #profile' do
    context 'when authenticated' do
      before do
        allow(controller).to receive(:require_authentication!).and_return(true)
      end

      it 'renders the profile successfully' do
        get :profile
        expect(response).to have_http_status(:success)
      end
    end

    context 'when unauthenticated' do
      before do
        # Mirror the real ControllerMethods#require_authentication!: when unauthenticated it
        # sets a flash error, redirects to "/", and returns false (halting the action).
        allow(controller).to receive(:require_authentication!) do
          controller.flash[:error] = 'Please log in first.'
          controller.redirect_to '/'
          false
        end
      end

      it 'does not render profile and redirects to root' do
        get :profile
        expect(response).to redirect_to('/')
        expect(response).not_to have_http_status(:success)
        expect(flash[:error]).to be_present
      end
    end
  end

  describe 'POST #sensitive_action' do
    before do
      allow(controller).to receive(:require_authentication!).and_return(true)
    end

    context 'when active checkpoint' do
      before do
        allow(controller).to receive(:identity_checkpoint!).and_return({ active: true, claims: {}, sub: 'user123' })
      end

      it 'redirects to profile' do
        post :sensitive_action
        expect(response).to redirect_to('/profile')
        expect(flash[:notice]).to be_present
      end
    end

    context 'when inactive checkpoint' do
      before do
        allow(controller).to receive(:identity_checkpoint!).and_return({ active: false, claims: {} })
      end

      it 'redirects to root' do
        post :sensitive_action
        expect(response).to redirect_to('/')
        expect(flash[:error]).to be_present
      end
    end
  end
end
