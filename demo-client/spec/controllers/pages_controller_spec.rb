require 'rails_helper'

RSpec.describe PagesController, type: :controller do
  before do
    # Mocking OAuth2ClientKit methods
    allow(controller).to receive(:authenticated?).and_return(true)
    allow(controller).to receive(:current_user).and_return('user123')
    allow(controller).to receive(:current_id_token_claims).and_return({})
    allow(controller).to receive(:current_token_scopes).and_return([])
    allow(controller).to receive(:current_userinfo_claims).and_return({})
    allow(controller).to receive(:current_access_token_claims).and_return({})
    allow(controller).to receive(:current_raw_id_token).and_return('token')
    allow(controller).to receive(:current_access_token).and_return('token')
    allow(controller).to receive(:current_raw_refresh_token).and_return('token')
    allow(controller).to receive(:current_auth_flow).and_return('auth_code')
    allow(controller).to receive(:current_token_expires_at).and_return(Time.now + 3600)
    allow(controller).to receive(:current_token_type).and_return('Bearer')
    allow(controller).to receive(:oauth_redirect_uri).and_return('http://localhost')
    
    # Mock OAuth2ClientKit config
    config_mock = double('Config', issuer_url: 'http://auth', client_id: 'client')
    stub_const('OAuth2ClientKit', Class.new do
      def self.config; end
    end)
    allow(OAuth2ClientKit).to receive(:config).and_return(config_mock)
  end

  describe "GET #index" do
    it "renders the index successfully" do
      get :index
      expect(response).to have_http_status(:success)
    end
  end
  
  describe "GET #profile" do
    context "when authenticated" do
      before do
        allow(controller).to receive(:require_authentication!).and_return(true)
        allow(controller).to receive(:current_token_data).and_return({ raw_access_token: '123' })
        allow(controller).to receive(:ensure_fresh_access_token!)
      end

      it "renders the profile successfully" do
        get :profile
        expect(response).to have_http_status(:success)
      end
    end

    context "when unauthenticated" do
      before do
        # Mirror the real ControllerMethods#require_authentication!: when unauthenticated it
        # sets a flash error, redirects to "/", and returns false (halting the action).
        allow(controller).to receive(:require_authentication!) do
          controller.flash[:error] = "Please log in first."
          controller.redirect_to "/"
          false
        end
      end

      it "does not render profile and redirects to root" do
        get :profile
        expect(response).to redirect_to("/")
        expect(response).not_to have_http_status(:success)
        expect(flash[:error]).to be_present
      end
    end
    
    context "when token data is blank" do
      before do
        allow(controller).to receive(:require_authentication!).and_return(true)
        allow(controller).to receive(:current_token_data).and_return({})
      end

      it "redirects to root" do
        get :profile
        expect(response).to redirect_to("/")
        expect(flash[:error]).to be_present
      end
    end
  end

  describe "POST #sensitive_action" do
    before do
      allow(controller).to receive(:require_authentication!).and_return(true)
    end

    context "when active checkpoint" do
      before do
        allow(controller).to receive(:identity_checkpoint!).and_return({ active: true, claims: {}, sub: 'user123' })
      end

      it "redirects to profile" do
        post :sensitive_action
        expect(response).to redirect_to("/profile")
        expect(flash[:notice]).to be_present
      end
    end

    context "when inactive checkpoint" do
      before do
        allow(controller).to receive(:identity_checkpoint!).and_return({ active: false, claims: {} })
      end

      it "redirects to root" do
        post :sensitive_action
        expect(response).to redirect_to("/")
        expect(flash[:error]).to be_present
      end
    end
  end
end
