# frozen_string_literal: true

require 'rails_helper'

RSpec.describe SessionsController, type: :controller do
  let(:valid_email) { 'alice_smith@example.com' }
  let(:valid_password) { 'secret123' }
  let(:return_to) { 'http://localhost:9000/callback' }

  let(:redis_mock) { instance_double(Redis) }
  let(:http_mock) { instance_double(Net::HTTP) }

  # Builds a stub Net::HTTPResponse-like double with a given code/body.
  def http_response(code, body = '{}')
    instance_double(Net::HTTPResponse, code: code.to_s, body: body)
  end

  before do
    # Reset the memoised Redis client and stub the connection.
    described_class.instance_variable_set(:@redis_client, nil)
    allow(Redis).to receive(:new).and_return(redis_mock)
    allow(redis_mock).to receive(:set)
    allow(redis_mock).to receive(:del)

    # Stub the outbound Net::HTTP call to the Spring auth server so specs never hit the network.
    allow(Net::HTTP).to receive(:new).and_return(http_mock)
    allow(http_mock).to receive(:open_timeout=)
    allow(http_mock).to receive(:read_timeout=)
    allow(http_mock).to receive(:request)

    # Allow localhost:9000 as a trusted return host regardless of env at boot.
    allow(Rails.configuration.x.auth_server)
      .to receive(:allowed_return_hosts)
      .and_return(Set['localhost:9000', 'localhost'])
  end

  describe 'GET #new' do
    it 'assigns a sanitized return_to for a trusted host' do
      get :new, params: { return_to: return_to }
      expect(response).to have_http_status(:success)
      expect(controller.view_assigns['return_to']).to eq(return_to)
    end

    it 'drops an untrusted return_to (open-redirect defence)' do
      get :new, params: { return_to: 'http://evil.example.com/steal' }
      expect(controller.view_assigns['return_to']).to be_nil
    end

    it 'allows a relative-path return_to (same-origin)' do
      get :new, params: { return_to: '/dashboard' }
      expect(controller.view_assigns['return_to']).to eq('/dashboard')
    end

    it 'drops a malformed return_to that fails URI parsing' do
      get :new, params: { return_to: 'http://[::1:invalid' }
      expect(controller.view_assigns['return_to']).to be_nil
    end

    it 'drops a protocol-relative return_to (//evil.com)' do
      get :new, params: { return_to: '//evil.example.com/path' }
      expect(controller.view_assigns['return_to']).to be_nil
    end

    it 'drops a backslash-obfuscated return_to' do
      get :new, params: { return_to: '/\\evil.example.com' }
      expect(controller.view_assigns['return_to']).to be_nil
    end

    it 'drops a non-http(s) scheme even for an allowed host' do
      get :new, params: { return_to: 'javascript:alert(1)//localhost:9000' }
      expect(controller.view_assigns['return_to']).to be_nil
    end
  end

  describe 'POST #create' do
    context 'when the auth server confirms the credentials (200)' do
      render_views

      let(:user_id) { 'f47ac10b-58cc-4372-a567-0e02b2c3d479' }

      before do
        allow(http_mock).to receive(:request)
          .and_return(http_response(200, { id: user_id, email: valid_email, status: 'authenticated' }.to_json))
      end

      it 'SHA-256 pre-hashes the password before sending it to the auth server' do
        expected_digest = Digest::SHA256.hexdigest(valid_password)
        sent_body = nil
        sent_api_key = nil
        allow(http_mock).to receive(:request) do |req|
          sent_body = JSON.parse(req.body)
          sent_api_key = req['X-Admin-Api-Key']
          http_response(200, { id: user_id, email: valid_email }.to_json)
        end

        post :create, params: { email: valid_email, password: valid_password }

        expect(http_mock).to have_received(:request)
        expect(sent_body['email']).to eq(valid_email)
        expect(sent_body['password']).to eq(expected_digest)
        expect(sent_body['password']).not_to eq(valid_password)
        expect(sent_api_key).to be_present
      end

      it 'creates a Redis session (2h TTL) and sets a hardened cookie, then redirects to return_to' do
        post :create, params: { email: valid_email, password: valid_password, return_to: return_to }

        expect(response).to redirect_to(return_to)
        session_id = cookies[:SHARED_SESSION_ID]
        expect(session_id).to be_present
        expect(session_id).to match(/\A[0-9a-fA-F-]{36}\z/) # UUID
        expect(redis_mock).to have_received(:set).with("session:#{session_id}", anything, ex: 7200)
      end

      it 'renders the success page when no return_to is provided' do
        post :create, params: { email: valid_email, password: valid_password }
        expect(response).to have_http_status(:ok)
        expect(response.body).to include('Authentication Successful')
      end

      it 'invalidates a pre-existing session (session-fixation defence)' do
        old_session = SecureRandom.uuid
        request.cookies[:SHARED_SESSION_ID] = old_session

        post :create, params: { email: valid_email, password: valid_password }

        expect(redis_mock).to have_received(:del).with("session:#{old_session}")
      end
    end

    context 'when the account is flagged as fraud (403)' do
      before { allow(http_mock).to receive(:request).and_return(http_response(403, '{"error":"account_suspended"}')) }

      it 'renders a suspension message with 403 when no return_to' do
        post :create, params: { email: valid_email, password: valid_password }
        expect(response).to have_http_status(:forbidden)
        expect(controller.view_assigns['error_message']).to match(/suspended/i)
        expect(redis_mock).not_to have_received(:set)
      end

      it 'redirects to the client with account_suspended when return_to is present' do
        post :create, params: { email: valid_email, password: valid_password, return_to: return_to }
        expect(response).to redirect_to(/error=account_suspended/)
      end
    end

    context 'when credentials are rejected (401 / 404)' do
      %w[401 404].each do |code|
        it "renders 'incorrect username or password' (422) for HTTP #{code}" do
          allow(http_mock).to receive(:request).and_return(http_response(code))
          post :create, params: { email: valid_email, password: valid_password }
          expect(response).to have_http_status(:unprocessable_entity)
          expect(controller.view_assigns['error_message']).to eq('incorrect username or password')
          expect(redis_mock).not_to have_received(:set)
        end
      end
    end

    context 'when the auth server errors (non-200)' do
      before { allow(http_mock).to receive(:request).and_return(http_response(500, 'boom')) }

      it 'renders a generic internal error (500) without leaking details' do
        post :create, params: { email: valid_email, password: valid_password }
        expect(response).to have_http_status(:internal_server_error)
        expect(controller.view_assigns['error_message']).to eq('An internal error occurred')
      end
    end

    context 'when the HTTP call raises' do
      before { allow(http_mock).to receive(:request).and_raise(Errno::ECONNREFUSED) }

      it 'is rescued and rendered as a generic 500' do
        post :create, params: { email: valid_email, password: valid_password }
        expect(response).to have_http_status(:internal_server_error)
        expect(controller.view_assigns['error_message']).to eq('An internal error occurred')
      end
    end

    context 'with blank credentials' do
      it 'short-circuits with 422 before any HTTP call' do
        post :create, params: { email: '', password: '' }
        expect(http_mock).not_to have_received(:request)
        expect(response).to have_http_status(:unprocessable_entity)
        expect(controller.view_assigns['error_message']).to eq('incorrect username or password')
      end
    end

    context 'with simulated errors (demo failure injection)' do
      it 'redirects to the client callback with the error code when return_to present' do
        post :create, params: { simulate_error: 'access_denied', return_to: return_to }
        expect(response).to redirect_to(/error=access_denied/)
      end

      it 'maps an unknown simulate_error to account_suspended' do
        post :create, params: { simulate_error: 'something_else', return_to: return_to }
        expect(response).to redirect_to(/error=account_suspended/)
      end

      it 'renders new (422) when no return_to is provided' do
        post :create, params: { simulate_error: 'access_denied' }
        expect(response).to have_http_status(:unprocessable_entity)
        expect(controller.view_assigns['error_message']).to be_present
      end

      it 'falls back to the validated return_to if building the error redirect raises' do
        allow(ERB::Util).to receive(:url_encode).and_raise(StandardError, 'encode boom')
        post :create, params: { simulate_error: 'access_denied', return_to: return_to }
        expect(response).to redirect_to(return_to)
      end
    end
  end

  describe 'DELETE #destroy' do
    it 'deletes a valid session from Redis and clears the cookie' do
      session_id = SecureRandom.uuid
      request.cookies[:SHARED_SESSION_ID] = session_id
      delete :destroy
      expect(redis_mock).to have_received(:del).with("session:#{session_id}")
      expect(cookies[:SHARED_SESSION_ID]).to be_blank
      expect(response).to redirect_to('/login')
    end

    it 'ignores a malformed (non-UUID) session id without touching Redis' do
      request.cookies[:SHARED_SESSION_ID] = 'not-a-uuid'
      delete :destroy
      expect(redis_mock).not_to have_received(:del)
      expect(response).to redirect_to('/login')
    end
  end

  describe 'GET #health' do
    it 'returns UP status' do
      get :health
      expect(response).to have_http_status(:success)
      expect(response.parsed_body['status']).to eq('UP')
    end
  end
end
