require 'rails_helper'

RSpec.describe SessionsController, type: :controller do
  let(:valid_username) { 'test_user' }
  let(:valid_password) { 'password' }
  let(:invalid_password) { '' }
  let(:redis_mock) { instance_double(Redis) }
  
  before do
    SessionsController.instance_variable_set(:@redis_client, nil)
    allow(Redis).to receive(:new).and_return(redis_mock)
    allow(redis_mock).to receive(:set)
    allow(redis_mock).to receive(:del)
  end

  describe 'GET #new' do
    it 'assigns a sanitized return_to' do
      get :new, params: { return_to: 'http://localhost:9000/callback' }
      expect(response).to have_http_status(:success)
      expect(controller.view_assigns["return_to"]).to eq('http://localhost:9000/callback')
    end
  end

  describe 'POST #create' do
    context 'with valid credentials' do
      it 'creates a session in Redis and sets secure cookie' do
        post :create, params: { username: valid_username, password: valid_password, return_to: 'http://localhost:9000/callback' }
        
        expect(response).to redirect_to('http://localhost:9000/callback')
        
        expect(cookies[:SHARED_SESSION_ID]).to be_present
        session_id = cookies[:SHARED_SESSION_ID]
        expect(redis_mock).to have_received(:set).with(
          "session:#{session_id}",
          anything,
          ex: 7200
        )
      end
    end

    context 'with invalid credentials' do
      it 'renders new with error' do
        post :create, params: { username: valid_username, password: invalid_password }
        expect(response).to have_http_status(:unprocessable_entity)
        expect(flash[:error]).to eq('Invalid credentials')
      end
    end

    context 'with simulated errors' do
      it 'redirects with error parameters' do
        post :create, params: { simulate_error: 'access_denied', return_to: 'http://localhost:9000/callback' }
        expect(response).to redirect_to(/error=access_denied/)
      end
      
      it 'renders new when no return_to is provided for an error' do
        post :create, params: { simulate_error: 'access_denied' }
        expect(response).to have_http_status(:unprocessable_entity)
      end
    end
  end

  describe 'DELETE #destroy' do
    it 'deletes the session from Redis and cookies' do
      cookies[:SHARED_SESSION_ID] = SecureRandom.uuid
      delete :destroy
      expect(redis_mock).to have_received(:del)
      expect(cookies[:SHARED_SESSION_ID]).to be_nil
      expect(response).to redirect_to('/login')
    end
  end

  describe 'GET #health' do
    it 'returns UP status' do
      get :health
      expect(response).to have_http_status(:success)
      json_response = JSON.parse(response.body)
      expect(json_response['status']).to eq('UP')
    end
  end
end
