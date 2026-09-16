# frozen_string_literal: true

require 'rails_helper'

RSpec.describe ApplicationController, type: :controller do
  controller do
    def index
      render plain: 'Hello'
    end
  end
  it 'can render' do
    get :index
    expect(response.body).to eq('Hello')
  end
end
