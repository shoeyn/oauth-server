# frozen_string_literal: true

require 'rails_helper'
require_relative '../../app/services/par_oauth2_client'

# The app/services/par_oauth2_client.rb file provides backward-compatibility
# aliases so older external test suites/scripts can keep referencing the
# pre-gem class names. These specs assert the aliases resolve to the gem's
# client class, which is the actual contract that file exists to guarantee.
RSpec.describe ParOAuth2Client do
  it 'aliases ParOAuth2Client to the packaged gem client' do
    expect(described_class).to eq(OAuth2ClientKit::Client)
  end

  it 'aliases the lower-case ParOauth2Client variant to the packaged gem client' do
    expect(ParOauth2Client).to eq(OAuth2ClientKit::Client)
  end
end
