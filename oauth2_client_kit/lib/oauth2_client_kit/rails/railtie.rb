# frozen_string_literal: true

module OAuth2ClientKit
  class Railtie < ::Rails::Railtie
    config.after_initialize do
      if defined?(OAuth2ClientKit::AuthController)
        OAuth2ClientKit::AuthController.skip_before_action :verify_authenticity_token, only: [:backchannel_logout], raise: false
      end
    end
  end
end
