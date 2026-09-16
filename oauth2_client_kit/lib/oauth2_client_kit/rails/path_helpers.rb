# frozen_string_literal: true

module OAuth2ClientKit
  # URL helper paths for OAuth 2.1 client flows.
  module PathHelpers
    def auth_start_path(params = {})
      "/auth/start#{"?#{URI.encode_www_form(params)}" if params.any?}"
    end

    def auth_refresh_path
      '/auth/refresh'
    end

    def auth_revoke_path
      '/auth/revoke'
    end

    def logout_path
      '/logout'
    end

    def callback_path
      '/callback'
    end
  end
end
