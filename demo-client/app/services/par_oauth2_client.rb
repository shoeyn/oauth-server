# frozen_string_literal: true

require "oauth2_client_kit"

# Backward compatibility alias for external test suites and scripts.
# All RFC 9126, 7523, 7636, 9449, 9207, and OIDC protocol mechanics
# are now packaged and maintained inside the oauth2_client_kit gem.
ParOAuth2Client = OAuth2ClientKit::Client
ParOauth2Client = OAuth2ClientKit::Client
