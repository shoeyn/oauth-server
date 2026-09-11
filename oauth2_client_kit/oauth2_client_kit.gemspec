# frozen_string_literal: true

require_relative "lib/oauth2_client_kit/version"

Gem::Specification.new do |spec|
  spec.name          = "oauth2_client_kit"
  spec.version       = OAuth2ClientKit::VERSION
  spec.authors       = ["Enterprise Security Team"]
  spec.summary       = "High-Assurance OAuth 2.1 & OpenID Connect Client Gem with DPoP, PAR, and PKCE"
  spec.description   = "Reusable Ruby client library providing RFC 9126 (PAR), RFC 7523 (private_key_jwt), RFC 9449 (DPoP sender constraint), RFC 7636 (PKCE S256), multi-key JWKS rotation, and seamless Rails Engine integration."
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.files = Dir["lib/**/*.rb", "README.md", "oauth2_client_kit.gemspec"]
  spec.require_paths = ["lib"]

  spec.add_dependency "oauth2", "~> 2.0"
  spec.add_dependency "jwt", "~> 3.2"
  spec.add_dependency "redis", "~> 5.0"
  spec.add_dependency "faraday", ">= 2.0"
end
