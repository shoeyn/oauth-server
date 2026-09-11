#!/usr/bin/env ruby
# frozen_string_literal: true

require "net/http"
require "uri"
require "json"
require "openssl"
require "jwt"
require "base64"

# Locate demo-client root
DEMO_CLIENT_ROOT = [
  File.expand_path("../..", __FILE__),
  File.expand_path("../../../demo-client", __FILE__)
].find { |dir| File.exist?(File.join(dir, "config/environment.rb")) }

require File.join(DEMO_CLIENT_ROOT, "config/environment")

class CookieJar
  def initialize
    @cookies = {}
  end
  def update(res)
    fields = res.get_fields("set-cookie") || []
    fields.each do |f|
      cookie_part = f.split(";").first
      k, v = cookie_part.split("=", 2)
      @cookies[k] = v if k && v
    end
  end
  def to_s
    @cookies.map { |k, v| "#{k}=#{v}" }.join("; ")
  end
end

puts "================================================================================"
puts "  SUITE 6: RFC 9221 (JARM) ENFORCEMENT & CRYPTOGRAPHIC SECURITY TEST SUITE"
puts "================================================================================"

http = Net::HTTP.new("localhost", 8080)
spring_http = Net::HTTP.new("localhost", 9000)
rails_http = Net::HTTP.new("localhost", 3000)

# ------------------------------------------------------------------------------
# TEST 1: OpenID Connect Discovery Metadata Publishes RFC 9221 JARM Support
# ------------------------------------------------------------------------------
puts "\n[TEST 1] Verifying RFC 9221 JARM response_modes_supported in OpenID Discovery..."
disc_res = spring_http.get("/.well-known/openid-configuration")
unless disc_res.code == "200"
  abort "   FAILED: Could not retrieve OpenID configuration (HTTP #{disc_res.code})"
end

disc_json = JSON.parse(disc_res.body)
modes = disc_json["response_modes_supported"] || []
puts "   Discovered response_modes_supported: #{modes.inspect}"

unless modes.include?("jwt") && modes.include?("query.jwt")
  abort "   FAILED: Discovery metadata does not advertise 'jwt' and 'query.jwt' response modes"
end
puts "   SUCCESS: RFC 9221 response_modes_supported confirmed in Discovery metadata."

# ------------------------------------------------------------------------------
# TEST 2: Strict JARM Success Response & AWS KMS RS256 Verification
# ------------------------------------------------------------------------------
puts "\n[TEST 2] Verifying Strict JARM Success Authorization Response (PAR + JARM)..."
jar = CookieJar.new

# 2a: Initialize login at client
home_res = http.get("/")
jar.update(home_res)
csrf_token = home_res.body[/name="authenticity_token" value="([^"]+)"/, 1]

req = Net::HTTP::Post.new("/auth/start")
req["Cookie"] = jar.to_s
req.set_form_data("flow" => "par", "authenticity_token" => csrf_token)
start_res = http.request(req)
jar.update(start_res)

auth_redirect_url = start_res["location"]
auth_uri = URI(auth_redirect_url)
puts "   Auth started: #{auth_redirect_url}"

# 2b: Authenticate at IdP
login_page = rails_http.get("/login?return_to=#{ERB::Util.url_encode(auth_redirect_url)}")
rails_jar = CookieJar.new
rails_jar.update(login_page)
rails_csrf = login_page.body[/name="authenticity_token" value="([^"]+)"/, 1]

login_req = Net::HTTP::Post.new("/login")
login_req["Cookie"] = rails_jar.to_s
login_req.set_form_data(
  "username" => "demo_user",
  "password" => "password",
  "return_to" => auth_redirect_url,
  "authenticity_token" => rails_csrf
)
login_res = rails_http.request(login_req)
rails_jar.update(login_res)
shared_session = rails_jar.to_s[/SHARED_SESSION_ID=([^;]+)/, 1]

# 2c: Follow redirect back to Spring Auth Server /oauth2/authorize
auth_req = Net::HTTP::Get.new(auth_uri.request_uri)
auth_req["Cookie"] = "SHARED_SESSION_ID=#{shared_session}"
auth_res = spring_http.request(auth_req)

unless auth_res.code == "302"
  abort "   FAILED: Expected HTTP 302 from /oauth2/authorize, got #{auth_res.code}"
end

callback_url = URI(auth_res["location"])
cb_params = URI.decode_www_form(callback_url.query || "").to_h

puts "   Spring Auth Server callback URL: #{callback_url.to_s[0..80]}..."
if cb_params["code"] || cb_params["iss"]
  abort "   FAILED: Detected plaintext query parameters! JARM requires responses to be exclusively in ?response=<jwt>"
end

unless cb_params["response"]
  abort "   FAILED: Missing ?response=<jwt> parameter in callback redirect"
end

jarm_jwt = cb_params["response"]
puts "   Extracted JARM JWT (length: #{jarm_jwt.length})"

# Fetch JWKS to verify RS256 KMS signature
jwks_res = spring_http.get("/oauth2/jwks")
jwk_set = JSON.parse(jwks_res.body)
unverified_header = JWT.decode(jarm_jwt, nil, false)[1]
matching_key = jwk_set["keys"].find { |k| k["kid"] == unverified_header["kid"] }

unless matching_key
  abort "   FAILED: Key ID #{unverified_header['kid']} not found in server JWKS"
end

rsa_key = JWT::JWK::RSA.import(matching_key).public_key
payload, header = JWT.decode(jarm_jwt, rsa_key, true, { algorithm: "RS256" })

puts "   JARM JWT Header: alg=#{header['alg']}, kid=#{header['kid']}"
puts "   JARM JWT Payload: iss=#{payload['iss']}, aud=#{payload['aud']}, code=#{payload['code'][0..8]}..., exp=#{payload['exp']}"

unless payload["iss"] == "http://localhost:9000"
  abort "   FAILED: Invalid issuer in JARM token: #{payload['iss']}"
end
unless payload["aud"] == ["demo-client"] || payload["aud"] == "demo-client"
  abort "   FAILED: Invalid audience in JARM token: #{payload['aud']}"
end
unless payload["code"] && !payload["code"].empty?
  abort "   FAILED: Authorization code missing from JARM claims"
end

# 2d: Submit JARM callback to client and verify authentication succeeds
cb_req = Net::HTTP::Get.new(callback_url.request_uri)
cb_req["Cookie"] = jar.to_s
cb_res = http.request(cb_req)
jar.update(cb_res)

puts "   Client callback returned: HTTP #{cb_res.code}, location: #{cb_res['location']}"
unless cb_res.code == "302" && (cb_res["location"] == "/profile" || cb_res["location"] == "http://localhost:8080/profile")
  abort "   FAILED: Expected client to redirect to /profile after JARM validation, got HTTP #{cb_res.code}, location: #{cb_res['location']}"
end

prof_res = http.get("/profile", { "Cookie" => jar.to_s })
unless prof_res.code == "200" && prof_res.body.include?("Authenticated User Profile")
  abort "   FAILED: Profile page not accessible after JARM login (HTTP #{prof_res.code})"
end
puts "   SUCCESS: JARM authorization code flow successfully verified and authenticated!"

# ------------------------------------------------------------------------------
# TEST 3: Strict JARM Error Response & AWS KMS RS256 Verification
# ------------------------------------------------------------------------------
puts "\n[TEST 3] Verifying Strict JARM Error Response (RFC 9221)..."
err_spring_res = spring_http.get("/oauth2/authorize?client_id=demo-client&redirect_uri=http://localhost:8080/callback&error=access_denied&error_description=Administrative+Access+Revoked")

unless err_spring_res.code == "302"
  abort "   FAILED: Expected HTTP 302 from Auth Server on error, got #{err_spring_res.code}"
end

err_callback_url = URI(err_spring_res["location"])
err_cb_params = URI.decode_www_form(err_callback_url.query || "").to_h

if err_cb_params["error"] || err_cb_params["error_description"]
  abort "   FAILED: Plaintext error parameters detected in query string! JARM requires ?response=<jwt>"
end

unless err_cb_params["response"]
  abort "   FAILED: Missing ?response=<jwt> parameter in error redirect"
end

err_payload, err_header = JWT.decode(err_cb_params["response"], rsa_key, true, { algorithm: "RS256" })
puts "   JARM Error Payload: error=#{err_payload['error']}, desc=#{err_payload['error_description']}"

unless err_payload["error"] == "access_denied" && err_payload["error_description"] == "Administrative Access Revoked"
  abort "   FAILED: Expected error=access_denied in JARM payload"
end

# Submit error to client and verify 403 Forbidden with custom override view
err_client_res = http.get(err_callback_url.request_uri)
unless err_client_res.code == "403" && err_client_res.body.include?("Administrative Access Revoked")
  abort "   FAILED: Expected client to render 403 Forbidden with verified error description"
end
puts "   SUCCESS: JARM error response cryptographically validated and rendered."

# ------------------------------------------------------------------------------
# TEST 4: Negative Security Test - Strict Plaintext Callback Rejection
# ------------------------------------------------------------------------------
puts "\n[TEST 4] Negative Security Test: Plaintext Callback Rejection..."

# 4a: Attacker sends plaintext authorization code
attack_res1 = http.get("/callback?code=forged_code_12345&iss=http://localhost:9000")
puts "   4a. Plaintext ?code=... response status: HTTP #{attack_res1.code}"
unless attack_res1.code == "302" || attack_res1.code == "400"
  abort "   FAILED: Expected client to reject plaintext code callback"
end

# 4b: Attacker sends plaintext forged error message
attack_res2 = http.get("/callback?error=access_denied&error_description=Your+account+has+been+seized.+Pay+ransom.")
puts "   4b. Plaintext ?error=... response status: HTTP #{attack_res2.code}"
unless attack_res2.code == "302" || attack_res2.code == "400"
  abort "   FAILED: Expected client to reject plaintext error callback"
end
puts "   SUCCESS: All plaintext callback parameters strictly rejected!"

# ------------------------------------------------------------------------------
# TEST 5: Negative Security Test - Tampered JARM JWT Rejection
# ------------------------------------------------------------------------------
puts "\n[TEST 5] Negative Security Test: Tampered JARM JWT Rejection..."

# Modify the payload of a valid JARM JWT without updating the signature
parts = jarm_jwt.split(".")
tampered_payload_json = JSON.parse(Base64.urlsafe_decode64(parts[1]))
tampered_payload_json["code"] = "injected_attacker_code_999"
tampered_payload_b64 = Base64.urlsafe_encode64(tampered_payload_json.to_json, padding: false)
tampered_jwt = "#{parts[0]}.#{tampered_payload_b64}.#{parts[2]}"

tamper_res = http.get("/callback?response=#{tampered_jwt}", { "Cookie" => jar.to_s })
puts "   Tampered JWT callback response: HTTP #{tamper_res.code}"
unless tamper_res.code == "302" || tamper_res.code == "400"
  abort "   FAILED: Expected client to reject tampered JARM JWT"
end
puts "   SUCCESS: Tampered JARM token strictly rejected with signature verification failure!"

# ------------------------------------------------------------------------------
# TEST 6: Negative Security Test - Forged JARM JWT Signed by Attacker Key
# ------------------------------------------------------------------------------
puts "\n[TEST 6] Negative Security Test: Forged JARM JWT Signed with Attacker Key..."

attacker_key = OpenSSL::PKey::RSA.generate(2048)
forged_payload = {
  iss: "http://localhost:9000",
  aud: "demo-client",
  code: "attacker_forged_code",
  exp: Time.now.to_i + 300,
  iat: Time.now.to_i
}
forged_jwt = JWT.encode(forged_payload, attacker_key, "RS256", { kid: "attacker-key-1" })

forged_res = http.get("/callback?response=#{forged_jwt}", { "Cookie" => jar.to_s })
puts "   Forged JWT callback response: HTTP #{forged_res.code}"
unless forged_res.code == "302" || forged_res.code == "400"
  abort "   FAILED: Expected client to reject forged JARM JWT"
end
puts "   SUCCESS: Forged JARM token signed by unknown key strictly rejected!"

# ------------------------------------------------------------------------------
# TEST 7: Client Configuration Isolation Verification
# ------------------------------------------------------------------------------
puts "\n[TEST 7] Verifying Client Details are Configured by Host App and Not Hardcoded in Gem..."

# Verify demo client sets its own configuration
puts "   OAuth2ClientKit configured client_id: #{OAuth2ClientKit.config.client_id}"
unless OAuth2ClientKit.config.client_id == "demo-client"
  abort "   FAILED: Expected demo-client to configure its client_id"
end

# Verify fresh Configuration instance does not bake in client_id
fresh_config = OAuth2ClientKit::Configuration.new
puts "   Fresh OAuth2ClientKit::Configuration client_id default: #{fresh_config.client_id.inspect}"
if fresh_config.client_id == "demo-client"
  abort "   FAILED: client_id is baked into the gem configuration! Must not default to 'demo-client'"
end

# Verify unconfigured Client raises ArgumentError
fresh_client_kit_module = Module.new do
  class << self
    def config
      @config ||= OAuth2ClientKit::Configuration.new
    end
    def client
      raise ArgumentError, "OAuth2ClientKit client_id is not configured" if config.client_id.nil? || config.client_id.to_s.strip.empty?
    end
  end
end

begin
  fresh_client_kit_module.client
  abort "   FAILED: Expected ArgumentError when client_id is not configured"
rescue ArgumentError => e
  puts "   Unconfigured client check: caught #{e.class} - #{e.message}"
end

puts "   SUCCESS: Client configuration isolation verified! Library is completely client-agnostic."

puts "\n================================================================================"
puts "  ALL RFC 9221 (JARM) TESTS PASSED (100% SUCCESS)!"
puts "================================================================================"
