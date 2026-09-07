#!/usr/bin/env ruby
# ==============================================================================
# Functional Test: Dynamic Client Registration & Real-Time Near-Cache Reload
# ==============================================================================
# Verifies:
# 1. Next.js Client Manager REST API connectivity (/api/clients) to Spring Admin API.
# 2. Dynamic creation of a new client via Next.js API into PostgreSQL.
# 3. Real-time near-cache invalidation by Spring Auth Server via Redis Pub/Sub.
# 4. Successful OAuth 2.1 authentication (private_key_jwt + DPoP + PKCE) for new client.
# 5. Dynamic deletion of the client from PostgreSQL and immediate HTTP 401 revocation in Spring.
# ==============================================================================

require "net/http"
require "uri"
require "json"
require "openssl"
require "jwt"
require "base64"
require "redis"
require "securerandom"

puts "================================================================================"
puts "  DYNAMIC CLIENT REGISTRATION & NEAR-CACHE HOT-RELOAD FUNCTIONAL TEST"
puts "================================================================================"

TEST_CLIENT_ID = "dynamic-functional-test-client"
NEXTJS_URL = "http://localhost:3001"
SPRING_URL = "http://localhost:9000"

nextjs_http = Net::HTTP.new("localhost", 3001)
spring_http = Net::HTTP.new("localhost", 9000)

# Helper for base64url encoding without padding
def base64url_encode(str)
  Base64.urlsafe_encode64(str, padding: false)
end

# ------------------------------------------------------------------------------
# STEP 1: Verify Next.js API & Spring Admin API Connectivity
# ------------------------------------------------------------------------------
puts "\n1. Checking Next.js Client Manager & Spring Admin API connection..."
res = nextjs_http.get("/api/clients")
if res.code.to_i != 200
  puts "   FAILED: Next.js API returned HTTP #{res.code} (#{res.body})"
  exit 1
end

existing_clients = JSON.parse(res.body)
client_ids = existing_clients.map { |c| c["clientId"] }
puts "   SUCCESS: Retrieved #{existing_clients.size} client(s) via Next.js API: #{client_ids.join(', ')}"

# ------------------------------------------------------------------------------
# STEP 2: Generate Ephemeral 2048-bit RSA Key Pair
# ------------------------------------------------------------------------------
puts "\n2. Generating ephemeral 2048-bit RSA key pair for '#{TEST_CLIENT_ID}'..."
rsa_key = OpenSSL::PKey::RSA.generate(2048)
public_key_pem = rsa_key.public_key.to_pem
puts "   RSA key pair generated successfully."

# ------------------------------------------------------------------------------
# STEP 3: Register Dynamic Client via Next.js API
# ------------------------------------------------------------------------------
puts "\n3. Registering new client via Next.js POST /api/clients..."
new_client_payload = {
  clientId: TEST_CLIENT_ID,
  clientName: "Dynamic Functional Test Client",
  clientAuthenticationMethods: ["private_key_jwt"],
  authorizationGrantTypes: ["authorization_code", "refresh_token", "client_credentials"],
  redirectUris: ["http://127.0.0.1:8080/callback", "http://localhost:8080/callback"],
  postLogoutRedirectUris: ["http://127.0.0.1:8080/"],
  scopes: ["openid", "profile", "email", "demo.secret_access"],
  requireProofKey: true,
  requireAuthorizationConsent: false,
  accessTokenTimeToLiveMinutes: 15,
  refreshTokenTimeToLiveDays: 30,
  publicKeyPem: public_key_pem
}

post_req = Net::HTTP::Post.new("/api/clients")
post_req["Content-Type"] = "application/json"
post_req.body = JSON.generate(new_client_payload)
post_res = nextjs_http.request(post_req)

if post_res.code.to_i != 201
  puts "   FAILED: Failed to create client via Next.js API: HTTP #{post_res.code} (#{post_res.body})"
  exit 1
end
puts "   SUCCESS: Client '#{TEST_CLIENT_ID}' persisted to PostgreSQL and Redis reload signal dispatched."

# Give Redis subscriber up to 250ms to update the in-memory cache
sleep 0.25

# ------------------------------------------------------------------------------
# STEP 4: Authenticate with New Client using private_key_jwt + DPoP + PKCE
# ------------------------------------------------------------------------------
puts "\n4. Testing OAuth 2.1 code exchange authentication for newly registered client..."

# A. Generate PKCE code_verifier and code_challenge
code_verifier = Base64.urlsafe_encode64(OpenSSL::Random.random_bytes(32), padding: false)
code_challenge = Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(code_verifier), padding: false)

# B. Generate ephemeral EC key for DPoP proof
dpop_key = OpenSSL::PKey::EC.generate("prime256v1")
jwk = {
  kty: "EC",
  crv: "P-256",
  x: base64url_encode(dpop_key.public_key.to_bn.to_s(2)[1..32]),
  y: base64url_encode(dpop_key.public_key.to_bn.to_s(2)[33..64])
}

# DPoP proof for PAR endpoint
par_dpop_header = { typ: "dpop+jwt", alg: "ES256", jwk: jwk }
par_dpop_payload = {
  jti: SecureRandom.uuid,
  htm: "POST",
  htu: "#{SPRING_URL}/oauth2/par",
  iat: Time.now.to_i
}
par_dpop_jwt = JWT.encode(par_dpop_payload, dpop_key, "ES256", par_dpop_header)

# Client Assertion for PAR endpoint signed with newly created RSA private key
par_assertion_payload = {
  iss: TEST_CLIENT_ID,
  sub: TEST_CLIENT_ID,
  aud: "#{SPRING_URL}/oauth2/par",
  jti: SecureRandom.uuid,
  exp: Time.now.to_i + 300,
  iat: Time.now.to_i
}
par_client_assertion = JWT.encode(par_assertion_payload, rsa_key, "RS256")

# Dispatch PAR request
par_req = Net::HTTP::Post.new("/oauth2/par")
par_req["DPoP"] = par_dpop_jwt
par_req.set_form_data(
  "response_type" => "code",
  "client_id" => TEST_CLIENT_ID,
  "redirect_uri" => "http://127.0.0.1:8080/callback",
  "code_challenge" => code_challenge,
  "code_challenge_method" => "S256",
  "state" => SecureRandom.hex(16),
  "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion" => par_client_assertion
)
par_res = spring_http.request(par_req)

if par_res.code.to_i != 201
  puts "   FAILED: PAR request failed for new client: HTTP #{par_res.code} (#{par_res.body})"
  exit 1
end

par_data = JSON.parse(par_res.body)
request_uri = par_data["request_uri"]
puts "   SUCCESS: PAR request accepted (request_uri: #{request_uri[0..25]}...)"

# Authenticate via Rails IdP to get a valid SHARED_SESSION_ID
rails_http = Net::HTTP.new("localhost", 3000)
login_page = rails_http.get("/login")
rails_csrf = login_page.body[/name="authenticity_token" value="([^"]+)"/, 1]
rails_jar_cookie = login_page.get_fields("set-cookie")&.first&.split(";")&.first

login_req = Net::HTTP::Post.new("/login")
login_req["Cookie"] = rails_jar_cookie if rails_jar_cookie
login_req.set_form_data(
  "username" => "alice_smith",
  "password" => "secret123",
  "return_to" => "#{SPRING_URL}/oauth2/authorize?client_id=#{TEST_CLIENT_ID}&request_uri=#{request_uri}",
  "authenticity_token" => rails_csrf
)
login_res = rails_http.request(login_req)
shared_session_cookie = login_res.get_fields("set-cookie").grep(/SHARED_SESSION_ID/).first.split(";").first

# Exchange request_uri for auth code
auth_req = Net::HTTP::Get.new("/oauth2/authorize?client_id=#{TEST_CLIENT_ID}&request_uri=#{request_uri}")
auth_req["Cookie"] = shared_session_cookie
auth_res = spring_http.request(auth_req)
callback_location = URI(auth_res["location"])
auth_code = URI.decode_www_form(callback_location.query).to_h["code"]
puts "   SUCCESS: Obtained authorization code: #{auth_code[0..20]}..."

# DPoP proof for Token endpoint
token_dpop_header = { typ: "dpop+jwt", alg: "ES256", jwk: jwk }
token_dpop_payload = {
  jti: SecureRandom.uuid,
  htm: "POST",
  htu: "#{SPRING_URL}/oauth2/token",
  iat: Time.now.to_i
}
token_dpop_jwt = JWT.encode(token_dpop_payload, dpop_key, "ES256", token_dpop_header)

# Client Assertion for Token endpoint
token_assertion_payload = {
  iss: TEST_CLIENT_ID,
  sub: TEST_CLIENT_ID,
  aud: "#{SPRING_URL}/oauth2/token",
  jti: SecureRandom.uuid,
  exp: Time.now.to_i + 300,
  iat: Time.now.to_i
}
token_client_assertion = JWT.encode(token_assertion_payload, rsa_key, "RS256")

token_req = Net::HTTP::Post.new("/oauth2/token")
token_req["DPoP"] = token_dpop_jwt
token_req.set_form_data(
  "grant_type" => "authorization_code",
  "code" => auth_code,
  "redirect_uri" => "http://127.0.0.1:8080/callback",
  "client_id" => TEST_CLIENT_ID,
  "code_verifier" => code_verifier,
  "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion" => token_client_assertion
)
token_res = spring_http.request(token_req)

if token_res.code.to_i != 200
  puts "   FAILED: Token exchange failed: HTTP #{token_res.code} (#{token_res.body})"
  exit 1
end

token_body = JSON.parse(token_res.body)
puts "   SUCCESS: Token issued to '#{TEST_CLIENT_ID}'!"
puts "   Token Type: #{token_body['token_type']} (DPoP sender-constrained)"
puts "   Assigned Scopes: #{token_body['scope']}"

# ------------------------------------------------------------------------------
# STEP 5: Delete Client via Next.js API and Verify Immediate Dynamic Revocation
# ------------------------------------------------------------------------------
puts "\n5. Deleting client via Next.js DELETE /api/clients/#{TEST_CLIENT_ID}..."
del_req = Net::HTTP::Delete.new("/api/clients/#{TEST_CLIENT_ID}")
del_res = nextjs_http.request(del_req)

if del_res.code.to_i != 200
  puts "   FAILED: Could not delete client: HTTP #{del_res.code} (#{del_res.body})"
  exit 1
end
puts "   SUCCESS: Client deleted from PostgreSQL and Redis reload broadcast."

# Give Redis reload subscriber up to 250ms
sleep 0.25

# Try authenticating again with deleted client assertion
puts "\n6. Verifying Spring immediately rejects deleted client (expecting HTTP 401)..."
unauthorized_assertion = JWT.encode(token_assertion_payload, rsa_key, "RS256")
rej_req = Net::HTTP::Post.new("/oauth2/par")
rej_req["DPoP"] = par_dpop_jwt
rej_req.set_form_data(
  "response_type" => "code",
  "client_id" => TEST_CLIENT_ID,
  "redirect_uri" => "http://127.0.0.1:8080/callback",
  "code_challenge" => code_challenge,
  "code_challenge_method" => "S256",
  "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion" => unauthorized_assertion
)
rej_res = spring_http.request(rej_req)

if rej_res.code.to_i == 401
  puts "   SUCCESS: Spring Auth Server returned HTTP 401 Unauthorized (invalid_client)."
  puts "   Dynamic unregistration confirmed without server restart!"
else
  puts "   FAILED: Expected HTTP 401, but got HTTP #{rej_res.code}: #{rej_res.body}"
  exit 1
end

puts "\n================================================================================"
puts "  DYNAMIC CLIENT & REDIS RELOAD TEST PASSED SUCCESSFULLY!"
puts "================================================================================"
exit 0
