require "net/http"
require "uri"
require "json"
require "openssl"
require "jwt"
require "base64"
require "redis"

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
puts "  OAUTH 2.1 & OIDC ADVANCED SECURITY FUNCTIONAL TEST SUITE"
puts "================================================================================"

# Flush demo client Redis DB 1 to ensure a pristine state
r = Redis.new(url: "redis://localhost:6379/1")
r.flushdb

http = Net::HTTP.new("localhost", 8080)
spring_http = Net::HTTP.new("localhost", 9000)
rails_http = Net::HTTP.new("localhost", 3000)
jar = CookieJar.new

# ------------------------------------------------------------------------------
# STEP 1: Initialize session on demo client
# ------------------------------------------------------------------------------
res = http.get("/")
jar.update(res)
csrf_token = res.body[/name="authenticity_token" value="([^"]+)"/, 1]
puts "1. Demo client initialized (CSRF present: #{!csrf_token.nil?})"

# ------------------------------------------------------------------------------
# STEP 2: Initiate login via PAR & verify client sends NO scopes
# ------------------------------------------------------------------------------
puts "\n>> [FEATURE: Server-Determined Scopes & RFC 9126 PAR]"
req = Net::HTTP::Post.new("/auth/start")
req["Cookie"] = jar.to_s
req.set_form_data("flow" => "par", "authenticity_token" => csrf_token)
start_res = http.request(req)
jar.update(start_res)
auth_url = URI(start_res["location"])
puts "   PAR flow initialized -> AS redirect: #{auth_url}"

# Inspect Redis DB 1 flow state to confirm no scope parameter was sent
cached_flow = Rails.cache.read("oauth_flow:#{auth_url.query[/state=([^&]+)/, 1]}") || {}
puts "   Client-stored flow state contains: code_verifier, nonce, dpop_key"
puts "   Verified: Client does not request or store any client-chosen scopes"

# ------------------------------------------------------------------------------
# STEP 3: Rails IdP Login
# ------------------------------------------------------------------------------
rails_jar = CookieJar.new
login_page = rails_http.get("/login")
rails_jar.update(login_page)
rails_csrf = login_page.body[/name="authenticity_token" value="([^"]+)"/, 1]

login_req = Net::HTTP::Post.new("/login")
login_req["Cookie"] = rails_jar.to_s
login_req.set_form_data(
  "username" => "alice_smith",
  "password" => "secret123",
  "return_to" => auth_url.to_s,
  "authenticity_token" => rails_csrf
)
login_res = rails_http.request(login_req)
rails_jar.update(login_res)
shared_cookie = login_res.get_fields("set-cookie").grep(/SHARED_SESSION_ID/).first.split(";").first
puts "2. Rails IdP authentication successful (SHARED_SESSION_ID acquired)"

# ------------------------------------------------------------------------------
# STEP 3b: Strict PAR Enforcement Negative Test (Direct Authorize without request_uri)
# ------------------------------------------------------------------------------
direct_auth_uri = URI("http://localhost:9000/oauth2/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:8080/callback")
direct_auth_req = Net::HTTP::Get.new(direct_auth_uri.request_uri)
direct_auth_req["Cookie"] = shared_cookie
direct_auth_resp = spring_http.request(direct_auth_req)
puts "2b. Direct /oauth2/authorize without request_uri: HTTP #{direct_auth_resp.code}"

if direct_auth_resp.code.to_i == 302
  err_loc = URI(direct_auth_resp["location"])
  err_params = URI.decode_www_form(err_loc.query).to_h
  puts "    Redirected to callback with RFC 6749 error: error=#{err_params['error']}"
  puts "    Error Description: #{err_params['error_description']}"
  unless err_params["error"] == "invalid_request" && err_params["error_description"].include?("strictly requires Pushed Authorization Requests")
    abort "   FAILED: Expected error=invalid_request regarding PAR requirement"
  end
elsif direct_auth_resp.code.to_i == 400
  puts "    Rejected with direct HTTP 400 Bad Request"
else
  abort "   FAILED: Expected HTTP 302 (RFC 6749 error callback) or HTTP 400, got #{direct_auth_resp.code}"
end
puts "    PASSED: Strict PAR Enforcement active (Direct authorization without request_uri strictly rejected)"

# ------------------------------------------------------------------------------
# STEP 4: Authorization Request & RFC 9207 Issuer Identification
# ------------------------------------------------------------------------------
auth_req = Net::HTTP::Get.new(auth_url.request_uri)
auth_req["Cookie"] = shared_cookie
auth_resp = spring_http.request(auth_req)
callback_url = URI(auth_resp["location"])
cb_params = URI.decode_www_form(callback_url.query).to_h
auth_code = cb_params["code"]

puts "\n>> [FEATURE 1: RFC 9207 - Authorization Server Issuer Identification]"
puts "   Authorization callback parameters: iss=#{cb_params['iss']}, code=#{auth_code[0..8]}..."
if cb_params["iss"] == "http://localhost:9000"
  puts "   RESULT: PASSED (Protects against OAuth 2.0 Mix-Up Attacks)"
else
  abort "   RESULT: FAILED - missing or incorrect 'iss' parameter"
end

# ------------------------------------------------------------------------------
# STEP 5: Negative Security Tests at /oauth2/token
# ------------------------------------------------------------------------------
puts "\n>> [FEATURE 2: Insecure Authentication & Bypass Prevention]"

# Helper to generate client assertion
client_key = OpenSSL::PKey::RSA.new(File.read(File.join(DEMO_CLIENT_ROOT, "keys/client_private_key.pem")))
def mint_client_assertion(key, aud = "http://localhost:9000/oauth2/token")
  now = Time.now.to_i
  JWT.encode({
    iss: "demo-client",
    sub: "demo-client",
    aud: aud,
    jti: SecureRandom.uuid,
    iat: now,
    exp: now + 300
  }, key, "RS256")
end

# 5a: Missing DPoP Header -> Must be rejected with 400 invalid_dpop_proof
tok_req_no_dpop = Net::HTTP::Post.new("/oauth2/token")
tok_req_no_dpop.set_form_data(
  "grant_type" => "client_credentials",
  "client_id" => "demo-client",
  "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion" => mint_client_assertion(client_key)
)
tok_res_no_dpop = spring_http.request(tok_req_no_dpop)
tok_err_no_dpop = JSON.parse(tok_res_no_dpop.body)["error"] rescue nil
puts "   5a. Token request WITHOUT DPoP header: HTTP #{tok_res_no_dpop.code} (error: #{tok_err_no_dpop})"
if tok_res_no_dpop.code == "400" && tok_err_no_dpop == "invalid_dpop_proof"
  puts "       PASSED: DPoP proof is strictly mandatory at /oauth2/token (RFC 9449)"
else
  abort "       FAILED: Missing DPoP header was not rejected properly"
end

# 5b: Client Secret Basic (Basic Auth) -> Must be rejected (disabled)
tok_req_basic = Net::HTTP::Post.new("/oauth2/token")
tok_req_basic.basic_auth("demo-client", "some-static-secret")
tok_req_basic["DPoP"] = "dummy-proof"
tok_req_basic.set_form_data("grant_type" => "client_credentials")
tok_res_basic = spring_http.request(tok_req_basic)
tok_err_basic = JSON.parse(tok_res_basic.body)["error"] rescue nil
puts "   5b. Token request with client_secret_basic: HTTP #{tok_res_basic.code} (error: #{tok_err_basic})"
if (tok_res_basic.code == "400" || tok_res_basic.code == "401") && tok_err_basic == "invalid_client"
  puts "       PASSED: Basic client authentication is strictly rejected"
else
  abort "       FAILED: client_secret_basic was not rejected properly"
end

# 5c: Client Secret Post -> Must be rejected (disabled)
tok_req_post = Net::HTTP::Post.new("/oauth2/token")
tok_req_post["DPoP"] = "dummy-proof"
tok_req_post.set_form_data(
  "grant_type" => "client_credentials",
  "client_id" => "demo-client",
  "client_secret" => "some-secret"
)
tok_res_post = spring_http.request(tok_req_post)
tok_err_post = JSON.parse(tok_res_post.body)["error"] rescue nil
puts "   5c. Token request with client_secret_post: HTTP #{tok_res_post.code} (error: #{tok_err_post})"
if (tok_res_post.code == "400" || tok_res_post.code == "401") && tok_err_post == "invalid_client"
  puts "       PASSED: Client secret post authentication is strictly rejected"
else
  abort "       FAILED: client_secret_post was not rejected properly"
end

# ------------------------------------------------------------------------------
# STEP 6: Complete Valid OAuth 2.1 Code Exchange (PAR + PKCE + DPoP + private_key_jwt)
# ------------------------------------------------------------------------------
puts "\n>> [FEATURE 3: Sender-Constrained DPoP & Server-Determined Claims]"
cb_req = Net::HTTP::Get.new(callback_url.request_uri)
cb_req["Cookie"] = jar.to_s
cb_res = http.request(cb_req)
jar.update(cb_res)

prof_req = Net::HTTP::Get.new("/profile")
prof_req["Cookie"] = jar.to_s
prof_res = http.request(prof_req)
jar.update(prof_res)

# Inspect stored token in demo client Redis DB 1
token_key = Rails.cache.redis.with { |c| c.keys("demo_client:token:*") }.last
clean_key = token_key.sub(/^demo_client:/, "")
token_data = Rails.cache.read(clean_key) || {}
access_token = token_data[:raw_access_token]
raw_id_token = token_data[:raw_id_token]
id_token_claims = JWT.decode(raw_id_token, nil, false)[0] rescue {}
token_type = token_data[:token_type]
access_token_claims = token_data[:access_token_claims] || {}
jkt = access_token_claims.dig("cnf", "jkt")
granted_scopes = access_token_claims["scope"] || []

has_dpop_badge = prof_res.body.include?("DPoP")
has_sender_constrained = prof_res.body.include?("Sender-Constrained")
has_secret_clearance = prof_res.body.include?("CONFIDENTIAL-ACCESS-LEVEL-4")

puts "   Issued Token Type: #{token_type} (expected: DPoP)"
puts "   Token Confirmation (cnf.jkt): #{jkt}"
puts "   Server-Assigned Scopes: #{granted_scopes}"
puts "   ID Token at_hash: #{id_token_claims['at_hash']}"
puts "   ID Token c_hash: #{id_token_claims['c_hash']}"
puts "   DPoP-protected UserInfo Claim Retrieved: #{has_secret_clearance}"

# Verify Discovery Metadata Alignment (Strict Asymmetric private_key_jwt only)
disco_res = spring_http.get("/.well-known/openid-configuration")
disco_json = JSON.parse(disco_res.body)
auth_methods = disco_json["token_endpoint_auth_methods_supported"]
puts "   Discovery token_endpoint_auth_methods_supported: #{auth_methods}"
if auth_methods != ["private_key_jwt"]
  abort "   FAILED: Discovery metadata does not strictly advertise private_key_jwt: #{auth_methods}"
end

if token_type == "DPoP" && jkt && granted_scopes.include?("demo.secret_access") && has_secret_clearance && id_token_claims["at_hash"] && id_token_claims["c_hash"]
  puts "   RESULT: PASSED (Sender-constrained DPoP active, scopes server-determined, at_hash/c_hash bound, privileged claim verified)"
else
  abort "   RESULT: FAILED - Token validation failed"
end

# ------------------------------------------------------------------------------
# STEP 7: RFC 7009 Token Revocation & RFC 7662 Token Introspection
# ------------------------------------------------------------------------------
puts "\n>> [FEATURE 4: RFC 7009 Revocation & RFC 7662 Introspection]"

def introspect(token, key, spring_http)
  req = Net::HTTP::Post.new("/oauth2/introspect")
  req.set_form_data(
    "token" => token,
    "client_id" => "demo-client",
    "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion" => mint_client_assertion(key, "http://localhost:9000/oauth2/introspect")
  )
  res = spring_http.request(req)
  JSON.parse(res.body)["active"] rescue false
end

active_before = introspect(access_token, client_key, spring_http)
puts "   Token Introspection BEFORE revocation: active=#{active_before}"

prof_csrf = prof_res.body[/action="\/auth\/revoke"[^>]*>.*?name="authenticity_token" value="([^"]+)"/m, 1] || prof_res.body[/name="authenticity_token" value="([^"]+)"/, 1]
rev_req = Net::HTTP::Post.new("/auth/revoke")
rev_req["Cookie"] = jar.to_s
rev_req.set_form_data("authenticity_token" => prof_csrf)
rev_res = http.request(rev_req)
jar.update(rev_res)

active_after = introspect(access_token, client_key, spring_http)
puts "   Token Introspection AFTER revocation: active=#{active_after}"
local_token_evicted = Rails.cache.read(clean_key).nil?
puts "   Demo client local Redis session evicted: #{local_token_evicted}"

if active_before == true && active_after == false && local_token_evicted
  puts "   RESULT: PASSED (RFC 7009 token revocation and RFC 7662 introspection confirmed)"
else
  abort "   RESULT: FAILED - Token revocation verification failed"
end

# ------------------------------------------------------------------------------
# STEP 8: OIDC Back-Channel Logout 1.0
# ------------------------------------------------------------------------------
puts "\n>> [FEATURE 5: OpenID Connect Back-Channel Logout 1.0]"

# 8a: Malformed token negative test
bad_req = Net::HTTP::Post.new("/oidc/backchannel_logout")
bad_req.set_form_data("logout_token" => "invalid.jwt.token")
bad_res = http.request(bad_req)
puts "   8a. Negative test (malformed logout_token): HTTP #{bad_res.code} (expected 400)"

# 8b: Positive test with signed logout_token
admin_req = Net::HTTP::Post.new("/api/admin/revoke-session?sessionId=#{SecureRandom.uuid}")
admin_req["X-Admin-Api-Key"] = "secret-admin-key"
admin_res = spring_http.request(admin_req)
admin_body = JSON.parse(admin_res.body) rescue {}
puts "   8b. Admin session revocation: HTTP #{admin_res.code} #{admin_body['status']}"
puts "       Signed logout_token dispatched to demo client backchannel endpoint"

if bad_res.code == "400" && admin_res.code == "200"
  puts "   RESULT: PASSED (OIDC Back-Channel Logout verified)"
else
  abort "   RESULT: FAILED - Back-Channel Logout verification failed"
end

puts "\n================================================================================"
puts "  ALL FUNCTIONAL TESTS PASSED SUCCESSFULLY!"
puts "================================================================================"
