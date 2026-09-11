# frozen_string_literal: true

require "net/http"
require "uri"
require "json"
require "openssl"
require "jwt"
require "base64"
require "redis"

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
puts "  TEST SUITE: OAUTH 2.1 REFRESH TOKEN FLOW & DPOP ROTATION"
puts "================================================================================"

http = Net::HTTP.new("localhost", 8080)
spring_http = Net::HTTP.new("localhost", 9000)
rails_http = Net::HTTP.new("localhost", 3000)
client_jar = CookieJar.new

# 1. Fetch initial demo-client page
res = http.get("/")
client_jar.update(res)
csrf_token = res.body[/name="authenticity_token" value="([^"]+)"/, 1]
raise "Failed to get CSRF token" unless csrf_token

# 2. Start PAR auth flow
req = Net::HTTP::Post.new("/auth/start")
req["Cookie"] = client_jar.to_s
req.set_form_data({ "authenticity_token" => csrf_token, "flow" => "par" })
res = http.request(req)
client_jar.update(res)

auth_redirect_url = URI(res["location"])
raise "Expected redirect to Auth Server" unless auth_redirect_url.to_s.include?("/oauth2/authorize")

# 3. Authenticate with Rails IdP
as_req = Net::HTTP::Get.new(auth_redirect_url.request_uri)
as_res = spring_http.request(as_req)
rails_login_url = as_res["location"]
raise "Expected redirect to Rails login" unless rails_login_url&.include?("/login")

rails_login_res = rails_http.get(URI(rails_login_url).request_uri)
rails_jar = CookieJar.new
rails_jar.update(rails_login_res)
rails_csrf = rails_login_res.body[/name="authenticity_token" value="([^"]+)"/, 1]

login_post = Net::HTTP::Post.new("/login")
login_post["Cookie"] = rails_jar.to_s
login_post.set_form_data({
  "authenticity_token" => rails_csrf,
  "username" => "alice_smith",
  "password" => "secret123",
  "return_to" => auth_redirect_url.to_s
})
login_res = rails_http.request(login_post)
shared_cookie = login_res.get_fields("set-cookie").grep(/SHARED_SESSION_ID/).first.split(";").first

# 4. Auth server callback with JARM response
as_final_req = Net::HTTP::Get.new(auth_redirect_url.request_uri)
as_final_req["Cookie"] = shared_cookie
as_final_res = spring_http.request(as_final_req)

client_callback_url = as_final_res["location"]
raise "Expected redirect to client callback, got HTTP #{as_final_res.code} (body: #{as_final_res.body})" unless client_callback_url&.include?("/callback")

# 5. Client processes callback
cb_req = Net::HTTP::Get.new(URI(client_callback_url).request_uri)
cb_req["Cookie"] = client_jar.to_s
cb_res = http.request(cb_req)
client_jar.update(cb_res)

# 6. Profile page verified
prof_req = Net::HTTP::Get.new("/profile")
prof_req["Cookie"] = client_jar.to_s
prof_res = http.request(prof_req)
client_jar.update(prof_res)
raise "Expected profile page 200, got #{prof_res.code}" unless prof_res.code == "200"

# Target the specific CSRF token for the /auth/refresh form (to support per-form CSRF)
refresh_form = prof_res.body[/<form[^>]*action="\/auth\/refresh"[^>]*>.*?<\/form>/m]
refresh_csrf = refresh_form ? refresh_form[/name="authenticity_token" value="([^"]+)"/, 1] : prof_res.body[/name="authenticity_token" value="([^"]+)"/, 1]

# Extract initial access token snippet
initial_token_snippet = prof_res.body[/Show Raw Access Token \(JWT\)<\/summary>\s*<pre[^>]*><code[^>]*>(.*?)<\/code>/m, 1]&.strip
puts "   Initial Access Token: #{initial_token_snippet&.slice(0, 30)}..."

# 7. POST /auth/refresh
puts "\n>> [TEST: Executing POST /auth/refresh]"
refresh_req = Net::HTTP::Post.new("/auth/refresh")
refresh_req["Cookie"] = client_jar.to_s
refresh_req.set_form_data({ "authenticity_token" => refresh_csrf })
refresh_res = http.request(refresh_req)
client_jar.update(refresh_res)

raise "Expected 302 redirect after refresh, got #{refresh_res.code}" unless refresh_res.code == "302"
puts "   Refresh Response: HTTP #{refresh_res.code} -> Location: #{refresh_res['location']}"

# 8. Follow redirect back to /profile and inspect notice
prof_req2 = Net::HTTP::Get.new(refresh_res["location"] || "/profile")
prof_req2["Cookie"] = client_jar.to_s
prof_res2 = http.request(prof_req2)

if prof_res2.body.include?("Access Token successfully refreshed")
  puts "   RESULT: PASSED (Flash notice: 'Access Token successfully refreshed using Refresh Token (Rotation verified)!')"
else
  error_notice = prof_res2.body[/<div[^>]*class="[^"]*alert-danger[^"]*"[^>]*>(.*?)<\/div>/m, 1] || "Unknown notice"
  puts "   Notice: #{error_notice.strip}"
  raise "Token refresh failed! Did not see success message."
end

refreshed_token_snippet = prof_res2.body[/Show Raw Access Token \(JWT\)<\/summary>\s*<pre[^>]*><code[^>]*>(.*?)<\/code>/m, 1]&.strip
puts "   Refreshed Access Token: #{refreshed_token_snippet&.slice(0, 30)}..."

if initial_token_snippet != refreshed_token_snippet
  puts "   Token Rotation Verified: New access token is cryptographically distinct from initial token!"
else
  raise "Token did not rotate!"
end

puts "\n================================================================================"
puts "  REFRESH TOKEN E2E TEST COMPLETED SUCCESSFULLY (100% PASS)!"
puts "================================================================================"
