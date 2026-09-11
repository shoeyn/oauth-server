#!/usr/bin/env ruby
# frozen_string_literal: true

require "net/http"
require "uri"
require "json"
require "erb"

puts "================================================================================"
puts "  FUNCTIONAL TEST: OAuth 2.1 Error Journey Handling & View Overrides"
puts "================================================================================"

class CookieJar
  def initialize
    @cookies = {}
  end

  def update(response)
    fields = response.get_fields("set-cookie")
    return unless fields
    fields.each do |c|
      cookie_part = c.split(";").first
      key, val = cookie_part.split("=", 2)
      @cookies[key.strip] = val ? val.strip : ""
    end
  end

  def to_s
    @cookies.map { |k, v| "#{k}=#{v}" }.join("; ")
  end
end

http = Net::HTTP.new("localhost", 8080)
spring_http = Net::HTTP.new("localhost", 9000)
rails_http = Net::HTTP.new("localhost", 3000)

# ------------------------------------------------------------------------------
# TEST 1: Direct Error Callback with Host App Override (access_denied) via RFC 9221 JARM
# ------------------------------------------------------------------------------
puts "\n[TEST 1] Verifying Host App Custom View Override for 'access_denied' via RFC 9221 JARM"
spring_res1 = spring_http.get("/oauth2/authorize?client_id=demo-client&redirect_uri=http://localhost:8080/callback&error=access_denied&error_description=User+account+is+locked+or+suspended")
unless spring_res1.code == "302"
  abort "   FAILED: Expected HTTP 302 from Spring Auth Server with JARM response, got #{spring_res1.code}"
end
jarm_loc1 = URI(spring_res1["location"])
res1 = http.get(jarm_loc1.request_uri)
puts "   HTTP Status: #{res1.code}"
unless res1.code == "403"
  abort "   FAILED: Expected HTTP 403 Forbidden for access_denied, got #{res1.code}"
end

unless res1.body.include?("Demo Client Custom Error View Override")
  abort "   FAILED: Expected host application custom override banner to be rendered"
end
unless res1.body.include?("access_denied") && res1.body.include?("User account is locked or suspended")
  abort "   FAILED: Error code or description missing from rendered override view"
end
puts "   SUCCESS: Custom view override 'oauth2_client_kit/auth/access_denied' rendered cleanly with 403 Forbidden via JARM."

# ------------------------------------------------------------------------------
# TEST 2: Direct Error Callback with Gem Built-in Fallback Template (account_suspended) via RFC 9221 JARM
# ------------------------------------------------------------------------------
puts "\n[TEST 2] Verifying Built-in Gem Fallback View for 'account_suspended' via RFC 9221 JARM"
spring_res2 = spring_http.get("/oauth2/authorize?client_id=demo-client&redirect_uri=http://localhost:8080/callback&error=account_suspended&error_description=Account+suspended+due+to+inactivity")
unless spring_res2.code == "302"
  abort "   FAILED: Expected HTTP 302 from Spring Auth Server with JARM response, got #{spring_res2.code}"
end
jarm_loc2 = URI(spring_res2["location"])
res2 = http.get(jarm_loc2.request_uri)
puts "   HTTP Status: #{res2.code}"
unless res2.code == "400"
  abort "   FAILED: Expected HTTP 400 Bad Request for account_suspended, got #{res2.code}"
end

unless res2.body.include?("Authentication Failed") && res2.body.include?("We could not complete your sign-in request")
  abort "   FAILED: Expected built-in gem default template to be rendered"
end
unless res2.body.include?("account_suspended") && res2.body.include?("Account suspended due to inactivity")
  abort "   FAILED: Error code or description missing from rendered gem default view"
end
puts "   SUCCESS: Gem default fallback template 'oauth2_client_kit/auth/error' rendered cleanly with 400 Bad Request via JARM."

# ------------------------------------------------------------------------------
# TEST 3: End-to-End IdP Simulated Error Return Flow (locked_user credentials)
# ------------------------------------------------------------------------------
puts "\n[TEST 3] Verifying End-to-End Auth Journey with Simulated IdP Failure"
jar = CookieJar.new

# Step 1: Demo client starts login
home_res = http.get("/")
jar.update(home_res)
csrf_token = home_res.body[/name="authenticity_token" value="([^"]+)"/, 1]

req = Net::HTTP::Post.new("/auth/start")
req["Cookie"] = jar.to_s
req.set_form_data("flow" => "par", "authenticity_token" => csrf_token)
start_res = http.request(req)
jar.update(start_res)

auth_redirect_url = start_res["location"]
puts "   Auth started: redirecting to #{auth_redirect_url}"

# Step 2: User arrives at Rails IdP login screen
rails_jar = CookieJar.new
login_page = rails_http.get("/login?return_to=#{ERB::Util.url_encode(auth_redirect_url)}")
rails_jar.update(login_page)
rails_csrf = login_page.body[/name="authenticity_token" value="([^"]+)"/, 1]

# Step 3: User submits simulated locked user failure at IdP
login_req = Net::HTTP::Post.new("/login")
login_req["Cookie"] = rails_jar.to_s
login_req.set_form_data(
  "username" => "locked_user",
  "password" => "password",
  "return_to" => auth_redirect_url,
  "authenticity_token" => rails_csrf,
  "simulate_error" => "access_denied"
)
login_res = rails_http.request(login_req)
puts "   IdP Login response: HTTP #{login_res.code}"
unless login_res.code == "303" || login_res.code == "302"
  abort "   FAILED: Expected IdP redirect on error simulation, got #{login_res.code}"
end

failure_url = login_res["location"]
puts "   IdP redirected to Auth Server: #{failure_url}"
fail_uri = URI(failure_url)
fail_params = URI.decode_www_form(fail_uri.query).to_h

unless fail_params["error"] == "access_denied"
  abort "   FAILED: Expected error=access_denied in redirect, got #{fail_params['error']}"
end
puts "   Verified failure parameters: error=#{fail_params['error']}, state=#{fail_params['state'] ? 'present' : 'none'}"

# Step 4: Auth Server processes IdP error and issues RFC 9221 KMS-signed JARM redirect
spring_err_res = spring_http.get(fail_uri.request_uri)
puts "   Auth Server JARM redirect response: HTTP #{spring_err_res.code}"
unless spring_err_res.code == "302"
  abort "   FAILED: Expected Auth Server to issue 302 JARM redirect, got #{spring_err_res.code}"
end

client_callback_url = URI(spring_err_res["location"])
cb_params = URI.decode_www_form(client_callback_url.query).to_h
if cb_params["response"].nil? || cb_params["response"].empty?
  abort "   FAILED: Expected RFC 9221 JARM signed 'response' parameter in callback"
end
puts "   Verified RFC 9221 JARM token present in client callback URL"

# Step 5: Browser follows redirect to Client callback
callback_req = Net::HTTP::Get.new(client_callback_url.request_uri)
callback_req["Cookie"] = jar.to_s
callback_res = http.request(callback_req)

puts "   Client callback response: HTTP #{callback_res.code}"
unless callback_res.code == "403"
  abort "   FAILED: Expected client to render 403 Forbidden, got #{callback_res.code}"
end
unless callback_res.body.include?("Demo Client Custom Error View Override")
  abort "   FAILED: Client did not render the overridden access_denied error template"
end

puts "   SUCCESS: End-to-end simulated failure journey completed seamlessly with RFC 9221 JARM!"

# ------------------------------------------------------------------------------
# TEST 4: Negative Security Test - Missing redirect_uri (No Fallback)
# ------------------------------------------------------------------------------
puts "\n[TEST 4] Verifying Error Request Without redirect_uri Strictly Rejects (No Fallback to Client Config)"
res_no_redirect = spring_http.get("/oauth2/authorize?client_id=demo-client&error=access_denied&error_description=Missing+redirect")
puts "   Missing redirect_uri response: HTTP #{res_no_redirect.code}"
unless res_no_redirect.code == "400"
  abort "   FAILED: Expected HTTP 400 Bad Request when redirect_uri is omitted, but got #{res_no_redirect.code} (possible fallback leakage)"
end
puts "   SUCCESS: Server strictly rejected error request with missing redirect_uri (no client fallback)."

# ------------------------------------------------------------------------------
# TEST 5: Negative Security Test - Unregistered / Malicious redirect_uri
# ------------------------------------------------------------------------------
puts "\n[TEST 5] Verifying Error Request With Unregistered redirect_uri Strictly Rejects"
res_bad_redirect = spring_http.get("/oauth2/authorize?client_id=demo-client&redirect_uri=http://attacker.com/callback&error=access_denied&error_description=Open+redirect+attempt")
puts "   Unregistered redirect_uri response: HTTP #{res_bad_redirect.code}"
unless res_bad_redirect.code == "400"
  abort "   FAILED: Expected HTTP 400 Bad Request for unregistered redirect_uri, but got #{res_bad_redirect.code} (open redirect risk)"
end
puts "   SUCCESS: Server strictly validated redirect_uri against client allowed URIs and rejected unauthorized target."

puts "\n================================================================================"
puts "  ALL ERROR JOURNEY TESTS PASSED (100% SUCCESS)!"
puts "================================================================================"
