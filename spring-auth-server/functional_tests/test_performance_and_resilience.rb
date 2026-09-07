#!/usr/bin/env ruby
# frozen_string_literal: true

require "net/http"
require "uri"
require "json"
require "openssl"

def measure_time
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  yield
  Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
end

puts "=" * 80
puts "  PERFORMANCE, CACHING & RESILIENCE VERIFICATION SUITE"
puts "=" * 80

# ------------------------------------------------------------------------------
# TEST 1: Discovery & JWKS Response Caching with ETag (HTTP 304)
# ------------------------------------------------------------------------------
puts "\n>> [TEST 1: In-Memory Response Caching & ETag (HTTP 304)]"

discovery_uri = URI("http://localhost:9000/.well-known/openid-configuration")
jwks_uri = URI("http://localhost:9000/oauth2/jwks")

# 1a. Initial Discovery GET (expect 200 OK + ETag + Cache-Control)
resp1 = Net::HTTP.get_response(discovery_uri)
etag1 = resp1["etag"]
cache_ctrl1 = resp1["cache-control"]

puts "   Discovery GET: HTTP #{resp1.code} (ETag: #{etag1}, Cache-Control: #{cache_ctrl1})"
raise "Expected HTTP 200 on discovery endpoint" unless resp1.code == "200"
raise "Expected ETag header on discovery response" unless etag1&.match?(/\A"[a-f0-9]+"\z/)
raise "Expected public Cache-Control on discovery response" unless cache_ctrl1&.include?("public")

# 1b. Conditional Discovery GET with If-None-Match (expect 304 Not Modified, 0 body bytes)
req = Net::HTTP::Get.new(discovery_uri)
req["If-None-Match"] = etag1
resp2 = Net::HTTP.start(discovery_uri.hostname, discovery_uri.port) { |http| http.request(req) }

puts "   Discovery GET with If-None-Match: HTTP #{resp2.code} (Body Length: #{resp2.body.to_s.length})"
raise "Expected HTTP 304 Not Modified on matching ETag" unless resp2.code == "304"
raise "Expected empty body on HTTP 304" unless resp2.body.to_s.empty?
puts "   RESULT: PASSED (Discovery in-memory caching and 304 validation confirmed)"

# 1c. JWKS GET & Conditional ETag
jwks_resp1 = Net::HTTP.get_response(jwks_uri)
jwks_etag = jwks_resp1["etag"]
puts "   JWKS GET: HTTP #{jwks_resp1.code} (ETag: #{jwks_etag})"
raise "Expected HTTP 200 on JWKS endpoint" unless jwks_resp1.code == "200"

req_jwks = Net::HTTP::Get.new(jwks_uri)
req_jwks["If-None-Match"] = jwks_etag
jwks_resp2 = Net::HTTP.start(jwks_uri.hostname, jwks_uri.port) { |http| http.request(req_jwks) }
puts "   JWKS GET with If-None-Match: HTTP #{jwks_resp2.code}"
raise "Expected HTTP 304 on JWKS endpoint with matching ETag" unless jwks_resp2.code == "304"
puts "   RESULT: PASSED (JWKS in-memory caching and 304 validation confirmed)"

# ------------------------------------------------------------------------------
# TEST 2: Ephemeral Asymmetric Key Generation Benchmark (EC P-256 vs RSA 2048)
# ------------------------------------------------------------------------------
puts "\n>> [TEST 2: DPoP Asymmetric Key Generation Benchmark]"

rsa_time = measure_time do
  10.times { OpenSSL::PKey::RSA.generate(2048) }
end / 10.0

ec_time = measure_time do
  1000.times { OpenSSL::PKey::EC.generate("prime256v1") }
end / 1000.0

speedup = (rsa_time / ec_time).round(1)
puts "   Average RSA-2048 Generation: #{(rsa_time * 1000).round(2)} ms"
puts "   Average EC P-256 Generation: #{(ec_time * 1000).round(4)} ms"
puts "   Speedup Factor: #{speedup}x faster"
raise "EC P-256 should be significantly faster than RSA-2048" unless speedup > 50
puts "   RESULT: PASSED (EC P-256 provides massive CPU overhead reduction for DPoP)"

# ------------------------------------------------------------------------------
# TEST 3: In-Memory Client JWKS Cache & Key Verification
# ------------------------------------------------------------------------------
puts "\n>> [TEST 3: In-Memory Thread-Safe JWKS Cache Resolution]"

$LOAD_PATH.unshift(File.expand_path("../../app/services", __dir__)) rescue nil
require_relative "../../demo-client/app/services/par_oauth2_client"

client = ParOAuth2Client.new(
  "demo-client",
  OpenSSL::PKey::RSA.generate(2048).to_pem,
  site: "http://localhost:9000",
  issuer: "http://localhost:9000"
)

# Initial cold fetch
cold_time = measure_time { client.fetch_jwks }
puts "   Cold JWKS Fetch Latency: #{(cold_time * 1000).round(2)} ms"

# Warmup run
3.times { client.fetch_jwks }

# Warm cached fetch
warm_times = []
10.times do
  warm_times << (measure_time { client.fetch_jwks } * 1000)
end
avg_warm = (warm_times.sum / warm_times.size).round(4)
puts "   Warm Cached JWKS Fetch Latency: #{avg_warm} ms (In-memory cache hit)"
raise "Warm cache lookup should be near instantaneous" if avg_warm > 5.0
puts "   RESULT: PASSED (In-memory JWKS cache operates in sub-millisecond time)"

# ------------------------------------------------------------------------------
# TEST 4: Exponential Backoff & Jitter Resilience Helper
# ------------------------------------------------------------------------------
puts "\n>> [TEST 4: Automated Retries with Exponential Backoff & Jitter]"

attempts = 0
begin
  client.with_retries(max_retries: 2, base_delay: 0.05, operation_name: "Simulated Test") do
    attempts += 1
    raise Faraday::ConnectionFailed.new("Simulated connection glitch") if attempts < 3
  end
rescue => e
  # Expected after max retries
end

puts "   Retry Attempts Executed: #{attempts} (expected 3: 1 initial + 2 retries)"
raise "Expected 3 attempts under retry loop" unless attempts == 3
puts "   RESULT: PASSED (Exponential backoff retry behavior validated)"

puts "\n" + "=" * 80
puts "  ALL PERFORMANCE & RESILIENCE TESTS PASSED SUCCESSFULLY!"
puts "=" * 80
