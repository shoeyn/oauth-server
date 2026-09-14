require 'net/http'
require 'json'
require 'securerandom'
require 'digest'

SPRING_ADMIN_URL = 'http://localhost:9001/api/admin/users'
ADMIN_API_KEY = 'secret-admin-key'

Before do
  @test_email = "test_user_#{SecureRandom.hex(4)}@example.com"
  @test_password = "password123"

  uri = URI(SPRING_ADMIN_URL)
  req = Net::HTTP::Post.new(uri)
  req['Content-Type'] = 'application/json'
  req['X-Admin-Api-Key'] = ADMIN_API_KEY
  # Two-stage password pipeline: the admin API stores BCrypt(<incoming>), and the Rails IdP sends
  # SHA-256(plaintext) at login. Seed with the SHA-256 digest so the seeded user can actually log in.
  req.body = { email: @test_email, password: Digest::SHA256.hexdigest(@test_password) }.to_json

  res = Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
  unless res.is_a?(Net::HTTPSuccess)
    raise "Failed to seed test user: #{res.code} #{res.body}"
  end
end

After do
  if @test_email
    uri = URI("#{SPRING_ADMIN_URL}/#{@test_email}")
    req = Net::HTTP::Delete.new(uri)
    req['X-Admin-Api-Key'] = ADMIN_API_KEY
    
    res = Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
    unless res.is_a?(Net::HTTPSuccess) || res.code == "404"
      puts "Warning: Failed to delete test user #{@test_email}: #{res.code} #{res.body}"
    end
  end
end
