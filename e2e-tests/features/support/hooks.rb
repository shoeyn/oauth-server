require 'net/http'
require 'json'
require 'securerandom'

SPRING_ADMIN_URL = 'http://localhost:9001/api/admin/users'
ADMIN_API_KEY = 'secret-admin-key'

Before do
  @test_email = "test_user_#{SecureRandom.hex(4)}@example.com"
  @test_password = "password123"
  
  uri = URI(SPRING_ADMIN_URL)
  req = Net::HTTP::Post.new(uri)
  req['Content-Type'] = 'application/json'
  req['X-Admin-Api-Key'] = ADMIN_API_KEY
  req.body = { email: @test_email, password: @test_password }.to_json
  
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
