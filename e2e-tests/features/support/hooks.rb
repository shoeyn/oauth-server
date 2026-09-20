# frozen_string_literal: true

require 'net/http'
require 'json'
require 'securerandom'
require 'digest'

require 'fileutils'
require 'time'

SPRING_ADMIN_URL = 'http://localhost:9001/api/admin/users'
ADMIN_API_KEY = 'secret-admin-key'

Before do
  @test_email = "test_user_#{SecureRandom.hex(4)}@example.com"
  @test_password = 'password123'

  uri = URI(SPRING_ADMIN_URL)
  req = Net::HTTP::Post.new(uri)
  req['Content-Type'] = 'application/json'
  req['X-Admin-Api-Key'] = ADMIN_API_KEY
  # Two-stage password pipeline: the admin API stores BCrypt(<incoming>), and the Rails IdP sends
  # SHA-256(plaintext) at login. Seed with the SHA-256 digest so the seeded user can actually log in.
  req.body = { email: @test_email, password: Digest::SHA256.hexdigest(@test_password) }.to_json

  res = Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
  raise "Failed to seed test user: #{res.code} #{res.body}" unless res.is_a?(Net::HTTPSuccess)
end

After do
  if @test_email
    uri = URI("#{SPRING_ADMIN_URL}/#{@test_email}")
    req = Net::HTTP::Delete.new(uri)
    req['X-Admin-Api-Key'] = ADMIN_API_KEY

    res = Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
    unless res.is_a?(Net::HTTPSuccess) || res.code == '404'
      puts "Warning: Failed to delete test user #{@test_email}: #{res.code} #{res.body}"
    end
  end
end

# rubocop:disable-next Metrics/BlockLength
at_exit do
  if ENV['ZAP_PROXY'] == 'true'
    zap_host = ENV.fetch('ZAP_HOST', '127.0.0.1')
    zap_port = ENV.fetch('ZAP_PORT', '8090')
    reports_dir = File.expand_path('../../../security-reports', __dir__)
    FileUtils.mkdir_p(reports_dir)

    puts "\n======================================================="
    puts '🛡️  OWASP ZAP Security Analysis (Proxy-Driven E2E Run)'
    puts '======================================================='

    begin
      alerts_uri = URI("http://#{zap_host}:#{zap_port}/JSON/alert/view/alerts/")
      alerts_res = Net::HTTP.get_response(alerts_uri)

      if alerts_res.is_a?(Net::HTTPSuccess)
        alerts_data = JSON.parse(alerts_res.body)
        raw_alerts = alerts_data.fetch('alerts', [])

        app_hosts = %w[localhost 127.0.0.1 host.docker.internal].freeze
        alerts = raw_alerts.select do |a|
          uri = begin
            URI.parse(a['url'])
          rescue StandardError
            nil
          end
          uri && app_hosts.include?(uri.host)
        end

        high = alerts.select { |a| a['risk'] == 'High' }
        medium = alerts.select { |a| a['risk'] == 'Medium' }
        low = alerts.select { |a| a['risk'] == 'Low' }
        info = alerts.select { |a| a['risk'] == 'Informational' }

        puts 'Detected Security Alerts Across Endpoints:'
        puts "  🔴 High:          #{high.count}"
        puts "  🟠 Medium:        #{medium.count}"
        puts "  🟡 Low:           #{low.count}"
        puts "  ℹ️  Informational: #{info.count}"

        summary_file = File.join(reports_dir, 'zap-summary.md')
        File.open(summary_file, 'w') do |f|
          f.puts '# OWASP ZAP Security Scan Summary'
          f.puts ''
          f.puts "Generated at: #{Time.now.utc.iso8601}"
          f.puts ''
          f.puts '| Risk Level | Alert Count |'
          f.puts '| :--- | :--- |'
          f.puts "| 🔴 High | #{high.count} |"
          f.puts "| 🟠 Medium | #{medium.count} |"
          f.puts "| 🟡 Low | #{low.count} |"
          f.puts "| ℹ️ Informational | #{info.count} |"
          f.puts ''
          f.puts '## Detected Alerts'
          f.puts ''
          alerts.each_with_index do |a, idx|
            risk = a['risk'].to_s.upcase
            name = a['name'].to_s.encode('UTF-8', invalid: :replace, undef: :replace)
            desc = a['description'].to_s.encode('UTF-8', invalid: :replace, undef: :replace)
            sol = a['solution'].to_s.encode('UTF-8', invalid: :replace, undef: :replace)
            f.puts "### #{idx + 1}. [#{risk}] #{name}"
            f.puts "- **URL**: `#{a['url']}` (#{a['method']})"
            f.puts "- **CWE / WASC**: CWE-#{a['cweid']} / WASC-#{a['wascid']}"
            f.puts "- **Description**: #{desc}"
            f.puts "- **Solution**: #{sol}"
            f.puts ''
          end
        end

        html_uri = URI("http://#{zap_host}:#{zap_port}/OTHER/core/other/htmlreport/")
        html_res = Net::HTTP.get_response(html_uri)
        if html_res.is_a?(Net::HTTPSuccess)
          html_file = File.join(reports_dir, 'zap-report.html')
          File.binwrite(html_file, html_res.body)
          puts "\n📄 Full Reports Saved:"
          puts "  - HTML: #{html_file}"
          puts "  - Markdown: #{summary_file}"
        end

        if ENV['FAIL_ON_ZAP_ALERTS'] == 'true' && (high.any? || medium.any?)
          puts "\n❌ FAIL_ON_ZAP_ALERTS is enabled and #{high.count + medium.count} High/Medium alerts were found!"
          exit 1
        end
      else
        puts "⚠️  Failed to query ZAP API: #{alerts_res.code} #{alerts_res.body}"
      end
    rescue StandardError => e
      puts "⚠️  Error communicating with OWASP ZAP: #{e.message}"
    end
    puts "=======================================================\n"
  end
end
