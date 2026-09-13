require 'simplecov'
SimpleCov.start 'rails' do
  add_filter '/config/'
  add_filter '/app/channels/' if Dir.glob('app/channels/**/*.rb').none? { |f| File.read(f) =~ /\S/ }
  add_filter '/app/jobs/' if Dir.glob('app/jobs/**/*.rb').none? { |f| File.read(f) =~ /\S/ }
  add_filter '/app/models/' if Dir.glob('app/models/**/*.rb').none? { |f| File.read(f) =~ /\S/ }
  minimum_coverage 100
end

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end
  config.shared_context_metadata_behavior = :apply_to_host_groups
end
