# config/puma.rb
# Production Performance & Concurrency Configuration
#
# ARCHITECTURAL NOTE (Production Deployment):
# Under production circumstances, ensure Puma is run as specified below (clustered workers + tuned threads)
# rather than development single-mode (5 threads), to prevent worker thread saturation during peak concurrent
# OAuth 2.1 authorization session bursts.

max_threads_count = Integer(ENV.fetch("RAILS_MAX_THREADS", 16))
min_threads_count = Integer(ENV.fetch("RAILS_MIN_THREADS", 8))
threads min_threads_count, max_threads_count

port ENV.fetch("PORT", 8080)
environment ENV.fetch("RAILS_ENV", "development")

# In production mode or when WEB_CONCURRENCY is set, run clustered worker processes
workers_count = Integer(ENV.fetch("WEB_CONCURRENCY", 0))
if ENV["RAILS_ENV"] == "production" && workers_count == 0
  workers_count = 2
end

if workers_count > 0
  workers workers_count
  preload_app!
end
