# config/puma.rb
# Production Performance & Concurrency Configuration for Rails IdP
#
# ARCHITECTURAL NOTE (Production Deployment):
# Under production circumstances, ensure Puma is run as specified below (clustered workers + tuned threads)
# and behind an Application Load Balancer / reverse proxy. Furthermore, when scaling beyond a single instance
# or running high thread counts, ensure Redis connections are managed via a connection pool (e.g. using the
# `connection_pool` gem) to eliminate socket contention under heavy concurrent login bursts.

max_threads_count = Integer(ENV.fetch("RAILS_MAX_THREADS", 16))
min_threads_count = Integer(ENV.fetch("RAILS_MIN_THREADS", 8))
threads min_threads_count, max_threads_count

port ENV.fetch("PORT", 3000)
environment ENV.fetch("RAILS_ENV", "development")

workers_count = Integer(ENV.fetch("WEB_CONCURRENCY", 0))
if ENV["RAILS_ENV"] == "production" && workers_count == 0
  workers_count = 2
end

if workers_count > 0
  workers workers_count
  preload_app!
end
