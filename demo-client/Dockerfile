FROM ruby:4.0-slim

WORKDIR /app

RUN apt-get update -qq && apt-get install -y build-essential libpq-dev git curl && rm -rf /var/lib/apt/lists/*

# Copy gem library first
COPY oauth2_client_kit /oauth2_client_kit

WORKDIR /app
COPY demo-client/Gemfile* ./
RUN bundle install

COPY demo-client .

ENV PORT=8080
ENV RAILS_ENV=production
ENV AUTH_SERVER_URL=http://localhost:9000
ENV AUTH_SERVER_URL_INTERNAL=http://spring-auth-server:9000
ENV CLIENT_PRIVATE_KEY_PATH=/app/keys/client_private_key.pem
ENV SECRET_KEY_BASE=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

EXPOSE 8080

CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
