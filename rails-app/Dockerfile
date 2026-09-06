FROM ruby:3.3-slim

WORKDIR /app

RUN apt-get update -qq && apt-get install -y build-essential curl && rm -rf /var/lib/apt/lists/*

COPY Gemfile ./
RUN bundle install

COPY . .

ENV RAILS_ENV=production
ENV SECRET_KEY_BASE=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
ENV REDIS_URL=redis://redis:6379

EXPOSE 3000
CMD ["bundle", "exec", "puma", "-b", "tcp://0.0.0.0:3000"]
