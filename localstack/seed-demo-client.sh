#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo "==> Seeding demo-client into LocalStack S3..."
if docker ps --format '{{.Names}}' | grep -q "poc-localstack"; then
  docker exec -i poc-localstack bash < "$DIR/init/01-init-s3.sh"
else
  echo "LocalStack container 'poc-localstack' is not running. Starting it via docker compose..."
  docker compose up -d localstack
  echo "Waiting for LocalStack to be ready..."
  until curl -s http://localhost:4566/_localstack/health | grep -q "\"s3\": \"\(running\|available\)"; do
    sleep 1
  done
  docker exec -i poc-localstack bash < "$DIR/init/01-init-s3.sh"
fi
echo "==> Seeding complete!"
