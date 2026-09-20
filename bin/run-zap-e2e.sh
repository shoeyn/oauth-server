#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Automated OWASP ZAP Proxy-Driven E2E Security Testing Runner
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "======================================================="
echo "🚀 Starting OWASP ZAP Security Test Suite"
echo "======================================================="

cd "${ROOT_DIR}"

# 1. Start ZAP daemon container
echo "📦 Starting OWASP ZAP proxy daemon via Docker Compose..."
docker compose --profile security up -d zap

# 2. Wait for ZAP API to become ready
echo "⏳ Waiting for ZAP API (port 8090) to be ready..."
MAX_RETRIES=40
RETRIES=0
until curl -4 -s http://127.0.0.1:8090/JSON/core/view/version/ > /dev/null 2>&1; do
  RETRIES=$((RETRIES + 1))
  if [ "${RETRIES}" -ge "${MAX_RETRIES}" ]; then
    echo "❌ Timed out waiting for ZAP daemon to respond on port 8090."
    docker compose logs zap
    exit 1
  fi
  sleep 1
done

ZAP_VERSION=$(curl -4 -s http://127.0.0.1:8090/JSON/core/view/version/ | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
echo "✅ OWASP ZAP v${ZAP_VERSION} is ready and listening on http://127.0.0.1:8090"

# 3. Clear previous scan alerts in ZAP before new test run
curl -4 -s -X GET "http://127.0.0.1:8090/JSON/core/action/newSession/?overwrite=true" > /dev/null 2>&1 || true

# 4. Run Cucumber E2E tests routed through ZAP proxy
echo "🧪 Running Cucumber E2E suite through ZAP proxy..."
cd "${ROOT_DIR}/e2e-tests"
export ZAP_PROXY=true
export ZAP_HOST=127.0.0.1
export ZAP_PORT=8090

bundle exec cucumber

echo "======================================================="
echo "🎉 OWASP ZAP E2E Security Run Complete!"
echo "Reports available in: ${ROOT_DIR}/security-reports/"
echo "  - Interactive HTML: ${ROOT_DIR}/security-reports/zap-report.html"
echo "  - Markdown Summary: ${ROOT_DIR}/security-reports/zap-summary.md"
echo "======================================================="
