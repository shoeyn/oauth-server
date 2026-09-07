#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PROJECT_ROOT="$( cd "$DIR/../.." >/dev/null 2>&1 && pwd )"

echo "================================================================================"
echo "  SUITE 1: OAuth 2.1 & OIDC Advanced Security Features"
echo "================================================================================"
cd "$PROJECT_ROOT/demo-client"
mise exec -- bundle exec ruby "$DIR/test_oauth_security_features.rb"

echo ""
echo "================================================================================"
echo "  SUITE 2: Dynamic S3 Client Config & Redis Hot-Reload"
echo "================================================================================"
mise exec -- bundle exec ruby "$DIR/test_s3_dynamic_client_reload.rb"

echo ""
echo "================================================================================"
echo "  SUITE 3: Performance, In-Memory Caching & Resilience"
echo "================================================================================"
mise exec -- bundle exec ruby "$DIR/test_performance_and_resilience.rb"

echo ""
echo "================================================================================"
echo "  SUITE 4: AWS KMS Cryptographic Signing & Security Verification"
echo "================================================================================"
mise exec -- bundle exec ruby "$DIR/test_kms_signing.rb"

echo ""
echo "================================================================================"
echo "  ALL FUNCTIONAL TEST SUITES PASSED SUCCESSFULLY!"
echo "================================================================================"
