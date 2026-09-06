#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PROJECT_ROOT="$( cd "$DIR/../.." >/dev/null 2>&1 && pwd )"

echo "Running OAuth 2.1 & OIDC Advanced Security Functional Test Suite..."
cd "$PROJECT_ROOT/demo-client"
mise exec -- bundle exec ruby "$DIR/test_oauth_security_features.rb"
