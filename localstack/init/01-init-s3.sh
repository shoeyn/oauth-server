#!/bin/bash
set -e

echo "==> Initializing LocalStack S3 for OAuth 2.1 Client Config Manager..."

# Create bucket if it doesn't exist
awslocal s3 mb s3://oauth2-clients || true

# Seed demo-client.json
cat << 'JSON' > /tmp/demo-client.json
{
  "clientId": "demo-client",
  "clientName": "Demo OAuth 2.1 Client",
  "clientAuthenticationMethods": ["private_key_jwt"],
  "authorizationGrantTypes": ["authorization_code", "refresh_token", "client_credentials"],
  "redirectUris": [
    "http://127.0.0.1:8080/callback",
    "http://localhost:8080/callback",
    "http://demo-client:8080/callback"
  ],
  "postLogoutRedirectUris": [
    "http://127.0.0.1:8080/",
    "http://localhost:8080/",
    "http://demo-client:8080/"
  ],
  "scopes": [
    "openid",
    "profile",
    "email",
    "user.read",
    "demo.secret_access"
  ],
  "requireProofKey": true,
  "requireAuthorizationConsent": false,
  "accessTokenTimeToLiveMinutes": 15,
  "refreshTokenTimeToLiveDays": 30,
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6D1AnI1dNJI8HgPYy97T\n+/20bMtT0/CfzbojjGz2YNItlGHunZ7nBHEVY+OWicTx743TfsH9iJFT6lu49suU\n8fJJjrqqZeghlvwlLqYV95+TyduLdPzzkjATR63nqqCHGN6deu4Dhr8+H7GxD+Nf\njyx2kUrGrvYypAwrbX9fYK5z/wWOFtrPwuBN+s+nx0PJqhcBbWLl2FOipxjoYCPQ\nGjgl/SxGMxx0I5FL/fh8xGINCBWYweC6i57EIKac5HImzRwKyB3v/mUWGl3j7/3n\nLW6TzrIbRxEfYBK0MZODWvQKj5t4ifiw52tOcO7CSZo4W/rqGXOVoQ97yb2WWCQE\n1QIDAQAB\n-----END PUBLIC KEY-----"
}
JSON

awslocal s3 cp /tmp/demo-client.json s3://oauth2-clients/clients/demo-client.json
echo "==> LocalStack S3 initialized and demo-client.json seeded successfully!"
