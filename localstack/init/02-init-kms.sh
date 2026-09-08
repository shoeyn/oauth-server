#!/bin/bash
set -e

echo "==> Initializing LocalStack AWS KMS for OAuth 2.1 Server Signing..."

# Check if alias/oauth2-signing-key already exists
EXISTING_ALIAS=$(awslocal kms list-aliases --query "Aliases[?AliasName=='alias/oauth2-signing-key'].TargetKeyId" --output text 2>/dev/null || true)

if [ -n "$EXISTING_ALIAS" ] && [ "$EXISTING_ALIAS" != "None" ]; then
    echo "==> KMS alias/oauth2-signing-key already exists (TargetKeyId: $EXISTING_ALIAS)."
else
    echo "==> Creating asymmetric RSA_2048 signing key in LocalStack KMS..."
    KEY_ID=$(awslocal kms create-key \
        --key-spec RSA_2048 \
        --key-usage SIGN_VERIFY \
        --description "OAuth 2.1 Server Signing Key" \
        --query 'KeyMetadata.KeyId' \
        --output text)

    echo "==> Key created with ID: $KEY_ID"
    awslocal kms create-alias --alias-name "alias/oauth2-signing-key" --target-key-id "$KEY_ID"
    echo "==> Alias alias/oauth2-signing-key created successfully!"
fi

# Check if alias/oauth2-signing-key-previous already exists
PREV_ALIAS=$(awslocal kms list-aliases --query "Aliases[?AliasName=='alias/oauth2-signing-key-previous'].TargetKeyId" --output text 2>/dev/null || true)

if [ -n "$PREV_ALIAS" ] && [ "$PREV_ALIAS" != "None" ]; then
    echo "==> KMS alias/oauth2-signing-key-previous already exists (TargetKeyId: $PREV_ALIAS)."
else
    echo "==> Creating previous asymmetric RSA_2048 signing key in LocalStack KMS..."
    PREV_KEY_ID=$(awslocal kms create-key \
        --key-spec RSA_2048 \
        --key-usage SIGN_VERIFY \
        --description "Previous Rotated OAuth 2.1 Server Signing Key" \
        --query 'KeyMetadata.KeyId' \
        --output text)

    echo "==> Previous key created with ID: $PREV_KEY_ID"
    awslocal kms create-alias --alias-name "alias/oauth2-signing-key-previous" --target-key-id "$PREV_KEY_ID"
    echo "==> Alias alias/oauth2-signing-key-previous created successfully!"
fi

echo "==> LocalStack KMS initialized successfully!"
