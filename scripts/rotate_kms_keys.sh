#!/bin/bash
set -e

echo "================================================================================"
echo "  AWS KMS ZERO-DOWNTIME ASYMMETRIC SIGNING KEY ROTATION TOOL"
echo "================================================================================"

# Use awslocal or aws CLI depending on environment
if command -v awslocal &> /dev/null; then
  AWS_CMD="awslocal"
elif docker exec poc-localstack awslocal version &> /dev/null; then
  AWS_CMD="docker exec poc-localstack awslocal"
else
  AWS_CMD="aws"
fi

ACTIVE_ALIAS="alias/oauth2-signing-key"
PREVIOUS_ALIAS="alias/oauth2-signing-key-previous"

echo ">> 1. Locating current active signing key..."
CURRENT_KEY_ID=$($AWS_CMD kms list-aliases --query "Aliases[?AliasName=='$ACTIVE_ALIAS'].TargetKeyId" --output text 2>/dev/null || true)

if [ -z "$CURRENT_KEY_ID" ] || [ "$CURRENT_KEY_ID" == "None" ]; then
  echo "   ERROR: Active alias '$ACTIVE_ALIAS' not found in KMS. Please initialize keys first."
  exit 1
fi
echo "   Current Active Key ID: $CURRENT_KEY_ID"

echo ""
echo ">> 2. Generating new asymmetric RSA_2048 signing key in AWS KMS..."
NEW_KEY_ID=$($AWS_CMD kms create-key \
  --key-spec RSA_2048 \
  --key-usage SIGN_VERIFY \
  --description "Rotated OAuth 2.1 Server Signing Key ($(date -u +%Y-%m-%dT%H:%M:%SZ))" \
  --query 'KeyMetadata.KeyId' \
  --output text)
echo "   New Key Created: $NEW_KEY_ID"

echo ""
echo ">> 3. Updating previous key alias to preserve in-flight token verification..."
PREV_ALIAS_EXISTS=$($AWS_CMD kms list-aliases --query "Aliases[?AliasName=='$PREVIOUS_ALIAS'].TargetKeyId" --output text 2>/dev/null || true)

if [ -n "$PREV_ALIAS_EXISTS" ] && [ "$PREV_ALIAS_EXISTS" != "None" ]; then
  $AWS_CMD kms update-alias --alias-name "$PREVIOUS_ALIAS" --target-key-id "$CURRENT_KEY_ID"
  echo "   Updated '$PREVIOUS_ALIAS' -> $CURRENT_KEY_ID"
else
  $AWS_CMD kms create-alias --alias-name "$PREVIOUS_ALIAS" --target-key-id "$CURRENT_KEY_ID"
  echo "   Created '$PREVIOUS_ALIAS' -> $CURRENT_KEY_ID"
fi

echo ""
echo ">> 4. Promoting new key to active signing alias..."
$AWS_CMD kms update-alias --alias-name "$ACTIVE_ALIAS" --target-key-id "$NEW_KEY_ID"
echo "   Promoted '$ACTIVE_ALIAS' -> $NEW_KEY_ID"

echo ""
echo "================================================================================"
echo "  KEY ROTATION COMPLETED SUCCESSFULLY!"
echo "================================================================================"
echo "  • Active Signing Key (New):       $NEW_KEY_ID ($ACTIVE_ALIAS)"
echo "  • In-Flight Verification (Old):   $CURRENT_KEY_ID ($PREVIOUS_ALIAS)"
echo ""
echo "  Operational Notes:"
echo "  1. Restart/Reload Spring Authorization Server to refresh JWKS public keys."
echo "  2. /oauth2/jwks will serve BOTH keys in the JWKS array."
echo "  3. Newly minted tokens will be signed with $NEW_KEY_ID."
echo "  4. In-flight tokens signed with $CURRENT_KEY_ID remain valid until TTL expiration."
echo "  5. After the grace period (e.g. 24h), retire old key: $AWS_CMD kms disable-key --key-id $CURRENT_KEY_ID"
echo "================================================================================"
