-- ==============================================================================
-- Flyway Migration V3: Seed Default Demo Client & Public Key
-- ==============================================================================
-- Guarantees that on a completely fresh environment / new PC bootup,
-- 'demo-client' is immediately seeded into PostgreSQL with:
-- 1. Strict RFC 9126 PAR enforcement (settings.client.require-pushed-authorization-requests = true)
-- 2. Asymmetric private_key_jwt authentication (RFC 7523)
-- 3. Pre-populated RSA-2048 public key in oauth2_client_public_key
-- ==============================================================================

INSERT INTO oauth2_registered_client (
    id,
    client_id,
    client_id_issued_at,
    client_secret,
    client_secret_expires_at,
    client_name,
    client_authentication_methods,
    authorization_grant_types,
    redirect_uris,
    post_logout_redirect_uris,
    scopes,
    client_settings,
    token_settings
) VALUES (
    'demo-client',
    'demo-client',
    CURRENT_TIMESTAMP,
    NULL,
    NULL,
    'Demo Client',
    'private_key_jwt',
    'authorization_code,refresh_token,client_credentials',
    'http://127.0.0.1:8080/callback,http://localhost:8080/callback,http://demo-client:8080/callback',
    'http://127.0.0.1:8080/,http://localhost:8080/,http://demo-client:8080/',
    'openid,profile,email,user.read,demo.secret_access',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":false,"settings.client.require-pushed-authorization-requests":true}',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.access-token-time-to-live":["java.time.Duration",900.000000000],"settings.token.reuse-refresh-tokens":false,"settings.token.refresh-token-time-to-live":["java.time.Duration",2592000.000000000],"settings.token.id-token-signature-algorithm":{"@class":"org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","name":"RS256"}}'
) ON CONFLICT (id) DO UPDATE SET
    client_settings = EXCLUDED.client_settings,
    redirect_uris = EXCLUDED.redirect_uris,
    scopes = EXCLUDED.scopes;

INSERT INTO oauth2_client_public_key (
    client_id,
    public_key_pem,
    created_at,
    updated_at
) VALUES (
    'demo-client',
    '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6D1AnI1dNJI8HgPYy97T
+/20bMtT0/CfzbojjGz2YNItlGHunZ7nBHEVY+OWicTx743TfsH9iJFT6lu49suU
8fJJjrqqZeghlvwlLqYV95+TyduLdPzzkjATR63nqqCHGN6deu4Dhr8+H7GxD+Nf
jyx2kUrGrvYypAwrbX9fYK5z/wWOFtrPwuBN+s+nx0PJqhcBbWLl2FOipxjoYCPQ
Gjgl/SxGMxx0I5FL/fh8xGINCBWYweC6i57EIKac5HImzRwKyB3v/mUWGl3j7/3n
LW6TzrIbRxEfYBK0MZODWvQKj5t4ifiw52tOcO7CSZo4W/rqGXOVoQ97yb2WWCQE
1QIDAQAB
-----END PUBLIC KEY-----',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
) ON CONFLICT (client_id) DO UPDATE SET
    public_key_pem = EXCLUDED.public_key_pem,
    updated_at = CURRENT_TIMESTAMP;
