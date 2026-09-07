-- Indices to accelerate automated batch pruning of expired OAuth 2.1 authorizations
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_refresh_expiry ON oauth2_authorization (refresh_token_expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_access_expiry ON oauth2_authorization (access_token_expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_code_expiry ON oauth2_authorization (authorization_code_expires_at);
