-- v2: scopes on clients and refresh tokens, session metadata on refresh tokens

-- Allowed scopes per OAuth client (empty = no scopes)
ALTER TABLE oauth_clients
    ADD COLUMN allowed_scopes text[] NOT NULL DEFAULT '{}';

-- Granted scopes on refresh tokens (carried forward on rotation)
ALTER TABLE refresh_tokens
    ADD COLUMN scopes text[] NOT NULL DEFAULT '{}';

-- Session metadata for session visibility
ALTER TABLE refresh_tokens
    ADD COLUMN user_agent text,
    ADD COLUMN ip_address text;
