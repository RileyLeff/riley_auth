-- Add compound index on refresh_tokens(user_id, client_id)
-- Optimizes token lookups during refresh and logout-all-for-client operations.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_client
    ON refresh_tokens(user_id, client_id);
