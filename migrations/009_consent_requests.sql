-- Phase 8: Consent UI Support
-- Stores pending consent requests so the authorize flow can redirect to an
-- external consent UI and resume after the user approves/denies.

CREATE TABLE consent_requests (
    -- Uses gen_random_uuid() (UUIDv4) instead of uuidv7() so that consent_id
    -- values are cryptographically random and not predictable from timestamps.
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id   uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes      text[] NOT NULL DEFAULT '{}',
    redirect_uri text NOT NULL,
    state       text,
    code_challenge text,
    code_challenge_method text,
    nonce       text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);

CREATE INDEX idx_consent_requests_expires_at ON consent_requests(expires_at);
