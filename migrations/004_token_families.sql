-- v3: refresh token family tracking for reuse detection (RFC 6819)

-- Every refresh token belongs to a family. On rotation, the new token
-- inherits the family_id. If a consumed token is re-presented, all tokens
-- in that family are revoked (credential theft signal).
ALTER TABLE refresh_tokens
    ADD COLUMN family_id uuid NOT NULL DEFAULT uuidv7();

CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens(family_id);

-- Track consumed tokens to detect reuse. A consumed token appearing again
-- means both the attacker and legitimate client hold tokens from the same
-- family — revoke the entire family.
CREATE TABLE consumed_refresh_tokens (
    token_hash text PRIMARY KEY,
    family_id uuid NOT NULL,
    consumed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_consumed_refresh_tokens_consumed_at
    ON consumed_refresh_tokens(consumed_at);

CREATE INDEX idx_consumed_refresh_tokens_family_id
    ON consumed_refresh_tokens(family_id);
