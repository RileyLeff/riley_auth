-- Add nonce column to refresh_tokens so that nonce is preserved across token
-- rotations during OIDC flows. The authorization request's nonce is stored on
-- the initial refresh token and carried forward on each refresh, allowing the
-- ID token issued on refresh to include the original nonce.
ALTER TABLE refresh_tokens ADD COLUMN nonce text;
