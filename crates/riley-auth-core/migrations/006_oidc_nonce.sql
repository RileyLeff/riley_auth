-- Add nonce column to authorization_codes for OIDC compliance.
-- The nonce is passed by the client during authorization and echoed back
-- in the ID token, allowing the client to mitigate replay attacks.
ALTER TABLE authorization_codes ADD COLUMN nonce text;
