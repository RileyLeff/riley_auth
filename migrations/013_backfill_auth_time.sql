-- Backfill auth_time for pre-migration refresh tokens.
-- Uses created_at as a reasonable approximation of the original
-- authentication event time.
UPDATE refresh_tokens
SET auth_time = EXTRACT(EPOCH FROM created_at)::bigint
WHERE auth_time IS NULL;
