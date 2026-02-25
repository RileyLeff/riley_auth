-- v5 Phase 3: Track auth_time for OIDC compliance.
-- Stores the Unix timestamp of the original authentication event,
-- propagated through token rotation per OIDC Core 1.0 Section 12.2.
ALTER TABLE refresh_tokens ADD COLUMN auth_time bigint;
